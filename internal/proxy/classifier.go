package proxy

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/web"
)

// Classify determines the OID4VP/VCI traffic class from the request/response.
func Classify(entry *TrafficEntry) {
	entry.Class = classifyEntry(entry)
	entry.ClassLabel = entry.Class.Label()
	entry.Decoded = decodeEntry(entry)
}

func classifyEntry(e *TrafficEntry) TrafficClass {
	u, _ := url.Parse(e.URL)
	path := ""
	query := url.Values{}
	if u != nil {
		path = u.Path
		query = u.Query()
	}

	// VCI: .well-known/openid-credential-issuer
	if strings.Contains(path, ".well-known/openid-credential-issuer") {
		return ClassVCIMetadata
	}

	// VCI: credential_offer or credential_offer_uri in query
	if query.Has("credential_offer") || query.Has("credential_offer_uri") {
		return ClassVCICredentialOffer
	}

	// VP Auth Request: client_id + response_type=vp_token
	if query.Get("client_id") != "" && query.Get("response_type") == "vp_token" {
		return ClassVPAuthRequest
	}

	// VP Request Object: response body is a JWT
	if e.Method == "GET" && isJWTBody(e.ResponseBody) {
		return ClassVPRequestObject
	}

	// POST-based classification
	if e.Method == "POST" {
		// VP Auth Response: body has vp_token
		if hasFormField(e.RequestBody, "vp_token") || hasJSONField(e.RequestBody, "vp_token") {
			return ClassVPAuthResponse
		}

		// VCI Token Request: path ends with /token
		if strings.HasSuffix(path, "/token") {
			return ClassVCITokenRequest
		}

		// VCI Credential Request: path ends with /credential
		if strings.HasSuffix(path, "/credential") || strings.HasSuffix(path, "/credentials") {
			return ClassVCICredentialRequest
		}
	}

	return ClassUnknown
}

func decodeEntry(e *TrafficEntry) map[string]any {
	decoded := make(map[string]any)

	switch e.Class {
	case ClassVPAuthRequest:
		u, _ := url.Parse(e.URL)
		if u != nil {
			q := u.Query()
			decoded["client_id"] = q.Get("client_id")
			decoded["response_type"] = q.Get("response_type")
			if v := q.Get("response_mode"); v != "" {
				decoded["response_mode"] = v
			}
			if v := q.Get("nonce"); v != "" {
				decoded["nonce"] = v
			}
			if v := q.Get("state"); v != "" {
				decoded["state"] = v
			}
			if v := q.Get("request_uri"); v != "" {
				decoded["request_uri"] = v
			}
			if v := q.Get("response_uri"); v != "" {
				decoded["response_uri"] = v
			}
		}

	case ClassVPRequestObject:
		if header, payload, _, err := format.ParseJWTParts(strings.TrimSpace(e.ResponseBody)); err == nil {
			decoded["header"] = header
			decoded["payload"] = payload
		}

	case ClassVPAuthResponse:
		fields := parseFormOrJSON(e.RequestBody)
		if vpToken, ok := fields["vp_token"]; ok {
			decoded["vp_token_preview"] = truncate(vpToken, 100)
			if cred, err := web.Decode(vpToken); err == nil {
				decoded["vp_token_decoded"] = cred
			}
		}
		if v, ok := fields["state"]; ok {
			decoded["state"] = v
		}
		if v, ok := fields["presentation_submission"]; ok {
			var ps map[string]any
			if err := json.Unmarshal([]byte(v), &ps); err == nil {
				decoded["presentation_submission"] = ps
			}
		}

	case ClassVCICredentialOffer:
		u, _ := url.Parse(e.URL)
		if u != nil {
			if offer := u.Query().Get("credential_offer"); offer != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(offer), &m); err == nil {
					decoded["credential_offer"] = m
				}
			}
			if uri := u.Query().Get("credential_offer_uri"); uri != "" {
				decoded["credential_offer_uri"] = uri
			}
		}

	case ClassVCIMetadata:
		if e.ResponseBody != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &m); err == nil {
				decoded["metadata"] = m
			}
		}

	case ClassVCITokenRequest:
		fields := parseFormOrJSON(e.RequestBody)
		for k, v := range fields {
			decoded[k] = v
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
			}
		}

	case ClassVCICredentialRequest:
		if e.RequestBody != "" {
			var reqBody map[string]any
			if err := json.Unmarshal([]byte(e.RequestBody), &reqBody); err == nil {
				decoded["request"] = reqBody
			}
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
				// Try to decode the credential inside the response
				if cred, ok := resp["credential"].(string); ok {
					if credDecoded, err := web.Decode(cred); err == nil {
						decoded["credential_decoded"] = credDecoded
					}
				}
			}
		}
	}

	if len(decoded) == 0 {
		return nil
	}
	return decoded
}

func isJWTBody(body string) bool {
	body = strings.TrimSpace(body)
	parts := strings.SplitN(body, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && !strings.ContainsAny(body, " \n\t{<")
}

func hasFormField(body, field string) bool {
	values, err := url.ParseQuery(body)
	if err != nil {
		return false
	}
	return values.Has(field)
}

func hasJSONField(body, field string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	_, ok := m[field]
	return ok
}

func parseFormOrJSON(body string) map[string]string {
	result := make(map[string]string)

	// Try URL-encoded form first
	values, err := url.ParseQuery(body)
	if err == nil && len(values) > 0 {
		for k := range values {
			result[k] = values.Get(k)
		}
		return result
	}

	// Try JSON
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		for k, v := range m {
			switch val := v.(type) {
			case string:
				result[k] = val
			default:
				if b, err := json.Marshal(v); err == nil {
					result[k] = string(b)
				}
			}
		}
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
