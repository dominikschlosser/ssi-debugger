package wallet

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/openid4"
)

// ParseAuthorizationRequest parses an OID4VP authorization request from a URI or query params.
func ParseAuthorizationRequest(raw string) (*openid4.AuthorizationRequest, error) {
	raw = strings.TrimSpace(raw)

	reqType, result, err := openid4.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing authorization request: %w", err)
	}

	if reqType != openid4.TypeVP {
		return nil, fmt.Errorf("expected VP authorization request, got VCI")
	}

	authReq, ok := result.(*openid4.AuthorizationRequest)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	return authReq, nil
}

// ParseAuthorizationRequestFromParams parses an authorization request from URL query parameters.
func ParseAuthorizationRequestFromParams(params url.Values) (*openid4.AuthorizationRequest, error) {
	// Build a synthetic URI for the openid4 parser
	u := url.URL{
		Scheme:   "openid4vp",
		Host:     "authorize",
		RawQuery: params.Encode(),
	}
	return ParseAuthorizationRequest(u.String())
}

// GetResponseURI returns the URI where the VP response should be posted.
func GetResponseURI(authReq *openid4.AuthorizationRequest) string {
	if authReq.ResponseURI != "" {
		return authReq.ResponseURI
	}
	return authReq.RedirectURI
}

// GetResponseMode returns the response mode from the auth request.
func GetResponseMode(authReq *openid4.AuthorizationRequest) string {
	if authReq.ResponseMode != "" {
		return authReq.ResponseMode
	}
	return "direct_post"
}
