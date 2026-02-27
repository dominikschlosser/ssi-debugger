package wallet

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SubmitDirectPost submits a VP token via direct_post to the response URI.
func SubmitDirectPost(responseURI, state string, vpToken any) (*DirectPostResult, error) {
	form := url.Values{}
	if state != "" {
		form.Set("state", state)
	}

	tokenJSON, err := json.Marshal(vpToken)
	if err != nil {
		return nil, fmt.Errorf("marshaling vp_token: %w", err)
	}
	form.Set("vp_token", string(tokenJSON))

	resp, err := http.PostForm(responseURI, form)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}

	// Try to parse redirect_uri from response
	var respJSON map[string]any
	if err := json.Unmarshal(body, &respJSON); err == nil {
		if redirectURI, ok := respJSON["redirect_uri"].(string); ok {
			result.RedirectURI = redirectURI
		}
	}

	// Also check Location header
	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURI = loc
	}

	return result, nil
}

// DirectPostResult represents the result of a direct_post submission.
type DirectPostResult struct {
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// SubmitDirectPostJWT submits an encrypted JARM response via direct_post.jwt.
// The vp_token and state are inside the encrypted responseJWT payload.
func SubmitDirectPostJWT(responseURI string, responseJWT string) (*DirectPostResult, error) {
	form := url.Values{}
	form.Set("response", responseJWT)

	resp, err := http.PostForm(responseURI, form)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}

	var respJSON map[string]any
	if err := json.Unmarshal(body, &respJSON); err == nil {
		if redirectURI, ok := respJSON["redirect_uri"].(string); ok {
			result.RedirectURI = redirectURI
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURI = loc
	}

	return result, nil
}

// FormatDirectPostResult formats a direct post result for terminal output.
func FormatDirectPostResult(result *DirectPostResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Response: %d", result.StatusCode)
	if result.RedirectURI != "" {
		fmt.Fprintf(&sb, " → %s", result.RedirectURI)
	}
	return sb.String()
}
