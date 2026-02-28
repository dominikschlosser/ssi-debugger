// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import (
	"testing"
)

func TestResolveCredentialIdentifier_FromAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
		"authorization_details": []any{
			map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "pid-config",
				"credential_identifiers":      []any{"cred-id-abc", "cred-id-def"},
			},
		},
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"pid-config"})
	if got != "cred-id-abc" {
		t.Errorf("expected cred-id-abc, got %s", got)
	}
}

func TestResolveCredentialIdentifier_FallbackToConfigID(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"pid-config"})
	if got != "pid-config" {
		t.Errorf("expected pid-config, got %s", got)
	}
}

func TestResolveCredentialIdentifier_EmptyAuthDetails(t *testing.T) {
	tokenResp := map[string]any{
		"access_token":          "token123",
		"authorization_details": []any{},
	}

	got := resolveCredentialIdentifier(tokenResp, []string{"fallback"})
	if got != "fallback" {
		t.Errorf("expected fallback, got %s", got)
	}
}

func TestResolveCredentialIdentifier_NoConfigIDs(t *testing.T) {
	tokenResp := map[string]any{
		"access_token": "token123",
	}

	got := resolveCredentialIdentifier(tokenResp, nil)
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestExtractCredential_SingleField(t *testing.T) {
	resp := map[string]any{
		"credential": "eyJhbGci...",
	}

	got := extractCredential(resp)
	if got != "eyJhbGci..." {
		t.Errorf("expected eyJhbGci..., got %s", got)
	}
}

func TestExtractCredential_CredentialsArray(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{
			map[string]any{
				"credential": "eyJhbGci-from-array",
			},
		},
	}

	got := extractCredential(resp)
	if got != "eyJhbGci-from-array" {
		t.Errorf("expected eyJhbGci-from-array, got %s", got)
	}
}

func TestExtractCredential_CredentialsArrayRawStrings(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{
			"raw-credential-string",
		},
	}

	got := extractCredential(resp)
	if got != "raw-credential-string" {
		t.Errorf("expected raw-credential-string, got %s", got)
	}
}

func TestExtractCredential_Empty(t *testing.T) {
	resp := map[string]any{
		"status": "ok",
	}

	got := extractCredential(resp)
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestExtractCredential_EmptyCredentialsArray(t *testing.T) {
	resp := map[string]any{
		"credentials": []any{},
	}

	got := extractCredential(resp)
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestResolveCredentialFormat(t *testing.T) {
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid-sdjwt": map[string]any{
				"format": "dc+sd-jwt",
			},
			"pid-mdoc": map[string]any{
				"format": "mso_mdoc",
			},
		},
	}

	tests := []struct {
		name     string
		configID string
		want     string
	}{
		{"sd-jwt config", "pid-sdjwt", "dc+sd-jwt"},
		{"mdoc config", "pid-mdoc", "mso_mdoc"},
		{"unknown config", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCredentialFormat(metadata, tt.configID)
			if got != tt.want {
				t.Errorf("resolveCredentialFormat(%s) = %s, want %s", tt.configID, got, tt.want)
			}
		})
	}
}

func TestResolveCredentialFormat_NoConfigs(t *testing.T) {
	metadata := map[string]any{}
	got := resolveCredentialFormat(metadata, "anything")
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestGetTokenEndpoint_DirectInMetadata(t *testing.T) {
	metadata := map[string]any{
		"token_endpoint": "https://issuer.example/token",
	}
	got := getTokenEndpoint(metadata, "https://issuer.example")
	if got != "https://issuer.example/token" {
		t.Errorf("expected direct token_endpoint, got %s", got)
	}
}

func TestGetTokenEndpoint_Fallback(t *testing.T) {
	metadata := map[string]any{}
	got := getTokenEndpoint(metadata, "https://issuer.example")
	// Falls back to issuer + /token when no OAuth metadata can be fetched
	if got != "https://issuer.example/token" {
		t.Errorf("expected fallback token endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_DirectInMetadata(t *testing.T) {
	metadata := map[string]any{
		"credential_endpoint": "https://issuer.example/credential",
	}
	got := getCredentialEndpoint(metadata, "https://issuer.example")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected direct credential_endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_Fallback(t *testing.T) {
	metadata := map[string]any{}
	got := getCredentialEndpoint(metadata, "https://issuer.example")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected fallback credential endpoint, got %s", got)
	}
}

func TestGetCredentialEndpoint_TrailingSlash(t *testing.T) {
	metadata := map[string]any{}
	got := getCredentialEndpoint(metadata, "https://issuer.example/")
	if got != "https://issuer.example/credential" {
		t.Errorf("expected trimmed trailing slash, got %s", got)
	}
}
