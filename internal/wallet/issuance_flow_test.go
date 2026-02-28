package wallet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

// mockIssuerOpts configures the mock issuer for tests.
type mockIssuerOpts struct {
	// tokenCNonce, if non-empty, is returned in the token response.
	tokenCNonce string
	// nonceEndpoint, if true, serves a nonce endpoint.
	nonceEndpoint bool
	// credentialResponse is the raw JSON object returned by the credential endpoint.
	// If nil, a default response with a single SD-JWT credential is returned.
	credentialResponse map[string]any
	// credentialConfigFormat overrides the format in credential_configurations_supported.
	credentialConfigFormat string
}

func setupMockIssuer(t *testing.T, w *Wallet, opts mockIssuerOpts) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)

	credResp := opts.credentialResponse
	if credResp == nil {
		credResp = map[string]any{"credential": credRaw}
	}

	configFormat := opts.credentialConfigFormat
	if configFormat == "" {
		configFormat = "dc+sd-jwt"
	}

	// Use a closure-based handler to capture serverURL dynamically.
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			meta := map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": configFormat,
					},
				},
			}
			if opts.nonceEndpoint {
				meta["nonce_endpoint"] = serverURL + "/nonce"
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "unsupported_grant_type"})
				return
			}
			resp := map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			}
			if opts.tokenCNonce != "" {
				resp["c_nonce"] = opts.tokenCNonce
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(resp)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/nonce"):
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "nonce-from-endpoint"})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-access-token" {
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(credResp)

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))

	serverURL = srv.URL

	// Build the credential offer URI
	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	return srv, offerURI
}

func generateTestCredential(t *testing.T, w *Wallet) string {
	t.Helper()
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test-issuer.example",
		VCT:       "TestIssuedCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test", "family_name": "User"},
		Key:       w.IssuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("generating test credential: %v", err)
	}
	return cred
}

func TestProcessCredentialOffer_HappyPath(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
	if result.Issuer != srv.URL {
		t.Errorf("expected issuer %s, got %s", srv.URL, result.Issuer)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].ID != result.CredentialID {
		t.Errorf("credential ID mismatch")
	}
}

func TestProcessCredentialOffer_NonceFallback(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:   "",
		nonceEndpoint: true,
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer with nonce fallback: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
}

func TestProcessCredentialOffer_Draft14CredentialsArray(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{
				map[string]any{"credential": credRaw},
			},
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer (draft 14): %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
}

func TestProcessCredentialOffer_Draft14RawStringArray(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{credRaw},
		},
	})
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer (draft 14 raw strings): %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
}
