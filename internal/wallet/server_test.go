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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/trustlist"
	"github.com/dominikschlosser/oid4vc-dev/internal/validate"
)

func newTestServer(t *testing.T, autoAccept bool) *Server {
	t.Helper()
	w := generateTestWallet(t)
	w.AutoAccept = autoAccept
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	return NewServer(w, 0, nil)
}

func newStrictTestServer(t *testing.T, autoAccept bool) *Server {
	t.Helper()
	srv := newTestServer(t, autoAccept)
	srv.wallet.ValidationMode = ValidationModeStrict
	return srv
}

func serverRequest(t *testing.T, srv *Server, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func decodeJSONArray(t *testing.T, w *httptest.ResponseRecorder) []any {
	t.Helper()
	var result []any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON array: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func decodeCompactJWTHeader(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.SplitN(strings.TrimSpace(raw), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding compact JWT header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing compact JWT header: %v", err)
	}
	return header
}

func decodeCompactJWTPayload(t *testing.T, raw string, dest any) {
	t.Helper()
	parts := strings.SplitN(strings.TrimSpace(raw), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", raw)
	}
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding compact JWT payload: %v", err)
	}
	if err := json.Unmarshal(payloadBytes, dest); err != nil {
		t.Fatalf("parsing compact JWT payload: %v", err)
	}
}

func verifyCompactJWTSignatureWithX5CLeaf(t *testing.T, raw string, header map[string]any) {
	t.Helper()
	token, err := sdjwt.Parse(strings.TrimSpace(raw))
	if err != nil {
		t.Fatalf("parsing signed JWT: %v", err)
	}
	entries, err := normalizeMetadataX5CEntries(header["x5c"])
	if err != nil {
		t.Fatalf("parsing x5c header: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected x5c entries in JWT header")
	}
	leafDER, err := base64.StdEncoding.DecodeString(entries[0])
	if err != nil {
		t.Fatalf("decoding x5c leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing x5c leaf: %v", err)
	}
	result := sdjwt.Verify(token, leafCert.PublicKey)
	if result == nil || !result.SignatureValid {
		t.Fatal("expected compact JWT signature to verify with x5c leaf")
	}
}

// --- Credential Management API Tests ---

func TestListCredentials(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/credentials", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	creds := decodeJSONArray(t, w)
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestAuthorize_StrictRejectsTransactionData(t *testing.T) {
	srv := newStrictTestServer(t, true)
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&transaction_data=%5B%5D", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "transaction_data") {
		t.Fatalf("expected transaction_data error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsInvalidMDocAlgValuesSupported(t *testing.T) {
	srv := newTestServer(t, true)
	requestJWT := makeTestJWT(map[string]any{
		"alg": "none",
		"typ": "oauth-authz-req+jwt",
	}, map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_uri":  "https://verifier.example/response",
		"nonce":         "nonce",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid_mdoc",
					"format": "mso_mdoc",
				},
			},
		},
		"client_metadata": map[string]any{
			"vp_formats_supported": map[string]any{
				"mso_mdoc": map[string]any{
					"alg_values_supported": []any{"ES256"},
				},
			},
		},
	})

	req := httptest.NewRequest("GET", "/authorize?request="+url.QueryEscape(requestJWT), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "COSE algorithm number") {
		t.Fatalf("expected mdoc alg validation error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsInvalidOuterClientMetadata(t *testing.T) {
	srv := newTestServer(t, true)
	clientMetadata := `{"vp_formats_supported":{"mso_mdoc":{"alg_values_supported":["ES256"]}}}`
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&response_uri=https://verifier.example/response&client_metadata="+url.QueryEscape(clientMetadata), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "COSE algorithm number") {
		t.Fatalf("expected mdoc alg validation error, got %s", w.Body.String())
	}
}

func TestAuthorize_RejectsUnsupportedRequestURIMethod(t *testing.T) {
	srv := newTestServer(t, true)
	req := httptest.NewRequest("GET", "/authorize?client_id=https://verifier.example&response_type=vp_token&response_uri=https://verifier.example/response&request_uri=https://verifier.example/request.jwt&request_uri_method=put", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "request_uri_method") {
		t.Fatalf("expected request_uri_method error, got %s", w.Body.String())
	}
}

func TestImportCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	// Import an SD-JWT credential via API
	sdjwt := generateSDJWTForTest(t, srv)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(sdjwt))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %v", result["format"])
	}
	if result["id"] == nil {
		t.Error("expected id in response")
	}
}

func TestImportCredentialAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "POST", "/api/credentials", "")

	// Request with empty body
	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(""))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = w
}

func TestImportCredentialAPI_Invalid(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader("not-a-credential"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid credential, got %d", w.Code)
	}
}

func TestDeleteCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	// Get credentials first
	w := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds := decodeJSONArray(t, w)
	id := creds[0].(map[string]any)["id"].(string)

	// Delete it
	req := httptest.NewRequest("DELETE", "/api/credentials/"+id, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	// Verify it's gone
	w2 := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds2 := decodeJSONArray(t, w2)
	if len(creds2) != 1 {
		t.Errorf("expected 1 credential after deletion, got %d", len(creds2))
	}
}

func TestDeleteCredentialAPI_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("DELETE", "/api/credentials/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Consent Request API Tests ---

func TestListPendingRequests_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/requests", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	requests := decodeJSONArray(t, w)
	if len(requests) != 0 {
		t.Errorf("expected 0 pending requests, got %d", len(requests))
	}
}

func TestApproveRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/approve", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDenyRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/deny", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Activity Log API Tests ---

func TestLogAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/log", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Static Files Tests ---

func TestStaticFiles_Index(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "OID4VC Dev Wallet") {
		t.Error("expected index.html to contain 'OID4VC Dev Wallet'")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("expected index.html to reference app.js")
	}
}

func TestStaticFiles_CSS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/style.css", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "--bg") {
		t.Error("expected CSS to contain --bg custom property")
	}
}

func TestStaticFiles_JS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/app.js", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/api/credentials") {
		t.Error("expected app.js to reference /api/credentials")
	}
}

// --- Presentation API Tests ---

func TestPresentationAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("POST", "/api/presentations", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPresentationAPI_InvalidURI(t *testing.T) {
	srv := newTestServer(t, true)
	w := serverRequest(t, srv, "POST", "/api/presentations", `{"uri":"not-a-valid-uri"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Full Presentation E2E Test (auto-accept) ---

func TestPresentationFlow_AutoAccept(t *testing.T) {
	srv := newTestServer(t, true)

	// Create a mock verifier that receives the VP token
	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"redirect_uri": "https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	// Build a DCQL authorization request
	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	// Send request to /authorize
	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"test-nonce-123"},
		"state":         {"test-state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	// Verify the verifier received the VP token
	if receivedBody == "" {
		t.Fatal("verifier did not receive VP token")
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}

	vpTokenRaw := parsedForm.Get("vp_token")
	if vpTokenRaw == "" {
		t.Fatal("expected vp_token in verifier request")
	}

	// Per OID4VP 1.0: vp_token is a JSON object where values are arrays of strings
	var vpToken map[string][]any
	if err := json.Unmarshal([]byte(vpTokenRaw), &vpToken); err != nil {
		t.Fatalf("vp_token should be a JSON object: %v", err)
	}
	pidArr, ok := vpToken["pid"]
	if !ok {
		t.Fatal("expected 'pid' key in vp_token")
	}
	if len(pidArr) != 1 {
		t.Errorf("expected single-element array for 'pid', got %d elements", len(pidArr))
	}
	if _, ok := pidArr[0].(string); !ok {
		t.Errorf("expected string presentation in array, got %T", pidArr[0])
	}

	state := parsedForm.Get("state")
	if state != "test-state" {
		t.Errorf("expected state 'test-state', got %s", state)
	}

	// Response should contain redirect_uri from verifier
	response, ok := result["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response object in result")
	}
	if response["redirect_uri"] != "https://verifier.example/done" {
		t.Errorf("expected redirect_uri, got %v", response["redirect_uri"])
	}
}

func TestPresentationFlow_AutoAccept_NoMatch(t *testing.T) {
	srv := newTestServer(t, true)

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeJSON(t, w)
	if result["status"] != "no_match" {
		t.Errorf("expected status 'no_match', got %v", result["status"])
	}
}

func TestPresentationFlow_AutoAccept_MultipleCredentials(t *testing.T) {
	srv := newTestServer(t, true)

	// Create verifier that captures the request body
	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	// Request both SD-JWT and mDoc credentials
	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	// Should have submitted tokens for both credentials
	vpTokenKeys, ok := result["vp_token_keys"].([]any)
	if !ok {
		t.Fatal("expected vp_token_keys in result")
	}
	if len(vpTokenKeys) != 2 {
		t.Errorf("expected 2 vp_token_keys, got %d", len(vpTokenKeys))
	}

	// Validate the actual vp_token structure sent to the verifier
	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}

	// Per OID4VP 1.0: vp_token is a JSON object with query IDs as keys and arrays as values
	var vpToken map[string][]any
	if err := json.Unmarshal([]byte(parsedForm.Get("vp_token")), &vpToken); err != nil {
		t.Fatalf("vp_token should be a JSON object with array values: %v", err)
	}

	// Must have both credential query IDs
	if _, ok := vpToken["pid_sdjwt"]; !ok {
		t.Error("expected 'pid_sdjwt' key in vp_token")
	}
	if _, ok := vpToken["pid_mdoc"]; !ok {
		t.Error("expected 'pid_mdoc' key in vp_token")
	}

	// Each value must be a single-element array (multiple not set)
	for _, qid := range []string{"pid_sdjwt", "pid_mdoc"} {
		arr := vpToken[qid]
		if len(arr) != 1 {
			t.Errorf("expected single-element array for %q, got %d elements", qid, len(arr))
		}
		if _, ok := arr[0].(string); !ok {
			t.Errorf("expected string presentation for %q, got %T", qid, arr[0])
		}
	}

	// Must not have extra keys
	if len(vpToken) != 2 {
		t.Errorf("expected exactly 2 keys in vp_token, got %d", len(vpToken))
	}
}

func TestPresentationFlow_AutoAccept_POST(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	form := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestAuthorize_MissingClientID(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("GET", "/authorize?response_type=vp_token", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing client_id, got %d", w.Code)
	}
}

// --- Consent Flow (Interactive) ---

func TestConsentFlow_ApproveAndDeny(t *testing.T) {
	srv := newTestServer(t, false) // interactive mode

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	// Start the authorize flow in a goroutine (it blocks waiting for consent)
	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for the consent request to appear
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	// Approve via API
	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}

	// The authorize should now complete
	w := <-resultCh
	if w.Code != http.StatusOK {
		t.Fatalf("authorize expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestConsentFlow_Deny(t *testing.T) {
	srv := newTestServer(t, false)

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for consent request
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	// Deny
	denyReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(denyRec, denyReq)

	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d", denyRec.Code)
	}

	w := <-resultCh
	result := decodeJSON(t, w)
	if result["status"] != "denied" {
		t.Errorf("expected status 'denied', got %v", result["status"])
	}
}

// --- Trust List API Tests ---

func TestTrustListAPI(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Errorf("expected Content-Type application/jwt, got %s", ct)
	}

	// Should be a valid 3-part JWT
	jwt := w.Body.String()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Payload should be parseable and contain trust list fields
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if _, ok := payload["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in payload")
	}
	if _, ok := payload["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in payload")
	}
}

func TestTrustListAPI_ParseableByTrustlistParser(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tl, err := trustlist.Parse(w.Body.String())
	if err != nil {
		t.Fatalf("trust list parser failed: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("expected SchemeInfo to be parsed")
	}
	if tl.SchemeInfo.SchemeOperatorName != "OID4VC Dev Wallet" {
		t.Errorf("expected operator name 'OID4VC Dev Wallet', got %q", tl.SchemeInfo.SchemeOperatorName)
	}
	if tl.SchemeInfo.LoTEType != pidTrustListType {
		t.Errorf("unexpected LoTEType: %s", tl.SchemeInfo.LoTEType)
	}
	if tl.SchemeInfo.ListIssueDatetime == "" {
		t.Fatal("expected ListIssueDateTime to be parsed")
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(tl.Entities))
	}
	if tl.Entities[0].Name != "OID4VC Dev Wallet PID Provider" {
		t.Errorf("expected entity name 'OID4VC Dev Wallet PID Provider', got %q", tl.Entities[0].Name)
	}
	if len(tl.Entities[0].Services) != 2 {
		t.Fatalf("expected 2 services (issuance + revocation), got %d", len(tl.Entities[0].Services))
	}

	// Verify issuance service
	issuanceSvc := tl.Entities[0].Services[0]
	if issuanceSvc.ServiceType != "http://uri.etsi.org/19602/SvcType/PID/Issuance" {
		t.Errorf("unexpected issuance service type: %s", issuanceSvc.ServiceType)
	}
	if len(issuanceSvc.Certificates) != 1 {
		t.Fatalf("expected 1 certificate in issuance service, got %d", len(issuanceSvc.Certificates))
	}
	certPub, ok := issuanceSvc.Certificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key in issuance certificate")
	}
	if !certPub.Equal(&srv.wallet.CAKey.PublicKey) {
		t.Error("issuance certificate public key does not match wallet CA key")
	}

	// Verify revocation service
	revocationSvc := tl.Entities[0].Services[1]
	if revocationSvc.ServiceType != "http://uri.etsi.org/19602/SvcType/PID/Revocation" {
		t.Errorf("unexpected revocation service type: %s", revocationSvc.ServiceType)
	}
	if len(revocationSvc.Certificates) != 1 {
		t.Fatalf("expected 1 certificate in revocation service, got %d", len(revocationSvc.Certificates))
	}
}

func TestTrustListAPI_RemainsCertificateCentric(t *testing.T) {
	srv := newTestServer(t, false)

	resp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var payload map[string]any
	decodeCompactJWTPayload(t, resp.Body.String(), &payload)

	entities, ok := payload["TrustedEntitiesList"].([]any)
	if !ok || len(entities) == 0 {
		t.Fatalf("expected TrustedEntitiesList entries, got %T", payload["TrustedEntitiesList"])
	}
	entity, ok := entities[0].(map[string]any)
	if !ok {
		t.Fatalf("expected trusted entity object, got %T", entities[0])
	}
	services, ok := entity["TrustedEntityServices"].([]any)
	if !ok || len(services) == 0 {
		t.Fatalf("expected TrustedEntityServices entries, got %T", entity["TrustedEntityServices"])
	}

	forbiddenKeys := []string{
		"providerId",
		"providerClass",
		"currentStatus",
		"statusHistory",
		"authorizedAttestationTypes",
		"entitlements",
		"providesAttestations",
	}

	for _, serviceEntry := range services {
		service, ok := serviceEntry.(map[string]any)
		if !ok {
			t.Fatalf("expected service object, got %T", serviceEntry)
		}
		info, ok := service["ServiceInformation"].(map[string]any)
		if !ok {
			t.Fatalf("expected ServiceInformation object, got %T", service["ServiceInformation"])
		}
		for _, key := range forbiddenKeys {
			if _, exists := info[key]; exists {
				t.Errorf("trust list service must not expose %q", key)
			}
		}
	}
}

func TestJWTVCIssuerMetadata_ExposesSigningKeyTrustedByTrustList(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	expMin := time.Now().Add(24 * time.Hour).Unix()
	srv := NewServer(w, 0, nil)
	expMax := time.Now().Add(24 * time.Hour).Unix()

	metaResp := serverRequest(t, srv, "GET", "/.well-known/jwt-vc-issuer", "")
	if metaResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", metaResp.Code, metaResp.Body.String())
	}
	meta := decodeJSON(t, metaResp)
	if meta["issuer"] != w.IssuerURL {
		t.Fatalf("expected issuer %s, got %v", w.IssuerURL, meta["issuer"])
	}

	jwks, ok := meta["jwks"].(map[string]any)
	if !ok {
		t.Fatal("expected jwks object in metadata")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected a single JWK, got %v", jwks["keys"])
	}
	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected JWK object, got %T", keys[0])
	}
	wantKid := mock.KeyIDForPublicKey(&w.IssuerKey.PublicKey)
	if jwk["kid"] != wantKid {
		t.Fatalf("expected metadata kid %s, got %v", wantKid, jwk["kid"])
	}
	exp, ok := jwk["exp"].(float64)
	if !ok {
		t.Fatalf("expected numeric exp in JWK, got %T", jwk["exp"])
	}
	if got := int64(exp); got < expMin || got > expMax {
		t.Fatalf("expected JWK exp between %d and %d, got %d", expMin, expMax, got)
	}

	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("expected single leaf certificate in JWK x5c, got %v", jwk["x5c"])
	}
	leafB64, ok := x5c[0].(string)
	if !ok {
		t.Fatalf("expected string x5c leaf, got %T", x5c[0])
	}
	leafDER, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		t.Fatalf("decoding x5c leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing x5c leaf: %v", err)
	}

	tlResp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if tlResp.Code != http.StatusOK {
		t.Fatalf("expected trust list 200, got %d: %s", tlResp.Code, tlResp.Body.String())
	}
	tl, err := trustlist.Parse(strings.TrimSpace(tlResp.Body.String()))
	if err != nil {
		t.Fatalf("parsing trust list: %v", err)
	}
	tlCerts := trustlist.ExtractPublicKeys(tl)
	validatedKey, err := validate.ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err != nil {
		t.Fatalf("validating issuer metadata x5c against trust list: %v", err)
	}
	issuerPub, ok := validatedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", validatedKey)
	}
	if !issuerPub.Equal(&w.IssuerKey.PublicKey) {
		t.Fatal("issuer metadata leaf certificate does not contain the wallet issuer key")
	}

	var rawSDJWT string
	for _, cred := range w.GetCredentials() {
		if cred.Format == "dc+sd-jwt" {
			rawSDJWT = cred.Raw
			break
		}
	}
	if rawSDJWT == "" {
		t.Fatal("expected generated SD-JWT credential")
	}
	token, err := sdjwt.Parse(rawSDJWT)
	if err != nil {
		t.Fatalf("parsing generated SD-JWT: %v", err)
	}
	if token.Payload["iss"] != w.IssuerURL {
		t.Fatalf("expected SD-JWT iss %s, got %v", w.IssuerURL, token.Payload["iss"])
	}
	if token.Header["kid"] != wantKid {
		t.Fatalf("expected SD-JWT kid %s, got %v", wantKid, token.Header["kid"])
	}

	metaResp2 := serverRequest(t, srv, "GET", "/.well-known/jwt-vc-issuer", "")
	if metaResp2.Code != http.StatusOK {
		t.Fatalf("expected second metadata request 200, got %d: %s", metaResp2.Code, metaResp2.Body.String())
	}
	meta2 := decodeJSON(t, metaResp2)
	jwks2, ok := meta2["jwks"].(map[string]any)
	if !ok {
		t.Fatal("expected jwks object in second metadata response")
	}
	keys2, ok := jwks2["keys"].([]any)
	if !ok || len(keys2) != 1 {
		t.Fatalf("expected a single JWK in second metadata response, got %v", jwks2["keys"])
	}
	jwk2, ok := keys2[0].(map[string]any)
	if !ok {
		t.Fatalf("expected second JWK object, got %T", keys2[0])
	}
	if jwk2["exp"] != jwk["exp"] {
		t.Fatalf("expected JWK exp to stay stable across requests, got %v then %v", jwk["exp"], jwk2["exp"])
	}
}

func TestOpenIDCredentialIssuerMetadata_SignedJWTContainsIssuerInfo(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	resp := serverRequest(t, srv, "GET", "/.well-known/openid-credential-issuer", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if ct := resp.Header().Get("Content-Type"); ct != "application/openidvci-issuer-metadata+jwt" {
		t.Fatalf("expected signed issuer metadata content type, got %s", ct)
	}

	raw := strings.TrimSpace(resp.Body.String())
	header := decodeCompactJWTHeader(t, raw)
	if header["typ"] != "openidvci-issuer-metadata+jwt" {
		t.Fatalf("expected issuer metadata JWT typ, got %v", header["typ"])
	}
	verifyCompactJWTSignatureWithX5CLeaf(t, raw, header)

	var payload map[string]any
	decodeCompactJWTPayload(t, raw, &payload)
	if payload["credential_issuer"] != w.IssuerURL {
		t.Fatalf("expected credential_issuer %s, got %v", w.IssuerURL, payload["credential_issuer"])
	}

	configs, ok := payload["credential_configurations_supported"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential configurations, got %T", payload["credential_configurations_supported"])
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 credential configurations, got %d", len(configs))
	}

	issuerInfo, ok := payload["issuer_info"].([]any)
	if !ok || len(issuerInfo) != 1 {
		t.Fatalf("expected single issuer_info entry, got %v", payload["issuer_info"])
	}
	entry, ok := issuerInfo[0].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info object, got %T", issuerInfo[0])
	}
	if entry["format"] != "registrar_dataset" {
		t.Fatalf("expected registrar_dataset issuer_info, got %v", entry["format"])
	}
	record, ok := entry["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info data object, got %T", entry["data"])
	}
	if record["registryURI"] != w.IssuerURL+"/api/registrar/wrp" {
		t.Fatalf("expected registryURI %s, got %v", w.IssuerURL+"/api/registrar/wrp", record["registryURI"])
	}
	entitlements, ok := record["entitlements"].([]any)
	if !ok || len(entitlements) != 1 || entitlements[0] != pidProviderEntitlement {
		t.Fatalf("expected PID provider entitlement, got %v", record["entitlements"])
	}
	provides, ok := record["providesAttestations"].([]any)
	if !ok || len(provides) != 2 {
		t.Fatalf("expected 2 provided attestation entries, got %v", record["providesAttestations"])
	}

	var sawVCT, sawDocType bool
	for _, entry := range provides {
		att, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("expected providesAttestations object, got %T", entry)
		}
		meta, ok := att["meta"].(map[string]any)
		if !ok {
			t.Fatalf("expected attestation meta object, got %T", att["meta"])
		}
		switch att["format"] {
		case "dc+sd-jwt":
			values, ok := meta["vct_values"].([]any)
			if !ok || len(values) != 1 || values[0] != mock.DefaultPIDVCT {
				t.Fatalf("expected SD-JWT attestation with VCT %s, got %v", mock.DefaultPIDVCT, meta["vct_values"])
			}
			sawVCT = true
		case "mso_mdoc":
			if meta["doctype_value"] != "eu.europa.ec.eudi.pid.1" {
				t.Fatalf("expected mDoc attestation docType, got %v", meta["doctype_value"])
			}
			sawDocType = true
		}
	}
	if !sawVCT || !sawDocType {
		t.Fatalf("expected both SD-JWT and mDoc attestation entries, got %v", record["providesAttestations"])
	}
}

func TestRegistrarWRPList_FiltersByProvidesAttestation(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	matchResp := serverRequest(t, srv, "GET", "/api/registrar/wrp?providesattestation="+url.QueryEscape(mock.DefaultPIDVCT), "")
	if matchResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", matchResp.Code, matchResp.Body.String())
	}
	if ct := matchResp.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("expected registrar application/jwt content type, got %s", ct)
	}
	var matched []map[string]any
	decodeCompactJWTPayload(t, matchResp.Body.String(), &matched)
	if len(matched) != 1 {
		t.Fatalf("expected 1 matching registrar entry, got %d", len(matched))
	}
	if matched[0]["registryURI"] != w.IssuerURL+"/api/registrar/wrp" {
		t.Fatalf("expected matching registryURI, got %v", matched[0]["registryURI"])
	}

	missResp := serverRequest(t, srv, "GET", "/api/registrar/wrp?providesattestation="+url.QueryEscape("urn:example:unknown"), "")
	if missResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", missResp.Code, missResp.Body.String())
	}
	var unmatched []map[string]any
	decodeCompactJWTPayload(t, missResp.Body.String(), &unmatched)
	if len(unmatched) != 0 {
		t.Fatalf("expected no registrar entries for unmatched attestation, got %d", len(unmatched))
	}
}

func TestNonPIDMetadataAndTrustList_DoNotPretendToBePID(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	w.IssuedAttestations = []IssuedAttestationSpec{
		{Format: "dc+sd-jwt", VCT: "urn:test:employee:1"},
		{Format: "mso_mdoc", DocType: "org.iso.23220.photoid.1"},
	}
	srv := NewServer(w, 0, nil)

	metaResp := serverRequest(t, srv, "GET", "/.well-known/openid-credential-issuer", "")
	if metaResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", metaResp.Code, metaResp.Body.String())
	}
	var metaPayload map[string]any
	decodeCompactJWTPayload(t, metaResp.Body.String(), &metaPayload)
	issuerInfo, ok := metaPayload["issuer_info"].([]any)
	if !ok || len(issuerInfo) != 1 {
		t.Fatalf("expected single issuer_info entry, got %v", metaPayload["issuer_info"])
	}
	entry, ok := issuerInfo[0].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info object, got %T", issuerInfo[0])
	}
	record, ok := entry["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected issuer_info data object, got %T", entry["data"])
	}
	entitlements, ok := record["entitlements"].([]any)
	if !ok || len(entitlements) != 1 || entitlements[0] != nonQEAAProviderEntitlement {
		t.Fatalf("expected Non_Q_EAA entitlement, got %v", record["entitlements"])
	}
	provides, ok := record["providesAttestations"].([]any)
	if !ok || len(provides) != 2 {
		t.Fatalf("expected 2 provided attestation entries, got %v", record["providesAttestations"])
	}
	var sawCustomVCT, sawCustomDocType bool
	for _, raw := range provides {
		att, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("expected provided attestation object, got %T", raw)
		}
		meta, ok := att["meta"].(map[string]any)
		if !ok {
			t.Fatalf("expected provided attestation meta, got %T", att["meta"])
		}
		switch att["format"] {
		case "dc+sd-jwt":
			values, ok := meta["vct_values"].([]any)
			if ok && len(values) == 1 && values[0] == "urn:test:employee:1" {
				sawCustomVCT = true
			}
		case "mso_mdoc":
			if meta["doctype_value"] == "org.iso.23220.photoid.1" {
				sawCustomDocType = true
			}
		}
	}
	if !sawCustomVCT || !sawCustomDocType {
		t.Fatalf("expected custom non-PID attestation types, got %v", record["providesAttestations"])
	}

	trustListResp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if trustListResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", trustListResp.Code, trustListResp.Body.String())
	}
	var trustListPayload map[string]any
	decodeCompactJWTPayload(t, trustListResp.Body.String(), &trustListPayload)
	schemeInfo, ok := trustListPayload["ListAndSchemeInformation"].(map[string]any)
	if !ok {
		t.Fatalf("expected ListAndSchemeInformation object, got %T", trustListPayload["ListAndSchemeInformation"])
	}
	if schemeInfo["LoTEType"] != localTrustListType {
		t.Fatalf("expected local trust-list profile for non-PID wallet, got %v", schemeInfo["LoTEType"])
	}
	if _, ok := schemeInfo["StatusDeterminationApproach"]; ok {
		t.Fatalf("non-PID local trust list must not advertise PID status determination, got %v", schemeInfo["StatusDeterminationApproach"])
	}
	entities, ok := trustListPayload["TrustedEntitiesList"].([]any)
	if !ok || len(entities) != 1 {
		t.Fatalf("expected one trusted entity, got %v", trustListPayload["TrustedEntitiesList"])
	}
	entity, ok := entities[0].(map[string]any)
	if !ok {
		t.Fatalf("expected trusted entity object, got %T", entities[0])
	}
	services, ok := entity["TrustedEntityServices"].([]any)
	if !ok || len(services) != 2 {
		t.Fatalf("expected 2 trusted services, got %v", entity["TrustedEntityServices"])
	}
	gotTypes := make([]string, 0, len(services))
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("expected service object, got %T", raw)
		}
		info, ok := service["ServiceInformation"].(map[string]any)
		if !ok {
			t.Fatalf("expected ServiceInformation object, got %T", service["ServiceInformation"])
		}
		gotTypes = append(gotTypes, info["ServiceTypeIdentifier"].(string))
	}
	if gotTypes[0] != localIssuanceServiceType || gotTypes[1] != localRevocationServiceType {
		t.Fatalf("expected local issuance/revocation service types, got %v", gotTypes)
	}
}

func TestTrustListsAPI_MixedProfilesExposeMultipleTrustListsAndKeepLegacyPIDDefault(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://localhost:8443"
	if err := w.RegisterIssuedAttestation(applyPIDTrustProfileDefaults(IssuedAttestationSpec{
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
	})); err != nil {
		t.Fatalf("registering PID attestation: %v", err)
	}
	if err := w.RegisterIssuedAttestation(applyLocalTrustProfileDefaults(IssuedAttestationSpec{
		Format:  "mso_mdoc",
		DocType: "org.iso.23220.photoid.1",
		Entitlements: []string{
			nonQEAAProviderEntitlement,
		},
	})); err != nil {
		t.Fatalf("registering local attestation: %v", err)
	}
	srv := NewServer(w, 0, nil)

	indexResp := serverRequest(t, srv, "GET", "/api/trustlists", "")
	if indexResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", indexResp.Code, indexResp.Body.String())
	}
	index := decodeJSON(t, indexResp)
	rawLists, ok := index["trust_lists"].([]any)
	if !ok || len(rawLists) != 2 {
		t.Fatalf("expected 2 trust-list index entries, got %v", index["trust_lists"])
	}
	var sawPIDDefault, sawLocal bool
	for _, raw := range rawLists {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("expected trust-list entry object, got %T", raw)
		}
		path, ok := entry["path"].(string)
		if !ok || !strings.HasPrefix(path, "/api/trustlists/") {
			t.Fatalf("expected relative trust-list path, got %v", entry["path"])
		}
		switch entry["id"] {
		case "pid":
			if entry["default"] != true {
				t.Fatalf("expected pid trust list to be default, got %v", entry["default"])
			}
			if entry["advertised_url"] != "https://localhost:8443/api/trustlists/pid" {
				t.Fatalf("expected pid advertised_url, got %v", entry["advertised_url"])
			}
			if entry["url"] != entry["advertised_url"] {
				t.Fatalf("expected legacy url alias to match advertised_url, got %v vs %v", entry["url"], entry["advertised_url"])
			}
			sawPIDDefault = true
		case "local":
			if entry["path"] != "/api/trustlists/local" {
				t.Fatalf("expected local path, got %v", entry["path"])
			}
			if entry["advertised_url"] != "https://localhost:8443/api/trustlists/local" {
				t.Fatalf("expected local advertised_url, got %v", entry["advertised_url"])
			}
			sawLocal = true
		}
	}
	if !sawPIDDefault || !sawLocal {
		t.Fatalf("expected pid+local trust-list entries, got %v", rawLists)
	}

	legacyResp := serverRequest(t, srv, "GET", "/api/trustlist", "")
	if legacyResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", legacyResp.Code, legacyResp.Body.String())
	}
	var legacyPayload map[string]any
	decodeCompactJWTPayload(t, legacyResp.Body.String(), &legacyPayload)
	legacyScheme := legacyPayload["ListAndSchemeInformation"].(map[string]any)
	if legacyScheme["LoTEType"] != pidTrustListType {
		t.Fatalf("expected legacy /api/trustlist to return pid profile, got %v", legacyScheme["LoTEType"])
	}

	selectedResp := serverRequest(t, srv, "GET", "/api/trustlist?doctype="+url.QueryEscape("org.iso.23220.photoid.1"), "")
	if selectedResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", selectedResp.Code, selectedResp.Body.String())
	}
	var selectedPayload map[string]any
	decodeCompactJWTPayload(t, selectedResp.Body.String(), &selectedPayload)
	selectedScheme := selectedPayload["ListAndSchemeInformation"].(map[string]any)
	if selectedScheme["LoTEType"] != localTrustListType {
		t.Fatalf("expected doctype-selected trust list to return local profile, got %v", selectedScheme["LoTEType"])
	}

	byIDResp := serverRequest(t, srv, "GET", "/api/trustlists/local", "")
	if byIDResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", byIDResp.Code, byIDResp.Body.String())
	}
	var byIDPayload map[string]any
	decodeCompactJWTPayload(t, byIDResp.Body.String(), &byIDPayload)
	byIDScheme := byIDPayload["ListAndSchemeInformation"].(map[string]any)
	if byIDScheme["LoTEType"] != localTrustListType {
		t.Fatalf("expected /api/trustlists/local to return local profile, got %v", byIDScheme["LoTEType"])
	}
	uris, ok := byIDScheme["SchemeInformationURI"].([]any)
	if !ok || len(uris) != 1 {
		t.Fatalf("expected SchemeInformationURI entry, got %v", byIDScheme["SchemeInformationURI"])
	}
	uri, ok := uris[0].(map[string]any)
	if !ok || uri["uriValue"] != "https://localhost:8443/api/trustlists/local" {
		t.Fatalf("expected per-id SchemeInformationURI, got %v", byIDScheme["SchemeInformationURI"])
	}
}

// --- Offer API Tests ---

func TestOfferAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/offers", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- OnConsentRequest Callback Tests ---

func TestOnConsentRequest_CalledOnInteractiveFlow(t *testing.T) {
	srv := newTestServer(t, false) // interactive mode

	var callbackCalled bool
	var callbackReqID string
	srv.SetOnConsentRequest(func(req *ConsentRequest) {
		callbackCalled = true
		callbackReqID = req.ID
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	// Start authorize flow in goroutine (blocks waiting for consent)
	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for consent request to appear
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	if !callbackCalled {
		t.Error("expected onConsentRequest callback to be called")
	}
	if callbackReqID != reqID {
		t.Errorf("callback received request ID %s, expected %s", callbackReqID, reqID)
	}

	// Approve to let the goroutine finish
	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	<-resultCh
}

func TestOnConsentRequest_NotCalledOnAutoAccept(t *testing.T) {
	srv := newTestServer(t, true) // auto-accept mode

	callbackCalled := false
	srv.SetOnConsentRequest(func(req *ConsentRequest) {
		callbackCalled = true
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if callbackCalled {
		t.Error("onConsentRequest callback should not be called in auto-accept mode")
	}
}

func TestPresentationFlow_RequestURIMethodPost(t *testing.T) {
	w := generateTestWallet(t)
	w.AutoAccept = true
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	// Create a mock verifier that receives the VP token
	var receivedVPToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		receivedVPToken = parsed.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	// Create a mock request_uri endpoint that expects POST with wallet_metadata/wallet_nonce
	var receivedMethod string
	var receivedWalletMeta string
	var receivedWalletNonce string
	requestURIServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		r.ParseForm()
		receivedWalletMeta = r.Form.Get("wallet_metadata")
		receivedWalletNonce = r.Form.Get("wallet_nonce")

		dcqlQuery := map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"given_name"}}},
				},
			},
		}
		dcqlJSON, _ := json.Marshal(dcqlQuery)

		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"nonce":         "test-nonce",
			"state":         "test-state",
			"response_uri":  verifier.URL,
			"dcql_query":    json.RawMessage(dcqlJSON),
			"wallet_nonce":  receivedWalletNonce,
		})
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		rw.Write([]byte(jwt))
	}))
	defer requestURIServer.Close()

	// Send request with request_uri and request_uri_method=post
	params := url.Values{
		"client_id":          {"https://verifier.example"},
		"response_type":      {"vp_token"},
		"request_uri":        {requestURIServer.URL},
		"request_uri_method": {"post"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify request_uri endpoint was called with POST
	if receivedMethod != "POST" {
		t.Errorf("expected POST to request_uri, got %s", receivedMethod)
	}
	if receivedWalletMeta == "" {
		t.Error("expected wallet_metadata in POST body")
	}
	if receivedWalletNonce == "" {
		t.Error("expected wallet_nonce in POST body")
	}

	// Verify wallet_metadata is valid JSON with expected fields
	var meta map[string]any
	if err := json.Unmarshal([]byte(receivedWalletMeta), &meta); err != nil {
		t.Fatalf("wallet_metadata not valid JSON: %v", err)
	}
	if meta["vp_formats_supported"] == nil {
		t.Error("expected vp_formats_supported in wallet_metadata")
	}

	// Verify the verifier received the VP token
	if receivedVPToken == "" {
		t.Fatal("verifier did not receive VP token")
	}
}

func TestPresentationFlow_RequestURIMethodPost_Encrypted(t *testing.T) {
	encKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	w := generateTestWallet(t)
	w.AutoAccept = true
	w.RequireEncryptedRequest = true
	w.RequestEncryptionKey = encKey
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	srv := NewServer(w, 0, nil)

	// Create a mock verifier that receives the VP token
	var receivedVPToken string
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.ParseQuery(string(body))
		receivedVPToken = parsed.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	// Mock request_uri endpoint: reads wallet encryption key from wallet_metadata,
	// encrypts the request object JWT as JWE
	requestURIServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		walletMetaStr := r.Form.Get("wallet_metadata")
		walletNonce := r.Form.Get("wallet_nonce")

		// Parse wallet_metadata to get encryption key
		var meta map[string]any
		json.Unmarshal([]byte(walletMetaStr), &meta)
		jwks := meta["jwks"].(map[string]any)
		keys := jwks["keys"].([]any)
		jwk := keys[0].(map[string]any)
		pubKey, err := ecdsaPublicKeyFromJWK(jwk["x"].(string), jwk["y"].(string))
		if err != nil {
			t.Fatalf("parsing wallet key: %v", err)
		}

		dcqlQuery := map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
					"claims": []any{map[string]any{"path": []any{"given_name"}}},
				},
			},
		}
		dcqlJSON, _ := json.Marshal(dcqlQuery)

		jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{
			"client_id":     "https://verifier.example",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"nonce":         "test-nonce",
			"state":         "test-state",
			"response_uri":  verifier.URL,
			"dcql_query":    json.RawMessage(dcqlJSON),
			"wallet_nonce":  walletNonce,
		})

		// Encrypt the JWT with the wallet's public key
		jweStr, _, err := EncryptJWE([]byte(jwt), pubKey, "kid", "ECDH-ES", "A128GCM", nil)
		if err != nil {
			t.Fatalf("encrypting request object: %v", err)
		}
		rw.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		rw.Write([]byte(jweStr))
	}))
	defer requestURIServer.Close()

	params := url.Values{
		"client_id":          {"https://verifier.example"},
		"response_type":      {"vp_token"},
		"request_uri":        {requestURIServer.URL},
		"request_uri_method": {"post"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := decodeJSON(t, rec)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	// Verify the verifier received the VP token (wallet successfully decrypted the JWE)
	if receivedVPToken == "" {
		t.Fatal("verifier did not receive VP token — wallet failed to decrypt JWE request object")
	}
}

// --- Helper ---

func generateSDJWTForTest(t *testing.T, srv *Server) string {
	t.Helper()
	result, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"test": "value"},
		Key:       srv.wallet.IssuerKey,
	})
	if err != nil {
		t.Fatalf("generating test SD-JWT: %v", err)
	}
	return result
}
