package wallet

import (
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func generateTestWallet(t *testing.T) *Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating holder key: %v", err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	return New(holderKey, issuerKey, false)
}

func generateTestWalletWithPID(t *testing.T) *Wallet {
	t.Helper()
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID credentials: %v", err)
	}
	return w
}

func TestNew(t *testing.T) {
	w := generateTestWallet(t)

	if w.HolderKey == nil {
		t.Fatal("expected non-nil holder key")
	}
	if w.IssuerKey == nil {
		t.Fatal("expected non-nil issuer key")
	}
	if w.AutoAccept {
		t.Error("expected AutoAccept to be false")
	}
	if len(w.Credentials) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(w.Credentials))
	}
}

func TestGenerateDefaultCredentials(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	// First should be SD-JWT
	if creds[0].Format != "dc+sd-jwt" {
		t.Errorf("expected first credential to be dc+sd-jwt, got %s", creds[0].Format)
	}
	if creds[0].VCT != mock.DefaultPIDVCT {
		t.Errorf("expected VCT %s, got %s", mock.DefaultPIDVCT, creds[0].VCT)
	}
	if len(creds[0].Claims) == 0 {
		t.Error("expected SD-JWT to have claims")
	}
	if len(creds[0].Disclosures) == 0 {
		t.Error("expected SD-JWT to have disclosures")
	}

	// Second should be mDoc
	if creds[1].Format != "mso_mdoc" {
		t.Errorf("expected second credential to be mso_mdoc, got %s", creds[1].Format)
	}
	if creds[1].DocType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("expected DocType eu.europa.ec.eudi.pid.1, got %s", creds[1].DocType)
	}
	if len(creds[1].Claims) == 0 {
		t.Error("expected mDoc to have claims")
	}
}

func TestGenerateDefaultCredentials_Overwrite(t *testing.T) {
	w := generateTestWalletWithPID(t)

	// Run again — should replace, not duplicate
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID credentials second time: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials after overwrite, got %d", len(creds))
	}
}

func TestGenerateDefaultCredentials_ClaimOverrides(t *testing.T) {
	w := generateTestWallet(t)

	overrides := map[string]any{
		"given_name":  "MAX",
		"family_name": "MUSTERMANN-OVERRIDE",
	}
	if err := w.GenerateDefaultCredentials(overrides, ""); err != nil {
		t.Fatalf("generating PID credentials with overrides: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	// SD-JWT should have overridden claims
	sdjwtCred := creds[0]
	if sdjwtCred.Claims["given_name"] != "MAX" {
		t.Errorf("expected given_name MAX, got %v", sdjwtCred.Claims["given_name"])
	}
	if sdjwtCred.Claims["family_name"] != "MUSTERMANN-OVERRIDE" {
		t.Errorf("expected family_name MUSTERMANN-OVERRIDE, got %v", sdjwtCred.Claims["family_name"])
	}
	// Non-overridden claim should still be present
	if sdjwtCred.Claims["birthdate"] != "1984-08-12" {
		t.Errorf("expected birthdate 1984-08-12, got %v", sdjwtCred.Claims["birthdate"])
	}
}

func TestGenerateDefaultCredentials_OverwritePreservesOtherCreds(t *testing.T) {
	w := generateTestWallet(t)

	// Import a non-PID credential first
	key, _ := mock.GenerateKey()
	sdjwtRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCredential",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating test SD-JWT: %v", err)
	}
	if err := w.ImportCredential(sdjwtRaw); err != nil {
		t.Fatalf("importing test credential: %v", err)
	}

	// Generate PID credentials
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID: %v", err)
	}

	// Should have 3: test + SD-JWT PID + mDoc PID
	if len(w.GetCredentials()) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(w.GetCredentials()))
	}

	// Generate again — should replace only PIDs, keep test
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating PID second time: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials after overwrite, got %d", len(creds))
	}

	// Verify the non-PID credential is still there
	found := false
	for _, c := range creds {
		if c.VCT == "TestCredential" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected non-PID credential to be preserved")
	}
}

func TestImportSDJWT(t *testing.T) {
	w := generateTestWallet(t)

	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCredential",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	if err := w.ImportCredential(sdjwt); err != nil {
		t.Fatalf("importing SD-JWT: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Format != "dc+sd-jwt" {
		t.Errorf("expected dc+sd-jwt, got %s", creds[0].Format)
	}
	if creds[0].VCT != "TestCredential" {
		t.Errorf("expected VCT TestCredential, got %s", creds[0].VCT)
	}
	if creds[0].ID == "" {
		t.Error("expected non-empty credential ID")
	}
}

func TestImportMDoc(t *testing.T) {
	w := generateTestWallet(t)

	key, _ := mock.GenerateKey()
	mdocRaw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "org.test.credential",
		Namespace: "org.test.credential",
		Claims:    map[string]any{"field": "value"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating mDoc: %v", err)
	}

	if err := w.ImportCredential(mdocRaw); err != nil {
		t.Fatalf("importing mDoc: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Format != "mso_mdoc" {
		t.Errorf("expected mso_mdoc, got %s", creds[0].Format)
	}
	if creds[0].DocType != "org.test.credential" {
		t.Errorf("expected DocType org.test.credential, got %s", creds[0].DocType)
	}
}

func TestImportPlainJWT(t *testing.T) {
	w := generateTestWallet(t)

	jwt, err := signJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user123", "vct": "urn:test:credential", "given_name": "Erika", "family_name": "Mustermann"},
		w.IssuerKey,
	)
	if err != nil {
		t.Fatalf("creating test JWT: %v", err)
	}

	if err := w.ImportCredential(jwt); err != nil {
		t.Fatalf("importing plain JWT: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	cred := creds[0]
	if cred.Format != "jwt_vc_json" {
		t.Errorf("expected format jwt_vc_json, got %s", cred.Format)
	}
	if cred.VCT != "urn:test:credential" {
		t.Errorf("expected VCT urn:test:credential, got %s", cred.VCT)
	}
	if len(cred.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures, got %d", len(cred.Disclosures))
	}
	if cred.Claims["given_name"] != "Erika" {
		t.Errorf("expected given_name Erika, got %v", cred.Claims["given_name"])
	}
}

func TestImportInvalidCredential(t *testing.T) {
	w := generateTestWallet(t)
	err := w.ImportCredential("not-a-credential")
	if err == nil {
		t.Fatal("expected error importing invalid credential")
	}
}

func TestRemoveCredential(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	id := creds[0].ID

	if !w.RemoveCredential(id) {
		t.Fatal("expected RemoveCredential to return true")
	}
	if len(w.GetCredentials()) != 1 {
		t.Errorf("expected 1 credential after removal, got %d", len(w.GetCredentials()))
	}
}

func TestRemoveCredential_NotFound(t *testing.T) {
	w := generateTestWallet(t)
	if w.RemoveCredential("nonexistent") {
		t.Error("expected RemoveCredential to return false for nonexistent ID")
	}
}

func TestGetCredential(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	cred, ok := w.GetCredential(creds[0].ID)
	if !ok {
		t.Fatal("expected to find credential")
	}
	if cred.ID != creds[0].ID {
		t.Errorf("expected ID %s, got %s", creds[0].ID, cred.ID)
	}
}

func TestGetCredential_NotFound(t *testing.T) {
	w := generateTestWallet(t)
	_, ok := w.GetCredential("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent credential")
	}
}

func TestAddLog(t *testing.T) {
	w := generateTestWallet(t)

	w.AddLog("test", "test detail", true)
	w.AddLog("test", "failure detail", false)

	log := w.GetLog()
	if len(log) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(log))
	}
	if log[0].Action != "test" {
		t.Errorf("expected action 'test', got %s", log[0].Action)
	}
	if log[0].Success != true {
		t.Error("expected first log entry to be success")
	}
	if log[1].Success != false {
		t.Error("expected second log entry to be failure")
	}
}

func TestSubscribe(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.Subscribe()
	defer unsub()

	req := &ConsentRequest{
		ID:        "test-req",
		Type:      "presentation",
		Status:    "pending",
		ClientID:  "test-client",
		CreatedAt: time.Now(),
		ResultCh:  make(chan ConsentResult, 1),
	}

	go w.CreateConsentRequest(req)

	select {
	case received := <-ch:
		if received.ID != "test-req" {
			t.Errorf("expected request ID test-req, got %s", received.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscriber notification")
	}
}

func TestGetPendingRequests(t *testing.T) {
	w := generateTestWallet(t)

	req1 := &ConsentRequest{
		ID:        "req-1",
		Status:    "pending",
		CreatedAt: time.Now(),
		ResultCh:  make(chan ConsentResult, 1),
	}
	req2 := &ConsentRequest{
		ID:        "req-2",
		Status:    "approved",
		CreatedAt: time.Now(),
		ResultCh:  make(chan ConsentResult, 1),
	}

	w.CreateConsentRequest(req1)
	w.CreateConsentRequest(req2)

	pending := w.GetPendingRequests()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(pending))
	}
	if pending[0].ID != "req-1" {
		t.Errorf("expected req-1, got %s", pending[0].ID)
	}
}

func TestCredentialSummary(t *testing.T) {
	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		VCT:    mock.DefaultPIDVCT,
		Claims: map[string]any{"given_name": "Test"},
	}

	summary := CredentialSummary(cred)
	if summary["id"] != "test-id" {
		t.Errorf("expected id test-id, got %v", summary["id"])
	}
	if summary["format"] != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %v", summary["format"])
	}
	if summary["vct"] != mock.DefaultPIDVCT {
		t.Errorf("expected vct, got %v", summary["vct"])
	}
	if _, ok := summary["doctype"]; ok {
		t.Error("expected no doctype field for SD-JWT")
	}
}

func TestCredentialsJSON(t *testing.T) {
	w := generateTestWalletWithPID(t)

	data, err := w.CredentialsJSON()
	if err != nil {
		t.Fatalf("CredentialsJSON error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}
