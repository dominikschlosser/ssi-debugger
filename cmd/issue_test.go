// Copyright 2025 Dominik Schlosser
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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dominikschlosser/ssi-debugger/internal/mock"
)

// --- omitClaims unit tests ---

func TestOmitClaims_RemovesSpecifiedClaims(t *testing.T) {
	result := omitClaims(mock.PIDClaims, []string{"birth_place", "resident_address", "administrative_number"})

	for _, name := range []string{"birth_place", "resident_address", "administrative_number"} {
		if _, ok := result[name]; ok {
			t.Errorf("%s should have been omitted", name)
		}
	}

	for _, name := range []string{"family_name", "given_name", "birth_date"} {
		if _, ok := result[name]; !ok {
			t.Errorf("%s should still be present", name)
		}
	}

	expectedCount := len(mock.PIDClaims) - 3
	if len(result) != expectedCount {
		t.Errorf("expected %d claims, got %d", expectedCount, len(result))
	}
}

func TestOmitClaims_EmptyOmitReturnsOriginal(t *testing.T) {
	result := omitClaims(mock.PIDClaims, nil)
	if len(result) != len(mock.PIDClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.PIDClaims), len(result))
	}
}

func TestOmitClaims_OmitNonexistentClaimIsNoOp(t *testing.T) {
	result := omitClaims(mock.DefaultClaims, []string{"nonexistent_claim"})
	if len(result) != len(mock.DefaultClaims) {
		t.Errorf("expected %d claims, got %d", len(mock.DefaultClaims), len(result))
	}
}

func TestOmitClaims_TrimsWhitespace(t *testing.T) {
	result := omitClaims(mock.PIDClaims, []string{" birth_place ", " resident_address"})

	if _, ok := result["birth_place"]; ok {
		t.Error("birth_place should have been omitted (with whitespace trimming)")
	}
	if _, ok := result["resident_address"]; ok {
		t.Error("resident_address should have been omitted (with whitespace trimming)")
	}
}

func TestOmitClaims_DoesNotMutateOriginal(t *testing.T) {
	original := map[string]any{"a": 1, "b": 2, "c": 3}
	result := omitClaims(original, []string{"b"})

	if len(result) != 2 {
		t.Errorf("expected 2 claims in result, got %d", len(result))
	}
	if len(original) != 3 {
		t.Errorf("original should not be mutated, expected 3 claims, got %d", len(original))
	}
}

func TestOmitClaims_OmitAllClaims(t *testing.T) {
	claims := map[string]any{"a": 1, "b": 2}
	result := omitClaims(claims, []string{"a", "b"})
	if len(result) != 0 {
		t.Errorf("expected 0 claims, got %d", len(result))
	}
}

// --- resolveIssueClaims tests ---

func TestResolveIssueClaims_DefaultWhenEmpty(t *testing.T) {
	issuePID = false
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}
	if len(claims) != len(mock.DefaultClaims) {
		t.Errorf("expected %d default claims, got %d", len(mock.DefaultClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWhenFlagged(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = nil

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}
	if len(claims) != len(mock.PIDClaims) {
		t.Errorf("expected %d PID claims, got %d", len(mock.PIDClaims), len(claims))
	}
}

func TestResolveIssueClaims_PIDWithOmit(t *testing.T) {
	issuePID = true
	issueClaims = ""
	issueOmit = []string{"birth_place", "gender"}

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}

	expected := len(mock.PIDClaims) - 2
	if len(claims) != expected {
		t.Errorf("expected %d claims, got %d", expected, len(claims))
	}
	if _, ok := claims["birth_place"]; ok {
		t.Error("birth_place should be omitted")
	}
	if _, ok := claims["gender"]; ok {
		t.Error("gender should be omitted")
	}
}

func TestResolveIssueClaims_JSONString(t *testing.T) {
	issuePID = false
	issueClaims = `{"name":"Test","active":true}`
	issueOmit = nil

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}
	if claims["name"] != "Test" {
		t.Errorf("expected name=Test, got %v", claims["name"])
	}
	if claims["active"] != true {
		t.Errorf("expected active=true, got %v", claims["active"])
	}
}

func TestResolveIssueClaims_JSONStringWithOmit(t *testing.T) {
	issuePID = false
	issueClaims = `{"a":1,"b":2,"c":3}`
	issueOmit = []string{"b"}

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}
	if len(claims) != 2 {
		t.Errorf("expected 2 claims, got %d", len(claims))
	}
	if _, ok := claims["b"]; ok {
		t.Error("b should be omitted")
	}
}

func TestResolveIssueClaims_FileReference(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"file_claim":"works"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	issuePID = false
	issueClaims = "@" + claimsFile
	issueOmit = nil

	claims, err := resolveIssueClaims()
	if err != nil {
		t.Fatalf("resolveIssueClaims: %v", err)
	}
	if claims["file_claim"] != "works" {
		t.Errorf("expected file_claim=works, got %v", claims["file_claim"])
	}
}

func TestResolveIssueClaims_InvalidJSON(t *testing.T) {
	issuePID = false
	issueClaims = `{not json}`
	issueOmit = nil

	_, err := resolveIssueClaims()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestResolveIssueClaims_MissingFile(t *testing.T) {
	issuePID = false
	issueClaims = "@/nonexistent/path/claims.json"
	issueOmit = nil

	_, err := resolveIssueClaims()
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --- end-to-end cobra command tests ---

func TestIssueSDJWT_EndToEnd(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	// Reset flags to defaults
	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"
	issueExpires = "24h"

	rootCmd.SetArgs([]string{"issue", "sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt: %v", err)
	}
}

func TestIssueSDJWT_WithPID(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --pid: %v", err)
	}
}

func TestIssueSDJWT_WithPIDAndOmit(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--pid", "--omit", "birth_place,gender"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --pid --omit: %v", err)
	}
}

func TestIssueSDJWT_WithCustomClaims(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueKeyPath = ""
	issueOmit = nil
	issuePID = false

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--claims", `{"custom":"claim"}`})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --claims: %v", err)
	}
}

func TestIssueSDJWT_WithCustomIssuerVCTExp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--iss", "https://custom.example", "--vct", "custom:type", "--exp", "1h"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt with custom flags: %v", err)
	}
}

func TestIssueSDJWT_WithKeyFile(t *testing.T) {
	// Generate a key and write it as JWK to a temp file
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.jwk")
	if err := os.WriteFile(keyFile, []byte(mock.PrivateKeyJWK(key)), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"
	issueExpires = "24h"

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--key", keyFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue sdjwt --key: %v", err)
	}
}

func TestIssueSDJWT_InvalidExpDuration(t *testing.T) {
	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueIssuer = "https://issuer.example"
	issueVCT = "urn:eudi:pid:1"

	rootCmd.SetArgs([]string{"issue", "sdjwt", "--exp", "not-a-duration"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --exp duration")
	}
}

func TestIssueMDOC_EndToEnd(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc: %v", err)
	}
}

func TestIssueMDOC_WithPID(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil

	rootCmd.SetArgs([]string{"issue", "mdoc", "--pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc --pid: %v", err)
	}
}

func TestIssueMDOC_WithCustomDocType(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueClaims = ""
	issueKeyPath = ""
	issueOmit = nil
	issuePID = false

	rootCmd.SetArgs([]string{"issue", "mdoc", "--doc-type", "com.example.test", "--namespace", "com.example.test"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc with custom doc-type: %v", err)
	}
}

func TestIssueMDOC_WithClaimsFile(t *testing.T) {
	tmpDir := t.TempDir()
	claimsFile := filepath.Join(tmpDir, "claims.json")
	if err := os.WriteFile(claimsFile, []byte(`{"test":"value"}`), 0644); err != nil {
		t.Fatalf("writing claims file: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)

	issueKeyPath = ""
	issueOmit = nil
	issuePID = false
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc", "--claims", "@" + claimsFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue mdoc --claims @file: %v", err)
	}
}

func TestIssueMDOC_InvalidKeyFile(t *testing.T) {
	issueClaims = ""
	issueOmit = nil
	issuePID = false
	issueDocType = "eu.europa.ec.eudi.pid.1"
	issueNamespace = "eu.europa.ec.eudi.pid.1"

	rootCmd.SetArgs([]string{"issue", "mdoc", "--key", "/nonexistent/key.pem"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

// --- claims data tests ---

func TestDefaultClaims_HasExpectedFields(t *testing.T) {
	required := []string{"given_name", "family_name", "birth_date"}
	for _, name := range required {
		if _, ok := mock.DefaultClaims[name]; !ok {
			t.Errorf("DefaultClaims missing %q", name)
		}
	}
}

func TestPIDClaims_HasExpectedFields(t *testing.T) {
	required := []string{
		"family_name", "given_name", "birth_date",
		"age_over_18", "age_in_years", "age_birth_year",
		"family_name_birth", "given_name_birth",
		"birth_place", "birth_country", "birth_state", "birth_city",
		"resident_address", "resident_country", "resident_state", "resident_city",
		"resident_postal_code", "resident_street",
		"gender", "nationality",
		"issuance_date", "expiry_date",
		"issuing_authority", "document_number", "administrative_number",
		"issuing_country", "issuing_jurisdiction",
	}
	for _, name := range required {
		if _, ok := mock.PIDClaims[name]; !ok {
			t.Errorf("PIDClaims missing %q", name)
		}
	}

	if len(mock.PIDClaims) != 27 {
		t.Errorf("expected 27 PID claims, got %d", len(mock.PIDClaims))
	}
}

func TestPIDClaims_TypesAreCorrect(t *testing.T) {
	// Boolean
	if v, ok := mock.PIDClaims["age_over_18"].(bool); !ok || !v {
		t.Error("age_over_18 should be bool true")
	}
	// Integer
	if v, ok := mock.PIDClaims["gender"].(int); !ok || v != 1 {
		t.Errorf("gender should be int 1, got %T %v", mock.PIDClaims["gender"], mock.PIDClaims["gender"])
	}
	// String
	if v, ok := mock.PIDClaims["family_name"].(string); !ok || !strings.Contains(v, "MUSTERMANN") {
		t.Errorf("family_name should be string containing MUSTERMANN, got %v", v)
	}
}
