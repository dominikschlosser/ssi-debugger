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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func TestWalletStore_LoadOrCreate_NewWallet(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	if w.HolderKey == nil {
		t.Fatal("expected non-nil holder key")
	}
	if w.IssuerKey == nil {
		t.Fatal("expected non-nil issuer key")
	}
	if len(w.Credentials) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(w.Credentials))
	}

	// Keys should be persisted
	if _, err := os.Stat(filepath.Join(dir, "holder.pem")); err != nil {
		t.Errorf("expected holder.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "issuer.pem")); err != nil {
		t.Errorf("expected issuer.pem to exist: %v", err)
	}
}

func TestWalletStore_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Add a credential
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatalf("importing: %v", err)
	}

	// Save
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load again
	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}

	creds := w2.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential after reload, got %d", len(creds))
	}
	if creds[0].VCT != "TestCred" {
		t.Errorf("expected VCT TestCred, got %s", creds[0].VCT)
	}
	if len(creds[0].Disclosures) == 0 {
		t.Error("expected disclosures to be rehydrated")
	}
}

func TestWalletStore_KeyPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	w1, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Load again — same keys should be used
	w2, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate second time: %v", err)
	}

	if !w1.HolderKey.Equal(w2.HolderKey) {
		t.Error("expected same holder key across loads")
	}
	if !w1.IssuerKey.Equal(w2.IssuerKey) {
		t.Error("expected same issuer key across loads")
	}
}

func TestNewWalletStore_DefaultDir(t *testing.T) {
	store := NewWalletStore("")
	if store.Dir == "" {
		t.Error("expected non-empty default dir")
	}
}

func TestWalletStore_PathHelpers(t *testing.T) {
	store := NewWalletStore("/tmp/test-wallet")
	if store.walletPath() != "/tmp/test-wallet/wallet.json" {
		t.Errorf("wrong wallet path: %s", store.walletPath())
	}
	if store.holderKeyPath() != "/tmp/test-wallet/holder.pem" {
		t.Errorf("wrong holder key path: %s", store.holderKeyPath())
	}
	if store.issuerKeyPath() != "/tmp/test-wallet/issuer.pem" {
		t.Errorf("wrong issuer key path: %s", store.issuerKeyPath())
	}
	if store.issuerTLSCertPath() != "/tmp/test-wallet/issuer-tls-cert.pem" {
		t.Errorf("wrong issuer TLS cert path: %s", store.issuerTLSCertPath())
	}
	if store.issuerTLSKeyPath() != "/tmp/test-wallet/issuer-tls-key.pem" {
		t.Errorf("wrong issuer TLS key path: %s", store.issuerTLSKeyPath())
	}
}

func TestDefaultWalletDir(t *testing.T) {
	dir := DefaultWalletDir()
	if dir == "" {
		t.Error("expected non-empty dir")
	}
	if !strings.Contains(dir, ".oid4vc-dev") {
		t.Errorf("expected .oid4vc-dev in path, got %s", dir)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_Persists(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate second time: %v", err)
	}

	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("expected persisted issuer TLS certificate")
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to persist across loads")
	}
	if _, err := os.Stat(filepath.Join(dir, "issuer-tls-cert.pem")); err != nil {
		t.Fatalf("expected issuer-tls-cert.pem to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "issuer-tls-key.pem")); err != nil {
		t.Fatalf("expected issuer-tls-key.pem to exist: %v", err)
	}
}

func TestWalletStore_LoadOrCreateIssuerTLSCertificate_RegeneratesForNewHost(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)

	cert1, err := store.LoadOrCreateIssuerTLSCertificate("localhost")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate localhost: %v", err)
	}
	cert2, err := store.LoadOrCreateIssuerTLSCertificate("issuer.example")
	if err != nil {
		t.Fatalf("LoadOrCreateIssuerTLSCertificate issuer.example: %v", err)
	}

	if bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("expected issuer TLS certificate to regenerate for a different host")
	}
}
