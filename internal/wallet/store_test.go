package wallet

import (
	"os"
	"path/filepath"
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
	if err := w.ImportCredential(sdjwt); err != nil {
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
