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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

func TestParsePublicKey_PEM_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestParsePublicKey_PEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	pub, err := ParsePublicKey(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}

	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestParseJWK_EC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(key.PublicKey.X.Bytes()),
		"y":   format.EncodeBase64URL(key.PublicKey.Y.Bytes()),
	}
	data, _ := json.Marshal(jwk)

	pub, err := ParseJWK(data)
	if err != nil {
		t.Fatalf("ParseJWK() error: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.X.Cmp(key.PublicKey.X) != 0 || ecPub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("parsed key does not match original")
	}
}

func TestParseJWK_UnsupportedType(t *testing.T) {
	data := []byte(`{"kty":"OKP","crv":"Ed25519"}`)
	_, err := ParseJWK(data)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestLoadPublicKey_FileNotFound(t *testing.T) {
	_, err := LoadPublicKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadPublicKey_FromFile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(path, pemData, 0644)

	pub, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey() error: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestParsePublicKey_InvalidData(t *testing.T) {
	_, err := ParsePublicKey([]byte("not a key"))
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}
