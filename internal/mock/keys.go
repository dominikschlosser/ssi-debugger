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

package mock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
)

// GenerateKey creates an ephemeral P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyJWK returns the JSON JWK representation of a P-256 public key.
func PublicKeyJWK(key *ecdsa.PublicKey) string {
	keySize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad to key size
	for len(xBytes) < keySize {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < keySize {
		yBytes = append([]byte{0}, yBytes...)
	}

	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
	}

	b, _ := json.MarshalIndent(jwk, "", "  ")
	return string(b)
}

// PrivateKeyJWK returns the JSON JWK representation of a P-256 private key (includes d).
func PrivateKeyJWK(key *ecdsa.PrivateKey) string {
	keySize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	dBytes := key.D.Bytes()

	for len(xBytes) < keySize {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < keySize {
		yBytes = append([]byte{0}, yBytes...)
	}
	for len(dBytes) < keySize {
		dBytes = append([]byte{0}, dBytes...)
	}

	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
		"d":   format.EncodeBase64URL(dBytes),
	}

	b, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	return string(b)
}
