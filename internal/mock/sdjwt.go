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
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
)

// SDJWTConfig holds options for generating a mock SD-JWT credential.
type SDJWTConfig struct {
	Issuer    string
	VCT       string
	ExpiresIn time.Duration
	Claims    map[string]any
	Key       *ecdsa.PrivateKey
}

// GenerateSDJWT creates a mock SD-JWT credential with all claims selectively disclosable.
func GenerateSDJWT(cfg SDJWTConfig) (string, error) {
	now := time.Now()

	// Generate disclosures and compute digests
	var disclosures []string
	var digests []string

	for name, value := range cfg.Claims {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("generating salt: %w", err)
		}

		disclosure := []any{format.EncodeBase64URL(salt), name, value}
		discJSON, err := json.Marshal(disclosure)
		if err != nil {
			return "", fmt.Errorf("marshaling disclosure: %w", err)
		}

		encoded := format.EncodeBase64URL(discJSON)
		disclosures = append(disclosures, encoded)

		h := sha256.Sum256([]byte(encoded))
		digests = append(digests, format.EncodeBase64URL(h[:]))
	}

	// Build payload
	payload := map[string]any{
		"iss":     cfg.Issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(cfg.ExpiresIn).Unix(),
		"vct":     cfg.VCT,
		"_sd_alg": "sha-256",
		"_sd":     digests,
	}

	// Build header
	header := map[string]any{
		"alg": "ES256",
		"typ": "vc+sd-jwt",
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	headerB64 := format.EncodeBase64URL(headerJSON)
	payloadB64 := format.EncodeBase64URL(payloadJSON)

	// Sign with ECDSA (JWS r||s format)
	sigInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))

	r, s, err := ecdsa.Sign(rand.Reader, cfg.Key, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	// Encode r||s with fixed-size padding (32 bytes each for P-256)
	keySize := (cfg.Key.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	sigB64 := format.EncodeBase64URL(sig)

	// Assemble: header.payload.sig~disc1~disc2~
	jwt := headerB64 + "." + payloadB64 + "." + sigB64
	result := jwt + "~" + strings.Join(disclosures, "~") + "~"

	return result, nil
}

// signECDSA signs a digest and returns the JWS r||s encoded signature.
func signECDSA(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	keySize := (key.Curve.Params().BitSize + 7) / 8
	rBytes := padToSize(r.Bytes(), keySize)
	sBytes := padToSize(s.Bytes(), keySize)

	return append(rBytes, sBytes...), nil
}

func padToSize(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// verifyRoundTrip is a helper to verify a generated signature is valid (used in tests).
func verifyRoundTrip(key *ecdsa.PublicKey, sigInput []byte, sig []byte) bool {
	h := sha256.Sum256(sigInput)
	keySize := (key.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return false
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	return ecdsa.Verify(key, h[:], r, s)
}
