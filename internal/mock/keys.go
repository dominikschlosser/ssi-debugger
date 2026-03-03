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

package mock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// GenerateKey creates an ephemeral P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyJWKMap returns the JWK representation of a P-256 public key as a map.
func PublicKeyJWKMap(key *ecdsa.PublicKey) map[string]string {
	keySize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := padToKeySize(key.X.Bytes(), keySize)
	yBytes := padToKeySize(key.Y.Bytes(), keySize)

	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(xBytes),
		"y":   format.EncodeBase64URL(yBytes),
	}
}

func padToKeySize(b []byte, size int) []byte {
	for len(b) < size {
		b = append([]byte{0}, b...)
	}
	return b
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

// GenerateCACert creates a self-signed CA certificate for the given key.
func GenerateCACert(caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OID4VC Dev Wallet CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// GenerateLeafCert creates a leaf certificate signed by the CA.
func GenerateLeafCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafPubKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "OID4VC Dev Wallet Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, leafPubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating leaf certificate: %w", err)
	}

	return x509.ParseCertificate(der)
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
