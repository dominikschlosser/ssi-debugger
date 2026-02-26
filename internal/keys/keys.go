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

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
)

// LoadPublicKey loads a public key from a PEM file or JWK JSON file.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return ParsePublicKey(data)
}

// ParsePublicKey parses a public key from PEM or JWK bytes.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return parsePEMBlock(block)
	}
	return ParseJWK(data)
}

func parsePEMBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY", "EC PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
		return key, nil
	}
}

// ParseJWK parses a JWK JSON object into a public key.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	var jwk map[string]any
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWK(jwk)
	case "RSA":
		return parseRSAJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", kty)
	}
}

func parseECJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)

	xBytes, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func parseRSAJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)

	nBytes, err := format.DecodeBase64URL(nB64)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := format.DecodeBase64URL(eB64)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
