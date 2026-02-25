package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
)

// VerifyResult contains the result of signature and validity verification.
type VerifyResult struct {
	SignatureValid bool
	Expired        bool
	NotYetValid    bool
	Algorithm      string
	KeyID          string
	Issuer         string
	ExpiresAt      *time.Time
	IssuedAt       *time.Time
	NotBefore      *time.Time
	Errors         []string
}

// Verify verifies the SD-JWT signature using the provided public key.
func Verify(token *Token, pubKey crypto.PublicKey) *VerifyResult {
	result := &VerifyResult{}

	if kid, ok := token.Header["kid"].(string); ok {
		result.KeyID = kid
	}
	if alg, ok := token.Header["alg"].(string); ok {
		result.Algorithm = alg
	}
	if iss, ok := token.Payload["iss"].(string); ok {
		result.Issuer = iss
	}

	// Parse time claims
	now := time.Now()
	if exp, ok := token.Payload["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		result.ExpiresAt = &t
		result.Expired = now.After(t)
	}
	if iat, ok := token.Payload["iat"].(float64); ok {
		t := time.Unix(int64(iat), 0)
		result.IssuedAt = &t
	}
	if nbf, ok := token.Payload["nbf"].(float64); ok {
		t := time.Unix(int64(nbf), 0)
		result.NotBefore = &t
		result.NotYetValid = now.Before(t)
	}

	// Verify signature
	jwtRaw := strings.SplitN(token.Raw, "~", 2)[0]
	parts := strings.SplitN(jwtRaw, ".", 3)
	if len(parts) != 3 {
		result.Errors = append(result.Errors, "invalid JWT structure")
		return result
	}

	sigInput := []byte(parts[0] + "." + parts[1])
	sig, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decoding signature: %v", err))
		return result
	}

	alg := result.Algorithm
	switch alg {
	case "ES256":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA256)
	case "ES384":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA384)
	case "ES512":
		result.SignatureValid = verifyECDSA(pubKey, sigInput, sig, crypto.SHA512)
	case "RS256":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA256)
	case "RS384":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA384)
	case "RS512":
		result.SignatureValid = verifyRSA(pubKey, sigInput, sig, crypto.SHA512)
	case "PS256":
		result.SignatureValid = verifyRSAPSS(pubKey, sigInput, sig, crypto.SHA256)
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported algorithm: %s", alg))
	}

	if !result.SignatureValid && len(result.Errors) == 0 {
		result.Errors = append(result.Errors, "signature verification failed")
	}

	return result
}

func verifyECDSA(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	h := hash.New()
	h.Write(sigInput)
	digest := h.Sum(nil)

	// JWS ECDSA signature is r||s (raw, not DER)
	keySize := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return false
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	return ecdsa.Verify(ecKey, digest, r, s)
}

func verifyRSA(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := hash.New()
	h.Write(sigInput)
	return rsa.VerifyPKCS1v15(rsaKey, hash, h.Sum(nil), sig) == nil
}

func verifyRSAPSS(pubKey crypto.PublicKey, sigInput, sig []byte, hash crypto.Hash) bool {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := hash.New()
	h.Write(sigInput)
	return rsa.VerifyPSS(rsaKey, hash, h.Sum(nil), sig, nil) == nil
}
