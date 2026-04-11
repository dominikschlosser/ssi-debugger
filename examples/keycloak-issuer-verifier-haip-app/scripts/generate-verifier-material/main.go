package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

func getenvDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func main() {
	chainPath := getenvDefault("VERIFIER_CERT_CHAIN_PATH", "examples/keycloak-issuer-verifier-haip-app/verifier-cert-chain.pem")
	caPath := getenvDefault("VERIFIER_CA_CERT_PATH", "examples/keycloak-issuer-verifier-haip-app/verifier-ca-cert.pem")
	jwkPath := getenvDefault("VERIFIER_SIGNING_KEY_JWK_PATH", "examples/keycloak-issuer-verifier-haip-app/verifier-signing-key.jwk")

	if _, err := os.Stat(chainPath); err == nil {
		if _, err := os.Stat(caPath); err == nil {
			if _, err := os.Stat(jwkPath); err == nil {
				fmt.Printf("Reusing verifier materials:\n  %s\n  %s\n  %s\n", chainPath, caPath, jwkPath)
				return
			}
		}
	}

	caKey, err := mock.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating verifier CA key: %v\n", err)
		os.Exit(1)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating verifier CA cert: %v\n", err)
		os.Exit(1)
	}

	leafKey, err := mock.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating verifier signing key: %v\n", err)
		os.Exit(1)
	}
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &leafKey.PublicKey, mock.LeafCertOptions{
		CommonName: "Keycloak HAIP Verifier",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating verifier leaf cert: %v\n", err)
		os.Exit(1)
	}

	caPEM := pemEncode("CERTIFICATE", caCert.Raw)
	leafPEM := pemEncode("CERTIFICATE", leafCert.Raw)
	chainPEM := append([]byte{}, leafPEM...)
	chainPEM = append(chainPEM, caPEM...)

	if err := writeFile(chainPath, chainPEM); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", chainPath, err)
		os.Exit(1)
	}
	if err := writeFile(caPath, caPEM); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", caPath, err)
		os.Exit(1)
	}
	if err := writeFile(jwkPath, []byte(mock.PrivateKeyJWK(leafKey))); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", jwkPath, err)
		os.Exit(1)
	}

	if _, err := x509.ParseCertificate(leafCert.Raw); err != nil {
		fmt.Fprintf(os.Stderr, "error validating verifier leaf cert: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated verifier materials:\n  %s\n  %s\n  %s\n", chainPath, caPath, jwkPath)
}
