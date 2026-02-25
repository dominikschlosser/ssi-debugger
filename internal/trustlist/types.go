package trustlist

import "crypto"

// TrustList represents a parsed ETSI TS 119 602 trust list.
type TrustList struct {
	Raw       string
	Header    map[string]any
	SchemeInfo *SchemeInfo
	Entities  []TrustedEntity
}

// SchemeInfo contains list metadata.
type SchemeInfo struct {
	LoTEType           string
	SchemeOperatorName string
	ListIssueDatetime  string
}

// TrustedEntity represents a single trusted entity with its services.
type TrustedEntity struct {
	Name     string
	Services []TrustedService
}

// TrustedService represents a service provided by a trusted entity.
type TrustedService struct {
	ServiceType string
	Certificates []CertInfo
}

// CertInfo contains parsed certificate information.
type CertInfo struct {
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	PublicKey crypto.PublicKey
	Raw       []byte
}
