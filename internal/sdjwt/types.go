package sdjwt

// Token represents a parsed SD-JWT.
type Token struct {
	Raw           string
	Header        map[string]any
	Payload       map[string]any
	Signature     []byte
	Disclosures   []Disclosure
	KeyBindingJWT *JWT
	// ResolvedClaims contains all claims after resolving _sd digests.
	ResolvedClaims map[string]any
	// Warnings contains informational warnings about the credential structure.
	Warnings []string
}

// JWT represents a decoded JWT (header.payload.signature).
type JWT struct {
	Raw       string
	Header    map[string]any
	Payload   map[string]any
	Signature []byte
}

// Disclosure represents a single SD-JWT disclosure.
type Disclosure struct {
	Raw          string // base64url-encoded
	Decoded      string // JSON string
	Salt         string
	Name         string // empty for array element disclosures
	Value        any
	Digest       string // SHA-256 digest (base64url)
	IsArrayEntry bool
}
