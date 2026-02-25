package dcql

// Query is a DCQL query.
type Query struct {
	Credentials []CredentialQuery `json:"credentials"`
}

// CredentialQuery defines a single credential request.
type CredentialQuery struct {
	ID     string          `json:"id"`
	Format string          `json:"format"`
	Meta   *CredentialMeta `json:"meta,omitempty"`
	Claims []ClaimQuery    `json:"claims"`
}

// CredentialMeta contains format-specific metadata.
type CredentialMeta struct {
	VCTValues    []string `json:"vct_values,omitempty"`
	DoctypeValue string   `json:"doctype_value,omitempty"`
}

// ClaimQuery defines a single claim request.
// Path elements are strings (object keys) or nil (array wildcard).
type ClaimQuery struct {
	Path []any `json:"path"`
}
