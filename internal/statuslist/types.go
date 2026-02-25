package statuslist

// StatusRef is a reference to a status list entry in a credential.
type StatusRef struct {
	URI string `json:"uri"`
	Idx int    `json:"idx"`
}

// StatusResult contains the revocation check result.
type StatusResult struct {
	URI       string `json:"uri"`
	Index     int    `json:"index"`
	Status    int    `json:"status"`
	IsValid   bool   `json:"isValid"`
	BitsPerEntry int `json:"bitsPerEntry"`
	Error     string `json:"error,omitempty"`
}
