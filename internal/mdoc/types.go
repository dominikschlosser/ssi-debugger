package mdoc

import "time"

// Document represents a parsed mDOC credential.
type Document struct {
	Raw        []byte
	DocType    string
	NameSpaces map[string][]IssuerSignedItem
	IssuerAuth *IssuerAuth
	// DeviceSigned contains the device authentication data from a DeviceResponse.
	DeviceSigned *DeviceSigned
	// IsDeviceResponse indicates this was parsed from a DeviceResponse wrapper.
	IsDeviceResponse bool
}

// DeviceSigned contains the device-signed portion of a DeviceResponse document.
type DeviceSigned struct {
	DeviceAuth map[string]any
}

// IssuerSignedItem represents a single claim within a namespace.
type IssuerSignedItem struct {
	DigestID          uint64
	Random            []byte
	ElementIdentifier string
	ElementValue      any
}

// IssuerAuth represents the COSE_Sign1 issuer authentication.
type IssuerAuth struct {
	RawCOSE          []byte
	ProtectedHeader  map[any]any
	UnprotectedHeader map[any]any
	Payload          []byte
	Signature        []byte
	MSO              *MSO
}

// MSO is the Mobile Security Object.
type MSO struct {
	Version          string
	DigestAlgorithm  string
	DocType          string
	ValueDigests     map[string]map[uint64][]byte
	ValidityInfo     *ValidityInfo
	DeviceKeyInfo    map[string]any
	Status           map[string]any
}

// ValidityInfo contains credential validity dates.
type ValidityInfo struct {
	Signed     *time.Time
	ValidFrom  *time.Time
	ValidUntil *time.Time
}
