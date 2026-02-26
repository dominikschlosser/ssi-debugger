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

package format

import (
	"encoding/hex"
	"strings"
)

type CredentialFormat string

const (
	FormatSDJWT   CredentialFormat = "dc+sd-jwt"
	FormatJWT     CredentialFormat = "jwt"
	FormatMDOC    CredentialFormat = "mso_mdoc"
	FormatUnknown CredentialFormat = "unknown"
)

// Detect auto-detects the credential format from raw input.
// SD-JWT: contains '~' separator (e.g. "header.payload.sig~disclosure1~disclosure2~")
// mDOC: hex or base64url encoded CBOR (starts with CBOR map tag when decoded)
func Detect(input string) CredentialFormat {
	input = strings.TrimSpace(input)
	if input == "" {
		return FormatUnknown
	}

	// SD-JWT always contains ~ separators
	if strings.Contains(input, "~") {
		return FormatSDJWT
	}

	// Try hex decode — mDOC is often hex-encoded CBOR
	if isHex(input) {
		b, err := hex.DecodeString(input)
		if err == nil && len(b) > 0 && isCBORStart(b[0]) {
			return FormatMDOC
		}
	}

	// Try base64url decode — mDOC can also be base64url
	b, err := DecodeBase64URL(input)
	if err == nil && len(b) > 0 && isCBORStart(b[0]) {
		return FormatMDOC
	}

	// Could be a plain JWT (no disclosures) — check for 2-dot structure
	parts := strings.Split(input, ".")
	if len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 {
		return FormatJWT
	}

	return FormatUnknown
}

func isHex(s string) bool {
	if len(s) < 2 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isCBORStart checks if a byte looks like a CBOR map or tag start.
// CBOR maps start with 0xa0-0xbf (major type 5), or tagged with 0xd8 (tag).
func isCBORStart(b byte) bool {
	major := b >> 5
	return major == 5 || // map
		major == 6 || // tag (e.g. tag 24)
		major == 4 // array (DeviceResponse is an array sometimes)
}
