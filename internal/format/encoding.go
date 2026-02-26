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
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// DecodeBase64URL decodes a base64url-encoded string (with or without padding).
func DecodeBase64URL(s string) ([]byte, error) {
	// Try without padding first (most common in JWTs)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Try with padding
		b, err = base64.URLEncoding.DecodeString(s)
	}
	return b, err
}

// DecodeBase64Std decodes a standard base64-encoded string.
func DecodeBase64Std(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	return b, err
}

// EncodeBase64URL encodes bytes as base64url without padding.
func EncodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeHexOrBase64URL tries hex first, then base64url.
func DecodeHexOrBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if isHex(s) {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return DecodeBase64URL(s)
}
