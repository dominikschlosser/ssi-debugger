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

import "testing"

func TestDetect_SDJWT(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  CredentialFormat
	}{
		{"with disclosures", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~disc2~", FormatSDJWT},
		{"single disclosure", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~disc1~", FormatSDJWT},
		{"trailing tilde only", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig~", FormatSDJWT},
		{"plain JWT no tilde", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig", FormatJWT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != tt.want {
				t.Errorf("Detect(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDetect_MDOC(t *testing.T) {
	// 0xa2 = CBOR map(2) — a valid CBOR start byte
	hexMDOC := "a26a6e616d65537061636573a0"
	got := Detect(hexMDOC)
	if got != FormatMDOC {
		t.Errorf("Detect(hex mDOC) = %q, want %q", got, FormatMDOC)
	}
}

func TestDetect_Unknown(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"random text", "hello world"},
		{"just dots", "a.b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.input)
			if got != FormatUnknown {
				t.Errorf("Detect(%q) = %q, want %q", tt.input, got, FormatUnknown)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef01", true},
		{"ABCDEF01", true},
		{"0123456789abcdef", true},
		{"abc", false},     // odd length
		{"xyz123", false},  // non-hex chars
		{"", false},        // empty
		{"a", false},       // too short
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isHex(tt.input)
			if got != tt.want {
				t.Errorf("isHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCBORStart(t *testing.T) {
	tests := []struct {
		b    byte
		want bool
	}{
		{0xa0, true},  // empty CBOR map
		{0xa2, true},  // CBOR map(2)
		{0xbf, true},  // CBOR map indefinite
		{0xd8, true},  // CBOR tag
		{0x80, true},  // CBOR array(0)
		{0x00, false}, // CBOR unsigned int
		{0x60, false}, // CBOR text string
	}
	for _, tt := range tests {
		got := isCBORStart(tt.b)
		if got != tt.want {
			t.Errorf("isCBORStart(0x%02x) = %v, want %v", tt.b, got, tt.want)
		}
	}
}
