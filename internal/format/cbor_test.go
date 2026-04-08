// Copyright 2026 Dominik Schlosser
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
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestStripCBORTag_StripsExpectedTag(t *testing.T) {
	content, err := cbor.Marshal([]any{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	tagged, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := StripCBORTag(tagged, 18)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("unexpected untagged content: %x", got)
	}
}

func TestStripCBORTag_PreservesUntaggedValue(t *testing.T) {
	data, err := cbor.Marshal([]any{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	got, err := StripCBORTag(data, 18)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("expected untagged data to pass through unchanged")
	}
}

func TestStripCBORTag_RejectsUnexpectedTag(t *testing.T) {
	tagged, err := cbor.Marshal(cbor.Tag{Number: 24, Content: []byte{0x01}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := StripCBORTag(tagged, 18); err == nil {
		t.Fatal("expected error for unexpected tag")
	}
}
