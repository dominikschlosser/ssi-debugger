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

package wallet

import (
	"testing"
)

func TestFormatDirectPostResult_Success(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 200,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 200" {
		t.Errorf("expected 'Response: 200', got %s", got)
	}
}

func TestFormatDirectPostResult_WithRedirect(t *testing.T) {
	result := &DirectPostResult{
		StatusCode:  200,
		RedirectURI: "https://verifier.example/success",
	}
	got := FormatDirectPostResult(result)
	expected := "Response: 200 → https://verifier.example/success"
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestFormatDirectPostResult_Error(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 400,
		Body:       `{"error": "invalid_request"}`,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 400" {
		t.Errorf("expected 'Response: 400', got %s", got)
	}
}
