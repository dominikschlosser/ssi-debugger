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

import "testing"

func TestIssuerURLFromBaseURL(t *testing.T) {
	got, err := IssuerURLFromBaseURL("http://host.docker.internal:8085/wallet", 8086)
	if err != nil {
		t.Fatalf("IssuerURLFromBaseURL: %v", err)
	}
	if got != "https://host.docker.internal:8086" {
		t.Fatalf("expected https://host.docker.internal:8086, got %s", got)
	}
}
