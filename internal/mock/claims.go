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

package mock

// DefaultClaims returns a minimal set of PID-like claims.
var DefaultClaims = map[string]any{
	"given_name":  "ERIKA",
	"family_name": "MUSTERMANN",
	"birth_date":  "1984-08-12",
}

// PIDClaims returns claims following the EUDI PID Rulebook (ARF Annex 3).
var PIDClaims = map[string]any{
	"family_name":            "MUSTERMANN",
	"given_name":             "ERIKA",
	"birth_date":             "1984-08-12",
	"age_over_18":            true,
	"age_in_years":           41,
	"age_birth_year":         1984,
	"family_name_birth":      "GABLER",
	"given_name_birth":       "ERIKA",
	"birth_place":            "BERLIN",
	"birth_country":          "DE",
	"birth_state":            "BE",
	"birth_city":             "BERLIN",
	"resident_address":       "HEIDESTRAẞE 17, 51147 KÖLN",
	"resident_country":       "DE",
	"resident_state":         "NW",
	"resident_city":          "KÖLN",
	"resident_postal_code":   "51147",
	"resident_street":        "HEIDESTRAẞE 17",
	"gender":                 1,
	"nationality":            "DE",
	"issuance_date":          "2024-01-15",
	"expiry_date":            "2029-01-15",
	"issuing_authority":      "DE",
	"document_number":        "T22000129",
	"administrative_number":  "123456789",
	"issuing_country":        "DE",
	"issuing_jurisdiction":   "DE-NW",
}
