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
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// ValidatePresentationRequest evaluates client_id, request-object metadata, and signature checks.
// In debug mode findings are returned as warnings; in strict mode any finding is fatal.
func ValidatePresentationRequest(mode ValidationMode, clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) ([]string, error) {
	var findings []string

	if finding := VerifyClientID(clientID, reqObj, responseURI); finding != "" {
		findings = append(findings, finding)
	}
	if finding := ValidateRequestObject(clientID, reqObj); finding != "" {
		findings = append(findings, finding)
	}
	if finding := VerifyRequestObjectSignature(reqObj); finding != "" {
		findings = append(findings, finding)
	}

	if mode == ValidationModeStrict && len(findings) > 0 {
		return nil, fmt.Errorf("authorization request validation failed: %s", strings.Join(findings, "; "))
	}

	return findings, nil
}
