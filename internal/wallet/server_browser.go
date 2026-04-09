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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// handleBrowserPresentationAPI executes an OpenID4VP Browser API request and
// returns the browser-facing result object that navigator.credentials.get()
// would yield to the RP page.
func (s *Server) handleBrowserPresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body BrowserAPIRequestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	requestOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	protocol, authReq, err := ParseBrowserAPIRequest(body, s.parseOpts, requestOrigin)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse browser request: %v", err), false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log("Received Browser API authorization request")
	s.log("  Protocol:      %s", protocol)
	s.log("  Client ID:     %s", authReq.ClientID)
	s.log("  Response Mode: %s", authReq.ResponseMode)
	if authReq.Nonce != "" {
		s.log("  Nonce:         %s", authReq.Nonce)
	}
	if requestOrigin != "" {
		s.log("  Origin:        %s", requestOrigin)
	}

	if override := s.wallet.ConsumeNextError(); override != nil {
		s.log("  Next-error override consumed: %s", override.Error)
		result, buildErr := s.buildBrowserAuthorizationErrorResult(authReq, protocol, override.Error, override.ErrorDescription)
		if buildErr != nil {
			s.log("  ERROR: Browser error response failed: %v", buildErr)
			s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
			return
		}
		s.wallet.AddLog("presentation", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true)
		writeJSON(w, http.StatusOK, result)
		return
	}

	findings, err := ValidateAuthorizationRequest(s.wallet.ValidationMode, authReq)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", err.Error(), false)
		s.wallet.NotifyError(WalletError{
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	for _, finding := range findings {
		s.log("  WARNING: %s", finding)
		s.wallet.AddLog("presentation", fmt.Sprintf("request validation warning: %s", finding), false)
	}

	if s.wallet.RequireHAIP {
		if violations := ValidateHAIPCompliance(authReq, authReq.RequestObject); len(violations) > 0 {
			for _, v := range violations {
				s.log("  HAIP VIOLATION: %s", v)
			}
			s.wallet.AddLog("presentation", fmt.Sprintf("HAIP violations: %v", violations), false)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "HAIP 1.0 compliance check failed: " + strings.Join(violations, "; "),
			})
			return
		}
	}

	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	var matches []CredentialMatch
	if authReq.DCQLQuery != nil {
		matches = s.wallet.EvaluateDCQL(authReq.DCQLQuery)
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if len(matches) == 0 {
		s.log("  Result:        no matching credentials")
		s.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "no_match",
			"error":  "no matching credentials found",
		})
		return
	}

	if s.wallet.AutoAccept {
		s.writeBrowserPresentationResult(w, authReq, protocol, matches)
		return
	}

	s.log("  Mode:          interactive — waiting for consent...")
	consentReq := &ConsentRequest{
		ID:           uuid.New().String(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
	}

	s.wallet.CreateConsentRequest(consentReq)
	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			s.log("  Consent:       denied")
			browserResult, buildErr := s.buildBrowserAuthorizationErrorResult(authReq, protocol, "access_denied", "User denied presentation")
			if buildErr != nil {
				s.log("  ERROR: Browser error response failed: %v", buildErr)
				s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
				consentReq.SubmissionCh <- SubmissionResult{Error: buildErr.Error()}
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
				return
			}
			s.wallet.AddLog("presentation", fmt.Sprintf("Returned Browser API denial to %s", authReq.ClientID), true)
			consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK, Error: "access_denied"}
			writeJSON(w, http.StatusOK, browserResult)
			return
		}

		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := s.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred, selectedKeys)
					s.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		submission := s.writeBrowserPresentationResult(w, authReq, protocol, matches)
		consentReq.SubmissionCh <- submission
	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

func (s *Server) writeBrowserPresentationResult(w http.ResponseWriter, authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) SubmissionResult {
	result, prepared, err := s.buildBrowserPresentationResult(authReq, protocol, matches)
	if err != nil {
		s.log("  ERROR: Browser API presentation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Browser API presentation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	if prepared.VPResult != nil {
		s.log("  VP tokens:     %d created", len(prepared.VPResult.TokenMap))
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	s.wallet.AddLog("presentation", fmt.Sprintf("Returned Browser API presentation to %s", authReq.ClientID), true)
	writeJSON(w, http.StatusOK, result)
	return SubmissionResult{StatusCode: http.StatusOK}
}
