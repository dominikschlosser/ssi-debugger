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

package proxy

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestTerminalWriterImplementsEntryWriter(t *testing.T) {
	var _ EntryWriter = &TerminalWriter{}
}

func TestTerminalWriterAllTrafficFalseSkipsUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: false}
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}

	output := captureOutput(t, func() { tw.WriteEntry(entry) })
	if output != "" {
		t.Fatalf("expected no terminal output for unknown traffic by default, got %q", output)
	}
}

func TestTerminalWriterAllTrafficTrueIncludesUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: true}
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}

	output := captureOutput(t, func() { tw.WriteEntry(entry) })
	if !strings.Contains(output, "[Unknown]") {
		t.Fatalf("expected unknown traffic to be printed when allTraffic=true, got %q", output)
	}
}

// captureOutput redirects both os.Stdout and color.Output to capture all print output.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	oldColor := color.Output
	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldColor

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintEntryIncludesDecodeHints(t *testing.T) {
	entry := &TrafficEntry{
		Method:           "POST",
		URL:              "http://example.com/response",
		StatusCode:       200,
		Class:            ClassVPAuthResponse,
		ClassLabel:       "VP Auth Response",
		Credentials:      []string{"eyJhbGciOiJFUzI1NiJ9.test.sig"},
		CredentialLabels: []string{"vp_token"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, 0) })

	if !strings.Contains(output, "oid4vc-dev decode") {
		t.Error("expected decode hint in output")
	}
	if !strings.Contains(output, "decode:") {
		t.Error("expected decode section in output")
	}
}

func TestPrintDecodeHintWithLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "id_token", 0) })

	if !strings.Contains(output, "oid4vc-dev decode") {
		t.Errorf("expected decode command, got %q", output)
	}
	if !strings.Contains(output, "id_token: oid4vc-dev decode") {
		t.Errorf("expected label in output, got %q", output)
	}
}

func TestPrintDecodeHintWithoutLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "", 0) })

	if !strings.Contains(output, "oid4vc-dev decode") {
		t.Errorf("expected decode command, got %q", output)
	}
	if strings.Contains(output, "(") {
		t.Errorf("expected no label parens, got %q", output)
	}
}

func TestPrintDecodeHintWithDashboardPort(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "vp_token", 9091) })

	if !strings.Contains(output, "http://localhost:9091/decode?credential=cred-value") {
		t.Errorf("expected decode URL in output, got %q", output)
	}
	if !strings.Contains(output, "vp_token") {
		t.Errorf("expected label in output, got %q", output)
	}
}

func TestPrintEntryWithDashboardPortRendersDecodeLinkPerCredential(t *testing.T) {
	entry := &TrafficEntry{
		Method:           "POST",
		URL:              "http://example.com/response",
		StatusCode:       200,
		Class:            ClassVPAuthResponse,
		ClassLabel:       "VP Auth Response",
		Credentials:      []string{"cred-a", "cred-b"},
		CredentialLabels: []string{"vp_token.pid[0]", "vp_token.mdl[0]"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, 9091) })

	if strings.Count(output, "http://localhost:9091/decode?credential=") != 2 {
		t.Errorf("expected 2 decode links, got %q", output)
	}
	if !strings.Contains(output, "http://localhost:9091/decode?credential=cred-a") {
		t.Errorf("expected decode link for cred-a, got %q", output)
	}
	if !strings.Contains(output, "http://localhost:9091/decode?credential=cred-b") {
		t.Errorf("expected decode link for cred-b, got %q", output)
	}
}

func TestPrintDecodeHintEscapesCredentialQueryParam(t *testing.T) {
	credential := `{"cred1":["mdoc-credential"],"cred2":"jwt-credential"}`

	output := captureOutput(t, func() { printDecodeHint(credential, "vp_token", 9091) })

	if !strings.Contains(output, "http://localhost:9091/decode?credential="+url.QueryEscape(credential)) {
		t.Errorf("expected escaped decode URL in output, got %q", output)
	}
}

func TestTruncateURL(t *testing.T) {
	tests := []struct {
		url    string
		maxLen int
		want   string
	}{
		{"http://example.com/short", 100, "http://example.com/short"},
		{"http://example.com/very-long-path", 20, "http://example.com/v..."},
		{"exact", 5, "exact"},
		{"", 10, ""},
	}

	for _, tt := range tests {
		got := truncateURL(tt.url, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateURL(%q, %d) = %q, want %q", tt.url, tt.maxLen, got, tt.want)
		}
	}
}

func TestPrintEntryGroupsRequestResponseAndDecodeSections(t *testing.T) {
	entry := &TrafficEntry{
		Method:     "POST",
		URL:        "http://issuer.example/oauth/token",
		StatusCode: 200,
		Class:      ClassVCITokenRequest,
		ClassLabel: "VCI Token Request",
		Decoded: map[string]any{
			"client_id":     "wallet-app",
			"grant_type":    "authorization_code",
			"code":          "abc123",
			"redirect_uri":  "app://callback",
			"code_verifier": "verifier",
			"response": map[string]any{
				"access_token":  "token-value",
				"token_type":    "DPoP",
				"expires_in":    300,
				"refresh_token": "refresh-value",
			},
		},
		Credentials:      []string{"token-value", "refresh-value"},
		CredentialLabels: []string{"access_token", "refresh_token"},
	}

	output := captureOutput(t, func() { PrintEntry(entry, 9091) })

	requestIndex := strings.Index(output, "  request:\n")
	responseIndex := strings.Index(output, "  response:\n")
	decodeIndex := strings.Index(output, "  decode:\n")
	if requestIndex < 0 || responseIndex < 0 || decodeIndex < 0 {
		t.Fatalf("expected request/response/decode sections, got %q", output)
	}
	if !(requestIndex < responseIndex && responseIndex < decodeIndex) {
		t.Fatalf("expected request, response, then decode order, got %q", output)
	}
	if !strings.Contains(output, "\n\n  response:\n") {
		t.Fatalf("expected blank line between request and response sections, got %q", output)
	}
	if !strings.Contains(output, "\n\n  decode:\n") {
		t.Fatalf("expected blank line before decode section, got %q", output)
	}
	if strings.Index(output, "grant_type: authorization_code") > strings.Index(output, "code_verifier: verifier") {
		t.Fatalf("expected prioritized request field order, got %q", output)
	}
	if strings.Index(output, "token_type: DPoP") > strings.Index(output, "access_token: token-value") {
		t.Fatalf("expected prioritized response field order, got %q", output)
	}
	if !strings.Contains(output, "access_token: http://localhost:9091/decode?credential=token-value") {
		t.Fatalf("expected working decode URL for access token, got %q", output)
	}
	if !strings.Contains(output, "refresh_token: http://localhost:9091/decode?credential=refresh-value") {
		t.Fatalf("expected working decode URL for refresh token, got %q", output)
	}
}

func TestTerminalWriterGroupsConsecutiveEntriesByFlow(t *testing.T) {
	tw := &TerminalWriter{}

	first := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/token",
		RequestBody: "grant_type=authorization_code&code=issued-code",
		StatusCode:  200,
		Class:       ClassVCITokenRequest,
		ClassLabel:  "VCI Token Request",
		FlowID:      "flow-7",
		Decoded: map[string]any{
			"grant_type": "authorization_code",
			"code":       "issued-code",
			"response": map[string]any{
				"access_token": "token-123",
			},
		},
	}
	second := &TrafficEntry{
		Method:     "POST",
		URL:        "http://issuer.example/credential",
		StatusCode: 200,
		Class:      ClassVCICredentialRequest,
		ClassLabel: "VCI Credential Request",
		FlowID:     "flow-7",
		Decoded: map[string]any{
			"request": map[string]any{
				"credential_identifier": "membership-credential_0000",
			},
		},
	}

	output := captureOutput(t, func() {
		tw.WriteEntry(first)
		tw.WriteEntry(second)
	})

	if strings.Count(output, "[flow-7]") != 1 {
		t.Fatalf("expected one flow header for consecutive flow entries, got %q", output)
	}
	if !strings.Contains(output, "VCI Authorization Code Flow") {
		t.Fatalf("expected VCI flow title, got %q", output)
	}
	if !strings.Contains(output, "code=issued-code") {
		t.Fatalf("expected flow summary with code, got %q", output)
	}
}
