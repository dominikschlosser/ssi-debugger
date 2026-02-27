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

package statuslist

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// ExtractStatusRef extracts the status list reference from SD-JWT claims or mDOC MSO status.
func ExtractStatusRef(claims map[string]any) *StatusRef {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return nil
	}
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return nil
	}

	ref := &StatusRef{}
	if uri, ok := sl["uri"].(string); ok {
		ref.URI = uri
	}
	switch v := sl["idx"].(type) {
	case float64:
		ref.Idx = int(v)
	case int64:
		ref.Idx = int(v)
	case int:
		ref.Idx = v
	}

	if ref.URI == "" {
		return nil
	}
	return ref
}

// Check fetches the status list and checks the credential's status.
func Check(ref *StatusRef) (*StatusResult, error) {
	result := &StatusResult{
		URI:   ref.URI,
		Index: ref.Idx,
	}

	// Fetch status list JWT
	req, err := http.NewRequest("GET", ref.URI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/statuslist+jwt")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching status list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status list returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Parse the status list JWT (we only need the payload)
	jwtStr := strings.TrimSpace(string(body))
	parts := strings.SplitN(jwtStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid status list JWT format")
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding status list payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing status list payload: %w", err)
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no status_list in JWT payload")
	}

	bits := 1
	if b, ok := sl["bits"].(float64); ok {
		bits = int(b)
	}
	result.BitsPerEntry = bits

	lst, ok := sl["lst"].(string)
	if !ok {
		return nil, fmt.Errorf("no lst in status_list")
	}

	// Decode and decompress the bitstring
	compressed, err := format.DecodeBase64URL(lst)
	if err != nil {
		return nil, fmt.Errorf("decoding lst: %w", err)
	}

	decompressed, err := zlibDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing status list: %w", err)
	}

	// Extract status value
	status, err := extractStatus(decompressed, ref.Idx, bits)
	if err != nil {
		return nil, err
	}

	result.Status = status
	result.IsValid = status == 0

	return result, nil
}

func zlibDecompress(data []byte) ([]byte, error) {
	// Try zlib first (with header)
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer r.Close()
		return io.ReadAll(r)
	}

	// Fall back to raw DEFLATE
	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()
	return io.ReadAll(fr)
}

func extractStatus(bitstring []byte, idx, bits int) (int, error) {
	bitPos := idx * bits
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	if byteIdx >= len(bitstring) {
		return 0, fmt.Errorf("index %d out of range (bitstring length: %d bytes)", idx, len(bitstring))
	}

	mask := (1 << bits) - 1
	value := (int(bitstring[byteIdx]) >> bitOffset) & mask

	return value, nil
}
