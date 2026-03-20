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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func TestWalletGeneratePID_SetsIssuerURLForSDJWT(t *testing.T) {
	tmpDir := t.TempDir()
	wDir := filepath.Join(tmpDir, "wallet")
	if err := os.MkdirAll(wDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	walletDir = wDir

	rootCmd.SetArgs([]string{"wallet", "generate-pid"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet generate-pid: %v", err)
	}

	store := wallet.NewWalletStore(wDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}

	creds := w.GetCredentials()
	if len(creds) == 0 {
		t.Fatal("expected generated credentials")
	}

	token, err := sdjwt.Parse(creds[0].Raw)
	if err != nil {
		t.Fatalf("parse generated SD-JWT: %v", err)
	}

	want := wallet.LocalIssuerURL(config.DefaultWalletPort+1, false)
	if token.Payload["iss"] != want {
		t.Fatalf("expected iss %s, got %v", want, token.Payload["iss"])
	}
}
