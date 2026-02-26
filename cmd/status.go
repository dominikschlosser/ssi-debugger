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

package cmd

import (
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
	"github.com/dominikschlosser/ssi-debugger/internal/statuslist"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status [input]",
	Short: "Check credential revocation via status list",
	Long:  "Extracts the status list reference from a credential and checks revocation status. This makes a network call to fetch the status list.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	var claims map[string]any

	detected := format.Detect(raw)
	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		claims = token.ResolvedClaims

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.Status != nil {
			claims = map[string]any{"status": doc.IssuerAuth.MSO.Status}
		} else {
			return fmt.Errorf("no status information found in mDOC")
		}

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	ref := statuslist.ExtractStatusRef(claims)
	if ref == nil {
		return fmt.Errorf("no status list reference found in credential")
	}

	if !opts.JSON {
		fmt.Printf("Checking status at: %s (index %d)\n", ref.URI, ref.Idx)
	}

	result, err := statuslist.Check(ref)
	if err != nil {
		return fmt.Errorf("status check failed: %w", err)
	}

	if opts.JSON {
		output.PrintJSON(result)
	} else {
		if result.IsValid {
			fmt.Printf("✓ Credential is valid (status=%d, bits=%d)\n", result.Status, result.BitsPerEntry)
		} else {
			fmt.Printf("✗ Credential is revoked (status=%d, bits=%d)\n", result.Status, result.BitsPerEntry)
		}
	}

	if !result.IsValid {
		return fmt.Errorf("credential is revoked")
	}

	return nil
}
