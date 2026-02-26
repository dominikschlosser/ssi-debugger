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
	"github.com/spf13/cobra"
)

var decodeCmd = &cobra.Command{
	Use:   "decode [input]",
	Short: "Auto-detect and decode a JWT, SD-JWT, or mDOC credential",
	Long:  "Decodes a credential, auto-detecting the format (JWT, SD-JWT, or mDOC). Input can be a file path, URL, raw credential string, or piped via stdin.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDecode,
}

func init() {
	rootCmd.AddCommand(decodeCmd)
}

func runDecode(cmd *cobra.Command, args []string) error {
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

	detected := format.Detect(raw)

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		output.PrintSDJWT(token, opts)

	case format.FormatJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		output.PrintJWT(token, opts)

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		output.PrintMDOC(doc, opts)

	default:
		return fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mDOC)")
	}

	return nil
}
