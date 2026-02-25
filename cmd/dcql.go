package cmd

import (
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/dcql"
	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
	"github.com/spf13/cobra"
)

var dcqlCmd = &cobra.Command{
	Use:   "dcql [input]",
	Short: "Generate a DCQL query from a credential's claims",
	Long:  "Generates a DCQL (Digital Credentials Query Language) query based on the claims found in an SD-JWT or mDOC credential.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDCQL,
}

func init() {
	rootCmd.AddCommand(dcqlCmd)
}

func runDCQL(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	detected := format.Detect(raw)

	var query *dcql.Query

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		query = dcql.FromSDJWT(token)

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		query = dcql.FromMDOC(doc)

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	// DCQL is a JSON query format — always output as JSON
	output.PrintJSON(query)

	return nil
}
