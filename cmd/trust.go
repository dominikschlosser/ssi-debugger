package cmd

import (
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/trustlist"
	"github.com/spf13/cobra"
)

var trustCmd = &cobra.Command{
	Use:   "trust <file|url>",
	Short: "Inspect an ETSI TS 119 602 trust list JWT",
	Long:  "Parses and displays the contents of an ETSI trust list JWT, including trusted entities and their X.509 certificates. Accepts a file path, URL, raw JWT string, or stdin.",
	Args:  cobra.ExactArgs(1),
	RunE:  runTrust,
}

func init() {
	rootCmd.AddCommand(trustCmd)
}

func runTrust(cmd *cobra.Command, args []string) error {
	raw, err := format.ReadInput(args[0])
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	tl, err := trustlist.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing trust list: %w", err)
	}

	if opts.JSON {
		out := map[string]any{
			"header": tl.Header,
		}
		if tl.SchemeInfo != nil {
			out["schemeInfo"] = map[string]any{
				"loTEType":           tl.SchemeInfo.LoTEType,
				"schemeOperatorName": tl.SchemeInfo.SchemeOperatorName,
				"listIssueDatetime":  tl.SchemeInfo.ListIssueDatetime,
			}
		}
		entities := make([]map[string]any, 0)
		for _, e := range tl.Entities {
			entity := map[string]any{
				"name": e.Name,
			}
			services := make([]map[string]any, 0)
			for _, s := range e.Services {
				svc := map[string]any{
					"serviceType": s.ServiceType,
				}
				certs := make([]map[string]any, 0)
				for _, c := range s.Certificates {
					certs = append(certs, map[string]any{
						"subject":   c.Subject,
						"issuer":    c.Issuer,
						"notBefore": c.NotBefore,
						"notAfter":  c.NotAfter,
					})
				}
				svc["certificates"] = certs
				services = append(services, svc)
			}
			entity["services"] = services
			entities = append(entities, entity)
		}
		out["entities"] = entities
		output.PrintJSON(out)
		return nil
	}

	// Terminal output
	fmt.Println("ETSI TS 119 602 Trust List")
	fmt.Println("──────────────────────────────────────────────────")

	if tl.SchemeInfo != nil {
		fmt.Printf("\n  Operator:  %s\n", tl.SchemeInfo.SchemeOperatorName)
		fmt.Printf("  Type:      %s\n", tl.SchemeInfo.LoTEType)
		fmt.Printf("  Issued:    %s\n", tl.SchemeInfo.ListIssueDatetime)
	}

	if alg, ok := tl.Header["alg"].(string); ok {
		fmt.Printf("  Algorithm: %s\n", alg)
	}

	fmt.Printf("\n  Trusted Entities (%d):\n", len(tl.Entities))
	for _, e := range tl.Entities {
		fmt.Printf("\n  ┌ %s\n", e.Name)
		for _, s := range e.Services {
			fmt.Printf("  │ Service: %s\n", s.ServiceType)
			for _, c := range s.Certificates {
				fmt.Printf("  │   Subject: %s\n", c.Subject)
				fmt.Printf("  │   Issuer:  %s\n", c.Issuer)
				fmt.Printf("  │   Valid:   %s → %s\n", c.NotBefore, c.NotAfter)
			}
		}
	}

	fmt.Println()
	return nil
}
