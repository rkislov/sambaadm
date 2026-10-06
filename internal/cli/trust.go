package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sambaadm/internal/service"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage domain trusts",
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusts",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		trusts, err := svcs.Trusts.List(context.Background())
		if err != nil {
			return err
		}
		return printTrusts(trusts)
	},
}

var trustShowCmd = &cobra.Command{
	Use:   "show <domain>",
	Short: "Show a trust",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		t, err := svcs.Trusts.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printTrusts([]service.Trust{*t})
	},
}

var trustCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a trust (requires samba-tool)",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		direction, _ := cmd.Flags().GetString("direction")
		typ, _ := cmd.Flags().GetString("type")
		prompt, _ := cmd.Flags().GetBool("prompt")
		password, _ := cmd.Flags().GetString("password")
		if prompt || password == "" {
			var err error
			password, err = readPassword("Trust password: ")
			if err != nil {
				return err
			}
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Trusts.Create(context.Background(), service.CreateTrustInput{
			Domain: domain, Direction: direction, Type: typ, Password: password,
		}, actorName(), "cli")
	},
}

var trustDeleteCmd = &cobra.Command{
	Use:   "delete <domain>",
	Short: "Delete a trust (requires samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Trusts.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

var trustValidateCmd = &cobra.Command{
	Use:   "validate <domain>",
	Short: "Validate a trust (requires samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		out, err := svcs.Trusts.Validate(context.Background(), args[0], actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	},
}

func init() {
	trustCreateCmd.Flags().String("domain", "", "trusted domain (required)")
	trustCreateCmd.Flags().String("direction", "both", "incoming|outgoing|both")
	trustCreateCmd.Flags().String("type", "external", "external|forest")
	trustCreateCmd.Flags().String("password", "", "trust password (prefer --prompt)")
	trustCreateCmd.Flags().Bool("prompt", true, "read trust password from terminal")
	_ = trustCreateCmd.MarkFlagRequired("domain")
	trustCmd.AddCommand(trustListCmd, trustShowCmd, trustCreateCmd, trustDeleteCmd, trustValidateCmd)
}

func printTrusts(trusts []service.Trust) error {
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(trusts)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tDIRECTION\tTYPE\tDN")
	for _, t := range trusts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Domain, t.Direction, t.Type, t.DN)
	}
	return w.Flush()
}
