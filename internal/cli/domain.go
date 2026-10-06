package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Domain information and FSMO",
}

var domainInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show domain information",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		info, err := svcs.Domain.Info(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("Base DN:   %s\n", info.BaseDN)
		fmt.Printf("DNS root:  %s\n", info.DNSRoot)
		fmt.Printf("NetBIOS:   %s\n", info.NetBIOS)
		fmt.Printf("Level:     %s\n", info.FunctionLvl)
		return nil
	},
}

var domainFSMOCmd = &cobra.Command{
	Use:   "fsmo",
	Short: "FSMO role operations",
}

var domainFSMOShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show FSMO role owners",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		roles, err := svcs.Domain.FSMOShow(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(roles)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ROLE\tOWNER\tSOURCE")
		for _, r := range roles {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Role, r.Owner, r.Source)
		}
		return w.Flush()
	},
}

var domainFSMOTransferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Transfer an FSMO role to this DC (samba-tool)",
	RunE: func(cmd *cobra.Command, args []string) error {
		role, _ := cmd.Flags().GetString("role")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Domain.FSMOTransfer(context.Background(), role, actorName(), "cli")
	},
}

var domainFSMOSeizeCmd = &cobra.Command{
	Use:   "seize",
	Short: "Seize an FSMO role (samba-tool, last resort)",
	RunE: func(cmd *cobra.Command, args []string) error {
		role, _ := cmd.Flags().GetString("role")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Domain.FSMOSeize(context.Background(), role, actorName(), "cli")
	},
}

var domainLevelCmd = &cobra.Command{
	Use:   "level",
	Short: "Domain / forest functional level",
}

var domainLevelShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show functional levels",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		lvl, err := svcs.Domain.LevelShow(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(lvl)
		}
		if lvl.Raw != "" {
			fmt.Println(lvl.Raw)
			return nil
		}
		fmt.Printf("Domain: %s\nForest: %s\n", lvl.Domain, lvl.Forest)
		return nil
	},
}

var domainLevelRaiseCmd = &cobra.Command{
	Use:   "raise",
	Short: "Raise domain/forest level (samba-tool)",
	RunE: func(cmd *cobra.Command, args []string) error {
		dom, _ := cmd.Flags().GetString("domain-level")
		forest, _ := cmd.Flags().GetString("forest-level")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Domain.LevelRaise(context.Background(), dom, forest, actorName(), "cli")
	},
}

func init() {
	domainFSMOTransferCmd.Flags().String("role", "", "schema|naming|pdc|rid|infrastructure|all")
	_ = domainFSMOTransferCmd.MarkFlagRequired("role")
	domainFSMOSeizeCmd.Flags().String("role", "", "schema|naming|pdc|rid|infrastructure|all")
	_ = domainFSMOSeizeCmd.MarkFlagRequired("role")
	domainLevelRaiseCmd.Flags().String("domain-level", "", "e.g. 2008_R2, 2012, 2016")
	domainLevelRaiseCmd.Flags().String("forest-level", "", "e.g. 2008_R2, 2012, 2016")

	domainFSMOCmd.AddCommand(domainFSMOShowCmd, domainFSMOTransferCmd, domainFSMOSeizeCmd)
	domainLevelCmd.AddCommand(domainLevelShowCmd, domainLevelRaiseCmd)
	domainCmd.AddCommand(domainInfoCmd, domainFSMOCmd, domainLevelCmd)
}
