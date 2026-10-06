package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var replCmd = &cobra.Command{
	Use:   "repl",
	Short: "Replication status and sync",
}

var replPartnersCmd = &cobra.Command{
	Use:   "partners",
	Short: "List replication partners (nTDSDSA)",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		partners, err := svcs.Repl.Partners(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(partners)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATUS\tDN")
		for _, p := range partners {
			fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Status, p.DN)
		}
		return w.Flush()
	},
}

var replStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show replication status (samba-tool drs showrepl)",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		st, err := svcs.Repl.Status(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(st)
		}
		if st.Raw != "" {
			fmt.Println(st.Raw)
		}
		if len(st.Partners) > 0 {
			fmt.Println("\nPartners:")
			for _, p := range st.Partners {
				fmt.Printf("  %s\t%s\n", p.Name, p.DN)
			}
		}
		return nil
	},
}

var replSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Trigger replication (samba-tool drs replicate)",
	RunE: func(cmd *cobra.Command, args []string) error {
		from, _ := cmd.Flags().GetString("from")
		dest, _ := cmd.Flags().GetString("dest")
		nc, _ := cmd.Flags().GetString("nc")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		if dest == "" {
			return svcs.Repl.SyncFrom(context.Background(), from, actorName(), "cli")
		}
		return svcs.Repl.Sync(context.Background(), dest, from, nc, actorName(), "cli")
	},
}

func init() {
	replSyncCmd.Flags().String("from", "", "source DC (required)")
	replSyncCmd.Flags().String("dest", "", "destination DC (default: this host / LDAP URI host)")
	replSyncCmd.Flags().String("nc", "", "naming context DN (default: domain base DN)")
	_ = replSyncCmd.MarkFlagRequired("from")
	replCmd.AddCommand(replPartnersCmd, replStatusCmd, replSyncCmd)
}
