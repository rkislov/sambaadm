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

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage domain groups",
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()

		groups, err := svcs.Groups.List(context.Background(), "")
		if err != nil {
			return err
		}
		return printGroups(groups)
	},
}

func init() {
	groupCmd.AddCommand(groupListCmd)
}

func printGroups(groups []service.Group) error {
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(groups)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMEMBERS\tDN")
	for _, g := range groups {
		fmt.Fprintf(w, "%s\t%d\t%s\n", g.SAMAccountName, len(g.Members), g.DN)
	}
	return w.Flush()
}
