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

var ouCmd = &cobra.Command{
	Use:   "ou",
	Short: "Manage organizational units",
}

var ouListCmd = &cobra.Command{
	Use:   "list",
	Short: "List OUs",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		ous, err := svcs.OU.List(context.Background())
		if err != nil {
			return err
		}
		return printOUs(ous)
	},
}

var ouTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "List OUs (tree-friendly flat list)",
	RunE:  ouListCmd.RunE,
}

var ouCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an OU",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		parent, _ := cmd.Flags().GetString("parent")
		desc, _ := cmd.Flags().GetString("description")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		ou, err := svcs.OU.Create(context.Background(), service.CreateOUInput{
			Name: name, ParentDN: parent, Description: desc,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Printf("created %s\n", ou.DN)
		return nil
	},
}

var ouDeleteCmd = &cobra.Command{
	Use:   "delete <dn>",
	Short: "Delete an OU by DN",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.OU.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

var ouMoveCmd = &cobra.Command{
	Use:   "move <dn>",
	Short: "Move an OU under a new parent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		to, _ := cmd.Flags().GetString("to")
		if to == "" {
			return fmt.Errorf("--to is required")
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.OU.Move(context.Background(), args[0], to, actorName(), "cli")
	},
}

func init() {
	ouCreateCmd.Flags().String("name", "", "OU name (required)")
	ouCreateCmd.Flags().String("parent", "", "parent DN (default: base DN)")
	ouCreateCmd.Flags().String("description", "", "description")
	_ = ouCreateCmd.MarkFlagRequired("name")
	ouMoveCmd.Flags().String("to", "", "new parent DN")
	_ = ouMoveCmd.MarkFlagRequired("to")
	ouCmd.AddCommand(ouListCmd, ouTreeCmd, ouCreateCmd, ouDeleteCmd, ouMoveCmd)
}

func printOUs(ous []service.OU) error {
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(ous)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDN")
	for _, o := range ous {
		fmt.Fprintf(w, "%s\t%s\n", o.Name, o.DN)
	}
	return w.Flush()
}
