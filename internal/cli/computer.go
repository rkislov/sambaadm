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

var computerCmd = &cobra.Command{
	Use:   "computer",
	Short: "Manage computer accounts",
}

var computerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List computers",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		computers, err := svcs.Computers.List(context.Background(), "")
		if err != nil {
			return err
		}
		return printComputers(computers)
	},
}

var computerShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a computer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		c, err := svcs.Computers.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printComputers([]service.Computer{*c})
	},
}

var computerDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a computer account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Computers.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

var computerMoveCmd = &cobra.Command{
	Use:   "move <name>",
	Short: "Move a computer to another OU",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		toOU, _ := cmd.Flags().GetString("to-ou")
		if toOU == "" {
			return fmt.Errorf("--to-ou is required")
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Computers.Move(context.Background(), args[0], toOU, actorName(), "cli")
	},
}

func init() {
	computerMoveCmd.Flags().String("to-ou", "", "destination OU DN")
	_ = computerMoveCmd.MarkFlagRequired("to-ou")
	computerCmd.AddCommand(computerListCmd, computerShowCmd, computerDeleteCmd, computerMoveCmd)
}

func printComputers(computers []service.Computer) error {
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(computers)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDNS\tOS\tDN")
	for _, c := range computers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.SAMAccountName, c.DNSHostName, c.OS, c.DN)
	}
	return w.Flush()
}
