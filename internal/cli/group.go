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

var groupShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		g, err := svcs.Groups.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printGroups([]service.Group{*g})
	},
}

var groupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		ou, _ := cmd.Flags().GetString("ou")
		desc, _ := cmd.Flags().GetString("description")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		g, err := svcs.Groups.Create(context.Background(), service.CreateGroupInput{
			Name: name, OU: ou, Description: desc,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Printf("created %s (%s)\n", g.SAMAccountName, g.DN)
		return nil
	},
}

var groupDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		if err := svcs.Groups.Delete(context.Background(), args[0], actorName(), "cli"); err != nil {
			return err
		}
		fmt.Println("deleted", args[0])
		return nil
	},
}

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member <group> <member-dn>",
	Short: "Add a member DN to a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Groups.AddMember(context.Background(), args[0], args[1], actorName(), "cli")
	},
}

var groupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member <group> <member-dn>",
	Short: "Remove a member DN from a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Groups.RemoveMember(context.Background(), args[0], args[1], actorName(), "cli")
	},
}

var groupMembersCmd = &cobra.Command{
	Use:   "members <group>",
	Short: "List group members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		members, err := svcs.Groups.Members(context.Background(), args[0])
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(members)
		}
		for _, m := range members {
			fmt.Println(m)
		}
		return nil
	},
}

func init() {
	groupCreateCmd.Flags().String("name", "", "group name (required)")
	groupCreateCmd.Flags().String("ou", "", "parent OU DN")
	groupCreateCmd.Flags().String("description", "", "description")
	_ = groupCreateCmd.MarkFlagRequired("name")
	groupCmd.AddCommand(
		groupListCmd, groupShowCmd, groupCreateCmd, groupDeleteCmd,
		groupAddMemberCmd, groupRemoveMemberCmd, groupMembersCmd,
	)
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
