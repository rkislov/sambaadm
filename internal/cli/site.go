package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var siteCmd = &cobra.Command{
	Use:   "site",
	Short: "Manage AD sites",
}

var siteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sites",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		sites, err := svcs.Sites.List(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(sites)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tDN")
		for _, s := range sites {
			fmt.Fprintf(w, "%s\t%s\n", s.Name, s.DN)
		}
		return w.Flush()
	},
}

var siteCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a site",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		site, err := svcs.Sites.Create(context.Background(), name, actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Println("created", site.DN)
		return nil
	},
}

var siteDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a site",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Sites.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

var subnetCmd = &cobra.Command{
	Use:   "subnet",
	Short: "Manage AD subnets",
}

var subnetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List subnets",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		subnets, err := svcs.Subnets.List(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(subnets)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SUBNET\tSITE\tDN")
		for _, s := range subnets {
			fmt.Fprintf(w, "%s\t%s\t%s\n", s.Name, s.Site, s.DN)
		}
		return w.Flush()
	},
}

var subnetCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a subnet linked to a site",
	RunE: func(cmd *cobra.Command, args []string) error {
		subnet, _ := cmd.Flags().GetString("subnet")
		site, _ := cmd.Flags().GetString("site")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		s, err := svcs.Subnets.Create(context.Background(), subnet, site, actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Println("created", s.DN)
		return nil
	},
}

var subnetDeleteCmd = &cobra.Command{
	Use:   "delete <subnet>",
	Short: "Delete a subnet",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Subnets.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

func init() {
	siteCreateCmd.Flags().String("name", "", "site name (required)")
	_ = siteCreateCmd.MarkFlagRequired("name")
	siteCmd.AddCommand(siteListCmd, siteCreateCmd, siteDeleteCmd)

	subnetCreateCmd.Flags().String("subnet", "", "CIDR, e.g. 10.0.0.0/24 (required)")
	subnetCreateCmd.Flags().String("site", "", "site name or DN (required)")
	_ = subnetCreateCmd.MarkFlagRequired("subnet")
	_ = subnetCreateCmd.MarkFlagRequired("site")
	subnetCmd.AddCommand(subnetListCmd, subnetCreateCmd, subnetDeleteCmd)
}
