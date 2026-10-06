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

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage AD-integrated DNS",
}

var dnsZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "DNS zone operations",
}

var dnsZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List DNS zones",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		zones, err := svcs.DNS.ListZones(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(zones)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSOURCE\tDN")
		for _, z := range zones {
			fmt.Fprintf(w, "%s\t%s\t%s\n", z.Name, z.Source, z.DN)
		}
		return w.Flush()
	},
}

var dnsZoneCreateCmd = &cobra.Command{
	Use:   "create <zone>",
	Short: "Create a DNS zone (samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.DNS.CreateZone(context.Background(), args[0], actorName(), "cli")
	},
}

var dnsZoneDeleteCmd = &cobra.Command{
	Use:   "delete <zone>",
	Short: "Delete a DNS zone (samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.DNS.DeleteZone(context.Background(), args[0], actorName(), "cli")
	},
}

var dnsRecordCmd = &cobra.Command{
	Use:   "record",
	Short: "DNS record operations",
}

var dnsRecordQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query DNS records",
	RunE: func(cmd *cobra.Command, args []string) error {
		zone, _ := cmd.Flags().GetString("zone")
		name, _ := cmd.Flags().GetString("name")
		typ, _ := cmd.Flags().GetString("type")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		recs, err := svcs.DNS.QueryRecords(context.Background(), zone, name, typ)
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(recs)
		}
		for _, r := range recs {
			fmt.Println(r.Raw)
		}
		return nil
	},
}

var dnsRecordAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a DNS record (A, CNAME, SRV, ...)",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := dnsRecordFlags(cmd)
		if err != nil {
			return err
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.DNS.AddRecord(context.Background(), in, actorName(), "cli")
	},
}

var dnsRecordUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a DNS record",
	RunE: func(cmd *cobra.Command, args []string) error {
		zone, _ := cmd.Flags().GetString("zone")
		name, _ := cmd.Flags().GetString("name")
		typ, _ := cmd.Flags().GetString("type")
		oldData, _ := cmd.Flags().GetString("old-data")
		newData, _ := cmd.Flags().GetString("data")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.DNS.UpdateRecord(context.Background(), service.UpdateDNSRecordInput{
			Zone: zone, Name: name, Type: typ, OldData: oldData, NewData: newData,
		}, actorName(), "cli")
	},
}

var dnsRecordDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a DNS record",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := dnsRecordFlags(cmd)
		if err != nil {
			return err
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.DNS.DeleteRecord(context.Background(), in, actorName(), "cli")
	},
}

func dnsRecordFlags(cmd *cobra.Command) (service.AddDNSRecordInput, error) {
	zone, _ := cmd.Flags().GetString("zone")
	name, _ := cmd.Flags().GetString("name")
	typ, _ := cmd.Flags().GetString("type")
	data, _ := cmd.Flags().GetString("data")
	if zone == "" || name == "" || typ == "" || data == "" {
		return service.AddDNSRecordInput{}, fmt.Errorf("--zone, --name, --type and --data are required")
	}
	return service.AddDNSRecordInput{Zone: zone, Name: name, Type: typ, Data: data}, nil
}

func init() {
	dnsZoneCmd.AddCommand(dnsZoneListCmd, dnsZoneCreateCmd, dnsZoneDeleteCmd)

	for _, c := range []*cobra.Command{dnsRecordAddCmd, dnsRecordDeleteCmd, dnsRecordUpdateCmd, dnsRecordQueryCmd} {
		c.Flags().String("zone", "", "zone name")
		c.Flags().String("name", "@", "record name")
		c.Flags().String("type", "A", "record type (A, CNAME, SRV, ...)")
	}
	dnsRecordAddCmd.Flags().String("data", "", "record data (IP, target, or SRV fields)")
	dnsRecordDeleteCmd.Flags().String("data", "", "record data to delete")
	dnsRecordUpdateCmd.Flags().String("old-data", "", "previous record data")
	dnsRecordUpdateCmd.Flags().String("data", "", "new record data")
	_ = dnsRecordAddCmd.MarkFlagRequired("zone")
	_ = dnsRecordAddCmd.MarkFlagRequired("data")
	_ = dnsRecordDeleteCmd.MarkFlagRequired("zone")
	_ = dnsRecordDeleteCmd.MarkFlagRequired("data")
	_ = dnsRecordUpdateCmd.MarkFlagRequired("zone")
	_ = dnsRecordUpdateCmd.MarkFlagRequired("old-data")
	_ = dnsRecordUpdateCmd.MarkFlagRequired("data")
	_ = dnsRecordQueryCmd.MarkFlagRequired("zone")

	dnsRecordCmd.AddCommand(dnsRecordQueryCmd, dnsRecordAddCmd, dnsRecordUpdateCmd, dnsRecordDeleteCmd)
	dnsCmd.AddCommand(dnsZoneCmd, dnsRecordCmd)
}
