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

var printerCmd = &cobra.Command{
	Use:   "printer",
	Short: "Manage Samba printer shares and list CUPS queues",
}

var printerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List printer shares / CUPS queues",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		list, err := svcs.Printers.List(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(list)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tCUPS\tSMB\tPATH\tCOMMENT")
		for _, p := range list {
			fmt.Fprintf(w, "%s\t%v\t%v\t%s\t%s\n", p.Name, p.CUPS, p.InSMBConf, p.Path, p.Comment)
		}
		return w.Flush()
	},
}

var printerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a printable Samba share (+ spool dir)",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		path, _ := cmd.Flags().GetString("path")
		comment, _ := cmd.Flags().GetString("comment")
		cups, _ := cmd.Flags().GetString("cups-name")
		guest, _ := cmd.Flags().GetBool("guest-ok")
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		p, err := svcs.Printers.Create(context.Background(), service.CreatePrinterInput{
			Name: name, Path: path, Comment: comment, PrinterName: cups, GuestOK: &guest,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(p)
		}
		fmt.Printf("created printer share %s → %s (cups=%s)\n", p.Name, p.Path, p.PrinterName)
		return nil
	},
}

var printerDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Remove a printer share from smb.conf",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Printers.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

func init() {
	printerCreateCmd.Flags().String("name", "", "share name (required)")
	printerCreateCmd.Flags().String("path", "", "spool path")
	printerCreateCmd.Flags().String("comment", "", "comment")
	printerCreateCmd.Flags().String("cups-name", "", "CUPS queue name (default: share name)")
	printerCreateCmd.Flags().Bool("guest-ok", false, "guest ok")
	_ = printerCreateCmd.MarkFlagRequired("name")

	printerCmd.AddCommand(printerListCmd, printerCreateCmd, printerDeleteCmd)
	rootCmd.AddCommand(printerCmd)
}
