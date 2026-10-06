package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"sambaadm/internal/service"
)

var gpoCmd = &cobra.Command{
	Use:   "gpo",
	Short: "Manage Group Policy Objects",
}

var gpoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List GPOs",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		gpos, err := svcs.GPO.List(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(gpos)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DISPLAY\tGUID\tSOURCE")
		for _, g := range gpos {
			fmt.Fprintf(w, "%s\t%s\t%s\n", g.DisplayName, g.GUID, g.Source)
		}
		return w.Flush()
	},
}

var gpoShowCmd = &cobra.Command{
	Use:   "show <gpo>",
	Short: "Show GPO details (samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		out, err := svcs.GPO.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	},
}

var gpoCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a GPO (samba-tool)",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		out, err := svcs.GPO.Create(context.Background(), name, actorName(), "cli")
		if err != nil {
			return err
		}
		if out != "" {
			fmt.Println(out)
		}
		return nil
	},
}

var gpoDeleteCmd = &cobra.Command{
	Use:   "delete <gpo>",
	Short: "Delete a GPO (samba-tool)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.GPO.Delete(context.Background(), args[0], actorName(), "cli")
	},
}

var gpoLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Link a GPO to a container DN",
	RunE: func(cmd *cobra.Command, args []string) error {
		container, _ := cmd.Flags().GetString("container")
		gpo, _ := cmd.Flags().GetString("gpo")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.GPO.Link(context.Background(), container, gpo, actorName(), "cli")
	},
}

var gpoUnlinkCmd = &cobra.Command{
	Use:   "unlink",
	Short: "Unlink a GPO from a container DN",
	RunE: func(cmd *cobra.Command, args []string) error {
		container, _ := cmd.Flags().GetString("container")
		gpo, _ := cmd.Flags().GetString("gpo")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.GPO.Unlink(context.Background(), container, gpo, actorName(), "cli")
	},
}

var gpoBackupCmd = &cobra.Command{
	Use:   "backup <gpo>",
	Short: "Backup a GPO to a directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.GPO.Backup(context.Background(), args[0], path, actorName(), "cli")
	},
}

var gpoRestoreCmd = &cobra.Command{
	Use:   "restore <gpo>",
	Short: "Restore a GPO from a backup directory",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.GPO.Restore(context.Background(), args[0], path, actorName(), "cli")
	},
}

var gpoDistributeCmd = &cobra.Command{
	Use:   "distribute <gpo>",
	Short: "Distribute GPO SYSVOL to all domain controllers (DRS + rsync + ACL)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		job, err := svcs.GPO.StartDistribute(context.Background(), args[0], actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Printf("started distribute job %s\n", job.ID)
		// Poll until complete
		for {
			j, ok := svcs.GPO.GetDistributeJob(job.ID)
			if !ok {
				return fmt.Errorf("job disappeared")
			}
			fmt.Printf("\r[%3d%%] %s", j.Progress, j.Status)
			for _, st := range j.Steps {
				if st.Status == service.StepRunning {
					fmt.Printf(" — %s", st.Title)
					break
				}
			}
			if j.Status == service.JobOK || j.Status == service.JobFailed {
				fmt.Println()
				for _, st := range j.Steps {
					fmt.Printf("  %-10s %s", st.Status, st.Title)
					if st.Message != "" {
						fmt.Printf(" (%s)", st.Message)
					}
					fmt.Println()
				}
				if j.Status == service.JobFailed {
					return fmt.Errorf("distribute failed: %s", j.Error)
				}
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	},
}

func init() {
	gpoCreateCmd.Flags().String("name", "", "display name (required)")
	_ = gpoCreateCmd.MarkFlagRequired("name")

	gpoLinkCmd.Flags().String("container", "", "container DN (required)")
	gpoLinkCmd.Flags().String("gpo", "", "GPO GUID or name (required)")
	_ = gpoLinkCmd.MarkFlagRequired("container")
	_ = gpoLinkCmd.MarkFlagRequired("gpo")

	gpoUnlinkCmd.Flags().String("container", "", "container DN (required)")
	gpoUnlinkCmd.Flags().String("gpo", "", "GPO GUID or name (required)")
	_ = gpoUnlinkCmd.MarkFlagRequired("container")
	_ = gpoUnlinkCmd.MarkFlagRequired("gpo")

	gpoBackupCmd.Flags().String("path", "", "backup directory (required)")
	_ = gpoBackupCmd.MarkFlagRequired("path")
	gpoRestoreCmd.Flags().String("path", "", "backup directory (required)")
	_ = gpoRestoreCmd.MarkFlagRequired("path")

	gpoCmd.AddCommand(
		gpoListCmd, gpoShowCmd, gpoCreateCmd, gpoDeleteCmd,
		gpoLinkCmd, gpoUnlinkCmd, gpoBackupCmd, gpoRestoreCmd,
		gpoDistributeCmd,
	)
}
