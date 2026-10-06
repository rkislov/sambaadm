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

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage local Samba file shares (smb.conf)",
}

var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List file shares from smb.conf",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		shares, err := svcs.Shares.ListFileShares(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(shares)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tPATH\tRO\tGUEST\tEXISTS\tCOMMENT")
		for _, s := range shares {
			fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%v\t%s\n",
				s.Name, s.Path, s.ReadOnly, s.GuestOK, s.PathExists, s.Comment)
		}
		return w.Flush()
	},
}

var shareShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show share parameters",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		sh, err := svcs.Shares.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(sh)
		}
		fmt.Printf("Name: %s\nPath: %s\nComment: %s\nBrowseable: %v\nReadOnly: %v\nGuestOK: %v\nValidUsers: %s\nWriteList: %s\n",
			sh.Name, sh.Path, sh.Comment, sh.Browseable, sh.ReadOnly, sh.GuestOK, sh.ValidUsers, sh.WriteList)
		for k, v := range sh.Params {
			fmt.Printf("  %s = %s\n", k, v)
		}
		return nil
	},
}

var shareCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a share, directory, and optional ACL",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		path, _ := cmd.Flags().GetString("path")
		comment, _ := cmd.Flags().GetString("comment")
		validUsers, _ := cmd.Flags().GetString("valid-users")
		writeList, _ := cmd.Flags().GetString("write-list")
		owner, _ := cmd.Flags().GetString("owner")
		mode, _ := cmd.Flags().GetString("mode")
		acl, _ := cmd.Flags().GetString("acl")
		ro, _ := cmd.Flags().GetBool("read-only")
		guest, _ := cmd.Flags().GetBool("guest-ok")
		noDir, _ := cmd.Flags().GetBool("no-dir")
		createDir := !noDir
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		sh, err := svcs.Shares.Create(context.Background(), service.CreateShareInput{
			Name: name, Path: path, Comment: comment,
			ValidUsers: validUsers, WriteList: writeList,
			Owner: owner, Mode: mode, ACL: acl,
			ReadOnly: &ro, GuestOK: &guest, CreateDir: &createDir,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(sh)
		}
		fmt.Printf("created share %s → %s\n", sh.Name, sh.Path)
		return nil
	},
}

var shareDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Remove a share from smb.conf",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rmDir, _ := cmd.Flags().GetBool("remove-dir")
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Shares.Delete(context.Background(), args[0], rmDir, actorName(), "cli")
	},
}

var shareSetCmd = &cobra.Command{
	Use:   "set <name> <key> <value>",
	Short: "Set an smb.conf parameter on a share",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Shares.SetParam(context.Background(), args[0], args[1], args[2], actorName(), "cli")
	},
}

var shareReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload smbd configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Shares.Reload(context.Background())
	},
}

func init() {
	shareCreateCmd.Flags().String("name", "", "share name (required)")
	shareCreateCmd.Flags().String("path", "", "absolute path (default: shares_root/name)")
	shareCreateCmd.Flags().String("comment", "", "comment")
	shareCreateCmd.Flags().String("valid-users", "", "valid users")
	shareCreateCmd.Flags().String("write-list", "", "write list")
	shareCreateCmd.Flags().String("owner", "", "directory owner user[:group]")
	shareCreateCmd.Flags().String("mode", "", "directory mode (octal)")
	shareCreateCmd.Flags().String("acl", "", "POSIX ACL for setfacl -m")
	shareCreateCmd.Flags().Bool("read-only", false, "read only share")
	shareCreateCmd.Flags().Bool("guest-ok", false, "guest ok")
	shareCreateCmd.Flags().Bool("no-dir", false, "do not create filesystem path")
	_ = shareCreateCmd.MarkFlagRequired("name")

	shareDeleteCmd.Flags().Bool("remove-dir", false, "also remove the share directory")

	shareCmd.AddCommand(shareListCmd, shareShowCmd, shareCreateCmd, shareDeleteCmd, shareSetCmd, shareReloadCmd)
	rootCmd.AddCommand(shareCmd)
}
