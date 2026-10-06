package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sambaadm/internal/service"
)

var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "Manage filesystem permissions on share paths",
}

var aclGetCmd = &cobra.Command{
	Use:   "get <path>",
	Short: "Show mode, owner and POSIX ACL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		info, err := svcs.FSACL.Get(context.Background(), args[0])
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("Path: %s\nExists: %v\nMode: %s\nOwner: %s\nGroup: %s\n",
			info.Path, info.Exists, info.Mode, info.Owner, info.Group)
		if info.ACLText != "" {
			fmt.Println("--- ACL ---")
			fmt.Println(info.ACLText)
		}
		if info.DefaultACL != "" {
			fmt.Println("--- default ACL ---")
			fmt.Println(info.DefaultACL)
		}
		return nil
	},
}

var aclSetCmd = &cobra.Command{
	Use:   "set <path>",
	Short: "Set owner, mode and/or POSIX ACL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		owner, _ := cmd.Flags().GetString("owner")
		mode, _ := cmd.Flags().GetString("mode")
		acl, _ := cmd.Flags().GetString("acl")
		def, _ := cmd.Flags().GetString("default-acl")
		rec, _ := cmd.Flags().GetBool("recursive")
		svcs, cleanup, err := openLocalServices()
		if err != nil {
			return err
		}
		defer cleanup()
		info, err := svcs.FSACL.Set(context.Background(), service.SetACLInput{
			Path: args[0], Owner: owner, Mode: mode, ACL: acl, DefaultACL: def, Recursive: rec,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("updated %s mode=%s owner=%s:%s\n", info.Path, info.Mode, info.Owner, info.Group)
		return nil
	},
}

func init() {
	aclSetCmd.Flags().String("owner", "", "user[:group]")
	aclSetCmd.Flags().String("mode", "", "octal mode")
	aclSetCmd.Flags().String("acl", "", "setfacl -m entries (e.g. u:alice:rwx,g:staff:rx)")
	aclSetCmd.Flags().String("default-acl", "", "default ACL (directories)")
	aclSetCmd.Flags().Bool("recursive", false, "apply ACL recursively")

	aclCmd.AddCommand(aclGetCmd, aclSetCmd)
	rootCmd.AddCommand(aclCmd)
}
