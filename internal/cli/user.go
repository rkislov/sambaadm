package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage domain users",
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	RunE: func(cmd *cobra.Command, args []string) error {
		ou, _ := cmd.Flags().GetString("ou")
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		users, err := svcs.Users.List(context.Background(), ou, "")
		if err != nil {
			return err
		}
		return printUsers(users)
	},
}

var userShowCmd = &cobra.Command{
	Use:   "show <login>",
	Short: "Show a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		u, err := svcs.Users.Show(context.Background(), args[0])
		if err != nil {
			return err
		}
		return printUsers([]service.User{*u})
	},
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		login, _ := cmd.Flags().GetString("login")
		display, _ := cmd.Flags().GetString("display")
		ou, _ := cmd.Flags().GetString("ou")
		mail, _ := cmd.Flags().GetString("mail")
		prompt, _ := cmd.Flags().GetBool("prompt")
		password, _ := cmd.Flags().GetString("password")
		if prompt || password == "" {
			var err error
			password, err = readPassword("Password: ")
			if err != nil {
				return err
			}
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		u, err := svcs.Users.Create(context.Background(), service.CreateUserInput{
			Login: login, Password: password, DisplayName: display,
			OU: ou, Mail: mail, Enabled: true,
		}, actorName(), "cli")
		if err != nil {
			return err
		}
		fmt.Printf("created %s (%s)\n", u.SAMAccountName, u.DN)
		return nil
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete <login>",
	Short: "Delete a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		if err := svcs.Users.Delete(context.Background(), args[0], actorName(), "cli"); err != nil {
			return err
		}
		fmt.Println("deleted", args[0])
		return nil
	},
}

var userEnableCmd = &cobra.Command{
	Use:   "enable <login>",
	Short: "Enable a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Users.Enable(context.Background(), args[0], actorName(), "cli")
	},
}

var userDisableCmd = &cobra.Command{
	Use:   "disable <login>",
	Short: "Disable a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Users.Disable(context.Background(), args[0], actorName(), "cli")
	},
}

var userSetPasswordCmd = &cobra.Command{
	Use:   "set-password <login>",
	Short: "Set user password (reads from prompt; requires LDAPS/ldapi)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword("New password: ")
		if err != nil {
			return err
		}
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()
		return svcs.Users.SetPassword(context.Background(), args[0], password, actorName(), "cli")
	},
}

var userMoveCmd = &cobra.Command{
	Use:   "move <login>",
	Short: "Move user to another OU",
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
		return svcs.Users.Move(context.Background(), args[0], toOU, actorName(), "cli")
	},
}

func init() {
	userListCmd.Flags().String("ou", "", "limit search to OU DN")
	userCreateCmd.Flags().String("login", "", "sAMAccountName (required)")
	userCreateCmd.Flags().String("display", "", "display name / CN")
	userCreateCmd.Flags().String("ou", "", "parent OU DN")
	userCreateCmd.Flags().String("mail", "", "email")
	userCreateCmd.Flags().String("password", "", "password (prefer --prompt)")
	userCreateCmd.Flags().Bool("prompt", true, "read password from terminal")
	_ = userCreateCmd.MarkFlagRequired("login")
	userMoveCmd.Flags().String("to-ou", "", "destination OU DN")
	_ = userMoveCmd.MarkFlagRequired("to-ou")

	userCmd.AddCommand(
		userListCmd, userShowCmd, userCreateCmd, userDeleteCmd,
		userEnableCmd, userDisableCmd, userSetPasswordCmd, userMoveCmd,
	)
}

func openServices() (*service.Services, func(), error) {
	auditLog, err := audit.New(rootCfg.Audit.File)
	if err != nil {
		return nil, nil, err
	}
	client := ldapproto.NewClient(rootCfg.LDAP)
	if err := client.Connect(context.Background()); err != nil {
		_ = auditLog.Close()
		return nil, nil, err
	}
	if rootCfg.LDAP.Bind.User != "" {
		pass := rootCfg.BindPassword()
		if err := client.BindSimple(context.Background(), rootCfg.LDAP.Bind.User, pass); err != nil {
			_ = client.Close()
			_ = auditLog.Close()
			return nil, nil, err
		}
	}
	svcs := service.New(client, auditLog)
	cleanup := func() {
		_ = client.Close()
		_ = auditLog.Close()
	}
	return svcs, cleanup, nil
}

func printUsers(users []service.User) error {
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(users)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LOGIN\tDISPLAY\tENABLED\tDN")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", u.SAMAccountName, u.DisplayName, u.Enabled, u.DN)
	}
	return w.Flush()
}
