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

func init() {
	userListCmd.Flags().String("ou", "", "limit search to OU DN")
	userCmd.AddCommand(userListCmd, userShowCmd)
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
		pass := os.Getenv(rootCfg.LDAP.Bind.PasswordEnv)
		if pass == "" {
			pass = os.Getenv("SAMBAADM_PASSWORD")
		}
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
