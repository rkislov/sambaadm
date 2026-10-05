package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Domain information and FSMO",
}

var domainInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show domain information",
	RunE: func(cmd *cobra.Command, args []string) error {
		svcs, cleanup, err := openServices()
		if err != nil {
			return err
		}
		defer cleanup()

		info, err := svcs.Domain.Info(context.Background())
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		fmt.Printf("Base DN:   %s\n", info.BaseDN)
		fmt.Printf("DNS root:  %s\n", info.DNSRoot)
		fmt.Printf("NetBIOS:   %s\n", info.NetBIOS)
		fmt.Printf("Level:     %s\n", info.FunctionLvl)
		return nil
	},
}

func init() {
	domainCmd.AddCommand(domainInfoCmd)
}
