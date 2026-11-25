package cli

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
	"sambaadm/internal/agent"
	"sambaadm/internal/service"
	"strings"
	"time"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{Use: "helper-check NODE", Short: "Проверить TLS и подписанный запрос к зарегистрированному helper", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
		defer cancel()
		client := &agent.Client{Config: rootCfg.Helpers}
		var result service.ControllerInventory
		if err := client.Call(ctx, args[0], "host.inventory", service.HostOperation{}, &result); err != nil {
			return err
		}
		if !strings.EqualFold(result.Controller, args[0]) {
			return fmt.Errorf("Helper вернул другое имя узла")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Helper "+args[0]+": TLS и подписанный запрос проверены")
		return nil
	}})
}
