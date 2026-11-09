package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sambaadm/internal/config"
	"sambaadm/internal/version"
)

var (
	cfgFile string
	server  string
	user    string
	realm   string
	jsonOut bool
	verbose bool
	debug   bool

	rootCfg *config.Config
)

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "sambaadm",
	Short: "Samba4 AD DC administration toolkit",
	Long: `sambaadm — аналог RSAT для Samba4 Active Directory.
Единый бинарник: CLI, веб-интерфейс и REST API.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Only a first server start creates configuration. Existing files and
		// all read-only CLI commands retain their normal loading behavior.
		if cmd.Name() == "serve" && !checkStartup {
			if err := ensureServerConfig(cmd); err != nil {
				return err
			}
		}
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		if server != "" {
			cfg.LDAP.URI = server
		}
		if user != "" {
			cfg.LDAP.Bind.User = user
		}
		if realm != "" {
			// realm is used by Kerberos bind; stored for later stages
			_ = realm
		}
		if verbose || debug {
			cfg.Logging.Level = "debug"
		}
		rootCfg = cfg
		return nil
	},
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to YAML config")
	rootCmd.PersistentFlags().StringVarP(&server, "server", "S", "", "LDAP URI (ldap://, ldaps://, ldapi://)")
	rootCmd.PersistentFlags().StringVarP(&user, "user", "U", "", "bind user")
	rootCmd.PersistentFlags().StringVar(&realm, "realm", "", "Kerberos realm")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "JSON output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug logging and startup diagnostics (no passwords)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(groupCmd)
	rootCmd.AddCommand(computerCmd)
	rootCmd.AddCommand(ouCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(domainCmd)
	rootCmd.AddCommand(replCmd)
	rootCmd.AddCommand(siteCmd)
	rootCmd.AddCommand(subnetCmd)
	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(gpoCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.String())
	},
}

func ensureServerConfig(cmd *cobra.Command) error {
	path := cfgFile
	if path == "" {
		cfg, err := config.Load("")
		if err != nil {
			return err
		}
		if cfg.Source != "" {
			return nil
		}
		path = "config.yaml"
	}
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := discoveredConfig(cmd.Context(), realm, "", user, "", "")
	if err != nil {
		return fmt.Errorf("предзаполнение config.yaml: %w; выполните sambaadm discover --realm DOMAIN --dc DC --output %s", err, path)
	}
	if err := writeDiscoveredConfig(path, data); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Создан %s. Проверьте служебную запись и группу администраторов; задайте SAMBAADM_PASSWORD.\n", path)
	cfgFile = path
	return nil
}
