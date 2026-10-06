package cli

import (
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
