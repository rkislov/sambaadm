package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime settings. Priority: flags > ENV > file > defaults.
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	LDAP    LDAPConfig    `mapstructure:"ldap"`
	Auth    AuthConfig    `mapstructure:"auth"`
	Audit   AuditConfig   `mapstructure:"audit"`
	Logging LoggingConfig `mapstructure:"logging"`
}

type ServerConfig struct {
	Listen  string    `mapstructure:"listen"`
	TLS     TLSConfig `mapstructure:"tls"`
	Metrics bool      `mapstructure:"metrics"`
}

type TLSConfig struct {
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
}

type LDAPConfig struct {
	URI    string     `mapstructure:"uri"`
	BaseDN string     `mapstructure:"base_dn"`
	Bind   BindConfig `mapstructure:"bind"`
}

type BindConfig struct {
	Type        string `mapstructure:"type"` // simple | kerberos
	User        string `mapstructure:"user"`
	PasswordEnv string `mapstructure:"password_env"`
}

type AuthConfig struct {
	SessionTTL time.Duration `mapstructure:"session_ttl"`
	Roles      RolesConfig   `mapstructure:"roles"`
}

type RolesConfig struct {
	Admins   []string `mapstructure:"admins"`
	Helpdesk []string `mapstructure:"helpdesk"`
}

type AuditConfig struct {
	File string `mapstructure:"file"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// Load reads configuration from file, environment and applies defaults.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetEnvPrefix("SAMBAADM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/sambaadm")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Explicit path that failed is an error; missing default file is OK.
			if cfgFile != "" {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.listen", ":8080")
	v.SetDefault("server.metrics", true)
	v.SetDefault("ldap.uri", "ldapi://%2Fvar%2Frun%2Fsamba%2Fldapi")
	v.SetDefault("ldap.bind.type", "simple")
	v.SetDefault("ldap.bind.password_env", "SAMBAADM_PASSWORD")
	v.SetDefault("auth.session_ttl", "8h")
	v.SetDefault("logging.level", "info")
}

// BindPassword resolves the LDAP bind password from the configured env var.
func (c *Config) BindPassword() string {
	env := c.LDAP.Bind.PasswordEnv
	if env == "" {
		env = "SAMBAADM_PASSWORD"
	}
	return os.Getenv(env)
}
