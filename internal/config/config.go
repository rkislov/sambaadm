package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sambaadm/internal/agent"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime settings. Priority: flags > ENV > file > defaults.
type Config struct {
	Source  string             `mapstructure:"-"`
	Server  ServerConfig       `mapstructure:"server"`
	LDAP    LDAPConfig         `mapstructure:"ldap"`
	Auth    AuthConfig         `mapstructure:"auth"`
	Audit   AuditConfig        `mapstructure:"audit"`
	Logging LoggingConfig      `mapstructure:"logging"`
	GPO     GPOConfig          `mapstructure:"gpo"`
	Samba   SambaConfig        `mapstructure:"samba"`
	Helpers agent.Config       `mapstructure:"helpers"`
	Helper  HelperServerConfig `mapstructure:"helper"`
}

type HelperServerConfig struct {
	DomainBackupEnabled bool      `mapstructure:"domain_backup_enabled"`
	Node                string    `mapstructure:"node"`
	TrustedKeys         []string  `mapstructure:"trusted_keys"`
	Listen              string    `mapstructure:"listen"`
	TLS                 TLSConfig `mapstructure:"tls"`
	SYSVOLPrefix        string    `mapstructure:"sysvol_prefix"`
	AuthLog             string    `mapstructure:"auth_log"`
	PasswordFile        string    `mapstructure:"password_file"`
	BackupRoot          string    `mapstructure:"backup_root"`
	StateDir            string    `mapstructure:"state_dir"`
	ADMXRoot            string    `mapstructure:"admx_root"`
}

// SambaConfig controls local smb.conf / file-share administration.
type SambaConfig struct {
	SMBConf      string `mapstructure:"smb_conf"`
	SharesRoot   string `mapstructure:"shares_root"`
	CreateMode   string `mapstructure:"create_mode"` // octal, e.g. "0755"
	AllowAnyPath bool   `mapstructure:"allow_any_path"`
	ReloadCmd    string `mapstructure:"reload_cmd"` // e.g. "smbcontrol all reload-config"
}

// GPOConfig controls remote policy editing and SYSVOL distribution.
type GPOConfig struct {
	ReplicationTimeout time.Duration `mapstructure:"replication_timeout"`
	DelegationStateDir string        `mapstructure:"delegation_state_dir"`
	ScriptBackupKeep   int           `mapstructure:"script_backup_keep"`
	ScriptBackupMaxMiB int           `mapstructure:"script_backup_max_mib"`
	RepairBackupKeep   int           `mapstructure:"repair_backup_keep"`
	RepairBackupMaxMiB int           `mapstructure:"repair_backup_max_mib"`
	SMBPort            int           `mapstructure:"smb_port"`
	EditorEnabled      bool          `mapstructure:"editor_enabled"`
	ADMXPath           string        `mapstructure:"admx_path"`
	SysvolPath         string        `mapstructure:"sysvol_path"` // Deprecated: remote editor ignores local SYSVOL.
	SyncMode           string        `mapstructure:"sync_mode"`   // drs | smb | both (legacy rsync aliases smb)
}

type ServerConfig struct {
	CertificateDir string    `mapstructure:"certificate_dir"`
	EnrollmentDir  string    `mapstructure:"enrollment_dir"`
	SurveyDir      string    `mapstructure:"survey_dir"`
	Listen         string    `mapstructure:"listen"`
	TLS            TLSConfig `mapstructure:"tls"`
	Metrics        bool      `mapstructure:"metrics"`
}

type TLSConfig struct {
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
}

type LDAPConfig struct {
	ManagedCAFile  string     `mapstructure:"-"`
	ManagedTLSFile string     `mapstructure:"-"`
	AllowLegacyCN  bool       `mapstructure:"allow_legacy_cn"`
	CACert         string     `mapstructure:"ca_cert"`
	URI            string     `mapstructure:"uri"`
	BaseDN         string     `mapstructure:"base_dn"`
	Bind           BindConfig `mapstructure:"bind"`
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
	File  string `mapstructure:"file"`
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
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if cfg.GPO.ReplicationTimeout < time.Second || cfg.GPO.ReplicationTimeout > 30*time.Minute {
		return nil, fmt.Errorf("gpo.replication_timeout must be 1s..30m")
	}
	if cfg.GPO.ScriptBackupKeep < 1 || cfg.GPO.ScriptBackupKeep > 100 || cfg.GPO.ScriptBackupMaxMiB < 1 || cfg.GPO.ScriptBackupMaxMiB > 1024 {
		return nil, fmt.Errorf("gpo.script_backup_keep must be 1..100 and script_backup_max_mib 1..1024")
	}
	cfg.Source = v.ConfigFileUsed()
	if !filepath.IsAbs(cfg.Server.CertificateDir) {
		return nil, fmt.Errorf("server.certificate_dir requires an absolute path")
	}
	cfg.LDAP.ManagedCAFile = filepath.Join(cfg.Server.CertificateDir, "ldap-ca.pem")
	cfg.LDAP.ManagedTLSFile = filepath.Join(cfg.Server.CertificateDir, "ldap-legacy-cn.json")
	if cfg.GPO.RepairBackupKeep < 1 || cfg.GPO.RepairBackupKeep > 100 || cfg.GPO.RepairBackupMaxMiB < 1 || cfg.GPO.RepairBackupMaxMiB > 10240 {
		return nil, fmt.Errorf("gpo.repair_backup_keep must be 1..100 and repair_backup_max_mib 1..10240")
	}
	if cfg.Server.EnrollmentDir != "" {
		if len(cfg.Helpers.Nodes) > 0 || cfg.Helpers.PrivateKey != "" || cfg.Helpers.HostNode != "" {
			return nil, fmt.Errorf("configure helpers or server.enrollment_dir separately")
		}
		var err error
		cfg.Helpers, err = ManagedHelpers(cfg.Server.EnrollmentDir)
		if err != nil {
			return nil, err
		}
	}
	if e := cfg.Helpers.Validate(); e != nil {
		return nil, e
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("helper.state_dir", "/var/lib/sambaadm-helper")
	for _, key := range []string{"ldap.allow_legacy_cn", "ldap.ca_cert", "ldap.base_dn", "ldap.bind.user", "server.tls.cert", "server.tls.key", "audit.file", "logging.file"} {
		v.SetDefault(key, "")
	}
	v.SetDefault("gpo.editor_enabled", false)
	v.SetDefault("gpo.replication_timeout", "5m")
	v.SetDefault("gpo.delegation_state_dir", "/var/lib/sambaadm/delegation")
	v.SetDefault("gpo.script_backup_keep", 10)
	v.SetDefault("gpo.script_backup_max_mib", 64)
	v.SetDefault("gpo.repair_backup_keep", 10)
	v.SetDefault("gpo.repair_backup_max_mib", 512)
	certificateDir := "/var/lib/sambaadm/certificates"
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		certificateDir = filepath.Join(base, "sambaadm", "certificates")
	}
	v.SetDefault("server.certificate_dir", certificateDir)
	v.SetDefault("server.survey_dir", "/var/lib/sambaadm/surveys")
	v.SetDefault("server.listen", ":8080")
	v.SetDefault("server.metrics", true)
	v.SetDefault("ldap.uri", "ldapi://%2Fvar%2Frun%2Fsamba%2Fldapi")
	v.SetDefault("ldap.bind.type", "simple")
	v.SetDefault("ldap.bind.password_env", "SAMBAADM_PASSWORD")
	v.SetDefault("auth.session_ttl", "8h")
	v.SetDefault("logging.level", "info")
	v.SetDefault("gpo.admx_path", "")
	v.SetDefault("gpo.sysvol_path", "/var/lib/samba/sysvol")
	v.SetDefault("gpo.sync_mode", "both")
	v.SetDefault("gpo.smb_port", 445)
	v.SetDefault("samba.smb_conf", "/etc/samba/smb.conf")
	v.SetDefault("samba.shares_root", "/srv/samba")
	v.SetDefault("samba.create_mode", "0755")
	v.SetDefault("samba.allow_any_path", false)
	v.SetDefault("samba.reload_cmd", "smbcontrol all reload-config")
}

// BindPassword resolves the LDAP bind password from the configured env var.
func (c *Config) BindPassword() string {
	env := c.LDAP.Bind.PasswordEnv
	if env == "" {
		env = "SAMBAADM_PASSWORD"
	}
	return os.Getenv(env)
}

// LDAPCAFile selects the CA uploaded by an administrator, falling back to YAML.
func (c LDAPConfig) LDAPCAFile() string {
	if c.ManagedCAFile != "" {
		if _, err := os.Stat(c.ManagedCAFile); !os.IsNotExist(err) {
			return c.ManagedCAFile
		}
	}
	return c.CACert
}

func (c LDAPConfig) LegacyCNAllowed() (bool, error) {
	if c.ManagedTLSFile == "" {
		return c.AllowLegacyCN, nil
	}
	raw, err := os.ReadFile(c.ManagedTLSFile)
	if os.IsNotExist(err) {
		return c.AllowLegacyCN, nil
	}
	if err != nil {
		return false, err
	}
	var allow bool
	if err := json.Unmarshal(raw, &allow); err != nil {
		return false, fmt.Errorf("invalid managed LDAP TLS policy: %w", err)
	}
	return allow, nil
}
