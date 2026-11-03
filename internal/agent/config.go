package agent

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var nodeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
var sshDestination = regexp.MustCompile(`^([a-zA-Z0-9_][a-zA-Z0-9_.-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func (c Config) Validate() error {
	if len(c.Nodes) == 0 {
		if c.HostNode != "" || c.PrivateKey != "" {
			return fmt.Errorf("helpers.nodes must include the host_node")
		}
		return nil
	}
	if len(c.Nodes) > 64 || !filepath.IsAbs(c.PrivateKey) {
		return fmt.Errorf("helpers require at most 64 nodes and an absolute private_key path")
	}
	seen := map[string]bool{}
	for _, n := range c.Nodes {
		key := strings.ToLower(n.Name)
		if !nodeName.MatchString(n.Name) || seen[key] {
			return fmt.Errorf("invalid or duplicate helper node")
		}
		seen[key] = true
		switch n.Transport {
		case "https":
			u, e := url.Parse(n.Endpoint)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return fmt.Errorf("helper API endpoint must be an HTTPS origin")
			}
			if n.CACert != "" && !filepath.IsAbs(n.CACert) {
				return fmt.Errorf("helper ca_cert must be absolute")
			}
		case "ssh":
			if !sshDestination.MatchString(n.Endpoint) || !filepath.IsAbs(n.SSHKey) || !filepath.IsAbs(n.KnownHosts) {
				return fmt.Errorf("SSH helper requires a literal destination and absolute ssh_key and known_hosts paths")
			}
		default:
			return fmt.Errorf("helper transport must be ssh or https")
		}
	}
	if !seen[strings.ToLower(c.HostNode)] {
		return fmt.Errorf("helpers.host_node must name a registered helper")
	}
	return nil
}
