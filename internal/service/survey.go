package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/config"
	"sambaadm/internal/version"
	"strings"
	"time"
)

const SurveyFormat = "sambaadm-node-survey-v1"
const SurveyLimit = 16 << 20

type SurveyObservation struct {
	Source   string    `json:"source"`
	Observed time.Time `json:"observed"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail"`
}
type NodeSurvey struct {
	Format   string              `json:"format"`
	Helper   string              `json:"helper"`
	Node     string              `json:"node"`
	Site     string              `json:"site,omitempty"`
	Started  time.Time           `json:"started"`
	Finished time.Time           `json:"finished"`
	Checks   []SurveyObservation `json:"checks"`
	Audit    *RODCAuthReport     `json:"audit"`
}

// Retain bounded stdout while draining the pipe so verbose probes cannot block.
type probeOutput struct {
	buf       bytes.Buffer
	truncated bool
}

func (w *probeOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 8192 - w.buf.Len()
	if n > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	_, err := w.buf.Write(p)
	return n, err
}
func surveyProbe(ctx context.Context, name string, args ...string) SurveyObservation {
	o := SurveyObservation{Source: strings.Join(append([]string{name}, args...), " "), Observed: time.Now().UTC(), Status: "unknown", Detail: "command unavailable"}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		probe, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(probe, path, args...)
		cmd.WaitDelay = time.Second
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		var output probeOutput
		cmd.Stdout = &output
		err := cmd.Run()
		o.Detail = strings.TrimSpace(output.buf.String())
		if err == nil && o.Detail != "" {
			o.Status = "observed"
		} else if o.Detail == "" {
			o.Detail = "no output or command failed"
		}
		if probe.Err() != nil {
			o.Detail = "probe cancelled or timed out"
		}
		if output.truncated {
			o.Status = "partial"
		}
		break
	}
	return o
}
func CollectNodeSurvey(ctx context.Context, cfg *config.Config, site string) (*NodeSurvey, error) {
	if strings.TrimSpace(cfg.Helper.Node) == "" || len(site) > 256 {
		return nil, fmt.Errorf("helper.node required; site limited to 256 bytes")
	}
	s := &NodeSurvey{Format: SurveyFormat, Helper: version.String(), Node: cfg.Helper.Node, Site: site, Started: time.Now().UTC()}
	probes := [][]string{{"uname", "-srmo"}, {"samba", "--version"}, {"systemctl", "is-active", "samba-ad-dc.service"}, {"systemctl", "is-active", "samba.service"}, {"chronyc", "-n", "tracking"}, {"chronyc", "-n", "sources"}, {"timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone"}}
	for _, pkg := range []string{"altlinux-release", "samba", "sssd", "gpupdate", "gpui", "admx-basealt", "chrony"} {
		probes = append(probes, []string{"rpm", "-q", pkg})
	}
	for _, key := range []string{"realm", "workgroup", "server role", "netbios name"} {
		args := []string{"testparm", "-s", "--parameter-name=" + key}
		if cfg.Samba.SMBConf != "" {
			args = append(args, cfg.Samba.SMBConf)
		}
		probes = append(probes, args)
	}
	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.Checks = append(s.Checks, surveyProbe(ctx, p[0], p[1:]...))
	}
	for _, src := range []struct {
		path    string
		allowed map[string]bool
		sep     string
	}{
		{"/etc/os-release", map[string]bool{"PRETTY_NAME": true, "VERSION_ID": true}, "="},
		{"/etc/resolv.conf", map[string]bool{"nameserver": true, "search": true, "domain": true}, " "},
	} {
		o := SurveyObservation{Source: src.path, Observed: time.Now().UTC(), Status: "unknown", Detail: "source unavailable or empty"}
		if f, err := os.Open(src.path); err == nil {
			var lines []string
			sc := bufio.NewScanner(io.LimitReader(f, 65537))
			for sc.Scan() {
				v := strings.TrimSpace(sc.Text())
				if i := strings.IndexAny(v, "#;"); i >= 0 {
					v = v[:i]
				}
				k, _, _ := strings.Cut(v, src.sep)
				if src.sep == " " {
					fields := strings.Fields(v)
					if len(fields) == 0 {
						continue
					}
					k = fields[0]
				}
				if src.allowed[k] {
					lines = append(lines, v)
				}
			}
			if len(lines) > 0 {
				o.Status = "observed"
				o.Detail = strings.Join(lines, "\n")
			}
			st, e := f.Stat()
			if sc.Err() != nil || e != nil || st.Size() > 65536 {
				o.Status = "partial"
			}
			f.Close()
		}
		s.Checks = append(s.Checks, o)
	}
	audit, err := readRODCAuthFile(ctx, s.Node, cfg.Helper.AuthLog, time.Time{}, "")
	if err != nil {
		audit = &RODCAuthReport{Controller: s.Node, Source: "Samba Authentication JSON audit", Status: "unavailable", Warning: "audit could not be parsed within limits"}
	}
	s.Audit = audit
	s.Finished = time.Now().UTC()
	return s, ctx.Err()
}

type SurveyMaterial struct {
	Kind     string          `json:"kind"`
	Node     string          `json:"node,omitempty"`
	Site     string          `json:"site,omitempty"`
	SHA256   string          `json:"sha256"`
	Snapshot *NodeSurvey     `json:"snapshot,omitempty"`
	Audit    *RODCAuthReport `json:"audit,omitempty"`
	Overview json.RawMessage `json:"overview,omitempty"`
}

func ParseSurvey(ctx context.Context, kind, node, site string, data []byte) (*SurveyMaterial, error) {
	if len(data) == 0 || len(data) > SurveyLimit || len(node) > 256 || len(site) > 256 {
		return nil, fmt.Errorf("invalid file or source size")
	}
	m := &SurveyMaterial{Kind: kind, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	switch kind {
	case "helper":
		var s NodeSurvey
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if d.Decode(&s) != nil || d.Decode(&struct{}{}) != io.EOF || s.Format != SurveyFormat || strings.TrimSpace(s.Node) == "" || len(s.Node) > 256 || len(s.Site) > 256 || s.Started.IsZero() || s.Finished.Before(s.Started) || len(s.Checks) == 0 || len(s.Checks) > 128 || s.Audit == nil || s.Audit.Controller != s.Node || len(s.Audit.Events) > 500 {
			return nil, fmt.Errorf("invalid helper snapshot")
		}
		for _, o := range s.Checks {
			if o.Source == "" || o.Observed.IsZero() || (o.Status != "observed" && o.Status != "unknown" && o.Status != "partial") {
				return nil, fmt.Errorf("invalid observation")
			}
		}
		m.Node = s.Node
		m.Site = s.Site
		m.Snapshot = &s
	case "audit":
		if strings.TrimSpace(node) == "" {
			return nil, fmt.Errorf("specify source controller for audit log")
		}
		events, bad, cut, err := readRODCAuth(ctx, bytes.NewReader(data), time.Time{}, "")
		if err != nil || len(events) == 0 {
			return nil, fmt.Errorf("no readable Samba Authentication events")
		}
		status := "available"
		if bad > 0 || cut {
			status = "partial"
		}
		m.Node = node
		m.Site = site
		m.Audit = &RODCAuthReport{Controller: node, Source: "Imported Samba Authentication JSON lines", Status: status, Malformed: bad, Truncated: cut, Events: events, Warning: "Source and coverage supplied by operator"}
	case "overview":
		var envelope struct {
			Schema   int
			Exported time.Time
			Sections map[string]struct {
				Source   string
				Status   string
				Finished time.Time
			}
		}
		if json.Unmarshal(data, &envelope) != nil || envelope.Schema != 1 || envelope.Exported.IsZero() || len(envelope.Sections) == 0 || len(envelope.Sections) > 256 {
			return nil, fmt.Errorf("invalid domain overview export")
		}
		for _, section := range envelope.Sections {
			if section.Source == "" || section.Finished.IsZero() || (section.Status != "available" && section.Status != "unavailable") {
				return nil, fmt.Errorf("invalid overview section")
			}
		}
		m.Node = node
		m.Site = site
		m.Overview = data
	default:
		return nil, fmt.Errorf("unknown import format")
	}
	return m, nil
}
