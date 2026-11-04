package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type RODCAuthEvent struct {
	Time           time.Time `json:"time"`
	Account        string    `json:"account"`
	Domain         string    `json:"domain"`
	Client         string    `json:"client"`
	Workstation    string    `json:"workstation"`
	Status         string    `json:"status"`
	Service        string    `json:"service"`
	Authentication string    `json:"authentication"`
}
type RODCAuthReport struct {
	Controller string          `json:"controller"`
	Source     string          `json:"source"`
	Status     string          `json:"status"`
	Truncated  bool            `json:"truncated"`
	Malformed  int             `json:"malformed"`
	Events     []RODCAuthEvent `json:"events"`
	Warning    string          `json:"warning"`
}

// Reads only the operator-configured file for this discovered RODC. No request
// can supply a filename, SSH command, or logging configuration to a controller.
func (s *RODCService) Authentications(ctx context.Context, name string, after time.Time, account string) (*RODCAuthReport, error) {
	return s.controllerAuthentications(ctx, name, after, account, true)
}

func (s *RODCService) ControllerAuthentications(ctx context.Context, name string, after time.Time, account string) (*RODCAuthReport, error) {
	return s.controllerAuthentications(ctx, name, after, account, false)
}

func (s *RODCService) controllerAuthentications(ctx context.Context, name string, after time.Time, account string, rodcOnly bool) (*RODCAuthReport, error) {
	dc, e := (&SiteService{ldap: s.ldap}).controller(ctx, name)
	if e != nil {
		return nil, e
	}
	if rodcOnly && !dc.RODC {
		return nil, topologyBad("select an RODC")
	}
	if s.helpers != nil {
		var out RODCAuthReport
		e := s.helpers.Call(ctx, dc.DNS, "rodc.auth", struct {
			After   string
			Account string
		}{after.Format(time.RFC3339Nano), account}, &out)
		return &out, e
	}
	return readRODCAuthFile(ctx, dc.DNS, "", after, account)
}
func readLocalRODCAuth(ctx context.Context, host, filename, afterText, account string) (*RODCAuthReport, error) {
	var after time.Time
	if afterText != "" {
		var e error
		after, e = time.Parse(time.RFC3339Nano, afterText)
		if e != nil {
			return nil, fmt.Errorf("invalid authentication time filter")
		}
	}
	return readRODCAuthFile(ctx, host, filename, after, account)
}
func readRODCAuthFile(ctx context.Context, host, filename string, after time.Time, account string) (*RODCAuthReport, error) {
	out := &RODCAuthReport{Controller: host, Source: "Samba Authentication JSON audit", Status: "unavailable", Events: []RODCAuthEvent{}, Warning: "No audit source configured for this controller. An empty result does not prove that no authentication occurred."}
	if filename == "" {
		return out, nil
	}
	f, e := os.Open(filename)
	if e != nil {
		out.Warning = "Configured authentication audit source is not readable."
		return out, nil
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		out.Warning = "Configured authentication audit source is not a regular file."
		return out, nil
	}
	start := int64(0)
	const maxBytes = 8 << 20
	if st.Size() > maxBytes {
		start = st.Size() - maxBytes
		out.Truncated = true
	}
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return nil, e
	}
	r := bufio.NewReader(io.LimitReader(f, st.Size()-start))
	if start > 0 {
		if _, e = r.ReadString('\n'); e != nil && e != io.EOF {
			return nil, e
		}
	}
	events, malformed, truncated, e := readRODCAuth(ctx, r, after, account)
	if e != nil {
		return nil, e
	}
	out.Events, out.Malformed = events, malformed
	out.Truncated = out.Truncated || truncated
	out.Status = "available"
	out.Warning = "Events come from the configured file for this controller. Only its retained tail is read; missing events, disabled auditing, log rotation and collection gaps are not evidence of no logins. Authentication success is not proof of a cached password or an interactive desktop logon."
	if out.Truncated || malformed > 0 {
		out.Status = "partial"
	}
	return out, nil
}
func readRODCAuth(ctx context.Context, r io.Reader, after time.Time, account string) ([]RODCAuthEvent, int, bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	out := []RODCAuthEvent{}
	malformed := 0
	truncated := false
	for scanner.Scan() {
		if e := ctx.Err(); e != nil {
			return nil, malformed, truncated, e
		}
		line := scanner.Bytes()
		i := bytes.IndexByte(line, '{')
		if i < 0 {
			continue
		}
		line = line[i:]
		var raw struct {
			Timestamp      string `json:"timestamp"`
			Type           string `json:"type"`
			Authentication *struct {
				Account     string `json:"clientAccount"`
				Domain      string `json:"clientDomain"`
				Remote      string `json:"remoteAddress"`
				Workstation string `json:"workstation"`
				Status      string `json:"status"`
				Service     string `json:"serviceDescription"`
				Auth        string `json:"authDescription"`
			} `json:"Authentication"`
		}
		if json.Unmarshal(line, &raw) != nil {
			malformed++
			continue
		}
		if raw.Type != "Authentication" {
			continue
		}
		if raw.Authentication == nil {
			malformed++
			continue
		}
		t, e := time.Parse(time.RFC3339Nano, raw.Timestamp)
		if e != nil {
			t, e = time.Parse("2006-01-02T15:04:05.999999999-0700", raw.Timestamp)
		}
		if e != nil {
			malformed++
			continue
		}
		a := raw.Authentication
		if a.Status == "" {
			malformed++
			continue
		}
		if !after.IsZero() && t.Before(after) {
			continue
		}
		if account != "" && !strings.Contains(strings.ToLower(a.Domain+"\\"+a.Account), strings.ToLower(account)) {
			continue
		}
		out = append(out, RODCAuthEvent{Time: t, Account: a.Account, Domain: a.Domain, Client: a.Remote, Workstation: a.Workstation, Status: a.Status, Service: a.Service, Authentication: a.Auth})
		if len(out) > 500 {
			out = out[1:]
			truncated = true
		}
	}
	if e := scanner.Err(); e != nil {
		return nil, malformed, truncated, fmt.Errorf("authentication audit exceeds line limit or cannot be read")
	}
	// Audit records are normally chronological; reverse the retained file order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, malformed, truncated, nil
}
