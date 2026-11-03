package service

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

//go:embed helper_rodc.py
var localRODCPreloadScript string

func (s *RODCService) preloadTarget(host string) bool { return s.helpers != nil && s.helpers.Has(host) }
func (s *RODCService) preload(ctx context.Context, state *RODCState, dn string) error {
	if s.helpers == nil {
		return fmt.Errorf("sambaadm-helper is required for RODC preload")
	}
	var out struct {
		Status     string `json:"status"`
		Controller string `json:"controller"`
		Account    string `json:"account"`
	}
	in := struct{ Controller, Source, DSAGUID, Account string }{state.Controller.DNS, state.Source, rodcGUIDString(state.guid), dn}
	if e := s.helpers.Call(ctx, state.Controller.DNS, "rodc.preload", in, &out); e != nil {
		return e
	}
	if out.Status != "preloaded" || !strings.EqualFold(out.Controller, state.Controller.DNS) || out.Account != dn {
		return fmt.Errorf("unexpected helper result; verify cache before retrying")
	}
	return nil
}
func runLocalRODCPreload(ctx context.Context, node string, raw json.RawMessage) (any, error) {
	var in struct{ Controller, Source, DSAGUID, Account string }
	if e := decodeHost(raw, &in); e != nil {
		return nil, e
	}
	if !strings.EqualFold(in.Controller, node) {
		return nil, fmt.Errorf("helper destination mismatch")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-c", localRODCPreloadScript)
	cmd.Stdin = bytes.NewReader(raw)
	output, e := cmd.Output()
	if e != nil {
		return nil, fmt.Errorf("RODC preload not confirmed; inspect RODC replication and PRP before retrying")
	}
	var out struct {
		Status     string `json:"status"`
		Controller string `json:"controller"`
		Account    string `json:"account"`
	}
	if json.Unmarshal(output, &out) != nil || out.Status != "preloaded" {
		return nil, fmt.Errorf("invalid local RODC preload result")
	}
	return out, nil
}
