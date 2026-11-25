// Isolated integration-test driver. No credentials are accepted on argv.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sambaadm/internal/agent"
	"sambaadm/internal/domaininit"
	"sambaadm/internal/service"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var req struct {
		Action string
		Config agent.Config
		Node   string
		Input  domaininit.Input
		ID     string
		CSR    []byte
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 190*time.Second)
	defer cancel()
	client := &agent.Client{Config: req.Config}
	var out any
	switch req.Action {
	case "sign":
		p := &domaininit.Plan{CSR: req.CSR}
		if err := domaininit.SignPlan(p, req.Input, "/var/lib/sambaadm/certificates"); err != nil {
			return err
		}
		out = p
	case "plan":
		p := &domaininit.Plan{}
		raw, _ := json.Marshal(req.Input)
		if err := client.Call(ctx, req.Node, "domain.init.plan", service.HostOperation{Input: raw}, p); err != nil {
			return err
		}
		if err := domaininit.SignPlan(p, req.Input, "/var/lib/sambaadm/certificates"); err != nil {
			return err
		}
		out = p
	case "start":
		raw, _ := json.Marshal(req.Input)
		var result domaininit.Status
		if err := client.Call(ctx, req.Node, "domain.init.start", service.HostOperation{Input: raw, Actor: "isolated-integration-test"}, &result); err != nil {
			return err
		}
		out = result
	case "status":
		var result domaininit.Status
		if err := client.Call(ctx, req.Node, "domain.init.status", service.HostOperation{Name: req.ID}, &result); err != nil {
			return err
		}
		out = result
	default:
		return fmt.Errorf("unsupported test operation")
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
