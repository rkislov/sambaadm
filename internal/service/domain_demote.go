package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sambaadm/internal/config"
	"sambaadm/internal/dcdemote"
	"strings"
)

func helperDomainDemote(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	engine := &dcdemote.Engine{Dir: filepath.Join(cfg.Helper.StateDir, "dc-demote"), Config: cfg.Source}
	if method == "domain.demote.status" {
		return engine.Read(in.Name)
	}
	var req struct {
		dcdemote.Input
		Reference dcdemote.Manifest `json:"reference"`
	}
	if err := decodeHost(in.Input, &req); err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.Node, cfg.Helper.Node) || cfg.Samba.SMBConf != "/etc/samba/smb.conf" {
		return nil, fmt.Errorf("Снятие роли доступно только зарегистрированному helper со стандартным smb.conf")
	}
	req.Input.Reference = req.Reference
	switch method {
	case "domain.demote.manifest":
		return engine.Manifest(ctx, req.Node, req.Realm)
	case "domain.demote.plan":
		return engine.Plan(ctx, req.Input)
	case "domain.demote.start":
		return engine.Start(ctx, req.Input, false)
	case "domain.demote.resume":
		return engine.Start(ctx, req.Input, true)
	}
	return nil, fmt.Errorf("Неизвестная операция снятия роли")
}
