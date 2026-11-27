package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sambaadm/internal/config"
	"sambaadm/internal/domaininit"
	"strings"
	"time"
)

// Deployment is a closed helper capability. The hostname must be the identity
// pinned during SSH enrollment; it cannot be repurposed to another target.
func helperDomainInit(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	engine := &domaininit.Engine{Dir: filepath.Join(cfg.Helper.StateDir, "domain-init")}
	if method == "domain.init.status" {
		return engine.Read(in.Name)
	}
	var req domaininit.Input
	if err := decodeHost(in.Input, &req); err != nil {
		return nil, err
	}
	if (req.Mode != "DC" && req.Mode != "RODC" && req.Mode != "member") || !filepath.IsAbs(cfg.Helper.StateDir) || !strings.EqualFold(req.Hostname+"."+req.Realm, cfg.Helper.Node) {
		return nil, fmt.Errorf("Разрешена подготовка нового сервера с именем зарегистрированного helper")
	}
	if method == "domain.init.plan" {
		check, cancel := context.WithTimeout(ctx, 180*time.Second)
		defer cancel()
		return engine.Plan(check, req)
	}
	if method == "domain.init.start" {
		return engine.Start(ctx, req)
	}
	return nil, fmt.Errorf("Неизвестная операция развёртывания")
}
