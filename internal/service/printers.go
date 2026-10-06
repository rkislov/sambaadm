package service

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"sambaadm/internal/audit"
	"sambaadm/internal/smbconf"
)

// Printer describes a Samba printable share and/or CUPS queue.
type Printer struct {
	Name        string `json:"name"`
	Comment     string `json:"comment,omitempty"`
	Path        string `json:"path,omitempty"` // spool dir
	PrinterName string `json:"printerName,omitempty"`
	Browseable  bool   `json:"browseable"`
	GuestOK     bool   `json:"guestOk"`
	CUPS        bool   `json:"cups"` // from lpstat
	InSMBConf   bool   `json:"inSmbConf"`
}

// CreatePrinterInput adds a printable share to smb.conf.
type CreatePrinterInput struct {
	Name        string `json:"name"`
	Comment     string `json:"comment,omitempty"`
	Path        string `json:"path,omitempty"`
	PrinterName string `json:"printerName,omitempty"` // cups queue; default = name
	Browseable  *bool  `json:"browseable,omitempty"`
	GuestOK     *bool  `json:"guestOk,omitempty"`
	CreateDir   *bool  `json:"createDir,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Mode        string `json:"mode,omitempty"`
}

// PrinterService manages Samba printer shares (smb.conf) and lists CUPS queues.
type PrinterService struct {
	audit  *audit.Logger
	shares *ShareService
}

func newPrinterService(auditLog *audit.Logger, shares *ShareService) *PrinterService {
	return &PrinterService{audit: auditLog, shares: shares}
}

// List merges smb.conf printable shares with CUPS queues from lpstat.
func (s *PrinterService) List(ctx context.Context) ([]Printer, error) {
	byName := map[string]*Printer{}

	doc, err := smbconf.ParseFile(s.shares.cfg.SMBConf)
	if err != nil {
		return nil, err
	}
	for _, name := range doc.SectionNames() {
		if strings.EqualFold(name, "global") {
			continue
		}
		sec, _ := doc.Get(name)
		p := sec.ParamsMap()
		printable := parseYes(p["printable"], false) || strings.EqualFold(name, "printers")
		if !printable {
			continue
		}
		pr := &Printer{
			Name:        sec.Name,
			Comment:     p["comment"],
			Path:        p["path"],
			PrinterName: firstNonEmpty(p["printer name"], sec.Name),
			Browseable:  parseYes(p["browseable"], true),
			GuestOK:     parseYes(p["guest ok"], false),
			InSMBConf:   true,
		}
		byName[strings.ToLower(sec.Name)] = pr
	}

	for _, q := range listCUPSQueues(ctx) {
		key := strings.ToLower(q)
		if existing, ok := byName[key]; ok {
			existing.CUPS = true
			continue
		}
		byName[key] = &Printer{Name: q, PrinterName: q, CUPS: true, Browseable: true}
	}

	out := make([]Printer, 0, len(byName))
	for _, name := range doc.SectionNames() {
		if pr, ok := byName[strings.ToLower(name)]; ok {
			out = append(out, *pr)
			delete(byName, strings.ToLower(name))
		}
	}
	for _, pr := range byName {
		out = append(out, *pr)
	}
	return out, nil
}

// Create adds a printable share; creates spool directory when requested.
func (s *PrinterService) Create(ctx context.Context, in CreatePrinterInput, actor, ip string) (*Printer, error) {
	name := strings.TrimSpace(in.Name)
	if err := validateShareName(name); err != nil {
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, err
	}
	if strings.EqualFold(name, "global") {
		err := fmt.Errorf("reserved name")
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, err
	}

	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = filepath.Join(s.shares.cfg.SharesRoot, "spool", name)
	}
	path = filepath.Clean(path)
	if err := s.shares.validatePath(path); err != nil {
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, err
	}

	doc, err := smbconf.ParseFile(s.shares.cfg.SMBConf)
	if err != nil {
		return nil, err
	}
	if _, ok := doc.Get(name); ok {
		err := fmt.Errorf("share %q already exists", name)
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, err
	}

	createDir := true
	if in.CreateDir != nil {
		createDir = *in.CreateDir
	}
	if createDir {
		mode := s.shares.cfg.CreateMode
		if in.Mode != "" {
			mode = in.Mode
		}
		if err := ensureDir(path, mode, in.Owner); err != nil {
			s.audit.Failure(actor, "printer.create", name, ip, err)
			return nil, err
		}
	}

	browseable := true
	if in.Browseable != nil {
		browseable = *in.Browseable
	}
	guestOK := false
	if in.GuestOK != nil {
		guestOK = *in.GuestOK
	}
	printerName := in.PrinterName
	if printerName == "" {
		printerName = name
	}

	doc.SetParam(name, "path", path)
	doc.SetParam(name, "printable", "yes")
	doc.SetParam(name, "printer name", printerName)
	doc.SetParam(name, "browseable", boolYesNo(browseable))
	doc.SetParam(name, "guest ok", boolYesNo(guestOK))
	doc.SetParam(name, "read only", "yes")
	if in.Comment != "" {
		doc.SetParam(name, "comment", in.Comment)
	}

	if err := doc.SaveAtomic(s.shares.cfg.SMBConf); err != nil {
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, err
	}
	if err := s.shares.Reload(ctx); err != nil {
		s.audit.Failure(actor, "printer.create", name, ip, err)
		return nil, fmt.Errorf("printer share saved but reload failed: %w", err)
	}
	s.audit.Success(actor, "printer.create", name, ip)
	return &Printer{
		Name: name, Path: path, PrinterName: printerName,
		Comment: in.Comment, Browseable: browseable, GuestOK: guestOK, InSMBConf: true,
	}, nil
}

// Delete removes a printable share from smb.conf.
func (s *PrinterService) Delete(ctx context.Context, name, actor, ip string) error {
	if strings.EqualFold(name, "printers") || strings.EqualFold(name, "print$") {
		err := fmt.Errorf("refusing to delete built-in %q", name)
		s.audit.Failure(actor, "printer.delete", name, ip, err)
		return err
	}
	return s.shares.Delete(ctx, name, false, actor, ip)
}

func listCUPSQueues(ctx context.Context) []string {
	cmd := exec.CommandContext(ctx, "lpstat", "-a")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "PrinterName accepting requests since ..."
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	return names
}
