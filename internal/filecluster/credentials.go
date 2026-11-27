package filecluster

import (
	"fmt"
	"regexp"
	"strings"
)

type CredentialInput struct {
	Reference string `json:"reference,omitempty"`
	Kind      string `json:"kind"`
	Node      string `json:"node"`
	Address   string `json:"address"`
	System    string `json:"system"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func (CredentialInput) String() string   { return "[private storage credential]" }
func (CredentialInput) GoString() string { return "[private storage credential]" }
func (in CredentialInput) Validate() error {
	if in.Reference != "" && !validJob.MatchString(in.Reference) {
		return fmt.Errorf("неверный идентификатор реквизитов")
	}
	if in.Kind != "fence" && in.Kind != "iscsi" && in.Kind != "domain-join" {
		return fmt.Errorf("неверный тип реквизитов")
	}
	if !dns.MatchString(in.Node) || !strings.Contains(in.Node, ".") || in.Address == "" || len(in.Address) > 253 || len(in.System) > 253 || len(in.Username) > 512 || in.Password == "" || len(in.Password) > 4096 || strings.ContainsAny(in.Address+in.System+in.Username+in.Password, "\x00\r\n") {
		return fmt.Errorf("неверные реквизиты хранилища/fencing")
	}
	if in.Kind == "iscsi" && in.System != "" && !regexp.MustCompile(`^iqn\.`).MatchString(in.System) {
		return fmt.Errorf("неверная iSCSI-цель")
	}
	return nil
}

type FenceTestInput struct {
	RequestID string `json:"requestID"`
	Cluster   Input  `json:"cluster"`
	Target    string `json:"target"`
	Confirm   bool   `json:"confirm"`
}

func (in FenceTestInput) Validate(localNode string) error {
	if !validJob.MatchString(in.RequestID) {
		return fmt.Errorf("нужен requestID проверки fencing")
	}
	if err := in.Cluster.Validate(); err != nil {
		return err
	}
	if !in.Confirm || in.Target == localNode {
		return fmt.Errorf("подтвердите проверку fencing другого узла")
	}
	self, target := false, false
	for _, node := range in.Cluster.Nodes {
		self = self || node.Name == localNode
		target = target || node.Name == in.Target
	}
	if !self || !target {
		return fmt.Errorf("узел не входит в выбранную пару helper")
	}
	return nil
}
