package filecluster

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var workgroupName = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,14}$`)
var dnsSID = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)
var revisionID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// StageInput is sent to both helpers. Only the first node can initialize the LUN.
type StageInput struct {
	RequestID     string `json:"requestID"`
	Cluster       Input  `json:"cluster"`
	AuthKey       string `json:"authKey"`
	Workgroup     string `json:"workgroup"`
	Controller    string `json:"controller"`
	OwnerGroupSID string `json:"ownerGroupSID"`
}

type ActivationInput struct {
	RequestID     string `json:"requestID"`
	Name          string `json:"name"`
	Revision      string `json:"revision"`
	CredentialRef string `json:"credentialRef,omitempty"`
	Label         string `json:"label,omitempty"`
}

type ClusterReadInput struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

func (in ClusterReadInput) Validate() error {
	if !clusterName.MatchString(in.Name) || !revisionID.MatchString(in.Revision) {
		return fmt.Errorf("нужны имя и ревизия кластера")
	}
	return nil
}

func (in StageInput) Payload(node, stateDir string) (map[string]any, error) {
	if err := in.Cluster.Validate(); err != nil {
		return nil, err
	}
	if in.Cluster.Storage != "iscsi" || in.Cluster.Filesystem != "zfs" {
		return nil, fmt.Errorf("применение поддерживает ZFS на iSCSI multipath")
	}
	if !validJob.MatchString(in.RequestID) || !workgroupName.MatchString(in.Workgroup) ||
		!dns.MatchString(in.Controller) || !strings.HasSuffix(in.Controller, "."+in.Cluster.Realm) ||
		!dnsSID.MatchString(in.OwnerGroupSID) {
		return nil, fmt.Errorf("нужны контроллер домена, NetBIOS и SID группы доступа")
	}
	if node != in.Cluster.Nodes[0].Name && node != in.Cluster.Nodes[1].Name {
		return nil, fmt.Errorf("helper не входит в пару")
	}
	for _, member := range in.Cluster.Nodes {
		if in.Cluster.Name+"."+in.Cluster.Realm == member.Name {
			return nil, fmt.Errorf("виртуальное имя SMB должно отличаться от имён узлов")
		}
	}
	key, err := base64.StdEncoding.DecodeString(in.AuthKey)
	defer clear(key)
	if err != nil || len(key) != 128 {
		return nil, fmt.Errorf("нужен общий 128-байтный ключ Corosync")
	}
	in.Cluster.Revision = ""
	files, err := Render(in.Cluster, stateDir)
	if err != nil {
		return nil, err
	}
	layout, err := PlanZFS(in.Cluster)
	if err != nil {
		return nil, err
	}
	in.RequestID = ""
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	revision := sha256.Sum256(raw)
	return map[string]any{"stage": in, "localNode": node, "revision": hex.EncodeToString(revision[:]), "files": files, "layout": layout}, nil
}

func (in ActivationInput) Validate(operation string) error {
	if !clusterName.MatchString(in.Name) || !revisionID.MatchString(in.Revision) || !validJob.MatchString(in.RequestID) {
		return fmt.Errorf("нужны имя, ревизия и requestID кластера")
	}
	switch operation {
	case "initialize":
		if !validJob.MatchString(in.CredentialRef) {
			return fmt.Errorf("нужны реквизиты присоединения к домену")
		}
	case "snapshot":
		if strings.TrimSpace(in.Label) == "" || len([]rune(in.Label)) > 120 || strings.ContainsFunc(in.Label, unicode.IsControl) {
			return fmt.Errorf("введите имя снимка до 120 символов")
		}
	case "online", "snapshot-timer", "snapshot-schedule":
	default:
		return fmt.Errorf("неизвестное действие кластера")
	}
	return nil
}
