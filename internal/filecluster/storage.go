package filecluster

import (
	"fmt"
	"net/netip"
)

type ISCSIConnectInput struct {
	RequestID     string   `json:"requestID"`
	TargetIQN     string   `json:"targetIQN"`
	Portals       []string `json:"portals"`
	CredentialRef string   `json:"credentialRef,omitempty"`
}

func (in ISCSIConnectInput) Validate() error {
	if !validJob.MatchString(in.RequestID) || !iqn.MatchString(in.TargetIQN) || len(in.Portals) < 1 || len(in.Portals) > 8 {
		return fmt.Errorf("выберите iSCSI-цель, порталы и requestID")
	}
	if in.CredentialRef != "" && !validJob.MatchString(in.CredentialRef) {
		return fmt.Errorf("неверная ссылка CHAP")
	}
	seen := map[string]bool{}
	for _, value := range in.Portals {
		p, err := netip.ParseAddrPort(value)
		if err != nil || p.Addr().Zone() != "" || p.Addr().IsLoopback() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Port() == 0 || seen[p.String()] {
			return fmt.Errorf("неверный или повторный iSCSI-портал")
		}
		seen[p.String()] = true
	}
	return nil
}

type MultipathInput struct {
	RequestID string `json:"requestID"`
	Name      string `json:"name"`
	WWID      string `json:"wwid"`
	TargetIQN string `json:"targetIQN"`
}

func (in MultipathInput) Validate() error {
	if !validJob.MatchString(in.RequestID) || !clusterName.MatchString(in.Name) || !wwid.MatchString(in.WWID) || !iqn.MatchString(in.TargetIQN) {
		return fmt.Errorf("выберите имя, WWID и iSCSI-цель")
	}
	return nil
}
