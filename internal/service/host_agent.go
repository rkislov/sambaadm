package service

import "context"

// Host mutations are audited both at the management server (browser actor)
// and at the helper (trusted key plus forwarded actor).
func (s *ShareService) hostCall(ctx context.Context, method string, in HostOperation, out any) error {
	e := s.helpers.Call(ctx, s.helpers.Config.HostNode, method, in, out)
	actions := map[string]string{"shares.create": "share.create", "shares.delete": "share.delete", "shares.access": "share.access", "shares.param": "share.set", "printers.create": "printer.create", "printers.delete": "printer.delete", "acl.set": "acl.set", "samba.profile.apply": "samba.profile"}
	if action := actions[method]; action != "" && s.audit != nil {
		target := s.helpers.Config.HostNode + " " + in.Name + in.Path
		if e != nil {
			s.audit.Failure(in.Actor, action, target, in.IP, e)
		} else {
			s.audit.Success(in.Actor, action, target, in.IP)
		}
	}
	return e
}
