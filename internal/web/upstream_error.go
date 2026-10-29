package web

import (
	"errors"
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"sambaadm/internal/service"
)

// Keep the upstream cause available, while distinguishing permissions from
// connectivity failures. Browser RBAC does not grant rights to the service bind.
func upstreamError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	body := map[string]string{"error": err.Error()}
	var rpc *win32.Error
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) ||
		(errors.As(err, &rpc) && (rpc.Code == 5 || rpc.Code == 0x2105)) {
		status = http.StatusForbidden
		body["code"] = "upstream_access_denied"
		body["hint"] = "Check the configured ldap.bind.user and its AD permissions. Browser login does not change the service account."
	}
	if errors.Is(err, service.ErrGroupMemberInput) {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, body)
}
