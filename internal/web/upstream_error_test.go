package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"sambaadm/internal/service"
)

func TestUpstreamErrorsDistinguishAccessFromConnectivity(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("DRS: %w", win32.ErrorDsDraAccessDenied), 403, "upstream_access_denied"},
		{fmt.Errorf("KCC: %w", win32.ErrorAccessDenied), 403, "upstream_access_denied"},
		{fmt.Errorf("modify: %w", ldap.NewError(50, errors.New("no rights"))), 403, "upstream_access_denied"},
		{errors.New("connection refused"), 502, ""},
		{fmt.Errorf("%w: OU cannot be a member", service.ErrGroupMemberInput), 400, ""},
	} {
		rec := httptest.NewRecorder()
		upstreamError(rec, tc.err)
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != tc.status || body["code"] != tc.code || body["error"] != tc.err.Error() {
			t.Fatalf("wrong error classification: %d %v", rec.Code, body)
		}
	}
}
