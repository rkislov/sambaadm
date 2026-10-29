package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

func TestIntegrationReplicationReportsServiceAccountAccessDenied(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	login := fmt.Sprintf("drs%d", time.Now().UnixNano())
	password := "Lab-DRS-ReadOnly1!"
	if _, err := s.Users.Create(ctx, CreateUserInput{Login: login, Password: password, Enabled: true}, "integration", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Users.Delete(context.Background(), login, "integration", ""); err != nil {
			t.Error(err)
		}
	})
	s.Repl.remote.User, s.Repl.remote.Password = login+"@sambaadm.test", func() string { return password }
	_, statusErr := s.Repl.Status(ctx)
	kccErr := s.Repl.KCC(ctx, "", "browser-domain-admin", "")
	for _, err := range []error{statusErr, kccErr} {
		var rpc *win32.Error
		if !errors.As(err, &rpc) || rpc.Code != 0x2105 || !strings.Contains(err.Error(), login+"@sambaadm.test") {
			t.Fatalf("expected typed service-account DRS access denial, got %v", err)
		}
	}
}
