// Package testkerberos creates disposable, cryptographically valid HTTP service
// tickets. It is never used by application code and never contacts a real KDC.
package testkerberos

import (
	"encoding/base64"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func Keytab(t *testing.T, principal, realm string) (*keytab.Keytab, string) {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(principal, realm, "Disposable-Test-Key-Only-135!", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	data, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "http.keytab")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return kt, path
}
func Token(t *testing.T, kt *keytab.Keytab, principal, serviceRealm, user, userRealm string, ttl time.Duration) string {
	t.Helper()
	creds := credentials.New(user, userRealm)
	spn, _ := types.ParseSPNString(principal)
	now := time.Now().UTC()
	start := now.Add(-time.Minute)
	if ttl < 0 {
		start = now.Add(-2 * time.Hour)
	}
	ticket, key, err := messages.NewTicket(creds.CName(), userRealm, spn, serviceRealm, types.NewKrbFlags(), kt, 18, 1, start, start, now.Add(ttl), now.Add(ttl))
	if err != nil {
		t.Fatal(err)
	}
	token, err := spnego.NewKRB5TokenAPREQ(&client.Client{Credentials: creds}, ticket, key, []int{gssapi.ContextFlagMutual}, []int{flags.APOptionMutualRequired})
	if err != nil {
		t.Fatal(err)
	}
	data, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(data)
}
