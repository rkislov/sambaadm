package samba

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResultLines(t *testing.T) {
	r := &Result{Stdout: "a\n\nb\n  c  \n"}
	got := r.Lines()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %#v", got)
	}
}

// The subprocess inspects the credential while it exists; the parent checks
// cleanup on both successful and failing commands.
func TestRunnerCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires shell")
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			t.Setenv("PASSWD", "ambient-secret")
			t.Setenv("PASSWD_FD", "999")
			t.Setenv("PASSWD_FILE", "/missing")
			script := filepath.Join(t.TempDir(), "tool")
			body := "#!/bin/sh\n[ -z \"${PASSWD+x}\" ] && [ -z \"${PASSWD_FD+x}\" ] || exit 21\nprintf '%s\\n' \"$PASSWD_FILE\"\ncat \"$PASSWD_FILE\"\nprintf '\\n%s\\n' \"$@\"\n"
			if fail {
				body += "echo failed >&2\nexit 7\n"
			}
			if err := os.WriteFile(script, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			r := NewRunner(script)
			r.Username = "service@example.test"
			r.Password = func() string { return "synthetic-password" }
			res, err := r.Run(context.Background(), "gpo", "listall")
			if (err != nil) != fail {
				t.Fatalf("unexpected error: %v", err)
			}
			lines := res.Lines()
			if len(lines) != 5 || lines[1] != "synthetic-password" || lines[4] != "--username=service@example.test" {
				t.Fatalf("unexpected output: %q", res.Stdout)
			}
			if _, err := os.Stat(lines[0]); !os.IsNotExist(err) {
				t.Fatalf("credential file survives: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-password") {
				t.Fatal("password in diagnostic")
			}
		})
	}
}
