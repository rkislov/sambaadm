package bootstrap

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshFixture(t *testing.T) (string, int, string, *atomic.Int32) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	var authentications atomic.Int32
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authentications.Add(1)
		if c.User() != "tester" || string(password) != "ssh-secret" {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, channels, requests, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for ch := range channels {
					channel, reqs, e := ch.Accept()
					if e != nil {
						return
					}
					go func() {
						defer channel.Close()
						for req := range reqs {
							switch req.Type {
							case "pty-req":
								req.Reply(true, nil)
							case "exec":
								var command struct{ Command string }
								ssh.Unmarshal(req.Payload, &command)
								req.Reply(true, nil)
								if strings.Contains(command.Command, "su - -c") {
									if strings.Contains(command.Command, "root-secret") {
										t.Error("password exposed in command")
									}
									io.WriteString(channel, "Pass")
									time.Sleep(time.Millisecond)
									io.WriteString(channel, "word: ")
									line, _ := bufio.NewReader(channel).ReadString('\n')
									status := uint32(0)
									if strings.TrimSpace(line) != "root-secret" {
										io.WriteString(channel, "su: Authentication failure\n")
										status = 1
									} else {
										io.WriteString(channel, "SAMBAADM_STAGE=/var/tmp/sambaadm-install.test\ninstalled\n")
									}
									channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
									return
								}
								io.WriteString(channel, "x86_64\n")
								channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
						}
					}()
				}
			}()
		}
	}()
	return "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey()), &authentications
}
func TestHostKeyPinnedBeforeCredentialsAndSuPasswordNotInCommand(t *testing.T) {
	host, port, key, auths := sshFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, e := Probe(ctx, host, port)
	if e != nil || got != key {
		t.Fatal(got, e)
	}
	if auths.Load() != 0 {
		t.Fatal("probe authenticated")
	}
	if c, e := Dial(ctx, host, port, "tester", "ssh-secret", "SHA256:changed"); e == nil {
		c.Close()
		t.Fatal("changed key accepted")
	}
	if auths.Load() != 0 {
		t.Fatal("password sent before key verification")
	}
	c, e := Dial(ctx, host, port, "tester", "ssh-secret", key)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	output, e := Su(ctx, c, "echo installed", "root-secret", nil)
	if e != nil || !strings.HasPrefix(output, "SAMBAADM_STAGE=") {
		t.Fatal(output, e)
	}
	if _, e = Su(ctx, c, "echo installed", "wrong-secret", nil); e == nil {
		t.Fatal("wrong su password accepted")
	}
}
func TestQuote(t *testing.T) {
	if got := Quote("a'$(id)\nb"); got != "'a'\"'\"'$(id)\nb'" {
		t.Fatal(got)
	}
}
