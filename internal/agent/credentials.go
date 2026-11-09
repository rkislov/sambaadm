package agent

import (
	"context"
	"fmt"
	"strings"
)

const CredentialVersion = 2

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c Credentials) String() string   { return "[redacted helper credentials]" }
func (c Credentials) GoString() string { return c.String() }
func (c Credentials) Valid() bool {
	return c.Username != "" && len(c.Username) <= 1024 && c.Password != "" && len(c.Password) <= 16384
}

type credentialKey struct{}
type CredentialProvider func() (Credentials, error)

// The context holds a revocable resolver, never a password copied into a job.
func WithCredentials(ctx context.Context, provider CredentialProvider) context.Context {
	return context.WithValue(ctx, credentialKey{}, provider)
}
func OperationCredentials(ctx context.Context) (Credentials, bool, error) {
	provider, ok := ctx.Value(credentialKey{}).(CredentialProvider)
	if !ok {
		return Credentials{}, false, nil
	}
	credentials, err := provider()
	if err != nil {
		return Credentials{}, true, err
	}
	if !credentials.Valid() {
		return Credentials{}, true, fmt.Errorf("session credentials unavailable; sign in again")
	}
	return credentials, true, nil
}
func CarryCredentials(to, from context.Context) context.Context {
	if provider, ok := from.Value(credentialKey{}).(CredentialProvider); ok {
		return WithCredentials(to, provider)
	}
	return to
}
func RedactCredentialError(err error, credentials Credentials) error {
	if err == nil || credentials.Password == "" {
		return err
	}
	// Preserve errors.Is semantics for filesystem error codes.
	return redactedCredentialError{err: err, text: strings.ReplaceAll(err.Error(), credentials.Password, "[redacted]")}
}

type redactedCredentialError struct {
	err  error
	text string
}

func (e redactedCredentialError) Error() string { return e.text }
func (e redactedCredentialError) Unwrap() error { return e.err }
