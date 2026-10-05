package auth

// Kerberos/SPNEGO SSO will be implemented with gokrb5.
// This file is a placeholder for Stage 1 scaffold.

// SPNEGOAuthenticator negotiates Kerberos SSO for Windows clients.
type SPNEGOAuthenticator struct {
	Realm string
	Keytab string
}

// Enabled reports whether Kerberos SSO is configured.
func (a *SPNEGOAuthenticator) Enabled() bool {
	return a != nil && a.Keytab != "" && a.Realm != ""
}
