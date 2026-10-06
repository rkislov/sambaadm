package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// readPassword prompts on stderr and reads a password without echo.
// Falls back to stdin line if not a terminal.
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func actorName() string {
	if user != "" {
		return user
	}
	if rootCfg != nil && rootCfg.LDAP.Bind.User != "" {
		return rootCfg.LDAP.Bind.User
	}
	return "cli"
}
