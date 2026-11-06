package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// The team password is an optional second way into the access accounts,
// next to the team key. Only its crypt(3) hash is ever stored: in the
// runtime config, so sentinel can put it back, and in /etc/shadow, where
// every password lives anyway.

// validPasswordHash accepts a modern crypt(3) hash that is safe to put in a
// shadow line: yescrypt, sha512, sha256 or bcrypt, with no separators.
func validPasswordHash(h string) error {
	ok := false
	for _, prefix := range []string{"$y$", "$6$", "$5$", "$2b$", "$2y$"} {
		if strings.HasPrefix(h, prefix) {
			ok = true
		}
	}
	if !ok || strings.ContainsAny(h, ": \t\r\n") || len(h) < 20 {
		return fmt.Errorf("config: team_password_hash must be a crypt hash ($6$..., $y$...), not a password")
	}
	return nil
}

// hashPassword makes a sha512-crypt hash with the system's openssl, so the
// plaintext is only ever in this process and the pipe to it.
var hashPassword = func(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("password: empty password")
	}
	cmd := exec.Command("openssl", "passwd", "-6", "-stdin")
	cmd.Stdin = strings.NewReader(plain + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("password: openssl passwd failed (install openssl or pass --password-hash): %w", err)
	}
	return strings.TrimSpace(out.String()), nil
}

// promptPassword reads a new password twice from the terminal without echo.
func promptPassword(_ io.Writer) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("password: no terminal to prompt on; pass --password-hash instead")
	}
	defer tty.Close()
	read := func(prompt string) (string, error) {
		fmt.Fprint(tty, prompt)
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	first, err := read("Team password: ")
	if err != nil {
		return "", err
	}
	second, err := read("Again: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("password: the two entries differ")
	}
	return first, nil
}

// accountPasswordField is what our accounts' shadow password field holds:
// the team password hash, or '*' (no password, not locked) without one.
func accountPasswordField() string {
	if cfg.TeamPasswordHash != "" {
		return cfg.TeamPasswordHash
	}
	return "*"
}
