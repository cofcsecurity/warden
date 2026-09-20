package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"warden/internal/audit"
)

// rotateSecretCmd sets or replaces opmenu's static, non-TOTP second
// factor — for competitions where phones/authenticator apps aren't
// available at all (e.g. PCDC), where TOTP simply can't be used. See
// internal/opmenu's StaticSecretPath doc comment for how it's checked.
func rotateSecretCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-secret [new-value]",
		Short: "Set or rotate opmenu's static, non-TOTP second factor",
		Long: `Sets the passphrase opmenu accepts as an alternative to a TOTP code, for
competitions where phones/authenticator apps aren't available at all.
Generates a random one if no value is given.

Takes effect immediately: opmenu reads this file fresh on every check,
never anything baked into the binary, so rotating it needs no rebuild or
redeploy — just run this again with a new value once you're on the box.

Run this locally; reaching a local shell already means you passed
opmenu's own second-factor check once (TOTP or a prior static secret),
so there's no separate confirmation gate here.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var value string
			if len(args) > 0 {
				value = args[0]
			}
			return runRotateSecret(value)
		},
	}
}

func runRotateSecret(value string) error {
	if value == "" {
		var err error
		value, err = randomSecret()
		if err != nil {
			return fmt.Errorf("rotate-secret: generate: %w", err)
		}
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("rotate-secret: value can't contain whitespace — it has to travel as one SSH command-line argument")
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(p.staticSecretPath), 0o700); err != nil {
		return fmt.Errorf("rotate-secret: mkdir for %s: %w", p.staticSecretPath, err)
	}
	if err := os.WriteFile(p.staticSecretPath, []byte(value+"\n"), 0o600); err != nil {
		return fmt.Errorf("rotate-secret: write %s: %w", p.staticSecretPath, err)
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("opmenu", "secret-rotated", nil); err != nil {
		return err
	}

	fmt.Printf("Static second factor set. Save this somewhere secure — it will not be printed again:\n  %s\n", value)
	return nil
}

func randomSecret() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
