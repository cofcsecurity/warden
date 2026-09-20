package main

import (
	"crypto/subtle"
	"os"
	"strings"
	"time"

	"warden/internal/totp"
)

// verifySecondFactor checks code against either the build-time TOTP secret
// or the current static secret file (see rotate-secret) — the same
// either-one check internal/opmenu's checkSecondFactor does for restore
// and shell over SSH. Local commands that do something destructive or
// state-changing (accept, uninstall) use this too, so a valid local shell
// alone is never enough on its own — proof of the same code a remote
// opmenu session would need is required either way. Reused rather than
// reimplemented per command so this doesn't drift into two different
// bars for "authorized," e.g. one command silently accepting TOTP only
// and leaving PCDC-style phone-free teams unable to use it (accept.go
// used to do exactly that, before this was extracted).
func verifySecondFactor(code string) (bool, error) {
	if code == "" {
		return false, nil
	}
	if buildTOTPSecret != "" {
		if ok, err := totp.Validate(buildTOTPSecret, code, time.Now(), 1); err == nil && ok {
			return true, nil
		}
	}
	p, err := loadPaths()
	if err != nil {
		return false, err
	}
	stored, err := os.ReadFile(p.staticSecretPath)
	if err != nil {
		return false, nil
	}
	expected := strings.TrimSpace(string(stored))
	if expected == "" {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1, nil
}
