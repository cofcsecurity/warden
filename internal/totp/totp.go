// Package totp is a minimal RFC 6238 TOTP implementation built only on the
// standard library, used to gate opmenu's sensitive commands behind a
// second factor.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPeriod is the standard 30-second TOTP step.
	DefaultPeriod = 30 * time.Second
	// DefaultDigits is the standard 6-digit code length.
	DefaultDigits = 6
)

// Generate returns the TOTP code for secret (base32-encoded, per the usual
// authenticator-app convention) at time t.
func Generate(secret string, t time.Time) (string, error) {
	return GenerateWithParams(secret, t, DefaultPeriod, DefaultDigits)
}

// GenerateWithParams is Generate with explicit period and digit count.
func GenerateWithParams(secret string, t time.Time, period time.Duration, digits int) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / int64(period.Seconds()))
	return hotp(key, counter, digits), nil
}

// Validate reports whether code is correct for secret at time t, allowing
// for the given number of periods of clock drift in either direction
// (skew=1 accepts the previous, current, and next 30-second window).
func Validate(secret, code string, t time.Time, skew int) (bool, error) {
	ok, _, err := ValidateAt(secret, code, t, skew)
	return ok, err
}

// ValidateAt is Validate, also returning which time step the code
// actually matched. Callers that must not accept the same code twice —
// anything reached over the network, where a code can be observed in
// flight — record that counter and refuse anything at or below it next
// time; RFC 6238 §5.2 requires exactly this, and without it a code
// captured from a session stays usable for the whole skew window.
func ValidateAt(secret, code string, t time.Time, skew int) (bool, int64, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return false, 0, err
	}

	counter := int64(t.Unix() / int64(DefaultPeriod.Seconds()))
	for delta := -skew; delta <= skew; delta++ {
		step := counter + int64(delta)
		want := hotp(key, uint64(step), DefaultDigits)
		if hmac.Equal([]byte(want), []byte(code)) {
			return true, step, nil
		}
	}
	return false, 0, nil
}

func decodeSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.TrimRight(secret, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	return key, nil
}

// hotp implements RFC 4226: an HMAC over the counter, truncated to a fixed
// number of decimal digits.
func hotp(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	code := truncated % pow10(digits)
	return fmt.Sprintf("%0*d", digits, code)
}

func pow10(n int) uint32 {
	v := uint32(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

// ParseDigits validates that code is numeric and of the expected length,
// for CLI flag validation ahead of Validate.
func ParseDigits(code string, digits int) error {
	if len(code) != digits {
		return fmt.Errorf("totp: code must be %d digits", digits)
	}
	if _, err := strconv.Atoi(code); err != nil {
		return fmt.Errorf("totp: code must be numeric: %w", err)
	}
	return nil
}

// ErrCodeAlreadyUsed is what ConsumeCounter returns for a code whose time
// step has already been spent. Callers surface it as a distinct rejection
// reason: "wrong code" and "right code, second time" are different
// situations for whoever is reading the audit log.
var ErrCodeAlreadyUsed = errors.New("totp: this code has already been used — wait for the next one")

// ConsumeCounter records that a time step has been used, and refuses
// anything at or below the last one recorded at path. This is the
// replay protection RFC 6238 §5.2 calls for: without it, a code observed
// in flight stays usable for the rest of its skew window, which is the
// attack a second factor exists to stop.
//
// One shared file across every entry point that checks a code (the SSH
// access layer, and the local commands that require one) so a code spent
// in one place can't be replayed into another. The cost, accepted
// deliberately, is that a code is good for exactly one command.
func ConsumeCounter(path string, counter int64) error {
	if path == "" {
		return nil // replay protection disabled (tests only)
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if last, convErr := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); convErr == nil && counter <= last {
			return ErrCodeAlreadyUsed
		}
	case !os.IsNotExist(err):
		return fmt.Errorf("totp: read %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(strconv.FormatInt(counter, 10)), 0o600); err != nil {
		return fmt.Errorf("totp: record used code in %s: %w", path, err)
	}
	return nil
}
