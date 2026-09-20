// Package totp is a minimal RFC 6238 TOTP implementation built only on the
// standard library, used to gate opmenu's sensitive commands behind a
// second factor.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
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
	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	counter := int64(t.Unix() / int64(DefaultPeriod.Seconds()))
	for delta := -skew; delta <= skew; delta++ {
		want := hotp(key, uint64(counter+int64(delta)), DefaultDigits)
		if hmac.Equal([]byte(want), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
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
