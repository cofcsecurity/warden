package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// Test vectors from RFC 6238 Appendix B, SHA-1 mode, 8-digit codes, using
// the ASCII seed "12345678901234567890" base32-encoded as our Generate API
// expects.
func TestGenerateRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
	}

	for _, c := range cases {
		got, err := GenerateWithParams(secret, time.Unix(c.unix, 0).UTC(), DefaultPeriod, 8)
		if err != nil {
			t.Fatalf("unix=%d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("unix=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestValidateAcceptsCurrentAndAdjacentWindows(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1111111111, 0).UTC()

	code, err := Generate(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Validate(secret, code, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("expected code to validate at generation time")
	}

	// one period later, still within skew=1
	ok, err = Validate(secret, code, now.Add(DefaultPeriod), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("expected code to validate one period later within skew")
	}

	// far outside any allowed skew
	ok, err = Validate(secret, code, now.Add(10*DefaultPeriod), 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("expected code to be rejected far outside skew window")
	}
}

func TestValidateRejectsWrongCode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1111111111, 0).UTC()

	ok, err := Validate(secret, "000000", now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("expected wrong code to be rejected")
	}
}
