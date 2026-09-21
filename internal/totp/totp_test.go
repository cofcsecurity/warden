package totp

import (
	"encoding/base32"
	"errors"
	"path/filepath"
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

func TestConsumeCounterRefusesAReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "second-factor-spent")

	if err := ConsumeCounter(path, 100); err != nil {
		t.Fatalf("first use of a step should be accepted: %v", err)
	}
	if err := ConsumeCounter(path, 100); !errors.Is(err, ErrCodeAlreadyUsed) {
		t.Errorf("expected the same step to be refused, got %v", err)
	}
	// An earlier step is refused too: a code from the skew window below
	// the last accepted one is just as replayed.
	if err := ConsumeCounter(path, 99); !errors.Is(err, ErrCodeAlreadyUsed) {
		t.Errorf("expected an earlier step to be refused, got %v", err)
	}
	if err := ConsumeCounter(path, 101); err != nil {
		t.Errorf("expected the next step to be accepted, got %v", err)
	}
}

func TestConsumeCounterWithNoPathIsANoop(t *testing.T) {
	for i := 0; i < 2; i++ {
		if err := ConsumeCounter("", 100); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
}

func TestValidateAtReportsTheMatchedStep(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	at := time.Unix(1700000000, 0)
	code, err := Generate(secret, at)
	if err != nil {
		t.Fatal(err)
	}

	ok, counter, err := ValidateAt(secret, code, at, 1)
	if err != nil || !ok {
		t.Fatalf("expected the code to validate, ok=%v err=%v", ok, err)
	}
	if want := at.Unix() / int64(DefaultPeriod.Seconds()); counter != want {
		t.Errorf("expected step %d, got %d", want, counter)
	}
}
