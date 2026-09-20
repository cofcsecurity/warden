package opmenu

import (
	"encoding/base32"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/audit"
	"warden/internal/totp"
)

func testHandler(t *testing.T, restoreCalled *bool) (*Handler, string) {
	t.Helper()
	secret := base32.StdEncoding.EncodeToString([]byte("test-secret-1234567890"))

	log, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	h := New(
		secret,
		func() (string, error) { return "ok", nil },
		func(target string, args []string) (string, error) {
			if restoreCalled != nil {
				*restoreCalled = true
			}
			return "restored " + target, nil
		},
		"", // no shell path in tests; shell path is exercised separately
		log,
	)
	return h, secret
}

func TestStatusNeedsNoTOTP(t *testing.T) {
	h, _ := testHandler(t, nil)

	out, err := h.Handle(Request{Command: CommandStatus})
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok" {
		t.Errorf("got %q, want %q", out, "ok")
	}
}

func TestRestoreRejectedWithoutTOTP(t *testing.T) {
	called := false
	h, _ := testHandler(t, &called)

	_, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}})
	if err == nil {
		t.Fatal("expected error for restore without TOTP")
	}
	if called {
		t.Errorf("RestoreFn should not have been invoked without a valid TOTP")
	}
}

func TestRestoreAcceptedWithValidTOTP(t *testing.T) {
	called := false
	h, secret := testHandler(t, &called)

	code, err := totp.Generate(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	out, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: code})
	if err != nil {
		t.Fatal(err)
	}
	if out != "restored nginx" {
		t.Errorf("got %q, want %q", out, "restored nginx")
	}
	if !called {
		t.Errorf("RestoreFn should have been invoked with a valid TOTP")
	}
}

func TestRestoreRejectedWithWrongTOTP(t *testing.T) {
	called := false
	h, _ := testHandler(t, &called)

	_, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: "000000"})
	if err == nil {
		t.Fatal("expected error for restore with wrong TOTP")
	}
	if called {
		t.Errorf("RestoreFn should not have been invoked with a wrong TOTP")
	}
}

func TestUnrecognizedCommandRejected(t *testing.T) {
	h, _ := testHandler(t, nil)

	_, err := h.Handle(Request{Command: "rm -rf /"})
	if err == nil {
		t.Fatal("expected error for unrecognized command")
	}
}
