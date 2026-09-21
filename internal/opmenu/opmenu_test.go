package opmenu

import (
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/audit"
	"warden/internal/totp"
)

func testHandler(t *testing.T, restoreCalled *bool) (*Handler, string) {
	t.Helper()
	h, secret, _ := testHandlerWithStaticSecret(t, restoreCalled, "")
	return h, secret
}

// testHandlerWithStaticSecret is testHandler plus a static-secret file
// (created with the given initial content, or left absent if empty), for
// exercising the non-TOTP fallback path.
func testHandlerWithStaticSecret(t *testing.T, restoreCalled *bool, staticSecretContent string) (*Handler, string, string) {
	t.Helper()
	secret := base32.StdEncoding.EncodeToString([]byte("test-secret-1234567890"))

	log, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	staticSecretPath := ""
	if staticSecretContent != "" {
		staticSecretPath = filepath.Join(t.TempDir(), "second-factor")
		if err := os.WriteFile(staticSecretPath, []byte(staticSecretContent), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	h := New(
		secret,
		staticSecretPath,
		filepath.Join(t.TempDir(), "second-factor-spent"),
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
	return h, secret, staticSecretPath
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

func TestRestoreAcceptedWithValidStaticSecret(t *testing.T) {
	called := false
	h, _, _ := testHandlerWithStaticSecret(t, &called, "my-static-passphrase\n")

	out, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: "my-static-passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "restored nginx" {
		t.Errorf("got %q, want %q", out, "restored nginx")
	}
	if !called {
		t.Errorf("RestoreFn should have been invoked with a valid static secret")
	}
}

func TestRestoreRejectedWithWrongStaticSecret(t *testing.T) {
	called := false
	h, _, _ := testHandlerWithStaticSecret(t, &called, "my-static-passphrase\n")

	_, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: "wrong-guess"})
	if err == nil {
		t.Fatal("expected error for restore with a wrong static secret")
	}
	if called {
		t.Errorf("RestoreFn should not have been invoked with a wrong static secret")
	}
}

func TestStaticSecretStillHonorsValidTOTP(t *testing.T) {
	// A configured static secret must not disable TOTP -- either should
	// still work.
	called := false
	h, secret, _ := testHandlerWithStaticSecret(t, &called, "my-static-passphrase\n")

	code, err := totp.Generate(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: code})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Errorf("RestoreFn should have been invoked with a valid TOTP code even though a static secret is also configured")
	}
}

func TestUnconfiguredStaticSecretPathNeverMatches(t *testing.T) {
	// StaticSecretPath == "" (the default/unconfigured state) must never
	// accidentally accept anything.
	called := false
	h, _ := testHandler(t, &called)

	_, err := h.Handle(Request{Command: CommandRestore, Args: []string{"nginx"}, TOTPCode: ""})
	if err == nil {
		t.Fatal("expected error for an empty code")
	}
	if called {
		t.Errorf("RestoreFn should not have been invoked")
	}
}

// TestTOTPCodeCannotBeReplayed covers the window a captured code used to
// stay good for: without this, anyone who observed a code had the rest of
// its ~90-second skew window to use it themselves.
func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	h, secret := testHandler(t, nil)
	code, err := totp.Generate(secret, timeNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.Handle(Request{Command: CommandRestore, TOTPCode: code, Args: []string{"nginx"}}); err != nil {
		t.Fatalf("first use of a fresh code should be accepted: %v", err)
	}

	_, err = h.Handle(Request{Command: CommandRestore, TOTPCode: code, Args: []string{"nginx"}})
	if err == nil {
		t.Fatal("expected the same code to be refused the second time")
	}
	if !strings.Contains(err.Error(), "already been used") {
		t.Errorf("expected the error to say why, got: %v", err)
	}
}

func TestSpentTOTPStateIsPerHandlerPath(t *testing.T) {
	// A handler with no replay-protection path configured (tests only)
	// must still work rather than refusing everything.
	h, secret := testHandler(t, nil)
	h.SpentTOTPPath = ""
	code, err := totp.Generate(secret, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := h.Handle(Request{Command: CommandRestore, TOTPCode: code, Args: []string{"nginx"}}); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
}
