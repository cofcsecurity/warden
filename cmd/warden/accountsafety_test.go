package main

import (
	"strings"
	"testing"
)

func TestCanLockAccountEmptyCulprit(t *testing.T) {
	ok, reason, err := canLockAccount("", false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected an empty culprit to never be lockable")
	}
	if !strings.Contains(reason, "no account") {
		t.Fatalf("expected the reason to explain no account was attributed, got %q", reason)
	}
}

func TestCanLockAccountRefusesRoot(t *testing.T) {
	ok, reason, err := canLockAccount("root", false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected root to never be lockable")
	}
	if !strings.Contains(reason, "root") {
		t.Fatalf("expected the reason to mention root, got %q", reason)
	}
}

func TestCanLockAccountRefusesRootEvenWithForce(t *testing.T) {
	ok, _, err := canLockAccount("root", true)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected root to never be lockable, even with force")
	}
}

func TestCanLockAccountRefusesNonLocalAccount(t *testing.T) {
	ok, reason, err := canLockAccount("definitely-not-a-real-local-or-domain-account-xyz123", false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected a nonexistent account to never be lockable")
	}
	if !strings.Contains(reason, "Active Directory") {
		t.Fatalf("expected the reason to point at Active Directory/directory-service remediation, got %q", reason)
	}
}

func TestCanLockAccountRefusesNonLocalAccountEvenWithForce(t *testing.T) {
	// force only overrides the configured SAFE_ACCOUNTS list — it can
	// never make a local lock work against an account that isn't local
	// to begin with, since that's a technical fact, not a policy choice.
	ok, _, err := canLockAccount("definitely-not-a-real-local-or-domain-account-xyz123", true)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected a nonexistent account to never be lockable, even with force")
	}
}

func TestCanLockAccountRespectsSafeAccountsListAndForceOverride(t *testing.T) {
	old := buildSafeAccounts
	defer func() { buildSafeAccounts = old }()
	buildSafeAccounts = "daemon,someone-else"

	// daemon is a near-universal /etc/passwd entry on both Linux and
	// macOS, and won't collide with opmenuUser() (derived from the test
	// binary's own path).
	ok, reason, err := canLockAccount("daemon", false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected an account on SAFE_ACCOUNTS to be refused without --force")
	}
	if !strings.Contains(reason, "SAFE_ACCOUNTS") {
		t.Fatalf("expected the reason to mention SAFE_ACCOUNTS, got %q", reason)
	}

	ok, _, err = canLockAccount("daemon", true)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected an account on SAFE_ACCOUNTS to be lockable with --force")
	}
}

func TestCanLockAccountAllowsOrdinaryLocalAccount(t *testing.T) {
	old := buildSafeAccounts
	defer func() { buildSafeAccounts = old }()
	buildSafeAccounts = ""

	ok, reason, err := canLockAccount("nobody", false)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected an ordinary, non-protected local account to be lockable, got reason=%q", reason)
	}
}

func TestConfiguredSafeAccountsParsesCommaSeparatedList(t *testing.T) {
	old := buildSafeAccounts
	defer func() { buildSafeAccounts = old }()
	buildSafeAccounts = " alovelace , scoring-agent ,,"

	got := configuredSafeAccounts()
	for _, want := range []string{"alovelace", "scoring-agent"} {
		if !got[want] {
			t.Errorf("expected %q in the parsed set, got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 entries (blank/whitespace-only ignored), got %v", got)
	}
}

func TestHardProtectedAccountsIncludesRootAndOpmenuUser(t *testing.T) {
	protected, err := hardProtectedAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if !protected["root"] {
		t.Error("expected root to be hard-protected")
	}
	opUser, err := opmenuUser()
	if err != nil {
		t.Fatal(err)
	}
	if !protected[opUser] {
		t.Errorf("expected the opmenu account (%s) to be hard-protected", opUser)
	}
}
