package anomaly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePasswdFile(t *testing.T, path string, users []string) {
	t.Helper()
	var content string
	for _, u := range users {
		content += u + ":x:1000:1000::/home/" + u + ":/bin/bash\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAccountsFirstRunBootstrapsSilently(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	writePasswdFile(t, passwdPath, []string{"alovelace", "root"})
	os.WriteFile(groupPath, []byte("sudo:x:27:alovelace\n"), 0o644)

	getentPasswd = func() ([]byte, error) { return nil, nil }

	findings, err := CheckAccounts(dir, passwdPath, groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckAccountsFlagsNewLocalUser(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	writePasswdFile(t, passwdPath, []string{"alovelace", "root"})
	os.WriteFile(groupPath, []byte(""), 0o644)
	getentPasswd = func() ([]byte, error) { return nil, nil }

	if _, err := CheckAccounts(dir, passwdPath, groupPath); err != nil {
		t.Fatal(err)
	}

	// A new account shows up.
	writePasswdFile(t, passwdPath, []string{"alovelace", "root", "backdoor"})

	findings, err := CheckAccounts(dir, passwdPath, groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Culprit != "backdoor" {
		t.Fatalf("expected culprit 'backdoor', got %+v", findings[0])
	}
}

func TestCheckAccountsFlagsDomainAccountWithNoCulprit(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	writePasswdFile(t, passwdPath, []string{"alovelace", "root"})
	os.WriteFile(groupPath, []byte(""), 0o644)
	getentPasswd = func() ([]byte, error) {
		return []byte("alovelace:x:1000:1000::/home/alovelace:/bin/bash\nroot:x:0:0::/root:/bin/bash\n"), nil
	}

	if _, err := CheckAccounts(dir, passwdPath, groupPath); err != nil {
		t.Fatal(err)
	}

	// A domain account (jsmith) now resolves via getent but was never in
	// the raw passwd file — the classic sssd/AD signature.
	getentPasswd = func() ([]byte, error) {
		return []byte("alovelace:x:1000:1000::/home/alovelace:/bin/bash\nroot:x:0:0::/root:/bin/bash\njsmith:*:1000001:1000001::/home/jsmith:/bin/bash\n"), nil
	}

	findings, err := CheckAccounts(dir, passwdPath, groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Culprit != "" {
		t.Fatalf("expected no culprit attributed for a domain account, got %+v", findings[0])
	}
	if !strings.Contains(findings[0].Description, "Active Directory") {
		t.Fatalf("expected the finding to point at Active Directory remediation, got %q", findings[0].Description)
	}
}

func TestIsLocalAccount(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	writePasswdFile(t, passwdPath, []string{"alovelace", "root"})

	ok, err := IsLocalAccount("alovelace", passwdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected alovelace to be reported as a local account")
	}

	ok, err = IsLocalAccount("jsmith", passwdPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected jsmith (not in the passwd file) to be reported as NOT local")
	}
}

// TestCheckAccountsFlagsPrivilegeChangesToAnExistingAccount is the gap a
// name-only baseline had: the privilege-escalation moves against an
// account that already exists never change a single name.
func TestCheckAccountsFlagsPrivilegeChangesToAnExistingAccount(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	getentPasswd = func() ([]byte, error) { return nil, nil }

	if err := os.WriteFile(passwdPath, []byte("alovelace:x:1000:1000::/home/alovelace:/bin/bash\nsvc:x:998:998::/var/empty:/usr/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(groupPath, []byte("sudo:x:27:\n"), 0o644)

	if _, err := CheckAccounts(dir, passwdPath, groupPath); err != nil {
		t.Fatal(err) // bootstrap
	}

	// alovelace gets UID 0; the service account gets a real shell; and
	// someone is quietly added to sudo. No new names anywhere.
	if err := os.WriteFile(passwdPath, []byte("alovelace:x:0:1000::/home/alovelace:/bin/bash\nsvc:x:998:998::/var/empty:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(groupPath, []byte("sudo:x:27:svc\n"), 0o644)

	findings, err := CheckAccounts(dir, passwdPath, groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected a finding for each of the three changes, got %+v", findings)
	}

	joined := ""
	for _, f := range findings {
		joined += f.Description + "\n"
	}
	for _, want := range []string{"uid 1000 -> 0", "shell /usr/sbin/nologin -> /bin/bash", `members "" -> svc`} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a finding mentioning %q, got:\n%s", want, joined)
		}
	}
}

// TestCheckAccountsIgnoresLegacyBaselineValues makes sure upgrading a box
// that already has the old name-only baseline doesn't report every
// account on it as modified on the next scan.
func TestCheckAccountsIgnoresLegacyBaselineValues(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	getentPasswd = func() ([]byte, error) { return nil, nil }

	writePasswdFile(t, passwdPath, []string{"alovelace", "root"})
	os.WriteFile(groupPath, []byte(""), 0o644)
	if err := os.WriteFile(filepath.Join(dir, "accounts-users.json"),
		[]byte(`{"alovelace":"1","root":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := CheckAccounts(dir, passwdPath, groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a legacy baseline must reseed quietly, got %+v", findings)
	}
}
