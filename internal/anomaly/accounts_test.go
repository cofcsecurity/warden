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
