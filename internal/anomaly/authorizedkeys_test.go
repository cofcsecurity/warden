package anomaly

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckAuthorizedKeysFirstRunBootstrapsSilently(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(path, []byte("ssh-ed25519 AAAA team@ccdc\n"), 0o600)

	sources := []AuthorizedKeysSource{{Path: path, Culprit: "alovelace"}}
	findings, err := CheckAuthorizedKeys(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckAuthorizedKeysFlagsNewLine(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(path, []byte("ssh-ed25519 AAAA team@ccdc\n"), 0o600)
	sources := []AuthorizedKeysSource{{Path: path, Culprit: "alovelace"}}

	if _, err := CheckAuthorizedKeys(baseDir, sources, nil); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(path, []byte("ssh-ed25519 AAAA team@ccdc\nssh-ed25519 BBBB attacker@evil\n"), 0o600)

	findings, err := CheckAuthorizedKeys(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Culprit != "alovelace" {
		t.Fatalf("expected one finding attributed to 'alovelace', got %+v", findings)
	}
}

func TestCheckAuthorizedKeysFlagsBrandNewFile(t *testing.T) {
	baseDir := t.TempDir()
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	os.WriteFile(existing, []byte("ssh-ed25519 AAAA team@ccdc\n"), 0o600)
	sources := []AuthorizedKeysSource{{Path: existing, Culprit: "alovelace"}}

	if _, err := CheckAuthorizedKeys(baseDir, sources, nil); err != nil {
		t.Fatal(err)
	}

	// A second account's authorized_keys appears for the first time.
	newFile := filepath.Join(dir, "new")
	os.WriteFile(newFile, []byte("ssh-ed25519 CCCC attacker@evil\n"), 0o600)
	sources = append(sources, AuthorizedKeysSource{Path: newFile, Culprit: "www-data"})

	findings, err := CheckAuthorizedKeys(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Culprit != "www-data" {
		t.Fatalf("expected one finding attributed to 'www-data', got %+v", findings)
	}
}
