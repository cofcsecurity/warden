package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/manifest"
	"warden/internal/store"
)

// armTestBaseline writes a manifest covering paths as they are right now,
// standing in for the install-time snapshot arm compares against.
func armTestBaseline(t *testing.T, manifestPath string, paths []string, classify manifest.Classify) {
	t.Helper()
	m, err := manifest.Generate(paths, classify, 3)
	if err != nil {
		t.Fatal(err)
	}
	m.CreatedAt = time.Now().Add(-45 * time.Minute).UTC()
	if err := m.SaveAs(manifestPath); err != nil {
		t.Fatal(err)
	}
}

func armTestClassify(confirmFirst ...string) manifest.Classify {
	set := map[string]bool{}
	for _, p := range confirmFirst {
		set[p] = true
	}
	return func(path string) manifest.Class {
		if set[path] {
			return manifest.ConfirmFirst
		}
		return manifest.SafeAutoRestore
	}
}

// TestReviewSinceBaselineCatchesEditsMadeWhileUnprotected is the whole
// point of the review: everything between install and arm happens on a
// box with auto-restore off, and arming turns whatever is on disk then
// into the enforced known-good state.
func TestReviewSinceBaselineCatchesEditsMadeWhileUnprotected(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest-config.json")

	nginxConf := filepath.Join(dir, "nginx.conf")
	passwd := filepath.Join(dir, "passwd")
	vsftpd := filepath.Join(dir, "vsftpd.conf")
	newFile := filepath.Join(dir, "sshd_config")

	for _, f := range []string{nginxConf, passwd, vsftpd} {
		if err := os.WriteFile(f, []byte("original\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	watched := []string{nginxConf, passwd, vsftpd, newFile}
	classify := armTestClassify(passwd, newFile)
	armTestBaseline(t, manifestPath, watched, classify)

	// The hardening window: a service config edited, a sensitive file
	// edited, one removed, one created.
	if err := os.WriteFile(nginxConf, []byte("hardened\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("original\nbackdoor:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vsftpd); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("PermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	review, err := reviewSinceBaseline(manifestPath, watched, classify)
	if err != nil {
		t.Fatal(err)
	}
	if review.NoBaseline {
		t.Fatal("expected a baseline to compare against")
	}
	if len(review.Changes) != 4 {
		t.Fatalf("expected all four changes reported, got %+v", review.Changes)
	}

	kinds := map[string]manifest.ChangeKind{}
	for _, c := range review.Changes {
		kinds[c.Path] = c.Kind
	}
	if kinds[nginxConf] != manifest.Modified {
		t.Errorf("expected the edited config reported as modified, got %q", kinds[nginxConf])
	}
	if kinds[vsftpd] != manifest.Removed {
		t.Errorf("expected the deleted config reported as removed, got %q", kinds[vsftpd])
	}
	if kinds[newFile] != manifest.Added {
		t.Errorf("expected the new file reported as added, got %q", kinds[newFile])
	}
}

func TestReviewSinceBaselineReportsNoChanges(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest-config.json")
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("settled\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	watched := []string{conf}
	armTestBaseline(t, manifestPath, watched, nil)

	review, err := reviewSinceBaseline(manifestPath, watched, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Changes) != 0 {
		t.Fatalf("expected no changes, got %+v", review.Changes)
	}

	var out bytes.Buffer
	printArmReview(&out, review, time.Now())
	if !strings.Contains(out.String(), "nothing changed") {
		t.Errorf("expected the all-clear, got:\n%s", out.String())
	}
}

// TestReviewWithNoBaselineDoesNotReportEveryPathAsNew: without a prior
// snapshot every watched path would diff as added, which is noise, not a
// finding.
func TestReviewWithNoBaselineDoesNotReportEveryPathAsNew(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	review, err := reviewSinceBaseline(filepath.Join(dir, "missing.json"), []string{conf}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !review.NoBaseline || len(review.Changes) != 0 {
		t.Fatalf("expected a no-baseline review with no changes, got %+v", review)
	}

	var out bytes.Buffer
	printArmReview(&out, review, time.Now())
	if !strings.Contains(out.String(), "first snapshot") {
		t.Errorf("expected the no-baseline case explained, got:\n%s", out.String())
	}
}

func TestArmPublishesReviewedObjects(t *testing.T) {
	p, _, _ := recoveryFixture(t)
	p.armedMarkerPath = filepath.Join(p.storeRoot, "armed")
	path := filepath.Join(p.storeRoot, "watched")
	if err := os.WriteFile(path, []byte("reviewed"), 0600); err != nil {
		t.Fatal(err)
	}
	old := configTierPaths
	configTierPaths = []string{path}
	t.Cleanup(func() { configTierPaths = old })
	var out bytes.Buffer
	if err := armWithPaths(p, &out); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 1 {
		t.Fatalf("wrong manifest: %+v", m)
	}
	data, err := store.Open(p.storeRoot).Get(m.Records[0].Hash)
	if err != nil || string(data) != "reviewed" {
		t.Fatalf("missing reviewed bytes: %q %v", data, err)
	}
	if _, err := os.Stat(p.armedMarkerPath); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p.configManifestPath)
	out.Reset()
	if err := armWithPaths(p, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p.configManifestPath)
	if !bytes.Equal(before, after) || !strings.Contains(out.String(), "already armed") {
		t.Fatalf("arming twice must not re-baseline: %s", out.String())
	}
}

// TestArmCoversPatternEntries: a glob in the profile baselines every file
// it matches, so a later new file there is drift.
func TestArmCoversPatternEntries(t *testing.T) {
	p, _, _ := recoveryFixture(t)
	p.armedMarkerPath = filepath.Join(p.storeRoot, "armed")
	dir := filepath.Join(t.TempDir(), "sudoers.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admins", "team"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	old := configTierPaths
	configTierPaths = []string{dir + "/*"}
	t.Cleanup(func() { configTierPaths = old })
	if err := armWithPaths(p, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 2 {
		t.Fatalf("expected both files baselined, got %+v", m.Records)
	}
}
