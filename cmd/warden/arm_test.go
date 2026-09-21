package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/manifest"
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

	// Confirm-first paths sort first: a long list of routine service
	// edits must not bury the ones an attacker would make.
	if !changeIsConfirmFirst(review.Changes[0]) || !changeIsConfirmFirst(review.Changes[1]) {
		t.Errorf("expected confirm-first changes listed first, got %+v", review.Changes)
	}
	if got := review.confirmFirstPaths(); len(got) != 2 {
		t.Errorf("expected two confirm-first paths, got %v", got)
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

	// "No changes" means opposite things depending on the order the team
	// worked in, and only they know which it was — so the output has to
	// carry both readings rather than picking one.
	var out bytes.Buffer
	printArmReview(&out, review, time.Now())
	got := out.String()
	for _, want := range []string{
		"Nothing has changed",
		"hardened BEFORE Warden was installed",
		"hardened AFTER",
		"detect",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the all-clear to mention %q, got:\n%s", want, got)
		}
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
	if !strings.Contains(out.String(), "never been snapshotted") {
		t.Errorf("expected the no-baseline case explained, got:\n%s", out.String())
	}
}

func TestPrintArmReviewNamesEveryChangeAndWarnsAboutSensitiveOnes(t *testing.T) {
	baselineAt := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	now := baselineAt.Add(45 * time.Minute)

	review := armReview{
		BaselineAt: baselineAt,
		Generation: 3,
		Changes: []manifest.Change{
			{Kind: manifest.Modified, Path: "/etc/passwd", Old: &manifest.Record{Class: manifest.ConfirmFirst}, New: &manifest.Record{Class: manifest.ConfirmFirst}},
			{Kind: manifest.Modified, Path: "/etc/nginx/nginx.conf", Old: &manifest.Record{Class: manifest.SafeAutoRestore}, New: &manifest.Record{Class: manifest.SafeAutoRestore}},
		},
	}

	var out bytes.Buffer
	printArmReview(&out, review, now)
	got := out.String()

	for _, want := range []string{
		"2 watched path(s) changed",
		"45m0s ago",
		"generation 3",
		"/etc/passwd",
		"confirm-first",
		"/etc/nginx/nginx.conf",
		"auto-restore",
		"enforced known-good state",
		"is a confirm-first path",
		"Check each one was your team",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the review to mention %q, got:\n%s", want, got)
		}
	}
}

func TestArmReviewAuditFieldsRecordWhatWasBaselined(t *testing.T) {
	review := armReview{
		Generation: 3,
		Changes: []manifest.Change{
			{Kind: manifest.Modified, Path: "/etc/passwd", New: &manifest.Record{Class: manifest.ConfirmFirst}},
			{Kind: manifest.Added, Path: "/etc/nginx/nginx.conf", New: &manifest.Record{Class: manifest.SafeAutoRestore}},
		},
	}

	fields := review.auditFields()
	changes, ok := fields["changes"].([]string)
	if !ok || len(changes) != 2 {
		t.Fatalf("expected both changes recorded, got %+v", fields["changes"])
	}
	if changes[0] != "modified /etc/passwd" || changes[1] != "added /etc/nginx/nginx.conf" {
		t.Errorf("expected kind and path per entry, got %v", changes)
	}
	cf, ok := fields["confirm_first"].([]string)
	if !ok || len(cf) != 1 || cf[0] != "/etc/passwd" {
		t.Errorf("expected the confirm-first path called out separately, got %+v", fields["confirm_first"])
	}
	if fields["baseline_generation"] != 3 {
		t.Errorf("expected the baseline generation recorded, got %v", fields["baseline_generation"])
	}
}

// TestConfirmArmRefusesWhenThereIsNobodyToAsk covers the path most
// operators hit: `ssh box "shell <code>"` runs over a no-pty channel, so
// stdin is a pipe with nothing in it. Proceeding silently there would
// defeat the review — the point is that a person read the list.
func TestConfirmArmRefusesWhenThereIsNobodyToAsk(t *testing.T) {
	err := confirmArm(strings.NewReader(""), 3)
	if err == nil {
		t.Fatal("expected a refusal rather than silently arming")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("expected the error to say how to proceed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "3 change(s)") {
		t.Errorf("expected the error to name the count, got: %v", err)
	}
}

func TestConfirmArmAcceptsOnlyAnExplicitYes(t *testing.T) {
	if err := confirmArm(strings.NewReader("y\n"), 2); err != nil {
		t.Errorf("expected y to confirm, got: %v", err)
	}
	if err := confirmArm(strings.NewReader("Y\n"), 2); err != nil {
		t.Errorf("expected Y to confirm, got: %v", err)
	}
	for _, answer := range []string{"n\n", "\n", "yes please\n", "no\n"} {
		if err := confirmArm(strings.NewReader(answer), 2); err == nil {
			t.Errorf("expected %q to be treated as declining", answer)
		}
	}
}
