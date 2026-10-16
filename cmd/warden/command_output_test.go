package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/audit"
	"warden/internal/manifest"
)

// Command output fixtures cover status, fleet, arming, and alert rendering.

func docFixture(t *testing.T, now time.Time) paths {
	t.Helper()
	dir := t.TempDir()
	p := paths{
		dataDir:            dir,
		configManifestPath: filepath.Join(dir, "manifest-config.json"),
		configManifestsDir: filepath.Join(dir, "manifests-config"),
		auditLogPath:       filepath.Join(dir, "audit.log"),
		armedMarkerPath:    filepath.Join(dir, "armed"),
		quarantineDir:      filepath.Join(dir, "quarantine"),
		storeRoot:          dir,
		bannedIPsPath:      filepath.Join(dir, "banned_ips.json"),
		accountLocksPath:   filepath.Join(dir, "account_locks.json"),
	}

	// A baseline of 23 watched paths, taken 6 minutes ago.
	var records []manifest.Record
	watched := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/hosts", "/etc/hostname", "/etc/crontab",
		"/etc/nginx/nginx.conf", "/etc/mysql/my.cnf", "/etc/postfix/main.cf",
		"/etc/pam.d/common-auth", "/etc/pam.d/common-password", "/etc/pam.d/common-account",
		"/etc/pam.d/common-session", "/etc/pam.d/sshd", "/etc/pam.d/sudo", "/etc/pam.d/su",
		"/etc/nsswitch.conf", "/etc/login.defs", "/etc/iptables/rules.v4", "/etc/redis/redis.conf",
	}
	for i, path := range watched {
		records = append(records, manifest.Record{
			Path:  path,
			Hash:  fmt.Sprintf("%064d", i),
			Mode:  0o644,
			MTime: now.Add(-3 * time.Hour),
			Class: classifyPath(path),
		})
	}
	m := &manifest.Manifest{Generation: 12, CreatedAt: now.Add(-7 * time.Minute).UTC(), Records: records}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(p.armedMarkerPath, []byte(now.Add(-3*time.Hour).Format(time.RFC3339)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func docAuditLog(t *testing.T, p paths, now time.Time) {
	t.Helper()

	// Written directly rather than through audit.Log so the entries can
	// be backdated: the ages are what status and fleet actually display.
	entries := []struct {
		ago               time.Duration
		component, action string
		fields            map[string]any
	}{
		{7 * time.Minute, "snapshot", "unchanged", map[string]any{"tier": "config", "generation": 12}},
		{6 * time.Minute, "scan", "pass", map[string]any{"armed": true, "findings": 0, "locked": 0, "banned": 0}},
		{4 * time.Minute, "replicate", "pass", map[string]any{"peers": 2, "failed": 0, "audit_bytes_pushed": 1841}},
		{3 * time.Minute, "sentinel", "pass", map[string]any{"ok": 10, "recreated": 0}},
		{90 * time.Second, "watch", "pass", map[string]any{"armed": true, "auto_restored": 1, "suppressed": 0, "flagged": 1, "reload_errors": 0}},
	}

	f, err := os.OpenFile(p.auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, e := range entries {
		line, err := json.Marshal(audit.Entry{
			Time:      now.Add(-e.ago).UTC(),
			Component: e.component,
			Action:    e.action,
			Fields:    e.fields,
			Host:      "box1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCommandOutputStatus(t *testing.T) {
	now := time.Now()
	p := docFixture(t, now)
	docAuditLog(t, p, now)

	report, err := collectStatus(p)
	if err != nil {
		t.Fatal(err)
	}
	out := report.text()
	for _, want := range []string{"armed: yes", "config snapshot: generation 12", "last scan:", "last replicate:", "responses: ban=flag lock=flag"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if !report.Armed || report.Tiers["config"].Generation != 12 || report.Components["watch"].Action != "pass" {
		t.Fatalf("json report wrong: %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"armed":true`, `"tiers"`, `"components"`, `"peers":[]`} {
		if !strings.Contains(string(data), field) {
			t.Errorf("status --json is missing %s: %s", field, data)
		}
	}
}

func TestCommandOutputArm(t *testing.T) {
	now := time.Now()
	var out bytes.Buffer
	sa := &manifest.Record{Class: manifest.SafeAutoRestore}
	review := armReview{
		BaselineAt: now.Add(-47 * time.Minute),
		Generation: 1,
		Changes: []manifest.Change{
			{Kind: manifest.Modified, Path: "/etc/nginx/nginx.conf", Old: sa, New: sa},
			{Kind: manifest.Added, Path: "/etc/redis/redis.conf", New: sa},
		},
	}
	printArmReview(&out, review, now)
	printArmReview(&out, armReview{BaselineAt: now.Add(-4 * time.Minute), Generation: 12}, now)
	for _, want := range []string{"47m0s ago", "/etc/nginx/nginx.conf", "added", "nothing changed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}

	var many []manifest.Change
	for i := 0; i < maxArmChanges+5; i++ {
		many = append(many, manifest.Change{Kind: manifest.Modified, Path: fmt.Sprintf("/etc/x%02d", i)})
	}
	out.Reset()
	printArmReview(&out, armReview{BaselineAt: now, Changes: many}, now)
	if !strings.Contains(out.String(), "and 5 more") {
		t.Errorf("long change lists must be capped: %s", out.String())
	}
}

func TestCommandOutputAlerts(t *testing.T) {
	base := time.Date(2026, 9, 21, 14, 3, 11, 0, time.Local)
	entries := []audit.Entry{
		{Time: base, Component: "react", Action: "alert", Fields: map[string]any{
			"path": "/etc/shadow", "kind": "modified", "suspect_ip": "198.51.100.23",
			"account": "root", "autobanned": true,
			"evidence": "exactly one non-team root session was open at the time",
		}},
		{Time: base.Add(2 * time.Minute), Component: "react", Action: "alert", Fields: map[string]any{
			"path": "/etc/sudoers", "kind": "modified", "autobanned": false,
			"evidence":      "more than one non-team IP had a session open ([198.51.100.23 198.51.100.77]) — too ambiguous to single one out automatically; ban whichever is yours to ban with 'warden ban <ip>'",
			"candidate_ips": []any{"198.51.100.23", "198.51.100.77"},
		}},
		{Time: base.Add(5 * time.Minute), Component: "react", Action: "alert", Fields: map[string]any{
			"source": "anomaly", "check": "suid", "culprit": "wwwrun", "locked_account": true,
			"description": "new setuid/setgid binary: /usr/local/bin/.dbus-helper (-rwsr-xr-x)",
			"suspect_ip":  "198.51.100.23", "autobanned": true,
		}},
		{Time: base.Add(6 * time.Minute), Component: "react", Action: "alert", Fields: map[string]any{
			"source": "anomaly", "check": "accounts", "culprit": "svc",
			"description":         "existing local account modified: svc (uid 998 -> 0; shell /usr/sbin/nologin -> /bin/bash)",
			"locked_account":      false,
			"lock_skipped_reason": "svc is on the SAFE_ACCOUNTS list; lock it by hand with 'warden lock-account svc --force' if that's wrong",
		}},
		{Time: base.Add(51 * time.Minute), Component: "watch", Action: "quarantined", Fields: map[string]any{
			"path": "/etc/sudoers.d/zz-backdoor", "kind": "added",
		}},
		{Time: base.Add(52 * time.Minute), Component: "sentinel", Action: "recreated", Fields: map[string]any{
			"registration": "main-keys", "problems": []any{"key file content changed"},
		}},
		{Time: base.Add(58 * time.Minute), Component: "react", Action: "manual-ban", Fields: map[string]any{
			"ip": "198.51.100.77", "reason": "second session during the sudoers edit",
		}},
	}

	capture, err := os.CreateTemp(t.TempDir(), "alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	oldStdout := os.Stdout
	os.Stdout = capture
	defer func() { os.Stdout = oldStdout }()
	for _, e := range entries {
		printAlert(e)
	}
	os.Stdout = oldStdout
	data, err := os.ReadFile(capture.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"198.51.100.23", "198.51.100.77", "wwwrun", "quarantined /etc/sudoers.d/zz-backdoor", "access recreated: main-keys (key file content changed)"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in %s", want, data)
		}
	}
}
