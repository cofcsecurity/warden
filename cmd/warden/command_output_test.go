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
	"warden/internal/heartbeat"
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
		staticSecretPath:   filepath.Join(dir, "second-factor"),
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
	if err := os.WriteFile(p.staticSecretPath, []byte("correct-horse-battery-staple\n"), 0o600); err != nil {
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

	out, err := runStatus(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"armed: yes", "manifest generation: 12", "last anomaly scan:", "last replication:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
}

func TestCommandOutputFleet(t *testing.T) {
	now := time.Now()
	p := docFixture(t, now)
	docAuditLog(t, p, now)

	receive := filepath.Join(t.TempDir(), "warden-backup")
	writeDocBeat(t, receive, "box2", now.Add(-4*time.Minute), true, 9, 1, 0, map[string]time.Duration{
		"watch": 2 * time.Minute, "sentinel": 5 * time.Minute, "scan": 9 * time.Minute, "replicate": 4 * time.Minute,
	})
	writeDocBeat(t, receive, "box6", now.Add(-3*time.Hour), true, 5, 0, 2, map[string]time.Duration{
		"watch": 3 * time.Hour,
	})

	var out bytes.Buffer
	if err := runFleet(&out, p, receive, now); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"box2", "box6", "OVERDUE", "1 peer(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func writeDocBeat(t *testing.T, receive, host string, at time.Time, armed bool, gen, bans, locks int, last map[string]time.Duration) {
	t.Helper()
	dir := filepath.Join(receive, "from-"+host, "heartbeat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lastPass := map[string]time.Time{}
	for component, ago := range last {
		lastPass[component] = at.Add(-ago).UTC()
	}
	data, err := heartbeat.Encode(heartbeat.Beat{
		Host: host, WrittenAt: at.UTC(), IntervalSeconds: 900,
		Armed: armed, Generation: gen, LastPass: lastPass,
		ActiveBans: bans, ActiveLocks: locks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, host+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCommandOutputArm(t *testing.T) {
	now := time.Now()
	p := docFixture(t, now)

	oldIP, oldTargets, oldTOTP, oldBan := buildTeamFromIP, buildReplicateTargets, buildTOTPSecret, buildAutobanEnabled
	defer func() {
		buildTeamFromIP, buildReplicateTargets, buildTOTPSecret, buildAutobanEnabled = oldIP, oldTargets, oldTOTP, oldBan
	}()
	buildTeamFromIP = "203.0.113.0/24"
	buildTOTPSecret = "JBSWY3DPEHPK3PXP"
	buildAutobanEnabled = "1"
	buildReplicateTargets = "ssh://warden-backup@box2/home/warden-backup/from-box1||key;;ssh://warden-backup@box6/home/warden-backup/from-box1||key"

	fixtureDir := t.TempDir()
	oldPaths, oldConfirm := configTierPaths, confirmFirstPaths
	defer func() { configTierPaths, confirmFirstPaths = oldPaths, oldConfirm }()
	var fixture []string
	confirm := map[string]bool{}
	for i := 0; i < 23; i++ {
		f := filepath.Join(fixtureDir, fmt.Sprintf("conf-%02d", i))
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		fixture = append(fixture, f)
		if i < 3 {
			confirm[f] = true
		}
	}
	configTierPaths, confirmFirstPaths = fixture, confirm

	var out bytes.Buffer
	printArmConfig(&out, p)

	cf := &manifest.Record{Class: manifest.ConfirmFirst}
	sa := &manifest.Record{Class: manifest.SafeAutoRestore}
	review := armReview{
		BaselineAt: now.Add(-47 * time.Minute),
		Generation: 1,
		Changes: []manifest.Change{
			{Kind: manifest.Modified, Path: "/etc/ssh/sshd_config", Old: sa, New: sa},
			{Kind: manifest.Modified, Path: "/etc/nginx/nginx.conf", Old: sa, New: sa},
			{Kind: manifest.Modified, Path: "/etc/shadow", Old: cf, New: cf},
			{Kind: manifest.Added, Path: "/etc/redis/redis.conf", New: sa},
		},
	}
	printArmReview(&out, review, now)
	if err := confirmArm(strings.NewReader("y\n"), len(review.Changes)); err != nil {
		t.Fatal(err)
	}
	printArmReview(&out, armReview{BaselineAt: now.Add(-4 * time.Minute), Generation: 12}, now)
	for _, want := range []string{"23 config-tier", "/etc/shadow", "/etc/nginx/nginx.conf", "generation 12"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
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
		{Time: base.Add(51 * time.Minute), Component: "react", Action: "alert", Fields: map[string]any{
			"source": "heartbeat", "peer": "box6",
			"description": "no heartbeat from box6 in 52m0s — that box may be down, cut off, or have had its timers killed",
			"last_seen":   "2026-09-21T13:02:44Z",
		}},
		{Time: base.Add(58 * time.Minute), Component: "react", Action: "manual-ban", Fields: map[string]any{
			"ip": "198.51.100.77", "reason": "second session during the sudoers edit",
		}},
		{Time: base.Add(94 * time.Minute), Component: "react", Action: "peer-returned", Fields: map[string]any{
			"source": "heartbeat", "peer": "box6",
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
	for _, want := range []string{"198.51.100.23", "198.51.100.77", "box6", "wwwrun"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in %s", want, data)
		}
	}
}
