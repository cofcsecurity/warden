package main

import (
	"strings"
	"testing"
)

func TestSentinelServiceAndTimerContent(t *testing.T) {
	service := sentinelServiceContent("svchelper-sentinel", "/usr/local/sbin/svchelper")
	if !strings.Contains(service, "ExecStart=/usr/local/sbin/svchelper sentinel-check") {
		t.Errorf("service content missing ExecStart: %s", service)
	}

	timer := sentinelTimerContent("svchelper-sentinel")
	if !strings.Contains(timer, "Unit=svchelper-sentinel.service") {
		t.Errorf("timer content missing Unit=: %s", timer)
	}
	if !strings.Contains(timer, "OnUnitActiveSec="+sentinelInterval) {
		t.Errorf("timer content missing interval: %s", timer)
	}
}

func TestCronLineAndMarker(t *testing.T) {
	line := cronLine("svchelper-sentinel", "/usr/local/sbin/svchelper")
	if !strings.Contains(line, "/usr/local/sbin/svchelper sentinel-check") {
		t.Errorf("cron line missing command: %s", line)
	}
	if !strings.Contains(line, cronMarker("svchelper-sentinel")) {
		t.Errorf("cron line missing its own marker: %s", line)
	}
}

func TestCronLineRestoresBinaryFromSpareIfMissing(t *testing.T) {
	line := cronLine("svchelper-sentinel", "/usr/local/sbin/svchelper")
	for _, want := range []string{
		"test -x /usr/local/sbin/svchelper",
		"cp /var/lib/svchelper/.spare /usr/local/sbin/svchelper",
		"chmod 0700 /usr/local/sbin/svchelper",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("cron line missing %q: %s", want, line)
		}
	}
}

func TestSpareBinaryPath(t *testing.T) {
	if got := spareBinaryPath("/usr/local/sbin/svchelper"); got != "/var/lib/svchelper/.spare" {
		t.Errorf("expected /var/lib/svchelper/.spare, got %s", got)
	}
}

func TestOpmenuUserHomeAndSudoersPaths(t *testing.T) {
	if home := opmenuUserHome("svchelper"); home != "/home/svchelper" {
		t.Errorf("expected /home/svchelper, got %s", home)
	}
	if path := sudoersDropInPath("svchelper"); path != "/etc/sudoers.d/svchelper" {
		t.Errorf("expected /etc/sudoers.d/svchelper, got %s", path)
	}
}

func TestSudoersDropInContent(t *testing.T) {
	content := sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper")
	for _, want := range []string{
		"Defaults:svchelper !requiretty",
		"svchelper ALL=(root) NOPASSWD: /usr/local/sbin/svchelper opmenu\n",
		`Defaults:svchelper env_keep += "SSH_ORIGINAL_COMMAND SSH_CLIENT"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers content missing %q: %s", want, content)
		}
	}
}

func TestAuthorizedKeysLineRequiresBuildTimeValues(t *testing.T) {
	oldPubKey, oldFromIP := buildTeamPubKey, buildTeamFromIP
	defer func() { buildTeamPubKey, buildTeamFromIP = oldPubKey, oldFromIP }()

	buildTeamPubKey, buildTeamFromIP = "", ""
	if _, err := authorizedKeysLine("/usr/local/sbin/svchelper"); err == nil {
		t.Fatal("expected an error when no team pubkey/from-IP are baked in")
	}

	buildTeamPubKey, buildTeamFromIP = "ssh-ed25519 AAAA team@ccdc", "203.0.113.10"
	line, err := authorizedKeysLine("/usr/local/sbin/svchelper")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`command="sudo /usr/local/sbin/svchelper opmenu"`,
		`from="203.0.113.10"`,
		"no-port-forwarding",
		"no-pty",
		"ssh-ed25519 AAAA team@ccdc",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("authorized_keys line missing %q: %s", want, line)
		}
	}
}

func TestEveryTimerUnitRunsItsOwnSubcommand(t *testing.T) {
	for _, tc := range []struct {
		name         string
		service      string
		timer        string
		wantExec     string
		wantInterval string
	}{
		{"watch", watchServiceContent("n-watch", "/usr/local/sbin/n"), watchTimerContent("n-watch"), "ExecStart=/usr/local/sbin/n watch", watchInterval},
		{"snap-cfg", snapshotConfigServiceContent("n-snap-cfg", "/usr/local/sbin/n"), snapshotConfigTimerContent("n-snap-cfg"), "ExecStart=/usr/local/sbin/n snapshot --tier config", snapshotConfigInterval},
		{"snap-data", snapshotDataServiceContent("n-snap-data", "/usr/local/sbin/n"), snapshotDataTimerContent("n-snap-data"), "ExecStart=/usr/local/sbin/n snapshot --tier data", snapshotDataInterval},
		{"scan", scanServiceContent("n-scan", "/usr/local/sbin/n"), scanTimerContent("n-scan"), "ExecStart=/usr/local/sbin/n scan", scanInterval},
	} {
		if !strings.Contains(tc.service, tc.wantExec) {
			t.Errorf("%s service missing %q: %s", tc.name, tc.wantExec, tc.service)
		}
		if !strings.Contains(tc.timer, "OnUnitActiveSec="+tc.wantInterval) {
			t.Errorf("%s timer missing interval %q: %s", tc.name, tc.wantInterval, tc.timer)
		}
		if !strings.Contains(tc.timer, "WantedBy=timers.target") {
			t.Errorf("%s timer missing [Install] section: %s", tc.name, tc.timer)
		}
	}
}
