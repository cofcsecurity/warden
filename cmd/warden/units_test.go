package main

import (
	"strings"
	"testing"
)

func TestOneshotServiceAndTimerContent(t *testing.T) {
	service := oneshotServiceContent("svchelper-refresh", "/usr/local/sbin/svchelper", "sentinel-check")
	for _, want := range []string{"ExecStart=/usr/local/sbin/svchelper sentinel-check --quiet", "StartLimitIntervalSec=0"} {
		if !strings.Contains(service, want) {
			t.Errorf("service content missing %q: %s", want, service)
		}
	}
	timer := oneshotTimerContent("svchelper-refresh", "30s", sentinelInterval, sentinelJitter)
	for _, want := range []string{"Unit=svchelper-refresh.service", "OnUnitActiveSec=" + sentinelInterval, "WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer content missing %q: %s", want, timer)
		}
	}
}

func TestUnitNamesDoNotNameTheTool(t *testing.T) {
	for _, suffix := range []string{sentinelSuffix, watchSuffix, snapshotConfigSuffix, snapshotDataSuffix, scanSuffix, replicateSuffix} {
		for _, word := range []string{"warden", "sentinel", "snapshot", "replicate"} {
			if strings.Contains(suffix, word) {
				t.Errorf("unit suffix %q gives away %q", suffix, word)
			}
		}
	}
}

func TestPathUnitWatchesEveryFile(t *testing.T) {
	content := pathUnitContent("svchelper-refresh", []string{"/home/svchelper/.ssh/authorized_keys", "/etc/sudoers.d"})
	for _, want := range []string{"PathChanged=/home/svchelper/.ssh/authorized_keys", "PathChanged=/etc/sudoers.d", "Unit=svchelper-refresh.service", "WantedBy=paths.target"} {
		if !strings.Contains(content, want) {
			t.Errorf("path unit missing %q: %s", want, content)
		}
	}
}

// The sshd hook must never be able to block or fail sshd's start.
func TestSSHDHookIsFailOpenAndNonBlocking(t *testing.T) {
	content := sshdDropInContent("/usr/bin/systemctl", "svchelper-refresh")
	if !strings.Contains(content, "ExecStartPre=-/usr/bin/systemctl start --no-block svchelper-refresh.service") {
		t.Fatalf("hook must be '-' prefixed and --no-block: %s", content)
	}
	if strings.Contains(content, "ExecStart=") || strings.Contains(content, "ExecReload") {
		t.Fatalf("hook must not touch sshd's own commands: %s", content)
	}
}

func TestCronLinesRestoreBinaryFromSpares(t *testing.T) {
	line := cronLine("svchelper-refresh", "/usr/local/sbin/svchelper")
	for _, want := range []string{
		"test -x /usr/local/sbin/svchelper",
		"cp /var/lib/svchelper/.spare /usr/local/sbin/svchelper",
		"/usr/local/sbin/svchelper sentinel-check",
		cronMarker("svchelper-refresh"),
	} {
		if !strings.Contains(line, want) {
			t.Errorf("cron line missing %q: %s", want, line)
		}
	}
	d := cronDContent("pcimonitor-refresh", "/usr/local/sbin/svchelper", "/usr/lib/svchelper/svchelper")
	for _, want := range []string{" root test -x /usr/local/sbin/svchelper", "cp /usr/lib/svchelper/svchelper /usr/local/sbin/svchelper"} {
		if !strings.Contains(d, want) {
			t.Errorf("cron.d content missing %q: %s", want, d)
		}
	}
}

func TestSudoersDropInContent(t *testing.T) {
	content := sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper", false)
	for _, want := range []string{
		"Defaults:svchelper !requiretty",
		"svchelper ALL=(root) NOPASSWD: /usr/local/sbin/svchelper opmenu\n",
		`env_keep += "SSH_ORIGINAL_COMMAND SSH_CLIENT SSH_CONNECTION TERM"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("sudoers content missing %q: %s", want, content)
		}
	}
	if !strings.Contains(sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper", true), "/usr/local/sbin/svchelper receive --source *") {
		t.Error("a box with paired sources must allow receive")
	}
}

func TestTeamKeyLine(t *testing.T) {
	withConfig(t)
	cfg.TeamKey, cfg.AllowFrom = "", ""
	if _, err := teamKeyLine("/usr/local/sbin/svchelper"); err == nil {
		t.Fatal("expected an error with no team key configured")
	}

	cfg.TeamKey, cfg.AllowFrom = "ssh-ed25519 AAAA team", "203.0.113.0/24,198.51.100.7"
	line, err := teamKeyLine("/usr/local/sbin/svchelper")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`command="sudo /usr/local/sbin/svchelper opmenu"`,
		`from="203.0.113.0/24,198.51.100.7"`,
		"no-port-forwarding",
		"ssh-ed25519 AAAA team",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("key line missing %q: %s", want, line)
		}
	}
	if strings.Contains(line, "no-pty") {
		t.Error("the team key must allow a pty so ssh -t gives a usable shell")
	}

	cfg.AllowFrom = allowAny
	line, _ = teamKeyLine("/usr/local/sbin/svchelper")
	if strings.Contains(line, "from=") {
		t.Errorf("allow_from any must drop the from= restriction: %s", line)
	}
}

func TestReceiveKeyLineIsUploadOnly(t *testing.T) {
	line := receiveKeyLine("/usr/local/sbin/svchelper", sourceConfig{Name: "boxA", Key: "ssh-ed25519 AAAA boxA"})
	for _, want := range []string{`command="sudo /usr/local/sbin/svchelper receive --source boxA"`, "no-pty", "no-port-forwarding"} {
		if !strings.Contains(line, want) {
			t.Errorf("receive line missing %q: %s", want, line)
		}
	}
}

func TestAuthorizedKeysContentIncludesPairedSources(t *testing.T) {
	withConfig(t)
	cfg.TeamKey = "ssh-ed25519 AAAA team"
	cfg.Sources = []sourceConfig{{Name: "boxA", Key: "ssh-ed25519 BBBB boxA"}}
	content, err := authorizedKeysContent("/usr/local/sbin/svchelper")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "opmenu") || !strings.Contains(lines[1], "receive --source boxA") {
		t.Fatalf("unexpected content:\n%s", content)
	}
}
