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
		`command="/usr/local/sbin/svchelper opmenu"`,
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
