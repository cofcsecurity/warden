package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"warden/internal/audit"
	"warden/internal/manifest"
)

func TestMatchesPatternAndClassify(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/etc/passwd", "/etc/passwd", true},
		{"/etc/pam.d/*", "/etc/pam.d/sshd", true},
		{"/etc/pam.d/*", "/etc/pam.d/sub/x", false},
		{"/var/www/**", "/var/www/html/a/b.php", true},
		{"/var/www/**", "/var/www", false},
		{"/home/*/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys", true},
	} {
		if got := matchesPattern(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchesPattern(%q, %q) = %v", tc.pattern, tc.path, got)
		}
	}
	for path, want := range map[string]manifest.Class{
		"/etc/ssh/sshd_config.d/50-cloud.conf":  manifest.SafeAutoRestore,
		"/etc/sudoers.d/team":                   manifest.SafeAutoRestore,
		"/etc/cron.d/backup":                    manifest.SafeAutoRestore,
		"/etc/passwd":                           manifest.SafeAutoRestore,
		"/etc/shadow":                           manifest.ConfirmFirst,
		"/etc/ufw/user.rules":                   manifest.ConfirmFirst,
		"/etc/systemd/system/evil.service":      manifest.ConfirmFirst,
		"/etc/systemd/system/x.service.d/o.cnf": manifest.ConfirmFirst,
		"/home/bob/.ssh/authorized_keys":        manifest.ConfirmFirst,
		"/var/spool/cron/crontabs/bob":          manifest.ConfirmFirst,
	} {
		if got := classifyPath(path); got != want {
			t.Errorf("classifyPath(%s) = %s, want %s", path, got, want)
		}
	}
	// New files may be quarantined only from auto-restore directories.
	for path, want := range map[string]bool{
		"/etc/sudoers.d/zz":                   true,
		"/etc/ssh/sshd_config.d/00-evil.conf": true,
		"/etc/pam.d/evil":                     true,
		"/etc/systemd/system/evil.service":    false,
		"/etc/nginx/nginx.conf":               false,
		"/home/bob/.ssh/authorized_keys":      false,
	} {
		if got := quarantinable(path); got != want {
			t.Errorf("quarantinable(%s) = %v, want %v", path, got, want)
		}
	}
}

func TestExpandPatternsSkipsDirsBigFilesAndOwnFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "d", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{"d/a": 3, "d/b": 3, "d/sub/c": 3, "d/big": 100} {
		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("x"), size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := expandPatterns([]string{dir + "/d/*"}, 0)
	if len(got) != 3 { // a, b, big; never the sub directory
		t.Fatalf("glob expansion = %v", got)
	}
	got = expandPatterns([]string{dir + "/d/**"}, 10)
	if len(got) != 3 { // a, b, sub/c; big is over the cap
		t.Fatalf("tree expansion = %v", got)
	}

	name, _ := binaryName()
	own := ownFiles()
	for _, path := range []string{
		"/etc/sudoers.d/" + name,
		"/home/" + name + "/.ssh/authorized_keys",
		"/var/lib/" + name + "/manifest-config.json",
		systemdUnitDir + "/" + name + "-refresh.timer",
		systemdUnitDir + "/ssh.service.d/" + name + ".conf",
	} {
		if !own(path) {
			t.Errorf("%s should count as Warden's own file", path)
		}
	}
	if own("/etc/sudoers.d/team") || own("/home/bob/.ssh/authorized_keys") {
		t.Error("other files must not count as Warden's own")
	}
}

func TestWatchPassIncludesDeletedBaselinedFiles(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := configTierPaths
	configTierPaths = []string{dir + "/*"}
	t.Cleanup(func() { configTierPaths = old })
	baseline := &manifest.Manifest{Records: []manifest.Record{{Path: keep}, {Path: filepath.Join(dir, "deleted")}, {Path: "/elsewhere/unwatched"}}}
	got := watchPassPaths(baseline)
	if len(got) != 2 || got[1] != filepath.Join(dir, "deleted") {
		t.Fatalf("watch pass paths = %v", got)
	}
}

func TestQuarantineFileKeepsACopy(t *testing.T) {
	dir := t.TempDir()
	p := paths{dataDir: dir, quarantineDir: filepath.Join(dir, "quarantine")}
	log, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	victim := filepath.Join(dir, "zz-backdoor")
	if err := os.WriteFile(victim, []byte("red ALL=(ALL) NOPASSWD: ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := quarantineFile(p, victim, log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("quarantined file still in place")
	}
	entries, _ := os.ReadDir(p.quarantineDir)
	if len(entries) != 1 {
		t.Fatalf("expected one quarantined copy, got %v", entries)
	}
	data, _ := os.ReadFile(filepath.Join(p.quarantineDir, entries[0].Name()))
	if !strings.Contains(string(data), "NOPASSWD") {
		t.Fatal("quarantine copy lost the content")
	}
}

func TestNewlyFlaggedReactsOncePerChange(t *testing.T) {
	p := paths{dataDir: t.TempDir()}
	change := manifest.Change{Path: "/etc/shadow", Kind: manifest.Modified, New: &manifest.Record{Hash: "a"}}
	if len(newlyFlagged(p, []manifest.Change{change})) != 1 {
		t.Fatal("first sighting must react")
	}
	if len(newlyFlagged(p, []manifest.Change{change})) != 0 {
		t.Fatal("the same drift must not react again")
	}
	change.New = &manifest.Record{Hash: "b"}
	if len(newlyFlagged(p, []manifest.Change{change})) != 1 {
		t.Fatal("a new change to the same path must react")
	}
}

func TestRuntimeConfigValidationAndMirrorFallback(t *testing.T) {
	withConfig(t)
	dir := t.TempDir()
	p := paths{dataDir: filepath.Join(dir, "state"), mirrorDir: filepath.Join(dir, "mirror")}
	good := runtimeConfig{TeamKey: testKey(t, "team"), AllowFrom: "10.0.0.0/24,192.0.2.7", Ban: modeFlag, Lock: modeAct, SafeAccounts: []string{"scorer"}}
	if err := saveRuntimeConfig(p, good); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.configPath(), p.configMirrorPath()} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v", path, err)
		}
	}

	// A wiped state directory must not lose the key.
	if err := os.RemoveAll(p.dataDir); err != nil {
		t.Fatal(err)
	}
	cfg = defaultRuntimeConfig()
	if err := loadRuntimeConfig(p); err != nil {
		t.Fatal(err)
	}
	if cfg.TeamKey != good.TeamKey || cfg.Lock != modeAct {
		t.Fatalf("mirror not used: %+v", cfg)
	}

	for _, bad := range []runtimeConfig{
		{Ban: "maybe", Lock: modeFlag},
		{Ban: modeFlag, Lock: modeFlag, AllowFrom: "example.com"},
		{Ban: modeFlag, Lock: modeFlag, TeamKey: "not a key"},
		{Ban: modeFlag, Lock: modeFlag, TeamKey: `command="x" ` + testKey(t, "t")},
		{Ban: modeFlag, Lock: modeFlag, SafeAccounts: []string{"-rf"}},
		{Ban: modeFlag, Lock: modeFlag, Sources: []sourceConfig{{Name: "../x", Key: testKey(t, "s")}}},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := parseRuntimeConfig([]byte(`{"team_key":"","ban":"flag","lock":"flag","surprise":1}`)); err == nil {
		t.Error("unknown fields must be rejected")
	}
}

func TestTeamNetworkContains(t *testing.T) {
	withConfig(t)
	cfg.AllowFrom = "203.0.113.0/24,198.51.100.7"
	for ip, want := range map[string]bool{"203.0.113.9": true, "198.51.100.7": true, "198.51.100.8": false, "bogus": false} {
		if got := teamNetworkContains(ip); got != want {
			t.Errorf("teamNetworkContains(%s) = %v", ip, got)
		}
	}
	cfg.AllowFrom = allowAny
	if teamNetworkContains("203.0.113.9") {
		t.Error("with no network restriction nothing is the team network")
	}
}

// pairFixture is a box with config paths in a temp dir and repairAccess
// stubbed out, so pairing never touches the real system.
func pairFixture(t *testing.T) paths {
	t.Helper()
	withConfig(t)
	dir := t.TempDir()
	p := paths{dataDir: filepath.Join(dir, "state"), mirrorDir: filepath.Join(dir, "mirror"), peerKeyPath: filepath.Join(dir, "state", "peer_key"), auditLogPath: filepath.Join(dir, "audit.log"), storeRoot: filepath.Join(dir, "state")}
	cfg = runtimeConfig{TeamKey: testKey(t, "team"), AllowFrom: "10.0.0.0/24", Ban: modeFlag, Lock: modeFlag}
	old := repairAccess
	repairAccess = func(paths) error { return nil }
	t.Cleanup(func() { repairAccess = old })
	hostKey := filepath.Join(dir, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(hostKey, []byte(testKey(t, "root@peer")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldHost := hostKeyPaths
	hostKeyPaths = []string{hostKey}
	t.Cleanup(func() { hostKeyPaths = oldHost })
	return p
}

func TestPairKeyAcceptAdd(t *testing.T) {
	p := pairFixture(t)
	signer, err := ensurePeerKey(p)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ensurePeerKey(p)
	if err != nil || string(again.PublicKey().Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("the backup key must be generated once and reused")
	}
	if info, err := os.Stat(p.peerKeyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("the private key must be root-only")
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	// On the peer: accept, and get back what the source needs.
	spec, err := runPairAccept(p, "boxA", pub+" comment", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(spec)
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "ssh+receiver://") || !strings.Contains(fields[0], "@10.0.0.2/boxA") {
		t.Fatalf("unexpected accept output %q", spec)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Name != "boxA" {
		t.Fatalf("source not recorded: %+v", cfg.Sources)
	}
	// Re-pairing a rebuilt source replaces its key, keeps one entry.
	if _, err := runPairAccept(p, "boxA", testKey(t, "rebuilt"), "10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Key == pub {
		t.Fatalf("re-pair must replace the old key: %+v", cfg.Sources)
	}
	if _, err := runPairAccept(p, "boxB", cfg.TeamKey, "10.0.0.2"); err == nil {
		t.Fatal("the team key must not be accepted as a box key")
	}
	if _, err := runPairAccept(p, "../evil", pub, "10.0.0.2"); err == nil {
		t.Fatal("unsafe source names must be refused")
	}

	// On the source: add the peer from that output.
	if err := runPairAdd(p, fields[0], fields[1]+" "+fields[2]); err != nil {
		t.Fatal(err)
	}
	if err := runPairAdd(p, fields[0], fields[1]+" "+fields[2]); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].HostKey == "" {
		t.Fatalf("peer not recorded once with its host key: %+v", cfg.Peers)
	}
	if err := runPairAdd(p, "http://x", ""); err == nil {
		t.Fatal("non-receiver URLs must be refused")
	}
	data, err := os.ReadFile(p.configMirrorPath())
	if err != nil || !strings.Contains(string(data), "ssh+receiver://") {
		t.Fatal("pairing must persist to both config copies")
	}
}

func TestOpmenuAllowsWardenCommandsOnly(t *testing.T) {
	for name, want := range map[string]bool{"status": true, "arm": true, "restore": true, "pair": true, "help": true, "opmenu": false, "receive": false, "rm": false, "bash": false} {
		if got := opmenuAllowed(name); got != want {
			t.Errorf("opmenuAllowed(%q) = %v", name, got)
		}
	}
}

func TestResolveTeamKey(t *testing.T) {
	key := testKey(t, "team")
	if got, err := resolveTeamKey(key); err != nil || got != key {
		t.Fatalf("literal key: %q %v", got, err)
	}
	file := filepath.Join(t.TempDir(), "team.pub")
	if err := os.WriteFile(file, []byte("# team key\n\n"+key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveTeamKey("@" + file); err != nil || got != key {
		t.Fatalf("@file: %q %v", got, err)
	}
	for _, bad := range []string{"http://example.com/team.pub", "not a key", "@" + filepath.Join(t.TempDir(), "missing")} {
		if _, err := resolveTeamKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSuggestedTeamNetworkUsesTheSSHClient(t *testing.T) {
	t.Setenv("SSH_CLIENT", "10.20.30.44 51000 22")
	if got := suggestedTeamNetwork(); got != "10.20.30.0/24" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("SSH_CLIENT", "")
	if got := suggestedTeamNetwork(); got != "" {
		t.Fatalf("no client should mean no suggestion, got %q", got)
	}
}

func TestChooseNameAvoids(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		a, err := chooseName("")
		if err != nil {
			t.Fatal(err)
		}
		b, err := chooseName(a)
		if err != nil || a == b || !validAccountName(a) {
			t.Fatalf("bad names %q %q %v", a, b, err)
		}
		seen[a] = true
	}
	if len(seen) < 2 {
		t.Fatal("names must vary between installs")
	}
}

func TestAbbreviateKeyHidesNothingSecretButShortens(t *testing.T) {
	got := abbreviateKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABCDEFGHIJKLMNOP team")
	if !strings.HasPrefix(got, "ssh-ed25519 AAAAC3Nz...") || !strings.HasSuffix(got, " team") {
		t.Fatalf("got %q", got)
	}
}

// fakeBox points the account files at temp copies.
func fakeBox(t *testing.T, passwd, shadow, mounts string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	oldP, oldS, oldShells, oldM := passwdPath, shadowPath, shellsPath, mountinfoPath
	passwdPath, shadowPath = write("passwd", passwd), write("shadow", shadow)
	shellsPath, mountinfoPath = write("shells", "/bin/sh\n/bin/bash\n"), write("mountinfo", mounts)
	t.Cleanup(func() { passwdPath, shadowPath, shellsPath, mountinfoPath = oldP, oldS, oldShells, oldM })
}

func TestAccountProblemsCatchesEveryLockoutMove(t *testing.T) {
	a := accessAccount{User: "netmgr", Home: "/home/netmgr"}
	future := time.Now().Unix()/86400 + 30
	past := time.Now().Unix()/86400 - 1
	for _, tc := range []struct {
		name, passwd, shadow, want string
	}{
		{"healthy", "netmgr:x:999:999::/home/netmgr:/bin/sh\n", "netmgr:*:19000:0:99999:7:::\n", ""},
		{"deleted", "root:x:0:0::/root:/bin/bash\n", "", "account missing"},
		{"nologin", "netmgr:x:999:999::/home/netmgr:/usr/sbin/nologin\n", "netmgr:*:19000::::::\n", "shell disabled"},
		{"locked", "netmgr:x:999:999::/home/netmgr:/bin/sh\n", "netmgr:!*:19000::::::\n", "account locked"},
		{"expired", "netmgr:x:999:999::/home/netmgr:/bin/sh\n", "netmgr:*:19000:0:99999:7::" + itoa(past) + ":\n", "account expired"},
		{"not yet expired", "netmgr:x:999:999::/home/netmgr:/bin/sh\n", "netmgr:*:19000:0:99999:7::" + itoa(future) + ":\n", ""},
		{"home moved", "netmgr:x:999:999::/tmp:/bin/sh\n", "netmgr:*:19000::::::\n", "home changed"},
		{"passwd restored without shadow", "netmgr:x:999:999::/home/netmgr:/bin/sh\n", "root:*:19000::::::\n", "no shadow entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeBox(t, tc.passwd, tc.shadow, "")
			problems, err := accountProblems(a)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(problems, "; ")
			if tc.want == "" && len(problems) > 0 || tc.want != "" && !strings.Contains(joined, tc.want) {
				t.Fatalf("problems = %q, want %q", joined, tc.want)
			}
		})
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestKeyFileProblems(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "home", ".ssh", "authorized_keys")
	a := accessAccount{User: "netmgr", Home: filepath.Join(dir, "home"), KeysPath: keys}
	fakeBox(t, "", "", "")
	if len(keyFileProblems(a, "line\n")) == 0 {
		t.Fatal("a missing key file is a problem")
	}
	fakeCommands(t)
	if err := repairKeyFile(a, "line\n"); err != nil {
		t.Fatal(err)
	}
	if problems := keyFileProblems(a, "line\n"); len(problems) != 0 {
		t.Fatalf("repaired file still has problems: %v", problems)
	}

	// A symlink planted at the key path must be replaced, never written through.
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(keys)
	if err := os.Symlink(target, keys); err != nil {
		t.Fatal(err)
	}
	if len(keyFileProblems(a, "line\n")) == 0 {
		t.Fatal("a symlinked key file is a problem")
	}
	if err := repairKeyFile(a, "line\n"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "precious\n" {
		t.Fatal("repair wrote through a symlink")
	}

	// A bind mount over the .ssh directory hides the real file from sshd.
	mounts := "36 25 0:32 / " + filepath.Dir(keys) + " rw,relatime shared:1 - tmpfs tmpfs rw\n"
	fakeBox(t, "", "", mounts)
	if m := shadowingMount(keys); m != filepath.Dir(keys) {
		t.Fatalf("shadowingMount = %q", m)
	}
}

// sshdConfigFixture fakes `sshd -T` with the given effective config.
func sshdConfigFixture(t *testing.T, effective string) *[]string {
	t.Helper()
	calls := fakeCommands(t)
	runCommand = func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
		if len(args) > 0 && args[0] == "-T" {
			return []byte(effective), nil
		}
		return nil, nil
	}
	return calls
}

func TestSSHDProblems(t *testing.T) {
	if !commandExists(sshdBinary()) {
		t.Skip("sshd not installed here; sshdProblems only runs where sshd exists")
	}
	withConfig(t)
	cfg.AllowFrom = "10.0.0.0/24"
	a := accessAccount{User: "netmgr", Home: "/home/netmgr", KeysPath: "/home/netmgr/.ssh/authorized_keys"}
	healthy := "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nauthenticationmethods any\nport 22\n"
	sshdConfigFixture(t, healthy)
	if p := sshdProblems(a); len(p) != 0 {
		t.Fatalf("healthy config reported %v", p)
	}
	for effective, want := range map[string]string{
		"pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n":                                            "pubkey",
		"pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n":                                               "does not read",
		"pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\ndenyusers netmgr\n":                         "DenyUsers",
		"pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nallowusers alice bob\n":                     "AllowUsers",
		"pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nforcecommand /bin/false":                    "ForceCommand",
		"pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nauthenticationmethods publickey,password\n": "more than a key",
	} {
		sshdConfigFixture(t, effective)
		if p := strings.Join(sshdProblems(a), "; "); !strings.Contains(p, want) {
			t.Errorf("%q: problems %q, want %q", effective, p, want)
		}
	}
}

func TestSSHDDropInIsScopedToOurAccount(t *testing.T) {
	a := accessAccount{User: "netmgr", KeysPath: "/home/netmgr/.ssh/authorized_keys"}
	body := sshdDropInBody(a, false)
	if !strings.HasPrefix(body, "Match User netmgr\n") {
		t.Fatalf("every setting must sit inside our Match block: %s", body)
	}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n")[1:] {
		if !strings.HasPrefix(line, "\t") {
			t.Fatalf("setting outside the Match block: %q", line)
		}
	}
	for _, want := range []string{"AuthorizedKeysFile /home/netmgr/.ssh/authorized_keys", "AllowUsers netmgr", "PubkeyAuthentication yes"} {
		if !strings.Contains(body, want) {
			t.Errorf("drop-in missing %q", want)
		}
	}
}

func TestEnsureSSHDDropInRemovesAnInvalidOne(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldConf := sshdConfigDir, sshdConfig
	sshdConfigDir, sshdConfig = filepath.Join(dir, "sshd_config.d"), filepath.Join(dir, "sshd_config")
	t.Cleanup(func() { sshdConfigDir, sshdConfig = oldDir, oldConf })
	if err := os.WriteFile(sshdConfig, []byte("Include "+sshdConfigDir+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := accessAccount{User: "netmgr", KeysPath: "/k", SSHDDropIn: filepath.Join(sshdConfigDir, "00-netmgr.conf")}
	calls := fakeCommands(t)
	if !commandExists("sshd") {
		changed, err := ensureSSHDDropIn(a)
		if err != nil || !changed || !sshdDropInPresent(a) {
			t.Fatalf("drop-in not written: %v %v", changed, err)
		}
		return
	}
	runCommand = func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, name)
		return []byte("bad option"), errors.New("exit 255")
	}
	if _, err := ensureSSHDDropIn(a); err == nil {
		t.Fatal("expected a failure when sshd -t rejects every form")
	}
	if _, err := os.Stat(a.SSHDDropIn); !os.IsNotExist(err) {
		t.Fatal("a drop-in that breaks sshd -t must be removed")
	}
}

func TestFirewallRuleMustLeadInput(t *testing.T) {
	if !commandExists("iptables") {
		t.Skip("iptables not installed here")
	}
	withConfig(t)
	cfg.AllowFrom = "10.0.0.0/24"
	fakeCommands(t)
	runCommand = func(name string, args ...string) ([]byte, error) {
		if name == "iptables" && len(args) > 1 && args[1] == "-S" {
			return []byte("-P INPUT ACCEPT\n-A INPUT -s 203.0.113.9/32 -j DROP\n-A INPUT -s 10.0.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT\n"), nil
		}
		return nil, nil
	}
	if len(firewallProblems()) == 0 {
		t.Fatal("a DROP above our allow rule must be a problem")
	}
}

func TestMatchNamesUser(t *testing.T) {
	for text, want := range map[string]bool{
		"Match User netmgr\n\tPubkeyAuthentication no\n": true,
		"match user alice,net*\n":                        true,
		"Match Address 10.0.0.0/8 User netmgr\n":         true,
		"Match User alice\n":                             false,
		"Match User !netmgr\n":                           false,
		"# Match User netmgr\n":                          false,
	} {
		if got := matchNamesUser(text, "netmgr"); got != want {
			t.Errorf("matchNamesUser(%q) = %v", text, got)
		}
	}
}

func TestEnsureShadowEntryAddsOnlyOurLine(t *testing.T) {
	fakeBox(t, "", "root:$6$abc:19000:0:99999:7:::\nalice:$6$def:19000:0:99999:7:::\n", "")
	if err := ensureShadowEntry("netmgr"); err != nil {
		t.Fatal(err)
	}
	if err := ensureShadowEntry("netmgr"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(shadowPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "root:$6$abc") || !strings.HasPrefix(lines[2], "netmgr:*:") {
		t.Fatalf("unexpected shadow:\n%s", data)
	}
}
