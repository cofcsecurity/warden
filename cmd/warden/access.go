package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"warden/internal/fsutil"
)

// The access chain is everything between "the team holds a key" and "the
// team has a root shell". Red locks us out by breaking any one link, so
// sentinel checks each link as an invariant and repairs it. Every check
// touches only Warden's own accounts, keys, drop-ins and rules; nothing
// here changes how sshd, PAM or sudo behave for any other user.

// runCommand runs an external tool. A var so tests can fake the box.
var runCommand = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return out, err
	case <-time.After(30 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return out, fmt.Errorf("%s: timed out", name)
	}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Files the account checks read and, for our own entries only, write.
var (
	passwdPath    = "/etc/passwd"
	shadowPath    = "/etc/shadow"
	shellsPath    = "/etc/shells"
	mountinfoPath = "/proc/self/mountinfo"
	sshdConfigDir = "/etc/ssh/sshd_config.d"
	sshdConfig    = "/etc/ssh/sshd_config"
)

// accessAccount is one account the team key logs in through.
type accessAccount struct {
	User       string
	Home       string
	KeysPath   string // the file our sshd drop-in pins for this user
	Sudoers    string
	SSHDDropIn string
}

// accessAccounts returns the main account and, when configured, the
// break-glass account. The two differ in account, home, key file, sudoers
// file and sshd drop-in, so no single deletion removes both.
func accessAccounts() ([]accessAccount, error) {
	user, err := opmenuUser()
	if err != nil {
		return nil, err
	}
	keys, err := authorizedKeysPath()
	if err != nil {
		return nil, err
	}
	accounts := []accessAccount{{
		User:       user,
		Home:       opmenuUserHome(user),
		KeysPath:   keys,
		Sudoers:    sudoersDropInPath(user),
		SSHDDropIn: filepath.Join(sshdConfigDir, "00-"+user+".conf"),
	}}
	if bg := cfg.BreakGlassUser; bg != "" {
		home := "/var/lib/" + bg
		// Outside /home and outside the account's own home, so wiping
		// either leaves this door intact. That needs our sshd drop-in to
		// point sshd at it; without drop-in support, use the default.
		keys := "/usr/lib/" + bg + "/keys"
		if !sshdReadsDropIns() {
			keys = home + "/.ssh/authorized_keys"
		}
		accounts = append(accounts, accessAccount{
			User:       bg,
			Home:       home,
			KeysPath:   keys,
			Sudoers:    sudoersDropInPath(bg),
			SSHDDropIn: filepath.Join(sshdConfigDir, "01-"+bg+".conf"),
		})
	}
	return accounts, nil
}

// passwdEntry is one line of /etc/passwd.
type passwdEntry struct {
	Name, UID, GID, Home, Shell string
}

func readPasswd(name string) (passwdEntry, bool, error) {
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		return passwdEntry{}, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 7 && f[0] == name {
			return passwdEntry{Name: f[0], UID: f[2], GID: f[3], Home: f[5], Shell: f[6]}, true, nil
		}
	}
	return passwdEntry{}, false, nil
}

func readShadowFields(name string) ([]string, bool, error) {
	data, err := os.ReadFile(shadowPath)
	if err != nil {
		return nil, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 8 && f[0] == name {
			return f, true, nil
		}
	}
	return nil, false, nil
}

// loginShell is the shell our accounts use. sshd runs the forced command
// through it, so it must be a real shell, never nologin.
func loginShell() string {
	for _, sh := range []string{"/bin/sh", "/usr/bin/sh", "/bin/bash"} {
		if info, err := os.Stat(sh); err == nil && info.Mode()&0o111 != 0 {
			return sh
		}
	}
	return "/bin/sh"
}

func shellListed(shell string) bool {
	data, err := os.ReadFile(shellsPath)
	if err != nil {
		return true // no /etc/shells means nothing restricts the shell
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == shell {
			return true
		}
	}
	return false
}

// accountProblems lists every reason the account cannot log in. Empty
// means healthy.
func accountProblems(a accessAccount) ([]string, error) {
	entry, ok, err := readPasswd(a.User)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []string{"account missing"}, nil
	}
	var problems []string
	if strings.HasSuffix(entry.Shell, "nologin") || strings.HasSuffix(entry.Shell, "/false") {
		problems = append(problems, "shell disabled: "+entry.Shell)
	} else if info, err := os.Stat(entry.Shell); err != nil || info.Mode()&0o111 == 0 {
		problems = append(problems, "shell not executable: "+entry.Shell)
	} else if !shellListed(entry.Shell) {
		problems = append(problems, "shell not in /etc/shells: "+entry.Shell)
	}
	if entry.Home != a.Home {
		problems = append(problems, "home changed: "+entry.Home)
	}
	fields, ok, err := readShadowFields(a.User)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if !ok && err == nil {
		// passwd can come back (watch restores it) without its shadow
		// line; pam_unix then refuses the account.
		problems = append(problems, "no shadow entry")
	}
	if ok {
		if strings.HasPrefix(fields[1], "!") {
			problems = append(problems, "account locked")
		}
		if fields[7] != "" {
			if days, err := strconv.Atoi(fields[7]); err == nil && days >= 0 && int64(days) <= time.Now().Unix()/86400 {
				problems = append(problems, "account expired")
			}
		}
	}
	return problems, nil
}

// repairAccount makes the account exist, unlocked, unexpired, with a real
// shell and its expected home. It uses the system's own account tools so
// shadow, gshadow and nscd stay consistent.
func repairAccount(a accessAccount) error {
	shell := loginShell()
	_, ok, err := readPasswd(a.User)
	if err != nil {
		return err
	}
	if !ok {
		if out, err := runCommand("useradd", "-r", "-M", "-d", a.Home, "-s", shell, a.User); err != nil {
			return fmt.Errorf("useradd %s: %w: %s", a.User, err, out)
		}
	}
	if err := ensureShadowEntry(a.User); err != nil {
		return err
	}
	// '*' is "no password, not locked": key login works, password login
	// never does. -e "" clears any expiry, -s and -d undo red's edits.
	if out, err := runCommand("usermod", "-p", "*", "-e", "", "-s", shell, "-d", a.Home, a.User); err != nil {
		return fmt.Errorf("usermod %s: %w: %s", a.User, err, out)
	}
	if !shellListed(shell) {
		f, err := os.OpenFile(shellsPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, shell)
			f.Close()
		}
	}
	return ensureRootOwnedDir(a.Home)
}

// ensureShadowEntry adds our account's shadow line if it is missing. Only
// our own line is ever written; the rest of the file is kept byte for byte,
// with its ownership and mode.
func ensureShadowEntry(user string) error {
	data, err := os.ReadFile(shadowPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, ok, _ := readShadowFields(user); ok {
		return nil
	}
	info, err := os.Stat(shadowPath)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%s:*:%d:0:99999:7:::\n", user, time.Now().Unix()/86400)
	next := append(bytes.TrimRight(data, "\n"), '\n')
	if len(bytes.TrimSpace(data)) == 0 {
		next = nil
	}
	return fsutil.WriteFile(shadowPath, append(next, line...), info.Mode().Perm())
}

// ensureRootOwnedDir keeps an account's home root-owned and not writable
// by the account, which sshd's StrictModes accepts and which stops the
// account itself from swapping out its key file.
func ensureRootOwnedDir(dir string) error {
	info, err := os.Lstat(dir)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dir); err != nil {
			return err
		}
		err = os.ErrNotExist
	}
	if err != nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(dir, 0o755)
}

// keyFileProblems checks that the key file holds exactly content and that
// sshd can actually see it (no mount shadowing it).
func keyFileProblems(a accessAccount, content string) []string {
	var problems []string
	data, err := os.ReadFile(a.KeysPath)
	if err != nil {
		problems = append(problems, "key file unreadable: "+err.Error())
	} else if string(data) != content {
		problems = append(problems, "key file content changed")
	}
	if info, err := os.Lstat(a.KeysPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		problems = append(problems, "key file is a symlink")
	}
	if m := shadowingMount(a.KeysPath); m != "" {
		problems = append(problems, "key path shadowed by mount at "+m)
	}
	return problems
}

func repairKeyFile(a accessAccount, content string) error {
	if m := shadowingMount(a.KeysPath); m != "" {
		if out, err := runCommand("umount", "-l", m); err != nil {
			return fmt.Errorf("umount %s: %w: %s", m, err, out)
		}
	}
	dir := filepath.Dir(a.KeysPath)
	for _, d := range []string{filepath.Dir(dir), dir} {
		if d == "/usr/lib" || d == "/home" || d == "/" {
			continue
		}
		if err := ensureRootOwnedDir(d); err != nil {
			return err
		}
	}
	if info, err := os.Lstat(a.KeysPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(a.KeysPath); err != nil {
			return err
		}
	}
	err := writeOwnFile(a.KeysPath, []byte(content), 0o644)
	if err != nil {
		// chattr +i is the usual way to make a deleted key stay deleted.
		_, _ = runCommand("chattr", "-i", "-a", a.KeysPath)
		_, _ = runCommand("chattr", "-i", "-a", dir)
		err = writeOwnFile(a.KeysPath, []byte(content), 0o644)
	}
	if err == nil && commandExists("restorecon") {
		// SELinux: give a recreated file and directory the labels sshd
		// expects there.
		_, _ = runCommand("restorecon", "-R", dir)
	}
	return err
}

// shadowingMount returns a mount point at or above path's directory other
// than the filesystem roots that are normally there, or "".
func shadowingMount(path string) string {
	data, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(path)
	best := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		mp := unescapeMount(f[4])
		if mp == "/" || mp == "/home" || mp == "/usr" || mp == "/var" || mp == "/usr/lib" {
			continue
		}
		if dir == mp || strings.HasPrefix(dir, mp+"/") {
			if len(mp) > len(best) {
				best = mp
			}
		}
	}
	return best
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// sshdDropIn is our Match block. It applies only to our account, so the
// effective config for every other user is unchanged. It pins the key file
// (so a global AuthorizedKeysFile change cannot hide ours), requires only a
// key, and adds our account to AllowUsers, which sshd accumulates rather
// than replaces, so it lets us in without letting anyone else in.
func sshdDropInBody(a accessAccount, minimal bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Match User %s\n", a.User)
	fmt.Fprintf(&b, "\tPubkeyAuthentication yes\n")
	fmt.Fprintf(&b, "\tAuthorizedKeysFile %s\n", a.KeysPath)
	if !minimal {
		fmt.Fprintf(&b, "\tAuthenticationMethods publickey\n")
		fmt.Fprintf(&b, "\tAllowUsers %s\n", a.User)
		fmt.Fprintf(&b, "\tPermitTTY yes\n")
	}
	return b.String()
}

// sshdReadsDropIns reports whether sshd_config includes sshd_config.d.
func sshdReadsDropIns() bool {
	data, err := os.ReadFile(sshdConfig)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "Include") {
			for _, inc := range f[1:] {
				if strings.Contains(inc, "sshd_config.d") {
					return true
				}
			}
		}
	}
	return false
}

// ensureSSHDDropIn installs our Match block if sshd reads drop-ins,
// validating with sshd -t and falling back to the minimal form. It
// returns whether sshd needs a reload.
func ensureSSHDDropIn(a accessAccount) (changed bool, err error) {
	if !sshdReadsDropIns() {
		return false, nil
	}
	for _, minimal := range []bool{false, true} {
		body := sshdDropInBody(a, minimal)
		current, _ := os.ReadFile(a.SSHDDropIn)
		if string(current) == body {
			return false, nil
		}
		if err := os.MkdirAll(sshdConfigDir, 0o755); err != nil {
			return false, err
		}
		if err := writeOwnFile(a.SSHDDropIn, []byte(body), 0o644); err != nil {
			return false, err
		}
		if !commandExists("sshd") {
			return true, nil
		}
		if _, err := runCommand(sshdBinary(), "-t"); err == nil {
			return true, nil
		}
	}
	// Neither form validates (an old sshd, or the config was already
	// broken); a drop-in that breaks sshd -t must never stay in place.
	_ = os.Remove(a.SSHDDropIn)
	return true, fmt.Errorf("sshd -t rejects our drop-in; removed it")
}

func sshdBinary() string {
	for _, p := range []string{"/usr/sbin/sshd", "/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sshd"
}

// sshdEffective asks sshd what it would apply to a login by user from addr.
func sshdEffective(user, addr string) (map[string][]string, error) {
	out, err := runCommand(sshdBinary(), "-T", "-C", fmt.Sprintf("user=%s,host=%s,addr=%s", user, "localhost", addr))
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w: %s", err, bytes.TrimSpace(out))
	}
	conf := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		key := strings.ToLower(f[0])
		conf[key] = append(conf[key], strings.Join(f[1:], " "))
	}
	return conf, nil
}

// probeAddress is an address inside the team network, used to evaluate
// Match Address blocks the way a real team login would.
func probeAddress() string {
	if cfg.AllowFrom == "" || cfg.AllowFrom == allowAny {
		return "127.0.0.1"
	}
	first := strings.TrimSpace(strings.Split(cfg.AllowFrom, ",")[0])
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	if ip, cidr, err := net.ParseCIDR(first); err == nil {
		ip = ip.Mask(cidr.Mask)
		if v4 := ip.To4(); v4 != nil {
			v4[3]++
			return v4.String()
		}
		return ip.String()
	}
	return "127.0.0.1"
}

// sshdProblems lists reasons sshd would refuse our key login.
func sshdProblems(a accessAccount) []string {
	if !commandExists(sshdBinary()) {
		return nil
	}
	conf, err := sshdEffective(a.User, probeAddress())
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	first := func(k string) string {
		if v := conf[k]; len(v) > 0 {
			return strings.ToLower(v[0])
		}
		return ""
	}
	if first("pubkeyauthentication") == "no" {
		problems = append(problems, "pubkey authentication disabled")
	}
	if m := first("authenticationmethods"); m != "" && m != "any" {
		ok := false
		for _, list := range strings.Fields(m) {
			if list == "publickey" {
				ok = true
			}
		}
		if !ok {
			problems = append(problems, "authentication methods require more than a key: "+m)
		}
	}
	files := strings.Fields(strings.Join(conf["authorizedkeysfile"], " "))
	pinned := false
	for _, f := range files {
		if expandKeysPath(f, a) == a.KeysPath {
			pinned = true
		}
	}
	if !pinned {
		problems = append(problems, "sshd does not read "+a.KeysPath+" (reads "+strings.Join(files, " ")+")")
	}
	if denied := strings.Fields(strings.Join(conf["denyusers"], " ")); matchesUser(denied, a.User) {
		problems = append(problems, "DenyUsers lists this account")
	}
	if allowed := strings.Fields(strings.Join(conf["allowusers"], " ")); len(allowed) > 0 && !matchesUser(allowed, a.User) {
		problems = append(problems, "AllowUsers excludes this account")
	}
	if fc := first("forcecommand"); fc != "" && fc != "none" {
		problems = append(problems, "a ForceCommand overrides ours: "+fc)
	}
	return problems
}

func expandKeysPath(f string, a accessAccount) string {
	f = strings.NewReplacer("%h", a.Home, "%u", a.User, "%%", "%").Replace(f)
	if !strings.HasPrefix(f, "/") {
		f = filepath.Join(a.Home, f)
	}
	return f
}

func matchesUser(patterns []string, user string) bool {
	for _, p := range patterns {
		p = strings.SplitN(p, "@", 2)[0]
		if ok, _ := filepath.Match(p, user); ok {
			return true
		}
	}
	return false
}

// sshdUnit is the installed sshd service name, which differs by distro.
func sshdUnit() string {
	for _, u := range []string{"ssh", "sshd"} {
		if unitFileExists(u) {
			return u
		}
	}
	return ""
}

// reloadSSHD applies a changed config. reload, not restart: established
// sessions, including the team's, are untouched.
func reloadSSHD() error {
	if commandExists("sshd") {
		if out, err := runCommand(sshdBinary(), "-t"); err != nil {
			return fmt.Errorf("sshd -t failed, not reloading: %s", bytes.TrimSpace(out))
		}
	}
	unit := sshdUnit()
	if unit == "" {
		return nil
	}
	if out, err := runCommand("systemctl", "reload", unit); err != nil {
		return fmt.Errorf("reload %s: %w: %s", unit, err, out)
	}
	return nil
}

// sshdServiceProblems checks that sshd is installed, not masked, and
// running.
func sshdServiceProblems() []string {
	unit := sshdUnit()
	if unit == "" {
		return nil
	}
	var problems []string
	if target, err := os.Readlink(filepath.Join(systemdUnitDir, unit+".service")); err == nil && target == "/dev/null" {
		problems = append(problems, "sshd unit masked")
	}
	if !systemdActive(unit) && !systemdActive(unit+".socket") {
		// Socket activation (Ubuntu 24.04+) leaves the service idle until
		// a connection arrives; an active socket is a running sshd.
		problems = append(problems, "sshd not running")
	}
	return problems
}

func systemdActive(unit string) bool {
	out, _ := runCommand("systemctl", "is-active", unit)
	state := strings.TrimSpace(string(out))
	return state == "active" || state == "activating" || state == "reloading"
}

func repairSSHDService() error {
	unit := sshdUnit()
	if unit == "" {
		return nil
	}
	if target, err := os.Readlink(filepath.Join(systemdUnitDir, unit+".service")); err == nil && target == "/dev/null" {
		if out, err := runCommand("systemctl", "unmask", unit); err != nil {
			return fmt.Errorf("unmask %s: %w: %s", unit, err, out)
		}
	}
	if target, err := os.Readlink(filepath.Join(systemdUnitDir, unit+".socket")); err == nil && target == "/dev/null" {
		_, _ = runCommand("systemctl", "unmask", unit+".socket")
	}
	if out, err := runCommand("systemctl", "start", unit); err != nil {
		return fmt.Errorf("start %s: %w: %s", unit, err, out)
	}
	return nil
}

// sshdPort is the port sshd listens on, for the firewall rule.
func sshdPort() string {
	if commandExists(sshdBinary()) {
		if conf, err := sshdEffective("root", probeAddress()); err == nil {
			if p := conf["port"]; len(p) > 0 {
				return p[0]
			}
		}
	}
	return "22"
}

// firewallRules returns the iptables rules that keep the team network able
// to reach sshd, first in INPUT. They only ever accept traffic from the
// team network, so they can lock nobody out.
func firewallRules() [][]string {
	if cfg.AllowFrom == "" || cfg.AllowFrom == allowAny {
		return nil
	}
	port := sshdPort()
	var rules [][]string
	for _, src := range strings.Split(cfg.AllowFrom, ",") {
		src = strings.TrimSpace(src)
		if ip := net.ParseIP(src); ip != nil && ip.To4() == nil {
			continue // iptables is v4; ip6tables is out of scope
		}
		if _, cidr, err := net.ParseCIDR(src); err == nil {
			if cidr.IP.To4() == nil {
				continue
			}
			src = cidr.String()
		} else {
			src += "/32"
		}
		rules = append(rules, []string{"-s", src, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", "ACCEPT"})
	}
	return rules
}

// firewallProblems reports whether our rules lead INPUT.
func firewallProblems() []string {
	rules := firewallRules()
	if len(rules) == 0 || !commandExists("iptables") {
		return nil
	}
	out, err := runCommand("iptables", "-w", "-S", "INPUT")
	if err != nil {
		return []string{"iptables -S failed: " + strings.TrimSpace(string(out))}
	}
	var appended []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A INPUT ") {
			appended = append(appended, strings.TrimPrefix(line, "-A INPUT "))
		}
	}
	for i, rule := range rules {
		if i >= len(appended) || appended[i] != strings.Join(rule, " ") {
			return []string{"team ssh allow rule is not first in INPUT"}
		}
	}
	return nil
}

func repairFirewall() error {
	rules := firewallRules()
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		// Drop any copies further down, then insert at the top.
		for {
			if _, err := runCommand("iptables", append([]string{"-w", "-D", "INPUT"}, rule...)...); err != nil {
				break
			}
		}
		if out, err := runCommand("iptables", append([]string{"-w", "-I", "INPUT", "1"}, rule...)...); err != nil {
			return fmt.Errorf("iptables insert: %w: %s", err, out)
		}
	}
	return nil
}

// sudoProblems checks that sudo still works at all: present, setuid, and
// its configuration valid and including sudoers.d. Flag only: sudo and
// /etc/sudoers are not Warden's to rewrite (watch restores the sudoers
// files from the baseline).
func sudoProblems() []string {
	var problems []string
	path, err := exec.LookPath("sudo")
	if err != nil {
		return []string{"sudo is missing"}
	}
	if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSetuid == 0 {
		problems = append(problems, "sudo is not setuid")
	}
	if commandExists("visudo") {
		if out, err := runCommand("visudo", "-c"); err != nil {
			problems = append(problems, "sudoers invalid: "+strings.TrimSpace(string(out)))
		}
	}
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		if !bytes.Contains(data, []byte("includedir /etc/sudoers.d")) {
			problems = append(problems, "/etc/sudoers no longer includes /etc/sudoers.d")
		}
	}
	return problems
}

// preloadProblems flags /etc/ld.so.preload. sudo is dynamically linked,
// so a preloaded library can break or hijack our access path. Flagged,
// never removed: deleting it is a judgment call for a human.
func preloadProblems() []string {
	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return []string{"/etc/ld.so.preload is set: " + strings.TrimSpace(string(data))}
}

// writeOwnFile writes one of Warden's own files atomically, refusing to
// follow a symlink red may have planted at the path.
func writeOwnFile(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
