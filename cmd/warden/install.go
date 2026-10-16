package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// installCmd puts Warden on the box it runs on. Its only required input is
// the team's SSH public key; everything else (names, the box's own
// backup key, units, accounts) is generated here, so nothing is prepared
// on a laptop and nothing secret is ever in the repository or binary.
func installCmd() *cobra.Command {
	var o installOptions
	cmd := &cobra.Command{
		Use:   "install --key <team-public-key | @file | https://url>",
		Short: "Install Warden on this box (run as root from a fresh clone)",
		Long: `Installs this binary under an inconspicuous name, creates the access
account (and a break-glass account), installs the team key, every trigger
and timer, and takes the first snapshots. Auto-restore stays off until
you run 'arm'.

The only input is the team's SSH public key. Make it once on any laptop
with the ssh-keygen that ships with it:

  ssh-keygen -t ed25519 -f team -C team

and give 'team.pub' here (pasted, @path, or an https URL).

Access is limited to the team network. It defaults to the /24 of the SSH
client you are installing from; --from takes addresses or CIDRs
(comma-separated), or "any" for key-only.

Running install again on an installed box updates it in place (new
binary, key or network) instead of adding a second copy.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(o, os.Stdin, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&o.key, "key", "", "team SSH public key, @file, or https:// URL (required on first install)")
	cmd.Flags().StringVar(&o.from, "from", "", `team network: addresses/CIDRs, comma-separated, or "any"`)
	cmd.Flags().StringVar(&o.name, "name", "", "name to install under (default: chosen to blend in)")
	cmd.Flags().BoolVar(&o.noBreakGlass, "no-break-glass", false, "skip the second, independent access account")
	cmd.Flags().BoolVarP(&o.yes, "yes", "y", false, "do not ask; accept defaults")
	cmd.Flags().StringVar(&o.ban, "ban", "", "IP ban response: off, flag or act (default flag)")
	cmd.Flags().StringVar(&o.lock, "lock", "", "account lock response: off, flag or act (default flag)")
	cmd.Flags().StringSliceVar(&o.safeAccounts, "safe-accounts", nil, "accounts never locked (team and scoring accounts)")
	return cmd
}

type installOptions struct {
	key, from, name, ban, lock string
	noBreakGlass, yes          bool
	safeAccounts               []string
}

// Name parts combine into a few hundred plausible service names. Obscurity
// is a speed bump, not the defense; redundancy and repair speed are.
var (
	namePrefixes = []string{"net", "sys", "log", "disk", "mem", "pkg", "ssl", "dns", "ntp", "udev", "acpi", "irq", "pci", "usb", "mount", "fsck", "swap", "kern", "proc", "power"}
	nameSuffixes = []string{"mgr", "helper", "agent", "sync", "relay", "proxy", "check", "monitor", "collector", "reporter", "handler", "probe"}
)

const installDir = "/usr/local/sbin"

func runInstall(o installOptions, in io.Reader, w io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("install: Linux only for now")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install: run as root")
	}
	reader := bufio.NewReader(in)

	existing := findExistingInstall()
	name := o.name
	if existing != "" {
		if name != "" && name != existing {
			return fmt.Errorf("install: already installed here as %q; re-run without --name to update it", existing)
		}
		name = existing
		fmt.Fprintf(w, "==> Updating the existing install (%s)\n", name)
	}

	next := defaultRuntimeConfig()
	if existing != "" {
		p := pathsForName(existing)
		if data, err := os.ReadFile(p.configPath()); err == nil {
			if c, err := parseRuntimeConfig(data); err == nil {
				next = c
			}
		}
	}

	if o.key != "" {
		key, err := resolveTeamKey(o.key)
		if err != nil {
			return err
		}
		next.TeamKey = key
	}
	if next.TeamKey == "" {
		return fmt.Errorf("install: --key is required (the team's SSH public key)")
	}

	switch {
	case o.from != "":
		next.AllowFrom = strings.ReplaceAll(o.from, " ", "")
	case next.AllowFrom == "":
		suggested := suggestedTeamNetwork()
		if !o.yes && isInteractive() {
			prompt := "Team network allowed to use the key"
			if suggested != "" {
				prompt += " [" + suggested + "]"
			}
			fmt.Fprintf(w, "%s (CIDRs, comma-separated, or 'any'): ", prompt)
			answer, _ := reader.ReadString('\n')
			if answer = strings.TrimSpace(answer); answer != "" {
				suggested = answer
			}
		}
		if suggested == "" {
			return fmt.Errorf("install: cannot tell the team network from this session; pass --from <cidr> (or --from any)")
		}
		next.AllowFrom = suggested
	}
	if err := validateAllowFrom(next.AllowFrom); err != nil {
		return err
	}

	if name == "" {
		chosen, err := chooseName("")
		if err != nil {
			return err
		}
		name = chosen
	}
	if !validAccountName(name) {
		return fmt.Errorf("install: invalid name %q", name)
	}
	if !o.noBreakGlass && next.BreakGlassUser == "" {
		bg, err := chooseName(name)
		if err != nil {
			return err
		}
		next.BreakGlassUser = bg
	}
	if o.noBreakGlass && existing == "" {
		next.BreakGlassUser = ""
	}
	if o.ban != "" {
		next.Ban = o.ban
	}
	if o.lock != "" {
		next.Lock = o.lock
	}
	if o.safeAccounts != nil {
		next.SafeAccounts = o.safeAccounts
	}
	if err := next.validate(); err != nil {
		return err
	}

	p := pathsForName(name)
	target := filepath.Join(installDir, name)

	fmt.Fprintf(w, "==> Installing the binary as %s\n", target)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := installBinary(self, target); err != nil {
		return err
	}
	if err := os.MkdirAll(p.dataDir, 0o700); err != nil {
		return err
	}
	if err := saveRuntimeConfig(p, next); err != nil {
		return err
	}

	fmt.Fprintln(w, "==> Creating access accounts, keys, triggers and timers")
	if err := runInstalled(w, target, "sentinel-check"); err != nil {
		// Report and carry on: a single link (say, no iptables) must not
		// leave the rest uninstalled. status and the next pass show it.
		fmt.Fprintf(w, "    warning: %v\n", err)
	}
	fmt.Fprintln(w, "==> Taking the first snapshots")
	for _, tier := range []string{"config", "data"} {
		if err := runInstalled(w, target, "snapshot", "--tier", tier, "--quiet"); err != nil {
			fmt.Fprintf(w, "    warning: %s snapshot: %v\n", tier, err)
		}
	}

	printInstallNextSteps(w, name, next)
	return nil
}

func runInstalled(w io.Writer, bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = w, w
	return cmd.Run()
}

func installBinary(src, dst string) error {
	if same, _ := sameFile(src, dst); same {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return writeOwnFile(dst, data, 0o700)
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// findExistingInstall returns the name of an install already on this box.
func findExistingInstall() string {
	dirs, _ := filepath.Glob("/var/lib/*/config.json")
	for _, cfgPath := range dirs {
		dir := filepath.Dir(cfgPath)
		name := filepath.Base(dir)
		if _, err := os.Stat(filepath.Join(dir, ".spare")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(installDir, name)); err != nil {
			if _, err := os.Stat(filepath.Join("/usr/lib", name, name)); err != nil {
				continue
			}
		}
		return name
	}
	return ""
}

// chooseName picks an unused plausible service name, never equal to avoid.
func chooseName(avoid string) (string, error) {
	var candidates []string
	for _, p := range namePrefixes {
		for _, s := range nameSuffixes {
			candidates = append(candidates, p+s)
		}
	}
	for i := len(candidates) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		candidates[i], candidates[j.Int64()] = candidates[j.Int64()], candidates[i]
	}
	for _, c := range candidates {
		if c != avoid && !nameCollides(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("install: every candidate name is taken; pass --name")
}

func nameCollides(name string) bool {
	for _, p := range []string{
		filepath.Join(installDir, name), "/usr/sbin/" + name, "/usr/bin/" + name,
		"/var/lib/" + name, "/usr/lib/" + name, "/home/" + name, "/etc/sudoers.d/" + name,
		filepath.Join(systemdUnitDir, name+sentinelSuffix+".service"),
	} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if _, ok, _ := readPasswd(name); ok {
		return true
	}
	return false
}

// resolveTeamKey accepts the key itself, @file, or an https URL. The
// first key line found is used.
func resolveTeamKey(arg string) (string, error) {
	var raw string
	switch {
	case strings.HasPrefix(arg, "@"):
		data, err := os.ReadFile(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return "", fmt.Errorf("install: read key: %w", err)
		}
		raw = string(data)
	case strings.HasPrefix(arg, "https://"):
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, arg, nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("install: fetch key: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("install: fetch key: %s", resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return "", err
		}
		raw = string(data)
	case strings.HasPrefix(arg, "http://"):
		return "", fmt.Errorf("install: fetch the key over https, not http")
	default:
		raw = arg
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateTeamKey(line); err != nil {
			return "", err
		}
		return line, nil
	}
	return "", fmt.Errorf("install: no SSH public key found in %q", arg)
}

// suggestedTeamNetwork is the /24 (or /64) around the SSH client running
// this install: by construction a network the team reaches the box from.
func suggestedTeamNetwork() string {
	fields := strings.Fields(os.Getenv("SSH_CLIENT"))
	if len(fields) == 0 {
		return ""
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func printInstallNextSteps(w io.Writer, name string, c runtimeConfig) {
	fmt.Fprintf(w, `
==> Installed as %[1]s. Auto-restore is OFF until you arm.

Connect from the team network with the team's private key:
  ssh -t -i team %[1]s@<this box>            root shell
  ssh -i team %[1]s@<this box> status        any warden command
`, name)
	if c.BreakGlassUser != "" {
		fmt.Fprintf(w, "  ssh -t -i team %s@<this box>            break-glass, same key, separate path\n", c.BreakGlassUser)
	}
	fmt.Fprintf(w, `
Next:
  1. Harden, then check that services and scoring work.
  2. ssh -i team %[1]s@<this box> arm
  3. Pair with another box so backups survive this one:
     ssh -i team %[1]s@<this box> pair add $(ssh -i team <user>@<peer> pair accept $(ssh -i team %[1]s@<this box> pair key))

To change a protected file after arming: disarm, change it, check, arm.
Responses: ban=%[2]s lock=%[3]s (change with 'config set ban act').
You can delete the clone you installed from; nothing here needs it.
`, name, c.Ban, c.Lock)
}

// rekeyCmd swaps the team key (and optionally the team network) in place.
func rekeyCmd() *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "rekey <team-public-key | @file | https://url>",
		Short: "Replace the team key on this box",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			key, err := resolveTeamKey(strings.Join(args, " "))
			if err != nil {
				return err
			}
			next := cfg
			next.TeamKey = key
			if from != "" {
				next.AllowFrom = strings.ReplaceAll(from, " ", "")
			}
			if err := saveRuntimeConfig(p, next); err != nil {
				return err
			}
			if err := repairAccess(p); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "rekeyed: the old key no longer works on this box")
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "also change the team network")
	return cmd
}

// configCmd shows or changes runtime settings without a rebuild.
func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or change this box's runtime settings",
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the runtime config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := cfg
			c.Sources = append([]sourceConfig(nil), cfg.Sources...)
			for i := range c.Sources {
				c.Sources[i].Key = abbreviateKey(c.Sources[i].Key)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "team_key:         %s\n", abbreviateKey(c.TeamKey))
			fmt.Fprintf(cmd.OutOrStdout(), "allow_from:       %s\n", c.AllowFrom)
			fmt.Fprintf(cmd.OutOrStdout(), "break_glass_user: %s\n", c.BreakGlassUser)
			fmt.Fprintf(cmd.OutOrStdout(), "ban:              %s\n", c.Ban)
			fmt.Fprintf(cmd.OutOrStdout(), "lock:             %s\n", c.Lock)
			fmt.Fprintf(cmd.OutOrStdout(), "safe_accounts:    %s\n", strings.Join(c.SafeAccounts, ","))
			fmt.Fprintf(cmd.OutOrStdout(), "peer_quota_mb:    %d\n", peerQuotaBytes()>>20)
			for _, peer := range c.Peers {
				fmt.Fprintf(cmd.OutOrStdout(), "peer:             %s\n", peer.URL)
			}
			for _, src := range c.Sources {
				fmt.Fprintf(cmd.OutOrStdout(), "source:           %s %s\n", src.Name, src.Key)
			}
			return nil
		},
	}
	set := &cobra.Command{
		Use:   "set <allow_from|ban|lock|safe_accounts|peer_quota_mb> <value>",
		Short: "Change one runtime setting (takes effect at once)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			next := cfg
			key, value := args[0], args[1]
			switch key {
			case "allow_from":
				next.AllowFrom = strings.ReplaceAll(value, " ", "")
			case "ban":
				next.Ban = value
			case "lock":
				next.Lock = value
			case "safe_accounts":
				next.SafeAccounts = nil
				for _, a := range strings.Split(value, ",") {
					if a = strings.TrimSpace(a); a != "" {
						next.SafeAccounts = append(next.SafeAccounts, a)
					}
				}
			case "peer_quota_mb":
				var mb int
				if _, err := fmt.Sscanf(value, "%d", &mb); err != nil {
					return fmt.Errorf("config: peer_quota_mb must be a number")
				}
				next.PeerQuotaMB = mb
			default:
				return fmt.Errorf("config: unknown or read-only setting %q", key)
			}
			if err := saveRuntimeConfig(p, next); err != nil {
				return err
			}
			if key == "allow_from" {
				if err := repairAccess(p); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s = %s\n", key, value)
			return nil
		},
	}
	cmd.AddCommand(show, set)
	return cmd
}

func abbreviateKey(key string) string {
	f := strings.Fields(key)
	if len(f) < 2 {
		return key
	}
	b := f[1]
	if len(b) > 16 {
		b = b[:8] + "..." + b[len(b)-8:]
	}
	out := f[0] + " " + b
	if len(f) > 2 {
		out += " " + strings.Join(f[2:], " ")
	}
	return out
}
