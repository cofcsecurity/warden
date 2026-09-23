package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"warden/internal/accountedit"
	"warden/internal/accountlock"
	"warden/internal/audit"
	"warden/internal/fsutil"
	"warden/internal/manifest"
	"warden/internal/store"
)

func accountEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "account-edit passwd USER | gpasswd [-a/-d USER | -M USERS] GROUP",
		Short: "Run a deliberate local password or group change and approve its exact result",
		Long: `Runs passwd USER, gpasswd GROUP, gpasswd -a/-d USER GROUP, or
gpasswd -M USER1,USER2 GROUP after a hidden Warden second-factor prompt.
-M replaces the complete supplementary member list; -M "" clears it. Requires root and an interactive terminal.
All four account files must already match the effective config baseline.
Only the requested fields are accepted. No passwords are collected by Warden.
Other Warden mutation commands report busy while this command holds its lock;
timer invocations retry on their next scheduled pass. The utility has a five-minute limit.`,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return cmd.Help()
			}
			req, err := accountedit.Parse(args)
			if err != nil {
				return err
			}
			if runtime.GOOS != "linux" || os.Geteuid() != 0 {
				return fmt.Errorf("account-edit requires root on Linux")
			}
			opUser, err := opmenuUser()
			if err != nil {
				return err
			}
			if req.Tool == "passwd" && req.Target == opUser {
				return fmt.Errorf("use Warden's access configuration for the opmenu account")
			}
			tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return fmt.Errorf("account-edit requires an interactive SSH terminal: %w", err)
			}
			defer tty.Close()
			if !term.IsTerminal(int(tty.Fd())) {
				return fmt.Errorf("account-edit requires a terminal")
			}
			if err := authorizeAccountEdit(tty); err != nil {
				return err
			}
			p, err := loadPaths()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(p.storeRoot, 0700); err != nil {
				return err
			}
			release, err := fsutil.Lock(filepath.Join(p.storeRoot, "operation.lock"))
			if err != nil {
				return err
			}
			defer release()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			state, err := term.GetState(int(tty.Fd()))
			if err != nil {
				return err
			}
			defer term.Restore(int(tty.Fd()), state)
			return performAccountEdit(p, "/etc", req, func() error {
				executable := filepath.Join("/usr/bin", req.Tool)
				info, err := os.Stat(executable)
				if err != nil {
					return err
				}
				st, ok := info.Sys().(*syscall.Stat_t)
				if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
					return fmt.Errorf("unsafe system utility %s", executable)
				}
				child := exec.CommandContext(ctx, executable, req.Args()...)
				child.Stdin, child.Stdout, child.Stderr = tty, tty, tty
				child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/root"}
				child.WaitDelay = 2 * time.Second
				return child.Run()
			})
		},
	}
}

func authorizeAccountEdit(tty *os.File) error {
	fd := int(tty.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, state)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	fmt.Fprint(tty, "Warden second factor: ")
	type result struct {
		code []byte
		err  error
	}
	done := make(chan result)
	go func() {
		code, err := term.ReadPassword(fd)
		select {
		case done <- result{code, err}:
		case <-ctx.Done():
			clear(code)
		}
	}()
	select {
	case <-ctx.Done():
		return fmt.Errorf("authorization cancelled")
	case r := <-done:
		fmt.Fprintln(tty)
		defer clear(r.code)
		if r.err != nil {
			return r.err
		}
		ok, err := verifySecondFactor(string(r.code))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("invalid or expired second factor")
		}
		return nil
	}
}

type accountFile struct {
	data     []byte
	mode     os.FileMode
	uid, gid uint32
}

func readAccountFiles(dir string) (map[string]accountFile, error) {
	out := map[string]accountFile{}
	for _, name := range accountedit.Files {
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) {
			f.Close()
			return nil, fmt.Errorf("unsafe account file %s", path)
		}
		data, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
		f.Close()
		if err != nil {
			return nil, err
		}
		if len(data) > 16<<20 {
			return nil, fmt.Errorf("account file too large: %s", path)
		}
		out[name] = accountFile{data, info.Mode(), stat.Uid, stat.Gid}
	}
	return out, nil
}

func accountBytes(files map[string]accountFile) map[string][]byte {
	out := map[string][]byte{}
	for name, file := range files {
		out[name] = file.data
	}
	return out
}

// Caller holds operation.lock across the utility and publication. This does not
// lock out external writers; before/after validation refuses unrelated changes.
func performAccountEdit(p paths, dir string, req accountedit.Request, run func() error) (retErr error) {
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		return err
	}
	if m.Generation == 0 {
		return fmt.Errorf("account-edit requires an existing config snapshot")
	}
	if err := verifyManifest(m, tierConfig); err != nil {
		return err
	}
	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	locks, err := accountlock.NewStore(p.accountLocksPath).Load()
	if err != nil {
		return err
	}
	for _, lock := range locks {
		if req.Tool == "passwd" && lock.User == req.Target {
			return fmt.Errorf("unlock-account %s before changing its password", req.Target)
		}
	}
	effective, err := accountBaseline(p, m, st)
	if err != nil {
		return err
	}
	before, err := readAccountFiles(dir)
	if err != nil {
		return err
	}
	base := map[string][]byte{}
	for _, name := range accountedit.Files {
		path := filepath.Join(dir, name)
		count := 0
		for i, rec := range m.Records {
			if rec.Path != path {
				continue
			}
			count++
			current := before[name]
			if rec.Symlink || current.mode != rec.Mode || store.Verify(effective.Records[i].Hash, current.data) != nil {
				return fmt.Errorf("review existing drift in %s before account-edit", path)
			}
			base[name], err = st.Get(rec.Hash)
			if err != nil {
				return err
			}
		}
		if count != 1 {
			return fmt.Errorf("account-edit requires exactly one config baseline record for %s", path)
		}
	}
	if err := req.ValidateBefore(accountBytes(before)); err != nil {
		return err
	}
	next := *m
	next.Signature = ""
	next.Records = append([]manifest.Record(nil), m.Records...)
	next.ApprovedGroups = maps.Clone(m.ApprovedGroups)
	next.Generation, err = allocateGeneration(p, tierConfig, m.Generation)
	if err != nil {
		return err
	}
	// Check signing capability and archive availability before changing credentials.
	if err := signManifest(&next, tierConfig); err != nil {
		return err
	}
	if err := os.MkdirAll(p.configManifestsDir, 0700); err != nil {
		return err
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	fields := map[string]any{"tool": req.Tool, "target": req.Target, "operation": req.Operation, "member": req.Member}
	if err := log.Log("account-edit", "started", fields); err != nil {
		return err
	}
	published := false
	defer func() {
		if retErr != nil && !published {
			_ = log.Log("account-edit", "incomplete", fields)
			retErr = fmt.Errorf("account-edit incomplete; system account files may already have changed, inspect them and the current Warden baseline before retrying: %w", retErr)
		}
	}()
	if err := run(); err != nil {
		return fmt.Errorf("account utility failed; no baseline accepted, inspect account state before retrying: %w", err)
	}
	after, err := readAccountFiles(dir)
	if err != nil {
		return err
	}
	for name, old := range before {
		current := after[name]
		if current.mode != old.mode || current.uid != old.uid || current.gid != old.gid {
			return fmt.Errorf("account metadata changed for %s; no baseline accepted", name)
		}
	}
	approved, err := req.Apply(base, accountBytes(before), accountBytes(after))
	if err != nil {
		return fmt.Errorf("account-edit validation failed; no baseline accepted: %w", err)
	}
	for i, rec := range next.Records {
		if filepath.Dir(rec.Path) != dir {
			continue
		}
		name := filepath.Base(rec.Path)
		content, ok := approved[name]
		if !ok || bytes.Equal(content, base[name]) {
			continue
		}
		next.Records[i].Hash, err = st.Put(content)
		if err != nil {
			return err
		}
	}
	if req.Tool == "gpasswd" {
		if next.ApprovedGroups == nil {
			next.ApprovedGroups = map[string]string{}
		}
		next.ApprovedGroups[req.Target], err = req.GroupHash(approved["group"])
		if err != nil {
			return err
		}
	}
	next.CreatedAt = time.Now().UTC()
	if err := signManifest(&next, tierConfig); err != nil {
		return err
	}
	// Validate again after preparing the stored generation. Later writes remain drift.
	final, err := readAccountFiles(dir)
	if err != nil {
		return err
	}
	for name, want := range after {
		got := final[name]
		if !bytes.Equal(got.data, want.data) || got.mode != want.mode || got.uid != want.uid || got.gid != want.gid {
			return fmt.Errorf("account files changed again; no baseline accepted")
		}
	}
	if err := next.Archive(p.configManifestsDir); err != nil {
		return err
	}
	if err := next.SaveAs(p.configManifestPath); err != nil {
		return err
	}
	published = true
	fields["generation"] = next.Generation
	if err := log.Log("account-edit", "accepted", fields); err != nil {
		return fmt.Errorf("account change accepted, but recording completion failed: %w", err)
	}
	fmt.Printf("accepted %s change for %s (generation %d)\n", req.Tool, req.Target, next.Generation)
	return nil
}
