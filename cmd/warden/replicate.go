package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/replicate"
	"warden/internal/store"
)

// replicateTarget is one configured replication peer: where to push, and
// (for ssh://) the pinned host key to verify it against.
type replicateTarget struct {
	url     string
	hostKey string // authorized_keys format; empty for file://
}

// parseReplicateTargets decodes buildReplicateTargets: records separated
// by ";;", each an "<url>||<hostkey>" pair (hostkey may be empty).
func parseReplicateTargets(raw string) []replicateTarget {
	var targets []replicateTarget
	for _, rec := range strings.Split(raw, ";;") {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		parts := strings.SplitN(rec, "||", 2)
		t := replicateTarget{url: strings.TrimSpace(parts[0])}
		if len(parts) == 2 {
			t.hostKey = strings.TrimSpace(parts[1])
		}
		targets = append(targets, t)
	}
	return targets
}

func replicateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "replicate",
		Short: "Push new snapshot objects and audit-log entries to every configured replication peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicate()
		},
	}
}

// runReplicate pushes both tiers, plus the audit log, to every configured
// peer — not just config: "always have a path to recovering a box" means
// the off-host copy has to include the same backups a local rm -rf would
// otherwise take out entirely. One peer being unreachable doesn't stop
// the others from getting pushed to — errors are collected and reported
// together.
func runReplicate() error {
	targets := parseReplicateTargets(buildReplicateTargets)
	if len(targets) == 0 {
		return fmt.Errorf("replicate: no targets configured (build with -ldflags -X main.buildReplicateTargets=...)")
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}
	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	state, err := loadAuditPushState(p.auditPushStatePath)
	if err != nil {
		return err
	}

	var errs []string
	auditBytes := 0
	for _, t := range targets {
		pushed, err := pushToTarget(p, st, t, state)
		auditBytes += pushed
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.url, err))
		}
	}

	// Saved even when a peer failed: whatever did get pushed is pushed,
	// and re-sending it would only create a duplicate segment.
	if err := saveAuditPushState(p.auditPushStatePath, state); err != nil {
		errs = append(errs, err.Error())
	}

	// A "pass" entry every run, success or failure, so `warden status`
	// can tell "replicated fine 3 minutes ago" from "this timer has been
	// dead since yesterday" — the same reason watch and sentinel-check
	// log one unconditionally.
	if logErr := log.Log("replicate", "pass", map[string]any{
		"peers":              len(targets),
		"failed":             len(errs),
		"audit_bytes_pushed": auditBytes,
	}); logErr != nil {
		return logErr
	}

	if len(errs) > 0 {
		return fmt.Errorf("replicate: %d of %d peers failed:\n%s", len(errs), len(targets), strings.Join(errs, "\n"))
	}
	return nil
}

// pushToTarget pushes both snapshot tiers and then the audit log to one
// peer, returning how many bytes of audit log it sent.
func pushToTarget(p paths, st *store.Store, t replicateTarget, state auditPushState) (int, error) {
	target, closeTarget, err := dialReplicateTarget(t.url, t.hostKey)
	if err != nil {
		return 0, err
	}
	defer closeTarget()

	r := replicate.New(target)
	pushed := 0
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		m, err := manifest.New(p.manifestPathForTier(tier))
		if err != nil {
			return 0, err
		}
		if m.Generation == 0 && len(m.Records) == 0 {
			continue // this tier has never been snapshotted yet; nothing to push
		}

		manifestData, err := readArchivedManifest(p.manifestsDirForTier(tier), m.Generation)
		if err != nil {
			return 0, err
		}
		if err := r.Push(string(tier), m, manifestData, st); err != nil {
			return 0, fmt.Errorf("push %s tier: %w", tier, err)
		}
		pushed++
	}

	// The audit log goes even if neither tier has been snapshotted yet:
	// a box that hasn't been snapshotted has still been logging, and
	// that record is exactly what a wipe would otherwise destroy.
	auditBytes, auditErr := pushAuditLog(p, r, t.url, state)

	if pushed == 0 && auditErr == nil {
		return auditBytes, fmt.Errorf("no local manifest yet for either tier; run 'warden snapshot' first")
	}
	return auditBytes, auditErr
}

// auditPushState maps a replication target URL to what was last pushed to
// it, so each pass ships only what was appended since — not a fresh copy
// of the whole log every fifteen minutes.
type auditPushState map[string]auditPushRecord

// auditPushRecord is how far into the audit log this peer has been
// brought up to date, plus a digest of exactly those bytes. The digest is
// what makes "has the log rotated?" answerable: a size alone can't tell a
// log that grew from one that rotated and was written past the old
// offset, and getting that wrong means either re-sending the whole log
// or silently skipping the start of the new one.
type auditPushRecord struct {
	Offset int64  `json:"offset"`
	Digest string `json:"digest"`
}

// auditPrefixDigest hashes the first n bytes of the log, the portion a
// peer already holds.
func auditPrefixDigest(data []byte, n int64) string {
	if n <= 0 || n > int64(len(data)) {
		return ""
	}
	sum := sha256.Sum256(data[:n])
	return hex.EncodeToString(sum[:])
}

// continuesFrom reports whether data is the same file the recorded
// offset/digest came from, simply grown — rather than a different file
// that happens to be at least that long.
func (rec auditPushRecord) continuesFrom(data []byte) bool {
	if rec.Offset == 0 {
		return true
	}
	if rec.Offset > int64(len(data)) {
		return false
	}
	return auditPrefixDigest(data, rec.Offset) == rec.Digest
}

func loadAuditPushState(path string) (auditPushState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return auditPushState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("replicate: read %s: %w", path, err)
	}
	state := auditPushState{}
	if err := json.Unmarshal(data, &state); err != nil {
		// A corrupt state file must not stop replication: starting over
		// re-pushes a segment the peer may already hold, which is
		// wasteful but harmless (it lands under a new, never-reused
		// name), where refusing to run would stop the evidence leaving
		// the box at all.
		return auditPushState{}, nil
	}
	return state, nil
}

func saveAuditPushState(path string, state auditPushState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("replicate: encode audit push state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("replicate: write %s: %w", path, err)
	}
	return nil
}

// pushAuditLog sends whatever has been appended to the audit log since
// this peer last heard from us, as one immutable segment.
//
// Rotation (see internal/audit's MaxLogBytes) is what the two offset
// adjustments below are for: when the live log is shorter than the offset
// recorded for a peer, it has rotated, and the tail of the now-rotated
// file is sent first so the bytes written between the last push and the
// rotation aren't lost — then the count restarts against the new file.
func pushAuditLog(p paths, r *replicate.Replicator, targetURL string, state auditPushState) (int, error) {
	data, err := os.ReadFile(p.auditLogPath)
	if os.IsNotExist(err) {
		return 0, nil // nothing has been logged on this box yet
	}
	if err != nil {
		return 0, fmt.Errorf("replicate: read %s: %w", p.auditLogPath, err)
	}

	host, _ := os.Hostname()
	now := time.Now()
	rec := state[targetURL]
	sent := 0

	if !rec.continuesFrom(data) {
		// The live log isn't the file this peer was last brought up to
		// date with, so it rotated (or was truncated) since. Whatever
		// was appended to the old file after the last push exists
		// nowhere else, so send that first, then start counting against
		// the new file.
		if rotated, err := os.ReadFile(audit.RotatedPath(p.auditLogPath)); err == nil &&
			rec.continuesFrom(rotated) && rec.Offset < int64(len(rotated)) {
			tail := rotated[rec.Offset:]
			// Stamped a tick before the live log's segment below: its
			// contents genuinely came first, and segment names are what
			// PullAudit reassembles the log in order by.
			name := replicate.AuditSegmentName(host, now.Add(-time.Millisecond), rec.Offset)
			if err := r.PushAudit(name, tail); err != nil {
				return sent, err
			}
			sent += len(tail)
		}
		rec.Offset = 0
	}

	tail := data[rec.Offset:]
	if len(tail) == 0 {
		return sent, nil
	}
	if err := r.PushAudit(replicate.AuditSegmentName(host, now, rec.Offset), tail); err != nil {
		return sent, err
	}
	state[targetURL] = auditPushRecord{
		Offset: int64(len(data)),
		Digest: auditPrefixDigest(data, int64(len(data))),
	}
	return sent + len(tail), nil
}

// dialReplicateTarget dials rawURL (ssh:// or file://), verifying against
// hostKey for an ssh:// target (ignored, and may be empty, for file://).
func dialReplicateTarget(rawURL, hostKey string) (replicate.Target, func() error, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse target URL: %w", err)
	}

	switch u.Scheme {
	case "file":
		target, err := replicate.NewFSTarget(u.Path)
		if err != nil {
			return nil, nil, err
		}
		return target, func() error { return nil }, nil

	case "ssh":
		return dialSSHReplicateTarget(u, hostKey)

	default:
		return nil, nil, fmt.Errorf("replicate: unsupported target scheme %q (want ssh:// or file://)", u.Scheme)
	}
}

func dialSSHReplicateTarget(u *url.URL, hostKeyStr string) (replicate.Target, func() error, error) {
	if buildReplicateKey == "" {
		return nil, nil, fmt.Errorf("replicate: ssh:// target needs buildReplicateKey baked in at build time")
	}
	if hostKeyStr == "" {
		return nil, nil, fmt.Errorf("replicate: ssh:// target %s has no pinned host key configured", u)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(buildReplicateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: decode replication key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse replication key: %w", err)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyStr))
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse pinned host key for %s: %w", u, err)
	}

	user := "warden"
	if u.User != nil {
		user = u.User.Username()
	}

	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	target, err := replicate.DialSSH(addr, user, signer, hostKey, u.Path)
	if err != nil {
		return nil, nil, err
	}
	return target, target.Close, nil
}

func readArchivedManifest(manifestsDir string, generation int) ([]byte, error) {
	path := manifest.ArchivePath(manifestsDir, generation)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replicate: read archived manifest %s: %w", path, err)
	}
	return data, nil
}
