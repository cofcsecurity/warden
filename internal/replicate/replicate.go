// Package replicate pushes new snapshot objects off-box, so a root
// compromise of the monitored host doesn't take the backups with it — and
// pulls them back, so a box that's been wiped and rebuilt has a way to
// recover its own prior backups from wherever they were replicated to.
package replicate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"warden/internal/manifest"
	"warden/internal/store"
)

// Target is where a Replicator pushes to and a Retriever pulls from. Both
// an SSH host and a local filesystem path (e.g. removable media, or
// another box in a replication mesh) satisfy this interface, so callers
// don't branch on which is configured.
//
// Every write method must be additive-only: an implementation must never
// delete or overwrite something that's already there. A compromised
// source box can then never destroy prior backups, only add to them —
// pulling data back out (Get/GetManifest/ManifestGenerations) is a
// separate, explicit recovery action, not something Push ever does.
//
// namespace separates the two snapshot tiers (config vs. data) within one
// Target's root; it is not for separating different source boxes sharing
// one destination — that's handled by each source using a distinct root
// path (e.g. ssh://backup-box/from-boxB vs. .../from-boxF).
type Target interface {
	Has(hash string) (bool, error)
	Put(hash string, content []byte) error
	Get(hash string) ([]byte, error)

	HasManifest(namespace string, generation int) (bool, error)
	PutManifest(namespace string, generation int, data []byte) error
	GetManifest(namespace string, generation int) ([]byte, error)
	// ManifestGenerations returns every generation number the target has
	// for namespace, sorted oldest first.
	ManifestGenerations(namespace string) ([]int, error)

	// The audit log travels the same additive-only way: one immutable
	// segment per push, holding whatever was appended to the log since
	// the last one. Without this, the audit trail was the one thing
	// replication didn't carry — a root compromise that deleted
	// audit.log destroyed the entire evidence record, on a box whose
	// backups were otherwise specifically built to survive exactly that.
	// Segment names sort into chronological order (see
	// AuditSegmentName), so concatenating them in order reconstructs the
	// log.
	HasAudit(name string) (bool, error)
	PutAudit(name string, data []byte) error
	GetAudit(name string) ([]byte, error)
	AuditSegments() ([]string, error)

	// PutHeartbeat leaves one "this box was alive at time T" record on
	// the peer (see internal/heartbeat). Write-once per name like
	// everything else here; names carry a timestamp, so each push adds
	// one small file rather than replacing a previous one. There's
	// deliberately no read method: a box reads the beats that arrived
	// *in its own* receiving directory, which is a local filesystem
	// read, not something it fetches back from a peer it pushed to.
	PutHeartbeat(name string, data []byte) error
}

// HeartbeatName builds the name for one pushed heartbeat: the box it came
// from and when it was written, fixed-width so names sort chronologically
// and can't collide between two pushes.
func HeartbeatName(host string, at time.Time) string {
	if host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s-%019d.json", sanitizeHost(host), at.UTC().UnixNano())
}

// AuditSegmentName builds the name for one pushed chunk of a box's audit
// log: the box it came from, when it was pushed, and the byte offset it
// starts at.
//
// Both numbers are fixed-width so the names sort chronologically as
// plain strings (see PullAudit), and the timestamp is nanoseconds
// rather than seconds specifically so two segments pushed in the same
// pass can't collide: a collision isn't a duplicate, it's silent data
// loss, since the write-once targets skip a name that already exists —
// which is exactly what a log that rotated and restarted at offset 0
// would produce.
func AuditSegmentName(host string, at time.Time, offset int64) string {
	if host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s-%019d-%012d.log", sanitizeHost(host), at.UTC().UnixNano(), offset)
}

// sanitizeHost keeps a hostname to characters that are safe in a
// filename and in a remote shell command, so an odd hostname can't
// become an injection or a path traversal on the peer. Dots go too,
// even though they're legal in both: a name that can't contain "." can't
// contain ".." either, which is one fewer thing to reason about at the
// far end. An FQDN reads fine as box_example_com.
func sanitizeHost(host string) string {
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// Replicator pushes store objects and manifest generations to a Target.
type Replicator struct {
	target Target
}

// New builds a Replicator against target.
func New(target Target) *Replicator {
	return &Replicator{target: target}
}

// Push replicates m: every object m's records reference that the target
// doesn't already have, then the manifest generation itself. Existing
// objects and generations are left untouched.
func (r *Replicator) Push(namespace string, m *manifest.Manifest, manifestData []byte, st *store.Store) error {
	for _, rec := range m.Records {
		has, err := r.target.Has(rec.Hash)
		if err != nil {
			return fmt.Errorf("replicate: check %s: %w", rec.Hash, err)
		}
		if has {
			continue
		}

		content, err := st.Get(rec.Hash)
		if err != nil {
			return fmt.Errorf("replicate: read %s from local store: %w", rec.Hash, err)
		}
		if err := r.target.Put(rec.Hash, content); err != nil {
			return fmt.Errorf("replicate: push %s: %w", rec.Hash, err)
		}
	}

	hasManifest, err := r.target.HasManifest(namespace, m.Generation)
	if err != nil {
		return fmt.Errorf("replicate: check manifest generation %d: %w", m.Generation, err)
	}
	if hasManifest {
		return nil
	}
	if err := r.target.PutManifest(namespace, m.Generation, manifestData); err != nil {
		return fmt.Errorf("replicate: push manifest generation %d: %w", m.Generation, err)
	}
	return nil
}

// PushAudit writes one audit-log segment to the target, unless a segment
// of that name is already there. Separate from Push: the audit log has
// no manifest and no generation, and a peer being unable to take it must
// not cost the snapshot push that already succeeded.
func (r *Replicator) PushAudit(name string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	has, err := r.target.HasAudit(name)
	if err != nil {
		return fmt.Errorf("replicate: check audit segment %s: %w", name, err)
	}
	if has {
		return nil
	}
	if err := r.target.PutAudit(name, data); err != nil {
		return fmt.Errorf("replicate: push audit segment %s: %w", name, err)
	}
	return nil
}

// PushHeartbeat writes this box's current heartbeat to the peer. Unlike
// Push and PushAudit, there's nothing to skip or resume: a beat is a
// fresh statement about right now, and its whole value is in having been
// written recently.
func (r *Replicator) PushHeartbeat(name string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if err := r.target.PutHeartbeat(name, data); err != nil {
		return fmt.Errorf("replicate: push heartbeat %s: %w", name, err)
	}
	return nil
}

// Retriever pulls manifest generations and their objects back from a
// Target — the reverse of Replicator, used to recover a box's own
// backups from a peer that holds a copy of them.
type Retriever struct {
	target Target
}

// NewRetriever builds a Retriever against target.
func NewRetriever(target Target) *Retriever {
	return &Retriever{target: target}
}

// LatestGeneration returns the highest generation number the target has
// for namespace.
func (r *Retriever) LatestGeneration(namespace string) (int, error) {
	gens, err := r.target.ManifestGenerations(namespace)
	if err != nil {
		return 0, fmt.Errorf("retrieve: list generations: %w", err)
	}
	if len(gens) == 0 {
		return 0, fmt.Errorf("retrieve: no generations available for %q on this target", namespace)
	}
	return gens[len(gens)-1], nil
}

// Pull fetches manifest generation from the target for namespace, along
// with every object it references, storing the objects in st. It does not
// touch any local manifest file — the caller decides whether and how to
// adopt the pulled manifest as live state (see cmd/warden's retrieve
// command, which treats this as a dry run unless --apply is given).
func (r *Retriever) Pull(namespace string, generation int, st *store.Store) (*manifest.Manifest, error) {
	data, err := r.target.GetManifest(namespace, generation)
	if err != nil {
		return nil, fmt.Errorf("retrieve: fetch manifest generation %d: %w", generation, err)
	}

	m, err := manifest.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("retrieve: parse manifest generation %d: %w", generation, err)
	}

	for _, rec := range m.Records {
		if st.Has(rec.Hash) {
			continue
		}
		content, err := r.target.Get(rec.Hash)
		if err != nil {
			return nil, fmt.Errorf("retrieve: fetch object %s (%s): %w", rec.Hash, rec.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return nil, fmt.Errorf("retrieve: store object %s (%s): %w", rec.Hash, rec.Path, err)
		}
	}

	return m, nil
}

// PullAudit reassembles every audit-log segment the target holds, in
// name order — which is chronological order per box, since that's what
// AuditSegmentName encodes. With several boxes replicating into one
// root, this returns all of their logs interleaved by box then time;
// each line carries its own host field (see internal/audit), so they
// stay tellable apart.
func (r *Retriever) PullAudit() ([]byte, error) {
	names, err := r.target.AuditSegments()
	if err != nil {
		return nil, fmt.Errorf("retrieve: list audit segments: %w", err)
	}
	sort.Strings(names)

	var out []byte
	for _, name := range names {
		data, err := r.target.GetAudit(name)
		if err != nil {
			return nil, fmt.Errorf("retrieve: fetch audit segment %s: %w", name, err)
		}
		out = append(out, data...)
	}
	return out, nil
}
