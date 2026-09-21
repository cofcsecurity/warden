package anomaly

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// baseline is a path -> content-hash map, persisted as JSON, that each
// check uses to remember what it saw last time. A path missing from disk
// on a given run is simply dropped from the saved baseline — its absence
// isn't itself a finding here (a config path that stops existing is
// already watch's job, for the paths that matter enough to be in
// configTierPaths).
type baseline map[string]string

func loadBaseline(path string) (baseline, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return baseline{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("anomaly: read %s: %w", path, err)
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("anomaly: parse %s: %w", path, err)
	}
	return b, nil
}

func saveBaseline(path string, b baseline) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("anomaly: mkdir for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("anomaly: encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("anomaly: write %s: %w", path, err)
	}
	return nil
}

func hashContent(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// firstRun reports whether a baseline file simply didn't exist yet — the
// caller uses this to decide whether to report zero findings (bootstrap)
// rather than flagging everything present as "new". Same tradeoff
// manifest.Generate's first snapshot already has: a first run assumes the
// box was clean at that moment, not a certainty (see docs/DESIGN.md's "No
// Clean Window: Assume Compromise").
func firstRun(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}
