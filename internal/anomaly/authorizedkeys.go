package anomaly

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AuthorizedKeysSource is one authorized_keys file to watch, paired with
// the account it belongs to (the caller derives this from the file's
// home directory — /home/<user>/.ssh/authorized_keys or
// /root/.ssh/authorized_keys — since that's a cmd/warden-level path
// enumeration concern, not something this package resolves itself).
type AuthorizedKeysSource struct {
	Path    string
	Culprit string
}

// CheckAuthorizedKeys flags any authorized_keys file that's new or
// changed since the last run — any account, not just the opmenu
// account's own file (already covered separately by
// cmd/warden/registrations.go's own single-line check). normalize, when
// non-nil, strips Warden's own expected line from the opmenu account's
// file before hashing, the same reasoning CheckCron's normalize param
// has.
func CheckAuthorizedKeys(baselineDir string, sources []AuthorizedKeysSource, normalize func(path string, content []byte) []byte) ([]Finding, error) {
	baselinePath := filepath.Join(baselineDir, "authorized_keys.json")
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	next := baseline{}
	var findings []Finding

	for _, src := range sources {
		content, err := os.ReadFile(src.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("anomaly: read %s: %w", src.Path, err)
		}
		var eventTime time.Time
		if info, err := os.Stat(src.Path); err == nil {
			eventTime = info.ModTime()
		}
		if normalize != nil {
			content = normalize(src.Path, content)
		}
		hash := hashContent(content)
		next[src.Path] = hash
		if bootstrap {
			continue
		}
		oldHash, existed := old[src.Path]
		switch {
		case !existed:
			findings = append(findings, Finding{
				Check:       "authorized_keys",
				Description: fmt.Sprintf("new authorized_keys file: %s (account: %s)", src.Path, src.Culprit),
				Detail:      src.Path,
				Culprit:     src.Culprit,
				EventTime:   eventTime,
			})
		case oldHash != hash:
			findings = append(findings, Finding{
				Check:       "authorized_keys",
				Description: fmt.Sprintf("authorized_keys changed: %s (account: %s)", src.Path, src.Culprit),
				Detail:      src.Path,
				Culprit:     src.Culprit,
				EventTime:   eventTime,
			})
		}
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}
