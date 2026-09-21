package anomaly

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CronSource is one thing CheckCron watches: either a single file (e.g.
// /etc/crontab) or a directory whose entries are each checked
// individually (e.g. /etc/cron.d, or a per-user crontab spool).
// CulpritIsFilename marks the classic per-user crontab spool layout
// (/var/spool/cron/crontabs/<user> or /var/spool/cron/<user>), where each
// entry's filename directly names the account it belongs to — unlike
// /etc/cron.d, whose entries are arbitrary script names, not usernames.
type CronSource struct {
	Path              string
	IsDir             bool
	CulpritIsFilename bool
}

// CheckCron flags any cron-related file under sources that's new or
// changed since the last run — any user's crontab, not just Warden's own
// sentinel entry (that's already covered separately by
// cmd/warden/registrations.go's own cron-entry check). normalize, when
// non-nil, is applied to a file's content before hashing, so the caller
// can strip Warden's own expected line out of root's crontab first —
// otherwise sentinel legitimately rewriting its own line every pass would
// false-positive here every time.
func CheckCron(baselineDir string, sources []CronSource, normalize func(path string, content []byte) []byte) ([]Finding, error) {
	baselinePath := filepath.Join(baselineDir, "cron.json")
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	next := baseline{}
	var findings []Finding

	check := func(path, culprit string) error {
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("anomaly: read %s: %w", path, err)
		}
		var eventTime time.Time
		if info, err := os.Stat(path); err == nil {
			eventTime = info.ModTime()
		}
		if normalize != nil {
			content = normalize(path, content)
		}
		hash := hashContent(content)
		next[path] = hash
		if bootstrap {
			return nil
		}
		oldHash, existed := old[path]
		switch {
		case !existed:
			findings = append(findings, Finding{
				Check:       "cron",
				Description: fmt.Sprintf("new cron file: %s", path),
				Detail:      path,
				Culprit:     culprit,
				EventTime:   eventTime,
			})
		case oldHash != hash:
			findings = append(findings, Finding{
				Check:       "cron",
				Description: fmt.Sprintf("cron file changed: %s", path),
				Detail:      path,
				Culprit:     culprit,
				EventTime:   eventTime,
			})
		}
		return nil
	}

	for _, src := range sources {
		if !src.IsDir {
			if err := check(src.Path, ""); err != nil {
				return nil, err
			}
			continue
		}
		entries, err := os.ReadDir(src.Path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("anomaly: read dir %s: %w", src.Path, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			full := filepath.Join(src.Path, e.Name())
			culprit := ""
			if src.CulpritIsFilename {
				culprit = e.Name()
			}
			if err := check(full, culprit); err != nil {
				return nil, err
			}
		}
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}
