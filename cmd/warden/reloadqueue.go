package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
	"warden/internal/fsutil"
)

type reloadQueue struct {
	path  string
	Units map[string]bool
}

func loadReloadQueue(p paths) (*reloadQueue, error) {
	q := &reloadQueue{path: filepath.Join(p.storeRoot, "pending-reloads.json"), Units: map[string]bool{}}
	data, err := os.ReadFile(q.path)
	if os.IsNotExist(err) {
		return q, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &q.Units); err != nil {
		return nil, err
	}
	if q.Units == nil {
		q.Units = map[string]bool{}
	}
	return q, nil
}
func (q *reloadQueue) save() error {
	data, err := json.Marshal(q.Units)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(q.path, data, 0600)
}
func (q *reloadQueue) add(path string) error {
	if unit, ok := serviceForPath(path); ok {
		q.Units[unit] = true
		return q.save()
	}
	return nil
}
func (q *reloadQueue) flush() []error {
	var errs []error
	var units []string
	for unit := range q.Units {
		units = append(units, unit)
	}
	sort.Strings(units)
	for _, unit := range units {
		if err := validateService(unit); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := runSystemctl("reload-or-restart", unit); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(q.Units, unit)
	}
	if err := q.save(); err != nil {
		errs = append(errs, err)
	}
	return errs
}

var serviceValidators = map[string][]string{}

func validateService(unit string) error {
	args := serviceValidators[unit]
	if len(args) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("validate %s: %w: %s", unit, err, out)
	}
	return nil
}
