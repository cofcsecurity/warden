package main

import (
	"warden/internal/accountlock"
	"warden/internal/manifest"
	"warden/internal/store"
)

// Effective manifests are temporary. Approved archives retain their original bytes.
func accountBaseline(p paths, m *manifest.Manifest, st *store.Store) (*manifest.Manifest, error) {
	locks, err := accountlock.NewStore(p.accountLocksPath).Load()
	if err != nil {
		return nil, err
	}
	copy := *m
	copy.Records = append([]manifest.Record(nil), m.Records...)
	for i, rec := range copy.Records {
		if len(locks) == 0 || rec.Path != "/etc/passwd" && rec.Path != "/etc/shadow" {
			continue
		}
		data, err := st.Get(rec.Hash)
		if err != nil {
			return nil, err
		}
		data, err = accountlock.Overlay(rec.Path, data, locks, nologinShellPath())
		if err != nil {
			return nil, err
		}
		hash, err := st.Put(data)
		if err != nil {
			return nil, err
		}
		copy.Records[i].Hash = hash
	}
	return &copy, nil
}
