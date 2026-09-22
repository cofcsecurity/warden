# Review findings

Reviewed recovery, replication, snapshots, restore, watch, and account locks after the host-profile changes.

Fixed in this pass:

- Missing local objects stopped restoration even when a peer held a copy. Recovery now searches configured replicas and verifies the bytes before caching them.
- Retrieval accepted bytes without checking the requested object hash. Malformed short hashes could also panic local store lookups. Store and retrieval reads now validate them.
- Nested shell quoting broke SSH writes to paths containing spaces or quotes. Remote writes now quote each path once, use unique temporary files, and publish without overwriting existing content. Local replica writes use the same no-overwrite publication rule.
- A stalled SSH handshake or command could prevent trying another replica. These operations now have timeouts.
- Watch interpreted a path removed from the host profile as a deleted file and restored it. It now limits changes to the current watch list and uses the current classification for deleted files.
- Retrieve dry runs wrote objects to the local store. They now read metadata only.
- The deployment guide's nologin account and forced false command blocked the replication transport. The guide now describes the required shell access and its limitations.

Remaining bugs, in priority order:

1. **Receiver permissions do not enforce append-only backups.** `SSHTarget` executes shell commands as the receiving account. A stolen key can bypass the client's write-once behavior and delete writable backups. Separate receiving accounts reduce exposure; a restricted receiver protocol and independent retention are needed to enforce it. Relevant code: `internal/replicate/ssh_target.go`.
2. **Active account locks can conflict with config restoration.** Locking changes the account's shell in `/etc/passwd`, which watch can restore from the baseline. `accountlock.Reconcile` does not reapply active locks. The recorded indefinite lock can therefore disagree with the operating system's state. Response and restoration need a shared account-state policy. Relevant code: `internal/accountlock/accountlock.go`, `internal/watch/watch.go`.
3. **Permission-only changes are missed.** Manifests record file modes, but Diff and restore Plan compare content hashes without comparing modes. Writing an existing file with `os.WriteFile` also leaves its existing permissions unchanged. A watched file made writable can remain writable after a content restore. Relevant code: `internal/manifest/manifest.go`, `internal/restore/restore.go`, `internal/watch/watch.go`.
4. **A failed restore can leave a service stopped.** After stopping a mapped unit, a write or verification error returns before starting it again. Restore needs staged writes and an explicit service recovery policy for failures. Relevant code: `internal/restore/restore.go`.
5. **Snapshot and pruning operations have no shared process lock.** Timers and manual commands can overlap. One pass can prune an object another pass has stored but not yet referenced in a saved manifest, or two snapshots can select the same generation. Serialize baseline updates and pruning. Relevant code: `cmd/warden/snapshot.go`, `internal/store/store.go`.

Feature candidates:

- `verify-backups --repair`: check retained generations and recover missing objects before a restore is needed; report which peers hold usable copies.
- A restricted replication receiver that permits validated reads and append-only writes inside a per-source root.
- Signed manifests and a persisted generation record to detect forged metadata and rollback when local metadata is lost.
- A profile validation command that checks file coverage and installed unit mappings before arming.

Recovery, profile, object-integrity, and shell-path regression tests pass. The remaining findings above are based on source review and still need implementation and regression coverage. A full scored-image deployment test was not run.
