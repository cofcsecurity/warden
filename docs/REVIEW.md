# Review findings

The [September 22 deployment review](REVIEW-2026-09-22.md) records six additional open findings against `8e45fe5`. The review below describes the preceding implementation.

Reviewed recovery, replication, snapshots, restore, watch, and account locks at commit `92834c8` on 2026-09-21. Eight isolated probes reproduced the failures below using temporary files, a fake account backend, and a fake systemctl command. No real accounts or services were changed. The implementation following this review addresses these findings; the original reproductions below describe the reviewed version.

Fixed in this pass:

- Missing local objects stopped restoration even when a peer held a copy. Recovery now searches configured replicas and verifies the bytes before caching them.
- Retrieval accepted bytes without checking the requested object hash. Malformed short hashes could also panic local store lookups. Store and retrieval reads now validate them.
- Nested shell quoting broke SSH writes to paths containing spaces or quotes. Remote writes now quote each path once, use unique temporary files, and publish without overwriting existing content. Local replica writes use the same no-overwrite publication rule.
- A stalled SSH handshake or command could prevent trying another replica. These operations now have timeouts.
- Watch interpreted a path removed from the host profile as a deleted file and restored it. It now limits changes to the current watch list and uses the current classification for deleted files.
- Retrieve dry runs wrote objects to the local store. They now read metadata only.
- The deployment guide's nologin account and forced false command blocked the replication transport. The guide now describes the required shell access and its limitations.

## Reproduced bugs

P1 findings can break recovery, leave services running altered configuration, or weaken account restrictions. P2 findings need a narrower trigger but still require a fix.

1. **P1: Pruning deletes objects referenced by the active baseline.** `pruneOldObjects` considers only the newest ten archives in each tier. After adopting an older generation with `retrieve --generation ... --apply`, its objects can fall outside that window. Even an unchanged armed snapshot invokes pruning. The next restore then depends on a peer still having those bytes.

   Reproduction: make generation 1 the live baseline, retain archives 1 through 11 with different content after generation 1, then prune. The probe reported `pruning deleted the active baseline's object`.

   Fix: include both live manifests in the retained object set and abort pruning if either existing live manifest cannot be read. Coordinate pruning with baseline writers using a process lock. Code: `cmd/warden/snapshot.go:237`.

2. **P1: Watch reloads a service before all of its files are repaired.** Watch calls the reload hook immediately after each file write. The CLI hook marks the service done after its first call, including failed calls. When two files map to one unit, the only reload sees one repaired file and one altered file. The later repair is never loaded. A subsequent clean watch pass does not retry the reload.

   Reproduction: alter two files mapped to the same fake unit. The fake systemctl checks both files at reload time. Its only invocation recorded `partial`, although both files were repaired before the pass ended.

   Fix: finish file repairs before reloading each affected unit once. Persist failed reloads for retry on later passes. Code: `internal/watch/watch.go`, `cmd/warden/watch.go:41`.

3. **P1: An indefinite account lock can remain recorded after its shell restriction is undone.** `/etc/passwd` is auto-restored by default. That can undo the shell change made by account locking. Reconcile reports the lock active without checking or reapplying it. The password lock may remain, but that does not establish that every login route is blocked.

   Reproduction: add a zero-duration lock, simulate an external reset of the backend's lock state, then reconcile an hour later. Result: `active=[example] but actual lock=false`. The `/etc/passwd` interaction was confirmed by source inspection; an SSH login against a real Linux host was not tested.

   Fix: define how active lock state overlays the approved account files, enforce that policy during restoration, and preserve the original shell for explicit unlock. Periodic re-locking alone leaves a gap after every restore. Code: `internal/accountlock/accountlock.go:277`, `cmd/warden/config.go`, `internal/watch/watch.go`.

4. **P1: Permission-only changes are missed.** Manifest Diff and restore Plan compare hashes without comparing modes. Existing-file writes also retain existing permissions. A config file made world-writable can be reported clean and retain that mode after a later content repair.

   Reproduction: snapshot a file with mode 0600, chmod it to 0666, and plan a restore. Result: `world-writable config is reported unchanged`.

   Fix: compare modes, restore them explicitly, and verify mode as well as content. Include executable and special permission bits in tests. Code: `internal/manifest/manifest.go`, `internal/restore/restore.go:58`, `internal/watch/watch.go:212`.

5. **P1: Snapshot failures suppress audit and heartbeat replication.** `pushToTarget` returns early on missing or broken snapshot metadata or failed object pushes. Audit and heartbeat transmission occurs only after the tier loop, so the same backup failure also removes evidence and makes a running host appear offline.

   Reproduction: use an empty snapshot store, an existing audit log, and a reachable filesystem peer. The command reports the missing manifest and sends neither the audit segment nor heartbeat.

   Fix: collect errors separately for each tier, audit, and heartbeat; attempt all independent transfers before returning the combined failures. Code: `cmd/warden/replicate.go:159`.

6. **P1: Local archives silently overwrite an existing generation.** `Manifest.Archive` uses `os.WriteFile` despite its no-overwrite contract. After an old generation is adopted, snapshot and accept derive the next number from that older live generation. This can reuse a generation already archived and replicated. Local and remote copies then disagree because remote writes retain their first copy.

   Reproduction: archive generation 1 twice with different records. Both calls succeed and the second replaces the first.

   Fix: publish archives atomically without replacement, reject conflicting records, and allocate generations monotonically under a shared process lock. Existing archives must be checked before allocating a number after rollback. Code: `internal/manifest/manifest.go:128`, `cmd/warden/snapshot.go`, `cmd/warden/accept.go:95`.

7. **P2: A failed restore leaves the mapped service stopped.** A write or verification error returns after the stop action, without service recovery. A missing parent directory alone is sufficient to trigger it.

   Reproduction: provide valid stored content but restore into a missing parent directory. The fake systemctl records only `stop`; Apply reports a write error.

   Fix: stage and validate writes before stopping services, track previous service state, and define rollback and restart behavior for each failure point. Do not blindly restart a service with partially repaired configuration. Code: `internal/restore/restore.go:123`.

8. **P2: A JSON null audit cursor crashes replication.** Unmarshalling `null` succeeds but leaves a nil map. The first successful audit push then assigns into that map and panics. Syntax-error recovery does not cover this case.

   Reproduction: put `null` in the audit push state file, create an audit log, load the state, and push. Result: `assignment to entry in nil map`.

   Fix: normalize null to an empty map and validate offsets and digests before using cursor entries. Code: `cmd/warden/replicate.go:251`.

## Additional source findings

- **Backup deletion remains possible with receiver credentials.** SSH transport executes arbitrary shell commands as an account that owns the backups. Client-side write-once behavior cannot stop a stolen key from deleting them. Enforce retention on the receiving host through a restricted protocol or separately controlled snapshots. Code: `internal/replicate/ssh_target.go`.
- **Baseline operations are not transactional.** Snapshot, accept, retrieve, and prune have no shared process lock; manifest and response-state files are written in place. Concurrent operations can lose updates, and interrupted writes can leave invalid JSON. Use atomic publication and a shared lock across operations that mutate baselines or prune objects.
- **Accept can save a manifest whose object was never stored.** Generate hashes the file, then accept reads it again and stores the second read without comparing its hash to the recorded one. A concurrent edit between those reads leaves the new manifest referencing absent content. Apply the verification already used by snapshot. Code: `cmd/warden/accept.go:104`.
- **Non-regular watched files can stall a check.** Generate skips directories but attempts to open and hash other file types. Replacing a watched path with a FIFO can block the open indefinitely; a device can provide an unbounded stream. Reject unsupported file types and avoid blocking opens. This was inspected in source, not exercised against devices. Code: `internal/manifest/manifest.go:207`.

## Proposed features

| Priority | Feature | Useful completion criteria |
| --- | --- | --- |
| 1 | `verify-backups --repair` | Check objects for active and retained generations; verify hashes on each configured replica; report missing, corrupt, and unreachable copies separately; repair the local cache from a verified source. Default mode must not modify anything. |
| 1 | Restricted backup receiver | Force one protocol entry point per SSH key; validate identifiers; confine each source to its own root; enforce write-once publication and receiver-owned retention. Tests must attempt deletion, overwrite, and path traversal. |
| 2 | Restore preflight and service transactions | Check destination parents, object availability, file type, and permissions before stopping services; validate service configuration; restore all files for a unit before starting or reloading it. Preserve the previous service state. |
| 2 | `profile validate` | Report uncovered detected services, missing paths, non-regular files, conflicting tier assignments, absent unit mappings, attribution-log availability, and whether configured replicas can be read. Support a strict pre-arm check. |
| 2 | Backup health in status | Show the last successful verification, usable replica count, pending service reloads, and incomplete snapshots. A delivered heartbeat must not imply that backups are recoverable. |
| 3 | Signed manifest lineage | Authenticate source identity and manifest content; maintain a generation record outside the source host; require an explicit choice for rollback. Hash checking alone does not authenticate metadata. |

Fix active-baseline retention, archive generation allocation, and service reload ordering before adding automated repair schedules. Otherwise a scheduled verifier can repair content that the next prune deletes, or report healthy backups while services still use altered configuration.

The eight probes failed against `92834c8`. They are now permanent regression tests in `cmd/warden/review_regression_test.go` and pass with the fixes. Additional tests cover receiver confinement and SSH transport, signed manifests, mode-only repairs, service rollback, pending reload retry, backup verification/repair, explicit rollback, process locking, and non-regular files. A scored-image deployment test has not been run.

Implemented commands: `verify-backups`, `profile validate`, `restore --preflight`, `arm --strict`, `receive`, and `manifest-keygen`. Status includes backup verification and pending reloads. Receiver restrictions and signature verification require the deployment configuration in DEPLOYMENT.md; existing shell targets remain compatible. Service syntax validation requires explicit validator commands in the host profile. Default verification is read-only. There is no new repair timer; verification runs when invoked by an operator or their existing scheduler.
