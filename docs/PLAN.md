# Implementation Plan

Tracks what's built against [DESIGN.md](DESIGN.md) and what's left, broken into phases. Update this as phases land — it's meant to stay current, not describe a single point in time.

## Phase 0 — Scaffold and core data layer (done)

- Repo layout, `go.mod`, `LICENSE.md`, `Makefile`, `.gitignore`.
- `internal/manifest`: record format, hashing, `Generate`/`Diff`, load/save. Unit tested.
- `internal/store`: content-addressed, gzip-compressed object store with dedup and mark-and-sweep `Prune`. Unit tested.
- `internal/audit`: append-only JSON-lines logger. Unit tested.
- `internal/totp`: RFC 6238 TOTP, verified against the RFC's own test vectors.
- `internal/watch`: `Check()` — generate, diff, auto-restore `safe-auto-restore` changes, flag `confirm-first` changes, save. Unit tested against real files on disk.
- `internal/opmenu`: whitelist dispatch (`status`/`restore`/`shell`), TOTP gate in front of everything but `status`, audit logging of every request (accepted or rejected). Unit tested. `StatusFn`/`RestoreFn` are injected and still stubbed by the CLI layer.
- `internal/sentinel`: `Run()` — check each registration, recreate what's missing, report what happened. Unit tested. Not yet wired to real registrations.
- `internal/restore`: `Plan()` (dry-run diff against a snapshot) implemented and usable; `Apply()` is a stub.
- `internal/replicate`: `Target` interface, `SSHTarget`/`FSTarget` types, all methods stubbed.
- `cmd/warden`: Cobra root and all six subcommands wired. `snapshot` and `watch` run end-to-end against real paths; `restore` dry-run works via `Plan`; `replicate`, `sentinel-check`, and `opmenu`'s restore/status paths are stubbed pending their packages.
- `deploy/systemd/*.template` and `deploy/install.sh`: structurally complete, with `CHANGE-ME` placeholders for anything box- or competition-specific.

## Phase 1 — Finish the local repair path (done)

The parts of the design that only need this box, no network.

- `internal/restore.Apply`: stops the mapped systemd unit via `os/exec`, writes from the store, reverifies the hash, restarts the unit. Returns one `EntryResult` per path instead of aborting the batch on the first failure. Unit tested, including the "no service mapped" and "unchanged path is skipped" cases.
- `internal/manifest`: added `Archive`/`LoadGeneration`/`Generations` so generations are retained as `manifest-<n>.json` files rather than overwritten in place. Unit tested.
- `cmd/warden/config.go`: `watchedPaths`/`classifyPath`/`serviceForPath` now hold a worked example (passwd/shadow/sudoers/sshd_config as confirm-first, nginx/apache/mysql/sshd as safe-auto-restore with service mappings) instead of being empty. **Still needs a real pass**: this is a template covering common CCDC services, not this season's actual scored image — confirm the real path list and service map before relying on it.
- Two snapshot tiers: `snapshot --tier config|data` (config is also what `watch` checks), `cmd/warden/snapshot.go` archives each generation and prunes `store` objects outside the last `retainGenerations`. `restore --snapshot <id>` now loads a specific archived generation via `manifest.LoadGeneration`. Two new systemd timer pairs added to `deploy/systemd/` and wired into `install.sh`.

## Phase 2 — Off-host replication (done)

- `internal/replicate.SSHTarget`: transfers over `golang.org/x/crypto/ssh` using small `sh -c` exec commands (`mkdir`/`test -e`/`cat > tmp && mv`) rather than SFTP, so the only third-party dependency stays the one the design calls for. Host key verified via `ssh.FixedHostKey` against a key pinned at build time — `DialSSH` takes the expected host key as a parameter, it never learns one on first connect. Tested against a real in-process SSH server (a minimal `ssh.ServerConfig` that execs through the local shell) covering Put/Has, additive-only (a second `Put` under the same hash doesn't clobber), and both host-key and client-key rejection.
- `internal/replicate.FSTarget`: same `Target` interface, plain files under `objects/`/`manifests/`, additive-only writes via temp-file-then-rename. Unit tested.
- `internal/replicate.Push`: walks a manifest's records, pulls anything missing from the local `store`, calls `target.Put`, then pushes the manifest generation itself if the target doesn't have it yet — restoring from a replica only needs to list `manifests/manifest-*.json` and take the max, no separate "latest" pointer to keep additive-only. Unit tested against a fake in-memory `Target`.
- `cmd/warden/replicate.go`: parses `buildReplicateURL` (`ssh://user@host[:port]/root` or `file:///path`) and dispatches to the right backend. New build-time values `buildReplicateKey` (base64 PEM, ssh:// only) and `buildReplicateHostKey` (authorized_keys-format pinned host key), wired into the `Makefile`.
- Still open, and it's a decision only the team can make: is there an actual second team-controlled box this season, or does `replicate` point at removable media instead? Generate the replication-only key pair and the destination's host key ahead of time either way (Phase 5).

## Phase 3 — opmenu's remaining commands (done)

The most sensitive component; landed after Phases 1–2 so `status` and `restore` had real logic to call into.

- `runStatus`: manifest generation, last snapshot time, and the last recorded `watch` and `sentinel-check` pass — read from a new `audit.Read`/`audit.LastByComponent` (both unit tested, including a skip-malformed-trailing-line case for a log truncated mid-write). Still no TOTP required, deliberately. `watch`/`sentinel-check` now also log a `"pass"` summary entry each run so there's always something recent for `status` to report, even when nothing changed.
- `runOpmenuRestore`: calls the same `restore.Plan`/`applyPlan` the `restore` subcommand does — the apply logic was factored out of `cmd/warden/restore.go` into shared `planLines`/`applyPlan` helpers so the two entry points can't drift. Defaults to dry-run; applies only when the parsed SSH command's last argument is literally `apply` (there's no `--flag` over a raw `$SSH_ORIGINAL_COMMAND` string).
- Verified the whole chain (manifest → audit log → status string; drift → plan → apply → restored content) against a temp directory standing in for `/var/lib/warden`, since `cmd/warden`'s data paths are fixed consts by design and not something a unit test can override.
- **Not done here, moved to Phase 6**: an end-to-end test of the SSH forced-command layer itself (`authorized_keys`' `from=`/`command=` actually blocking what they should). That's enforced by sshd against the installed `authorized_keys` line, not by anything in the `opmenu` package, so it belongs in the VM integration test where `install.sh` actually runs, not a Go unit test. `Handle`'s own dispatch/TOTP logic is already unit tested independent of that layer.

## Phase 4 — sentinel's real registrations (done)

- `cmd/warden/units.go`: unit/cron/authorized_keys names and content are all derived from the running binary's own install path (`os.Executable()`), not a second baked-in name — `deploy/install.sh`'s unit names are now derived from `INSTALL_PATH`'s basename too (`BINARY_NAME="$(basename "$INSTALL_PATH")"`), so both sides agree without a shared config file.
- `cmd/warden/registrations.go`: `buildRegistrations` wires three checks into `sentinel.Run` — `authorized_keys` entry, the sentinel's own systemd timer (service file + timer file + the `timers.target.wants` enabled symlink, since a timer file without the symlink never fires), and its own cron entry. Every `Check` reads the relevant file directly (`os.ReadFile`/`os.Lstat`), never `systemctl status`/`crontab -l`, per the design's threat model. Every `Recreate` is additive: the authorized_keys and cron writers only ever append/dedup their own line, never touching another key or job already on the box (unit tested explicitly for this). `systemctl daemon-reload`/`enable --now` remains the one shell-out, needed to actually activate a timer — the same exception already accepted for `restore.Apply`'s service restarts, and just as untestable without a real systemd, so it's unverified below the VM-integration level.
- All the file-manipulation logic (not the final `systemctl` call) took explicit paths as parameters rather than closing over the real `/etc`, `/root`, `/var/spool` consts directly, so it's unit tested against temp directories the normal way.

## Phase 5 — Deployment prep

Most of what's left here is team decisions and one-time manual steps, not code — `docs/DEPLOYMENT.md` is the actionable checklist; this section just tracks what tooling now exists to support it.

- `scripts/generate-keys.sh`: generates the replication-only SSH keypair and the TOTP seed into `secrets/` (added to `.gitignore`), and prints a ready-to-fill `make build` invocation. Verified its output round-trips through our own code (`ssh.ParsePrivateKey` on the base64'd key, `totp.Generate`/`Validate` on the seed) before trusting it.
- `deploy/install.sh` now refuses to run (`require_filled_in`) if `TEAM_PUBKEY`/`TEAM_FROM_IP` are still `CHANGE-ME` placeholders or the binary hasn't been built yet — it can't judge whether `INSTALL_PATH` genuinely blends in with a given box, though, so that part's still a manual call per box.
- `warden debug-config` (hidden, hasn't shipped to a box — meant to be run on the build machine against a native build right after `make build`): prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Answers "did my build actually capture what I intended" without needing to exercise opmenu/replicate for real first.
- **Still open, and these are the team's calls, not code**: the actual `INSTALL_PATH`/naming convention per box, the real `TEAM_FROM_IP`, whether there's a second box for replication (Phase 2) or removable media, and the rules-of-engagement confirmation with organizers/advisors — `docs/DEPLOYMENT.md` step 0, deliberately first, not last.

## Phase 6 — Verification (design doc's "Verification Plan")

- Unit tests: covered incrementally per phase above rather than as one pass at the end.
- **Integration test — done, against a real target, not a mock.** No hypervisor was available, so the stand-in was a privileged Debian 12 container running actual systemd as PID 1 (`docker run --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw ... /sbin/init`), with real `sshd`, `cron`, and `nginx` installed — close enough to a target box that `install.sh` needed zero changes to run against it unmodified. Ran the design doc's exact checklist: `install.sh` end to end, tampered a `safe-auto-restore` file and confirmed `watch` reverted it, tampered a `confirm-first` file and confirmed it was flagged but left alone, killed the sentinel's systemd timer + cron entry + `authorized_keys` line and confirmed `sentinel-check` respawned all three, and hit the real forced-command SSH entry with two separate client containers on a controlled subnet — the same key from the allowed IP got in, the identical key from a different IP was rejected by `from=`, and `opmenu`'s TOTP gate rejected a missing code, a wrong code, and accepted a real one (computed from the baked-in seed via `internal/totp` itself).
- **This found three real bugs, since fixed:**
  1. `deploy/install.sh`'s cron step aborted under `set -e`/`pipefail` on a box with no pre-existing root crontab — `grep -vF` on empty `crontab -l` output exits 1, killing the script before the new line was ever written. Wrapped in `|| true`.
  2. `cmd/warden/config.go`'s `objectsDir` was `dataDir + "/objects"`, but `store.New` already creates its own `objects/` subdirectory under whatever root it's given — every store operation was writing to a doubly-nested `.../objects/objects/...` path. Renamed to `storeRoot = dataDir` and passed that instead.
  3. The bigger one: `snapshot --tier config` and `snapshot --tier data` shared one `manifest.json`, so `install.sh` running the data-tier snapshot right after the config-tier one silently erased `watch`'s baseline (data tier's path list is still empty per Phase 1). Separately, `watch.Check()` was writing its own incrementing generation back to that same file on every run — interleaving with `snapshot`'s own generation numbers and, worse, capable of recording a baseline hash for content `watch` itself never called `store.Put` on, which would make a later restore of that exact state fail. Fixed both: each tier now has its own manifest lineage (`configManifestPath`/`configManifestsDir` vs. `dataManifestPath`/`dataManifestsDir`), and `watch` no longer writes the manifest at all — it treats the last `snapshot` as read-only truth, which is also simpler to reason about. `internal/watch`'s tests were updated to establish their baseline the way `snapshot` actually does, instead of relying on `Check()` to bootstrap itself.
- Adversarial test before the real competition: a teammate with no knowledge of where to look tries to find and kill this, timed, so the team knows its actual survival window instead of assuming one. **Not done here** — this needs an actual teammate and the real target distro/box, not something to fake in this session.

## Phase 7 — Backup resilience hardening (done)

Prompted by a direct question: where do objects/the binary actually live, and is it equally hard for red team to kill the process *and* to destroy the backups? Process-kill resistance was already solid (no long-lived daemon — the persistence is in the timer/cron/`authorized_keys` registrations, proven to respawn in Phase 6); backup-deletion resistance had two real gaps.

- `/var/lib/warden` was a literal, hardcoded, tool-named directory despite the binary itself being installed under a disguised name (`svchelper` in the example config) — anyone browsing `/var/lib` saw straight through it. `cmd/warden/config.go`'s path constants became `loadPaths()`, deriving the data directory from the binary's own install path the same way unit names, the cron entry, and the `authorized_keys` line already were. Verified in the VM test: `/var/lib/svchelper` now sits invisibly among the box's other legitimate `/var/lib/*` directories.
- `replicate` — the actual mechanism for getting backups off-box — was never scheduled. `install.sh` now installs a `*-replicate` timer (every 15 min ± 3 min) whenever a target is configured, and `sentinel-check` now also verifies and respawns *that* timer's registration, closing the gap where red team could disable backups leaving the box without touching anything else sentinel watches.
- `runReplicate` now pushes both tiers, not just config — recovering a box means having its service data too, not just its watched configs.

## Phase 8 — Multi-box mesh replication and recovery (done)

Prompted by defending 6–8 boxes at once: link them together so backups aren't dependent on a single, separately-provisioned backup box, and give Warden a way to *pull* backups back, not just push them.

- `internal/replicate.Target` gained read methods (`Get`/`GetManifest`/`ManifestGenerations`) alongside the existing write ones, and every manifest method gained a `namespace` parameter. That namespace fix wasn't optional: pushing both tiers to one destination without it meant config- and data-tier generation numbers (both starting at 1) collided on the remote side — caught before it shipped, by testing the two-tier push against a real peer rather than assuming the existing single-tier test coverage generalized.
- `internal/replicate.Retriever` (`LatestGeneration`/`Pull`) and a new `warden retrieve <peer-url> [--tier] [--generation] [--apply]` command: the reverse of `replicate`, for recovering a box's own backups from a peer after a wipe/rebuild. Verified end-to-end in the VM test — wiped a box's entire local warden state, ran `retrieve --apply` for both tiers from a peer, and confirmed `watch`/`restore` were immediately fully functional again (including auto-restoring a fresh tamper).
- `buildReplicateURL`/`buildReplicateHostKey` (one target) became `buildReplicateTargets` (one or more `<url>||<hostkey>` pairs, `;;`-separated) — `runReplicate` pushes to all of them, collecting errors so one unreachable peer doesn't block the others; `retrieve` looks up a peer's pinned host key from this same list rather than trusting one supplied ad hoc.
- **Recommended topology, documented in `docs/DEPLOYMENT.md`**: a bidirectional ring — each box replicates to both neighbors — giving every box's data 3 total copies (itself + 2 neighbors) and making every replication relationship mutual, so losing any single box, or two non-adjacent ones, never costs another box its last copy. A distinct replication keypair per box is recommended so one compromised box's key can't write to the whole mesh, only its own two peers.
- **A real bug the mesh test caught**: `DialSSH`'s `ssh.ClientConfig` didn't restrict `HostKeyAlgorithms`, so algorithm negotiation could settle on a host key type other than the one pinned (e.g. the peer's RSA key) even when the peer also held the exact ed25519 key that was pinned — `ssh.FixedHostKey` would then reject a legitimate peer for presenting "the wrong" key, when the real problem was never asking for the right one. A single-host-key test SSH server never exercised this (nothing to negotiate between); a real sshd offering multiple key types did. Fixed by setting `HostKeyAlgorithms: []string{hostKey.Type()}`.
- Also added `internal/manifest.Parse` (decode manifest JSON with no backing file, for a generation just pulled from a peer) and a receiving-account setup recipe in `docs/DEPLOYMENT.md` (a dedicated non-root `warden-backup` user per box, `command="/usr/bin/false"`-restricted, since a stolen replication key should never yield an interactive shell on the peer).

## Phase 9 — Active detection and accessible docs (docs done, detection not started)

Two asks:

- Active "suspicious behavior" detection beyond file-content drift — explicitly scoped as *not* a SIEM replacement: a bounded set of high-signal checks (new SUID/SGID binaries, unexpected listening ports, cron/`authorized_keys` tampering outside what `watch`/`sentinel` already cover) that flag rather than auto-fix, since the correct response to a genuinely novel compromise indicator is a human, not a file revert. **Not started.**
- A beginner-friendly explainer — what Warden does, how, and what it deliberately doesn't do — distinct from `USAGE.md`'s command reference and `DESIGN.md`'s design rationale. **Done**: `docs/EXPLAINER.md`.
