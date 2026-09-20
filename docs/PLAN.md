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

## Phase 3 — opmenu's remaining commands

The most sensitive component; do this after Phases 1–2 so `status` and `restore` have real logic to call into.

- `runStatus`: manifest generation, last snapshot time, last `watch` result, sentinel registration state — read-only, no TOTP required, so keep it that way deliberately.
- `runOpmenuRestore`: call `restore.Plan`/`Apply` the same way the `restore` subcommand does, defaulting to dry-run unless the parsed args explicitly ask to apply.
- End-to-end test of the forced-command path itself: a real `authorized_keys` entry, a real SSH client hitting it, confirming `from=` and the TOTP gate actually block what they're supposed to block. Unit tests around `Handle` already cover the dispatch logic; they don't cover the SSH layer in front of it.

## Phase 4 — sentinel's real registrations

- Build the actual `[]sentinel.Registration` list in `cmd/warden/sentinel.go`: authorized_keys entry (delegate the check to manifest/watch rather than duplicating it), systemd timer unit file, cron entry.
- Every check/recreate reads the relevant file directly — no `systemctl`/`crontab` shell-outs, per the design's threat model.

## Phase 5 — Deployment prep

- Fill in `deploy/install.sh`'s `CHANGE-ME` values and confirm the naming (`svchelper` is a placeholder) actually blends in with whatever's already running on the target boxes.
- Generate and securely distribute the TOTP seed and the team's replication-only SSH key ahead of time — neither belongs in this repo.
- Rules of engagement check: confirm with organizers/advisors that a forced-command SSH channel with auto-revert is permitted before any of this touches a real box. Don't skip this because the code is ready.

## Phase 6 — Verification (design doc's "Verification Plan")

- Unit tests: covered incrementally per phase above rather than as one pass at the end.
- Integration test in a VM mirroring the actual target distro: run `install.sh`, kill the sentinel and confirm it respawns, edit a watched config and confirm `watch` reverts it, delete the SSH key and confirm `sentinel-check` restores it.
- Adversarial test before the real competition: a teammate with no knowledge of where to look tries to find and kill this, timed, so the team knows its actual survival window instead of assuming one.
