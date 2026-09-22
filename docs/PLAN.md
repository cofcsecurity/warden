# Implementation Plan

Implementation history and remaining deployment checks. Later phases supersede earlier behavior; see [USAGE.md](USAGE.md) for the current interface.

## Phase 0: Scaffold and core data layer (done)

- Repo layout, `go.mod`, `LICENSE.md`, `Makefile`, `.gitignore`.
- `internal/manifest`: record format, hashing, `Generate`/`Diff`, load/save. Unit tested.
- `internal/store`: content-addressed, gzip-compressed object store with dedup and mark-and-sweep `Prune`. Unit tested.
- `internal/audit`: append-only JSON-lines logger. Unit tested.
- `internal/totp`: RFC 6238 TOTP, verified against the RFC's own test vectors.
- `internal/watch`: `Check()`, generate, diff, auto-restore `safe-auto-restore` changes, flag `confirm-first` changes, save. Unit tested against real files on disk.
- `internal/opmenu`: whitelist dispatch (`status`/`restore`/`shell`), TOTP gate in front of everything but `status`, audit logging of every request (accepted or rejected). Unit tested. `StatusFn`/`RestoreFn` are injected and still stubbed by the CLI layer.
- `internal/sentinel`: `Run()`, check each registration, recreate what's missing, report what happened. Unit tested. Not yet wired to real registrations.
- `internal/restore`: `Plan()` (dry-run diff against a snapshot) implemented and usable; `Apply()` is a stub.
- `internal/replicate`: `Target` interface, `SSHTarget`/`FSTarget` types, all methods stubbed.
- `cmd/warden`: Cobra root and all six subcommands wired. `snapshot` and `watch` run end-to-end against real paths; `restore` dry-run works via `Plan`; `replicate`, `sentinel-check`, and `opmenu`'s restore/status paths are stubbed pending their packages.
- `deploy/systemd/*.template` and `deploy/install.sh`: structurally complete, with `CHANGE-ME` placeholders for anything box- or competition-specific.

## Phase 1: Finish the local repair path (done)

The parts of the design that only need this box, no network.

- `internal/restore.Apply`: stops the mapped systemd unit via `os/exec`, writes from the store, reverifies the hash, restarts the unit. Returns one `EntryResult` per path instead of aborting the batch on the first failure. Unit tested, including the "no service mapped" and "unchanged path is skipped" cases.
- `internal/manifest`: added `Archive`/`LoadGeneration`/`Generations` so generations are retained as `manifest-<n>.json` files rather than overwritten in place. Unit tested.
- `cmd/warden/config.go`: `watchedPaths`/`classifyPath`/`serviceForPath` now hold a worked example (passwd/shadow/sudoers/sshd_config as confirm-first, nginx/apache/mysql/sshd as safe-auto-restore with service mappings) instead of being empty. **Still needs a real pass**: this is a template covering common CCDC services, not this season's actual scored image, confirm the real path list and service map before relying on it.
- Two snapshot tiers: `snapshot --tier config|data` (config is also what `watch` checks), `cmd/warden/snapshot.go` archives each generation and prunes `store` objects outside the last `retainGenerations`. `restore --snapshot <id>` now loads a specific archived generation via `manifest.LoadGeneration`. Two new systemd timer pairs added to `deploy/systemd/` and wired into `install.sh`.

## Phase 2: Off-host replication (done)

- `internal/replicate.SSHTarget`: transfers over `golang.org/x/crypto/ssh` using small `sh -c` exec commands (`mkdir`/`test -e`/`cat > tmp && mv`) rather than SFTP, so the only third-party dependency stays the one the design calls for. Host key verified via `ssh.FixedHostKey` against a key pinned at build time, `DialSSH` takes the expected host key as a parameter, it never learns one on first connect. Tested against a real in-process SSH server (a minimal `ssh.ServerConfig` that execs through the local shell) covering Put/Has, additive-only (a second `Put` under the same hash doesn't clobber), and both host-key and client-key rejection.
- `internal/replicate.FSTarget`: same `Target` interface, plain files under `objects/`/`manifests/`, additive-only writes via temp-file-then-rename. Unit tested.
- `internal/replicate.Push`: walks a manifest's records, pulls anything missing from the local `store`, calls `target.Put`, then pushes the manifest generation itself if the target doesn't have it yet, restoring from a replica only needs to list `manifests/manifest-*.json` and take the max, no separate "latest" pointer to keep additive-only. Unit tested against a fake in-memory `Target`.
- `cmd/warden/replicate.go`: parses `buildReplicateURL` (`ssh://user@host[:port]/root` or `file:///path`) and dispatches to the right backend. New build-time values `buildReplicateKey` (base64 PEM, ssh:// only) and `buildReplicateHostKey` (authorized_keys-format pinned host key), wired into the `Makefile`.
- Still open, and it's a decision only the team can make: is there an actual second team-controlled box this season, or does `replicate` point at removable media instead? Generate the replication-only key pair and the destination's host key ahead of time either way (Phase 5).

## Phase 3: opmenu's remaining commands (done)

The access menu uses the status and restore implementations from Phases 1 and 2.

- `runStatus`: manifest generation, last snapshot time, and the last recorded `watch` and `sentinel-check` pass, read from a new `audit.Read`/`audit.LastByComponent` (both unit tested, including a skip-malformed-trailing-line case for a log truncated mid-write). Status does not require TOTP. `watch`/`sentinel-check` now also log a `"pass"` summary entry each run so there's always something recent for `status` to report, even when nothing changed.
- `runOpmenuRestore`: calls the same `restore.Plan`/`applyPlan` the `restore` subcommand does, the apply logic was factored out of `cmd/warden/restore.go` into shared `planLines`/`applyPlan` helpers so the two entry points can't drift. Defaults to dry-run; applies only when the parsed SSH command's last argument is literally `apply` (there's no `--flag` over a raw `$SSH_ORIGINAL_COMMAND` string).
- Verified the whole chain (manifest → audit log → status string; drift → plan → apply → restored content) against a temp directory standing in for `/var/lib/warden`, since `cmd/warden`'s data paths are fixed consts by design and not something a unit test can override.
- **Not done here, moved to Phase 6**: an end-to-end test of the SSH forced-command layer itself (`authorized_keys`' `from=`/`command=` blocking what they should). That's enforced by sshd against the installed `authorized_keys` line, not by anything in the `opmenu` package, so it belongs in the VM integration test where `install.sh` runs, not a Go unit test. `Handle`'s own dispatch/TOTP logic is already unit tested independent of that layer.

## Phase 4: sentinel's real registrations (done)

- `cmd/warden/units.go`: unit/cron/authorized_keys names and content are all derived from the running binary's own install path (`os.Executable()`), not a second baked-in name, `deploy/install.sh`'s unit names are now derived from `INSTALL_PATH`'s basename too (`BINARY_NAME="$(basename "$INSTALL_PATH")"`), so both sides agree without a shared config file.
- `cmd/warden/registrations.go`: `buildRegistrations` wires three checks into `sentinel.Run`, `authorized_keys` entry, the sentinel's own systemd timer (service file + timer file + the `timers.target.wants` enabled symlink, since a timer file without the symlink never fires), and its own cron entry. Every `Check` reads the relevant file directly (`os.ReadFile`/`os.Lstat`), never `systemctl status`/`crontab -l`, per the design's threat model. Every `Recreate` is additive: the authorized_keys and cron writers only ever append/dedup their own line, never touching another key or job already on the box (unit tested explicitly for this). `systemctl daemon-reload`/`enable --now` remains the one shell-out, needed to activate a timer, the same exception already accepted for `restore.Apply`'s service restarts, and just as untestable without a real systemd, so it's unverified below the VM-integration level.
- All the file-manipulation logic (not the final `systemctl` call) took explicit paths as parameters rather than closing over the real `/etc`, `/root`, `/var/spool` consts directly, so it's unit tested against temp directories the normal way.

## Phase 5: Deployment prep

Remaining work is host-specific configuration and deployment. See [DEPLOYMENT.md](DEPLOYMENT.md).

- `scripts/generate-keys.sh`: generates the replication-only SSH keypair and the TOTP seed into `secrets/` (added to `.gitignore`), and prints a ready-to-fill `make build` invocation. Verified its output round-trips through our own code (`ssh.ParsePrivateKey` on the base64'd key, `totp.Generate`/`Validate` on the seed) before trusting it.
- `deploy/install.sh` now refuses to run (`require_filled_in`) if `TEAM_PUBKEY`/`TEAM_FROM_IP` are still `CHANGE-ME` placeholders or the binary hasn't been built yet, it can't judge whether `INSTALL_PATH` blends in with a given box, though, so that part's still a manual call per box.
- `warden debug-config` (hidden, hasn't shipped to a box, meant to be run on the build machine against a native build right after `make build`): prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Answers "did my build capture what I intended" without needing to exercise opmenu/replicate for real first.
- **Still open, and these are the team's calls, not code**: the `INSTALL_PATH`/naming convention per box, the real `TEAM_FROM_IP`, and whether there's a second box for replication (Phase 2) or removable media.

## Phase 6: Verification (design doc's "Verification Plan")

- Unit tests: covered incrementally per phase above rather than as one pass at the end.
- Integration used a privileged Debian 12 container with systemd as PID 1, sshd, cron, and nginx. It covered installation, auto-restore, confirm-first flagging, registration repair, source-IP restrictions, and valid/missing/invalid TOTP over SSH from separate client containers.
- Integration found three bugs, all fixed:
  1. `deploy/install.sh`'s cron step aborted under `set -e`/`pipefail` on a box with no pre-existing root crontab, `grep -vF` on empty `crontab -l` output exits 1, killing the script before the new line was ever written. Wrapped in `|| true`.
  2. `cmd/warden/config.go`'s `objectsDir` was `dataDir + "/objects"`, but `store.New` already creates its own `objects/` subdirectory under whatever root it's given, every store operation was writing to a doubly-nested `.../objects/objects/...` path. Renamed to `storeRoot = dataDir` and passed that instead.
  3. The bigger one: `snapshot --tier config` and `snapshot --tier data` shared one `manifest.json`, so `install.sh` running the data-tier snapshot right after the config-tier one silently erased `watch`'s baseline (data tier's path list is still empty per Phase 1). Separately, `watch.Check()` was writing its own incrementing generation back to that same file on every run, interleaving with `snapshot`'s own generation numbers and, worse, capable of recording a baseline hash for content `watch` itself never called `store.Put` on, which would make a later restore of that exact state fail. Fixed both: each tier now has its own manifest lineage (`configManifestPath`/`configManifestsDir` vs. `dataManifestPath`/`dataManifestsDir`), and `watch` no longer writes the manifest at all, it treats the last `snapshot` as read-only truth, which is also simpler to reason about. `internal/watch`'s tests were updated to establish their baseline the way `snapshot` does, instead of relying on `Check()` to bootstrap itself.
- Remaining verification: have a teammate attempt to disable Warden on the target distro and measure recovery time.

## Phase 7: Backup resilience hardening (done)

- `/var/lib/warden` was a literal, hardcoded, tool-named directory despite the binary itself being installed under a disguised name (`svchelper` in the example config), anyone browsing `/var/lib` saw straight through it. `cmd/warden/config.go`'s path constants became `loadPaths()`, deriving the data directory from the binary's own install path the same way unit names, the cron entry, and the `authorized_keys` line already were. Verified in the VM test: `/var/lib/svchelper` now sits invisibly among the box's other legitimate `/var/lib/*` directories.
- `replicate`, the mechanism for getting backups off-box, was never scheduled. `install.sh` now installs a `*-replicate` timer (every 15 min ± 3 min) whenever a target is configured, and `sentinel-check` now also verifies and respawns *that* timer's registration, closing the gap where red team could disable backups leaving the box without touching anything else sentinel watches.
- `runReplicate` now pushes both tiers, not just config, recovering a box means having its service data too, not just its watched configs.

## Phase 8: Multi-box mesh replication and recovery (done)

- `internal/replicate.Target` gained read methods (`Get`/`GetManifest`/`ManifestGenerations`) alongside the existing write ones, and every manifest method gained a `namespace` parameter. That namespace fix wasn't optional: pushing both tiers to one destination without it meant config- and data-tier generation numbers (both starting at 1) collided on the remote side, caught before it shipped, by testing the two-tier push against a real peer rather than assuming the existing single-tier test coverage generalized.
- `internal/replicate.Retriever` (`LatestGeneration`/`Pull`) and a new `warden retrieve <peer-url> [--tier] [--generation] [--apply]` command: the reverse of `replicate`, for recovering a box's own backups from a peer after a wipe/rebuild. Verified end-to-end in the VM test, wiped a box's entire local warden state, ran `retrieve --apply` for both tiers from a peer, and confirmed `watch`/`restore` were immediately fully functional again (including auto-restoring a fresh tamper).
- `buildReplicateURL`/`buildReplicateHostKey` (one target) became `buildReplicateTargets` (one or more `<url>||<hostkey>` pairs, `;;`-separated), `runReplicate` pushes to all of them, collecting errors so one unreachable peer doesn't block the others; `retrieve` looks up a peer's pinned host key from this same list rather than trusting one supplied ad hoc.
- **Recommended topology, documented in `docs/DEPLOYMENT.md`**: a bidirectional ring, each box replicates to both neighbors, giving every box's data 3 total copies (itself + 2 neighbors) and making every replication relationship mutual, so losing any single box, or two non-adjacent ones, never costs another box its last copy. A distinct replication keypair per box is recommended so one compromised box's key can't write to the whole mesh, only its own two peers.
- Multi-key SSH servers could negotiate a key type different from the pinned one. `DialSSH` now sets `HostKeyAlgorithms` to the pinned key's type. The issue was reproduced against sshd with multiple host keys.
- Also added `internal/manifest.Parse` (decode manifest JSON with no backing file, for a generation just pulled from a peer) and a receiving-account setup recipe in `docs/DEPLOYMENT.md` (a dedicated non-root `warden-backup` user per box, `command="/usr/bin/false"`-restricted, since a stolen replication key should never yield an interactive shell on the peer).

## Phase 9: Active detection and accessible docs (done)

- Active "suspicious behavior" detection beyond file-content drift, explicitly scoped as *not* a SIEM replacement: a bounded set of high-signal checks that flag rather than auto-fix, since the correct response to a novel compromise indicator is a human, not a file revert. **Done in Phase 21**: six checks, not the three originally scoped here (new SUID/SGID binaries, cron/`authorized_keys` tampering outside what `watch`/`sentinel` already cover, plus new local/domain accounts, new listening ports, and new packages), and an opt-in reaction (account lockout + IP ban) on top.
- A beginner-friendly explainer, what Warden does, how, and what it doesn't do, distinct from `USAGE.md`'s command reference and `DESIGN.md`'s design rationale. **Done**: `docs/EXPLAINER.md`.

## Phase 10: Default watch-list coverage, service detection, and gated auto-restore (done)

- **`configTierPaths` broadened** (`cmd/warden/config.go`): the shipped default now covers common CCDC-image services across both Debian- and RHEL-family paths (web, database, mail, DNS, file transfer/sharing, DHCP), not just the original nginx/apache/mysql trio. Safe to ship broad because `manifest.Generate` already skips any path that doesn't exist on a given box, nothing here requires a box to run all of it. Still not a substitute for confirming the real season's scored services (see `detect` below and the existing Phase 1 warning about never watching the scoring engine's own credentials).
- **`internal/detect`** (new package) + **`warden detect`** (new, read-only CLI command): scans running processes (via `/proc/<pid>/comm`, not `ps`, consistent with the rest of Warden never trusting an external binary it might not be able to verify) and on-disk config paths against a table of known CCDC services, and reports which of their configs are and aren't already in `configTierPaths`. Makes no changes itself, it's meant to answer "what should the watch list cover" before a competition, the same judgment call Phase 1 already flagged as the team's to make, just with less manual grepping.
- Added `arm` and `disarm`. Auto-restore is disabled until armed; suppressed drift and confirm-first changes are still logged. Arming takes a fresh config snapshot. Status reports armed state. These commands are available remotely through opmenu shell.
- Documentation updated throughout (`EXPLAINER.md`, `USAGE.md`, `DEPLOYMENT.md`) to cover the detect → harden → arm sequence as the first-hours-of-competition workflow, and `EXPLAINER.md`'s persistence-mechanism description was corrected, it previously described the timer/cron/authorized_keys trio as three equal mutual revivers, when only the timer and cron entry can trigger a check; the authorized_keys line is purely a passive target.

## Phase 11: Opt-in active response: attribute, ban, alert, accept (done)

- **`internal/attribution`** (new): parses sshd's own auth log (`/var/log/auth.log` or `/var/log/secure`) for `Accepted`/`Disconnected` line pairs and answers "which IPs had a session open at time T", never `last`/`who`/`w`, consistent with the rest of Warden's threat model of not trusting a binary that could be lying. A line it can't parse, or no log file at all, is "no evidence," never a guess.
- **`internal/autoban`** (new): a persisted ban list plus a `Firewall` interface (`iptables -I/-D INPUT -s <ip> -j DROP`, idempotent), kept as its own package specifically so `Reconcile`'s expire/reapply logic is unit-tested against a fake firewall, never a real one.
- **`internal/watch`**: `Result` now also carries `FlaggedChanges []manifest.Change` (full record detail, including the new MTime attribution needs), not just the flagged paths. Fixed a bug found while wiring this up: a *deleted* `ConfirmFirst` path (e.g. `rm /etc/shadow`) has no `New` record, so the old classification check (`change.New != nil && change.New.Class == ConfirmFirst`) never matched it, silently falling through to the auto-restore branch instead of flagging it, a deletion of the most sensitive files was being treated as ordinary drift. Now checks `Old.Class` when `New` is nil. Covered by a new test that fails on the old code.
- `react.go` separates response from integrity checks. It uses overlapping root SSH sessions, excludes the configured team IP or CIDR, and bans only a single remaining candidate IP. Every result is audited.
- **`warden ban <ip>` / `warden unban <ip>`** (new): manual override, same underlying `internal/autoban` primitives.
- `accept <path> <code>` updates one config baseline record after a second-factor check, preserving other records.
- `alerts` displays react entries in the calling session without broadcasting them.
- **`sentinel-check`**: now also calls `autoban.Reconcile` every pass, reapplies any active ban's firewall rule (in case it was flushed, e.g. by a reboot or `iptables -F`) and lifts explicitly timed bans after expiry; default IP bans now remain until `unban`.
- **Opt-in, off by default**: `AUTOBAN_ENABLED` is a new build-time value (`Makefile`, `main.go`), following `REPLICATE_TARGETS`'s existing pattern, attribution and flagging always run, but the firewall ban only fires if a build sets this, since it's a more assertive posture than the rest of Warden. Not wired into `opmenu`'s whitelist, `ban`/`unban`/`accept`/`alerts` are reachable via `shell`, the same way `arm`/`disarm`/`detect` already are.

## Phase 12: Deployment flow: cleanup, next-steps guidance, shell-history exposure (done)

- **`docs/DEPLOYMENT.md`** gained a "Quick reference" section up top mapping the whole flow (build machine → per-box deploy → verify → harden/arm → recovery) to its numbered sections, so a team can see the shape of the process before diving into any one step's detail.
- After access verification, the installer removes the transferred source binary and systemd templates as well as its own script.
- **`install.sh` now prints a "what's next" summary** (detect → harden → arm, plus a reminder to start `warden alerts` if `AUTOBAN_ENABLED`) right before it deletes itself, reading its own `debug-config` output to decide whether that last reminder applies, so the sequence doesn't depend on whoever ran the script separately remembering to open `docs/DEPLOYMENT.md`.
- Shell-history scrubbing was not added. Bash over opmenu's no-PTY channel is non-interactive and does not normally write history. Interactive shells retain their normal history behavior. DEPLOYMENT.md documents `HISTCONTROL=ignorespace` for those shells.

## Phase 13: Single-box build-and-install path (done)

- Added an on-host build driver. It collects configuration, can generate secrets, uses vendored modules when present, builds natively, verifies debug-config, and invokes the existing installer. Exported variables can supply configuration without prompts.
- **`deploy/install.sh`'s per-box `CHANGE-ME` values became `${VAR:-CHANGE-ME...}`**-style, so they can be overridden by exported environment variables instead of hand-editing the file, a small, fully backward-compatible change (identical behavior if nothing overrides them) that's what lets `build-and-install.sh` drive `install.sh` programmatically without duplicating its logic.
- On-host builds expose `-ldflags -X` secrets in the process command line during compilation. This is documented in the script, DESIGN.md, and DEPLOYMENT.md.
- Successful on-host installation removes the source checkout, vendored dependencies, Git metadata, and generated secrets. `KEEP_SOURCE=1` retains the checkout.
- DEPLOYMENT.md includes source transfer by scp, Git, or removable media and the on-host build procedure.

## Phase 14: Access layer off root, automatic naming, binary self-recovery (done)

- The team key now belongs to a dedicated non-root account named after the binary, with a validated NOPASSWD sudo rule for that binary. This supports `PermitRootLogin no`. Sentinel verifies both authorized_keys and sudoers. The installer creates the account and rule.
- The installer selects an unused name from two word lists, checking binaries, accounts, units, and sudoers files for collisions. `INSTALL_PATH` can override it. Generated names are enumerable and are not an access control.
- A spare binary and a cron-side `test`/`cp`/`chmod` sequence recover deletion without invoking the missing executable. The `binary-backup` registration keeps the spare synchronized. This does not detect a modified binary that still runs.
- Considered and declined a broader fix for the "PermitRootLogin no" conflict first: adding an install-time check that warns and requires override if that setting is found, before the account-based redesign was chosen as the fix instead of a workaround.

## Phase 15: Go auto-download, one-line bootstrap, cross-distro fixes (done)

- **`ensure_go`** (`scripts/build-and-install.sh`) replaces the old hard failure: if no `go` is found, it downloads the official upstream release for the box's own architecture (x86_64/aarch64) from go.dev, never a distro package, since names and versions vary and are often outdated, installs it to `/usr/local/go`, and continues. Requires the box to reach go.dev over HTTPS; falls back to a clear error pointing at the normal build-elsewhere path otherwise. Module *dependencies* (cobra, x/crypto, ...) already auto-download via plain `go build` when unvendored, this only closes the toolchain-itself gap.
- **`scripts/bootstrap.sh`** (new): a one-line entry point, `curl -fsSL <raw-url> | sudo bash`, that fetches the repo (git clone, or a tarball via curl/wget if git isn't present) into a randomly-named temp directory and hands off to `build-and-install.sh`. Same reachability/credentials caveats as cloning by hand.
- **Fixed a latent cross-distro bug**: `cronSpoolPath` was a hardcoded Debian/Ubuntu path (`/var/spool/cron/crontabs/root`); on RHEL-family boxes, `sentinel-check` would have silently written a cron entry to a file cron never reads there, since the real path is `/var/spool/cron/root`. Now a function that checks which layout is present.
- **`step_create_opmenu_user`** now detects the box's actual no-login shell (`/usr/sbin/nologin`, `/sbin/nologin`, or whatever `command -v nologin` finds) instead of assuming `/usr/sbin/nologin` exists, usrmerge makes that true on most current boxes, but not guaranteed everywhere.
- **Fixed the Phase 14 install-path prompt**: `build-and-install.sh`'s `collect_config` still manually prompted for `INSTALL_PATH` with a suggested default, defeating the auto-selection `install.sh` had just gained, it now leaves `INSTALL_PATH` empty by default too, so the single-box path gets the same automatic naming as the normal one.
- The installer detects existing state by matching `/var/lib/<name>/audit.log` and `.spare`, then asks before creating another installation.
- **`scripts/generate-team-key.sh`** (new): a small wizard for `TEAM_PUBKEY` specifically, meant to run on the operator's own machine, never a target box, generating the team's *login* private key on a box being defended would be exactly the exposure risk already avoided for TOTP/replication secrets. Prints the public key to reuse across every box in the competition, and reminds the operator it's one key for the whole season, not one per box. `build-and-install.sh`'s `TEAM_PUBKEY` prompt now points to it for anyone who doesn't already have a key.
- **`scripts/generate-keys.sh`/`show-totp-qr.sh`** (new): TOTP setup now prints a scannable QR code (`qrencode`, when available) and the `otpauth://` URI, not just a raw base32 string to type into an authenticator app by hand. `show-totp-qr.sh` redisplays it later (for onboarding another teammate) without regenerating the secret, which would invalidate everyone already using the old one.

## Phase 16: Static, rotatable second factor for events without phones (done)

- Added `StaticSecretPath`, read on every request and compared with `crypto/subtle.ConstantTimeCompare`. The static factor is an alternative to TOTP and can be rotated without rebuilding.
- **`warden rotate-secret [value]`** (new): writes (or replaces) that file, generating a random value if none is given, and logs the rotation to `audit.log`. Deliberately has no separate confirmation gate of its own, reaching a local shell to run it already means opmenu's own second-factor check (TOTP or a prior static secret) passed once already.
- **Made the default, not an opt-in step, after a follow-up ask**: initially shipped as something to run manually only if a team knew they'd need it; changed to `install.sh` running `rotate-secret` unconditionally as part of every install (a new `step_generate_static_secret`), immediately after the initial snapshot. Costs nothing for a team that ends up not using it, and means nobody has to remember a separate manual step, or worse, discover mid-competition that they needed to have done it days earlier.
- **Bootstrapping problem worked through explicitly**: a team with zero TOTP capability can't get their first `opmenu shell` to run `rotate-secret` the normal way, since that itself needs a passing second factor. Making generation automatic during install solves this directly, the value already exists by the time the operator needs it, printed once during the same install-time local/console access window already used to run `install.sh` itself, before ever depending on opmenu's SSH channel for a TOTP-gated action. `install.sh`'s next-steps summary and `docs/DEPLOYMENT.md` step 6 both point back to it rather than instructing a manual run.
- **`status`** now reports whether a static secret is currently set, alongside the existing armed-state line.

## Phase 17: Fixed the one-line bootstrap silently dying, then hanging, on its first prompt (done)

- Piping a script into Bash consumes stdin for script input. Later prompts encountered EOF and exited under `set -e`.
- Redirecting fd 0 near the top of a piped script caused Bash to read the remaining script from the terminal. That approach was removed.
- The scripts probe `/dev/tty` through fd 3 and redirect only the final `main "$@"` call when a controlling terminal exists. Without one, forwarded stdin is preserved. Phase 19 changes the documented bootstrap command.

## Phase 18: CI (done)

- CI runs on pushes and pull requests against main. Go checks include formatting, vet, build, and tests with the version from go.mod. A separate job runs `bash -n` on shell scripts outside vendor.

## Phase 19: Bootstrap command input (done)

- Bootstrap now uses `sudo bash -c "$(curl -fsSL <url>)"`. Passing the script as an argument preserves stdin for prompts.
- The terminal probe remains as a fallback for piped invocations; the documented command uses `bash -c`.

## Phase 20: PCDC hardening: on-box key generation, dependency bootstrapping, and uninstall (done)

- **On-box team-key generation** (`scripts/generate-team-key.sh --on-box`): the normal advice, generate `TEAM_PUBKEY` on a machine outside the competition network, doesn't hold at events where every box provided *is* the competition network (PCDC-style). Generates the keypair on the box itself, walks through getting the private half off before shredding it (an editor paste, not a heredoc, a heredoc-based first draft of this instruction turned out fragile against a real multi-hop terminal copy-paste, which surfaced as a live bug report; fixed by printing the key once instead of twice and pointing at `nano`/`vim` instead). `build-and-install.sh`'s wizard offers to run it inline rather than treating key generation as a separate step on a separately-chosen "safe" box, there's nothing to gain by picking one when none is safer than another.
- **`apt`/`dnf`/`yum` dependency auto-install**: `ensure_deps` (mirroring the existing `ensure_go`) installs `git`/`curl`/`cron`/`sudo`/`qrencode` if missing, best-effort. **Deliberately never installs `python3`**, even though the interactive TOTP-seed generator can use it if already present, it's also what tools like Ansible run on, and installing it as a side effect of setting up Warden would hand a defended box a capability red team's own tooling could use just as easily. Missing python3 degrades that one prompt gracefully instead (paste an existing seed, or skip TOTP and rely on the static secret alone).
- **`TEAM_FROM_IP` auto-detected** from the connecting operator's own subnet via `who -m` (not `SSH_CONNECTION`/`SSH_CLIENT`, `sudo` resets the environment by default on virtually every distro), a `/24` guess offered for confirmation, not applied unconfirmed, since it becomes the network ACL on the whole access layer.
- **`warden uninstall <code> [--force] [--yes]`**: reverses everything `install.sh` set up, for a setup gone wrong. Initially shipped with **no authorization check at all**: anyone with a root shell through *any* route, not just opmenu, could have run it to strip every persistence mechanism Warden has in one command. Fixed before this ever reached a real deployment: now requires the same TOTP-or-static-secret code `restore`/`shell`/`accept` already require (extracted into a shared `cmd/warden/secondfactor.go`'s `verifySecondFactor`, which `accept.go` was also quietly updated to use, it had been checking TOTP only, silently unusable at phone-free events), plus a typed `yes` confirmation on top. Refuses on an armed box without `--force`.
- Fixed early exits under `set -e`: `collect_config` now uses an explicit `if` for the optional auto-ban setting; `ask` handles EOF; client-IP detection and Go-version lookup handle empty grep results under `pipefail`.
- **`warden detect` now also lists everything currently protected on this box** (every `configTierPaths`/`dataTierPaths` entry that exists here), not just the services-found-vs-watched scan it already did, a plain answer to "what is Warden protecting right now," not just "what should be added."

## Phase 21: Active anomaly detection and opt-in account lockout (done)

- `internal/anomaly` implements six checks: local/domain accounts, SUID/SGID binaries, cron, authorized keys, listening TCP ports, and installed packages. TCP ownership comes from `/proc/net/tcp{,6}`. Package changes have no reliable culprit. Each check stores a JSON baseline; the first run establishes it without reporting findings.
- Domain accounts are detected by comparing `getent passwd` with `/etc/passwd`. They are flagged without a local culprit because local account tools cannot lock them.
- **`internal/accountlock`**: mirrors `internal/autoban`'s shape exactly. `Lock` = `passwd -l` + `usermod -s <nologin>` (covers SSH-key access, not just password auth) + best-effort session kill; `Unlock` restores the shell `Lock` recorded first.
- `canLockAccount` checks local-account membership, excludes root and opmenu, then checks `SAFE_ACCOUNTS`. Only the safe-account list can be overridden with manual `--force`. Both automatic and manual locks use this gate.
- **Armed-gating is stricter here than the existing guarded-file IP-ban**: both new reactions also require `isArmed(p)`, a deliberate divergence, since (unlike an inherently-suspicious `ConfirmFirst` edit) several of these six checks can trigger on things a team does routinely while still setting up.
- Uninstall now unlocks recorded accounts before deleting their state. Sentinel now calls `accountlock.Reconcile` so explicitly timed locks expire.
- Removed an outdated Makefile comment about rules of engagement.

## Phase 22: Code review fixes (done)

- Sentinel now checks all Warden timers through `timerRegistration`: watch, both snapshot tiers, scan, sentinel, and configured replication. Previously only sentinel and replication timers were repaired.
- Audit segments now replicate over the additive-only SSH channel. Per-peer offsets and digests track new data and rotation; `retrieve --audit` recovers the segments. Entries include a host field. Local retention is capped at 8 MiB plus one rotated file, and readers include both files.
- Manifests now record whether a path is a symlink. Both restore paths refuse to write through symlinks and flag them, preventing a watched path from redirecting a write elsewhere.
- Account baselines now record fields, and SUID baselines record content hashes. This detects modifications to existing entries, including UID changes, group membership changes, and replaced binary contents. Legacy name-only records are reseeded without reporting every entry as changed.
- Scan and replication now log a pass even when nothing changed. Status includes their most recent runs alongside watch and sentinel.
- Ambiguous attribution still suppresses automatic bans. Candidate IPs are recorded in `candidate_ips` and displayed by `warden alerts` for operator review. A second root session can force this ambiguous result.
- **Smaller fixes in the same pass**: TOTP codes are now single-use (`SpentTOTPPath`, RFC 6238 §5.2, a captured code was good for its whole ~90s window); `accountlock.Add` no longer records an already-`nologin` shell as the one to "restore" later (which would have left an account locked forever after a store/OS desync); `autoban.Reconcile`/`accountlock.Reconcile` handle each entry independently instead of aborting the batch on the first failure, so one flaky `iptables` call can't strand every later ban un-reasserted; `SSHTarget.ManifestGenerations` no longer reads any `ls` failure as "peer holds nothing," which could make `retrieve` report an empty peer that in fact holds everything; and `audit.Read` survives an over-long line instead of failing the whole read. `docs/EXPLAINER.md` also still told newcomers that detection was "a known gap," which Phase 21 had already shipped.

## Phase 23: Dead-man's switch, fleet view, and broader service coverage (done)

- Each replication push writes a heartbeat containing the hostname, timestamp, expected interval, armed state, manifest generation, recent passes, and active response counts. Sentinel reads received heartbeats and logs an overdue alert and a return event. It forgets expired peer records. Heartbeats can be forged by anyone with write access to the receiving directory and never trigger automatic response.
- **`warden fleet`**: this box plus every peer replicating to it, with overdue heartbeats marked. In the documented ring that's two neighbours per box; adding one box to every other box's `REPLICATE_TARGETS` makes it a full fleet view with no other change, and `--from` covers a receiving account somewhere unusual or a `file://` target on removable media.
- Added local `warden status`, using the same `runStatus` report as opmenu.
- Added default paths, unit mappings, and detection for Docker, containerd, MongoDB, Redis, Elasticsearch, Tomcat, WordPress, chrony/ntpd, SNMP, xrdp, VNC, PAM, and persistent firewall rules. PAM and firewall files were initially confirm-first; Phase 25 changes PAM to auto-restore.
- `serviceForPath` checks candidate unit names for the installed service, covering distro differences such as chrony/chronyd and redis/redis-server. If no unit exists, restore writes the file without a service operation. A test checks consistency between known config paths and the default watch list.
- The installer and build wizard print the commands for detection, hardening, scan baselining, and arming. They leave auto-restore disabled. Uninstall notes that peers will report missing heartbeats.

## Phase 24: Review what's being baselined at arming time (done)

Arming now shows changes since the previous baseline before accepting the current files. This lets operators review both hardening edits and possible tampering during the disarmed window.

- **`arm` now reviews before it writes anything**: every watched path added, modified or removed since the last baseline, each tagged with its class, confirm-first paths sorted first (accounts, sudo, SSH, PAM, firewall rules, the ones an attacker touches shouldn't be buried under routine service-config edits). The list is printed, logged as an `arm`/`pre-arm-review` audit entry, and has to be acknowledged before anything is snapshotted or armed.
- `arm` prompts and reads confirmation. EOF causes refusal with guidance to use `arm --yes`, which skips the prompt but retains the printed review. This avoids treating `/dev/null` as an interactive terminal.
- Both harden-before-install and harden-after-install are documented. An empty review is expected in the first case; in the second it may mean the changed files are absent from the watch list. Arming reports that possibility.
- Re-arming reviews changes made during the maintenance window before replacing the baseline.

## Phase 25: Make auto-restore restore (done)

- SSH, passwd, group, sudoers, and PAM files now default to auto-restore. Password hashes and saved firewall rules remain confirm-first because restoring them can undo credential rotation or a saved response rule. Runtime IP bans are maintained separately by sentinel.
- After restoring a file, watch reloads its installed service with `reload-or-restart`, once per unit per pass. Failures are logged without stopping other restores. This makes restored configuration available to running services.
- Armed config snapshots preserve baseline records for changed, deleted, and newly appearing paths, log declined changes, and avoid creating an unchanged generation. Only `accept` and `arm` update the armed config baseline. Data snapshots continue normally.
- Before reviewing changes, arm prints watched paths, second-factor and replication settings, active-response settings, and account exclusions.

## Host profiles and recovery follow-up

- `restore --tier config|data` supports latest and archived individual-file restores; opmenu keeps its config default.
- IP bans default to indefinite, with timed manual bans available. Account locks also default to indefinite; positive manual durations still expire.
- `/etc/warden/profile.json` replaces built-in watched paths, classes, and service mappings without rebuilding, and can extend detection. The actual scored image still needs operator review.
- Detection includes unknown running process names. Attribution falls back to the system journal and excludes logged team-key source IPs in addition to the configured team address.

## Backup recovery and review fixes

- Missing or corrupt objects are recovered from configured local replicas and SSH peers, verified against their manifest hash, and cached.
- Missing manifests fall back to local archives and peers. Explicit generations cannot fall back to another generation.
- Retrieve supports automatic source selection and a metadata-only dry run.
- SSH handshakes, session opens, and commands have timeouts. Remote writes quote paths correctly and use unique temporary files with no-overwrite publication. Local replica publication also avoids overwrites during concurrent writes.
- Watch honors the current profile for removed paths and deleted-file classifications.
- Remaining findings and feature candidates are recorded in [REVIEW.md](REVIEW.md).


### Review implementation

- Fixed active-baseline retention, generation reuse, mode drift, early service reload, restore failure cleanup, account-lock overlays, and audit cursor validation.
- Added atomic state publication and a shared mutation lock; accept verifies content before recording a new baseline; non-regular file reads fail without blocking.
- Added backup verification and local repair, restricted receivers, signed manifests, explicit rollback checks, profile validation, restore preflight, and backup health in status.
- Deployment options and migration steps are in DEPLOYMENT.md. No scheduled repair is enabled by default.
