# Warden

Design notes for the persistence and backup/restoration system.

Sep 20, 2026

## Project Description

Warden is a Go binary built for the CofC Cybersecurity Club's SECCDC/PCDC defense team. It provides two things: resilient, audited persistence back into a host red team is actively attacking, and automatic backup/restore for the configs and service data that keep a box scored. It works by piggybacking on services already running on the box and by continuously re-asserting known-good state, rather than by opening new listeners or holding a standing shell open.

## Overview and Goals

Warden gives the defense team a way back into a host during a CCDC-style competition that survives red team's attempts to kill it, without adding a new hole red team could also use.

Core constraints:

1. Survives kill attempts: no single point of failure. Killing one process or removing one config entry should not permanently cut access.
2. No new attack surface: prefer piggybacking on services already running rather than opening new listeners.
3. Retains repair access, not just entry: the point is to get back in and fix what broke, not just hold a shell.
4. Team-only: access is restricted to the defense team's key and source IP, not a general-purpose backdoor.
5. Auditable: every action Warden takes is logged, so the team can show exactly what it did if questioned.

## Rules of Engagement Note

Confirm this is allowed before deploying any of it. SECCDC, PCDC, and CCDC events generally have rules about what defensive tooling is permitted, and a hidden, self-reviving, forced-command SSH channel can look identical to a red-team implant if white team finds it and the team can't immediately explain it.

Before deployment:

1. Check the competition's rules of engagement for language on persistence mechanisms, backdoors, or non-standard access methods.
2. If anything here is ambiguous, ask an organizer or advisor before the competition starts, not during it.
3. Keep the audit log described throughout these notes current at all times, since it is the team's evidence if a judge asks what Warden did and why.

## Architecture Decision: Separate Binary

Warden ships as its own compiled binary, kept separate from any other tooling the team runs on the box (enumeration scripts, monitoring agents, and the like).

A read-only enumeration tool is lower value if red team dumps or reverses it. The moment persistence and backup/restore capability gets bundled into that same binary, it becomes the single highest-value target on the box: compromising it would hand over both recon and the team's own access channel. Keeping Warden as its own binary, with its own permissions, means reversing it only ever exposes Warden's own blast radius — not whatever else the team happens to run alongside it.

## Language and Build Strategy

Go, for reasons specific to this use case:

1. Static binaries. `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build` produces one file with zero runtime dependencies: no Python interpreter mismatch, no missing packages, nothing that relies on the target box's own tooling being intact.
2. Cross-compilation. Warden is built ahead of the competition wherever the team actually has a machine and permission to run `go build`, whether or not that's an official team laptop. If no such machine exists, see the build-location contingency later in this section. No compiler and no internet access are needed on the box itself.
3. No trust in system binaries for core logic. Given the team's own threat model (altered binaries, misconfigs), Warden's snapshot store and replication channel are pure Go, using only the standard library plus one vetted dependency (`golang.org/x/crypto/ssh`) for the off-host push. It never shells out to git, rsync, or tar, since any of those could be the exact binary red team has already altered.
4. Stripped binaries. Build with `-ldflags="-s -w"` to strip debug symbols, keeping the binary small and slightly harder to reverse casually.
5. Vendor dependencies (`go mod vendor`) before the competition, so a build never needs internet access.

## Repository and Package Structure

```
warden/
  cmd/warden/main.go        # Cobra root, wires subcommands to internal packages
  internal/
    manifest/               # hash format, load/save, diff
    store/                  # content-addressed snapshot storage
    replicate/               # off-host push, pure-Go SSH client
    watch/                   # integrity checking loop
    restore/                 # restore workflow
    audit/                   # append-only log writer
    opmenu/                   # forced-command handler for the access layer
    sentinel/                 # self-check-and-respawn logic
    totp/                     # minimal RFC 6238 implementation
  deploy/
    systemd/                 # unit + timer templates
    install.sh                # one-shot deploy script, run once per box
```

Conventions: each `internal/` package exposes a constructor (`manifest.New(path string) (*Manifest, error)`), no package-level globals, no `init()`. Cobra subcommands in `cmd/warden` stay thin and call into these packages, so every piece is independently testable.

Cobra subcommand surface:

| Command | Purpose |
| --- | --- |
| `warden snapshot` | Take a backup snapshot (config or data tier) |
| `warden replicate` | Push new snapshot objects to the off-host target |
| `warden watch` | Run one integrity check pass |
| `warden restore <target>` | Restore a target from a snapshot |
| `warden sentinel-check` | Verify the sentinel pair and respawn if needed |
| `warden opmenu` | Forced-command handler, never invoked directly by a human |

## Component: manifest Package

Purpose: the single source of truth for what known-good state looks like. Every other component reads from or writes to this.

Design steps:

1. Define a record: file path, SHA-256 hash, file mode, mtime, and a class field (safe-auto-restore or confirm-first). The class split is what lets the watcher decide whether to fix something immediately or flag it for a human.
2. Format: JSON, one manifest per snapshot generation. Human-readable on purpose, since it needs to be debuggable under pressure.
3. Hashing: `crypto/sha256` from the standard library, over file contents, not metadata, so a touch-only change doesn't false-positive.
4. Two core functions: `Generate(paths []string) (*Manifest, error)` builds a fresh manifest from current disk state; `Diff(old, new *Manifest) []Change` compares two manifests and returns what moved.
5. Store the manifest in the same off-host location as the backup objects (see the store and replicate sections), not only on local disk. If red team deletes the local copy, the record of what should be there still exists elsewhere.

## Component: store Package (Backup Engine)

Purpose: versioned, content-addressed storage for file contents, without depending on external tools.

Design steps:

1. Skip git, tar, and rsync. Build a minimal content-addressed store: hash each file's contents with SHA-256, write the content once to `objects/<hash prefix>/<hash>`, compressed with `compress/gzip` from the standard library. Skip the write if the object already exists.
2. A snapshot is a manifest pointing at object hashes, not a full copy of every file. Cheap, fast, and easy to diff.
3. Two tiers: a fast tier for config-sized files, run every few minutes; a slower tier for larger service data, run hourly. Implement as two separate Cobra invocations with different target lists, scheduled by two different systemd timers.
4. Retention: on each snapshot, prune object files no longer referenced by any of the last N manifests. Simple mark-and-sweep.

## Component: replicate Package (Off-Host Push)

Purpose: get snapshots off the box so a root compromise doesn't take the backups with it.

Design steps:

1. Use `golang.org/x/crypto/ssh` directly to push new objects and the manifest to a second team-controlled box. This is a deliberate exception to the no-external-dependencies rule, since implementing SSH from scratch isn't a good use of competition prep time and this library is widely used and auditable. Vendor it ahead of time.
2. Authenticate with a key generated only for this purpose, not a personal or team login key.
3. Push is additive-only from the source box's perspective: it can write new objects, never delete or overwrite existing ones on the destination. A compromised source box still can't destroy prior backups.
4. If no second box is available, point this package at a different local filesystem path (removable media) instead of a network destination. Same interface either way.

## Component: watch Package (Integrity Checker)

Purpose: this is the actual persistence mechanism, and the trigger for both auto-restore and alerting.

Design steps:

1. Not a long-lived daemon. Invoke via a systemd timer at a jittered interval, so the check doesn't have a fixed, fingerprintable period. Each run: generate a fresh manifest of watched paths, diff against the last known-good manifest, act on differences, exit.
2. For each changed file classed safe-auto-restore: pull the old content from the store and overwrite it immediately, then log it. For each classed confirm-first (keys, passwd, sudoers): don't touch it, write a high-priority alert to the audit log, and surface it in the operator menu's status view.
3. Include Warden's own dependencies (any external binary it ends up trusting) in the watch list too, closing the gap where the tool meant to catch altered binaries could itself be undermined by one.

## Component: opmenu Package (Access Layer)

Purpose: what the forced SSH command runs. Deliberately not a shell.

Design steps:

1. The forced-command key lives in a dedicated non-root account's `authorized_keys`, not root's: `command="sudo /usr/local/sbin/warden opmenu",from="<team IP>",no-port-forwarding,no-X11-forwarding,no-pty <key>`. That account (`cmd/warden/units.go`'s `opmenuUser`, reusing the disguised binary name) is granted narrow, passwordless sudo for exactly this binary via `/etc/sudoers.d/<name>` — nothing else. `PermitRootLogin no` disables root SSH authentication entirely, forced-command key included; a non-root account with a scoped sudo rule works regardless of that setting.
2. Read `$SSH_ORIGINAL_COMMAND` to see what the operator asked for (status, restore nginx, shell). Whitelist a small fixed set of accepted commands and reject everything else.
3. Require a second factor before anything beyond read-only status. Implement TOTP with `crypto/hmac` and `crypto/sha1` from the standard library (RFC 6238 is small enough that skipping a third-party dependency here is worth it, since this is the most sensitive component in the system). Also accept a static, rotatable passphrase (`internal/opmenu`'s `StaticSecretPath`, a file under the box's own data directory, never baked into the binary) as an alternative to TOTP — for competitions where phones/authenticator apps aren't available at all (PCDC-style), where TOTP simply can't be used. `install.sh` generates one by default on every install, not just when it's known to be needed, since a team that ends up not using it costs nothing by having it — no separate manual step to remember later. Purely additive either way: a configured static secret doesn't disable TOTP, both are checked. Weaker than TOTP (no time-based expiry — a captured value stays valid until rotated), which is why TOTP is checked first; `warden rotate-secret` changes it instantly, no rebuild or redeploy, since opmenu reads the file fresh on every check.
4. Only the shell command, after the TOTP check passes, execs an actual shell (`syscall.Exec` into `/bin/bash`). Every other path stays inside the Go binary. Since `opmenu` itself is invoked via `sudo`, it's already running as root by the time this runs, so the resulting shell is a real root shell.
5. Log every invocation, successful or rejected, to the audit log: timestamp, source IP, command requested, whether the second factor passed.
6. `sentinel-check` treats the sudoers file as its own registration alongside `authorized_keys`: without it, the forced command's `sudo` call has nothing granting it, so the entry is inert. A generated sudoers file is validated with `visudo -cf` before being written — a malformed one can break `sudo` for every account on the box, not just this one.

## Component: sentinel Package (Self-Healing Pair)

Purpose: make sure something is always checking that persistence itself is still alive.

Design steps:

1. Two independent triggers: a systemd timer and a separate cron entry, both running `warden sentinel-check`, registered two different ways so killing one registration doesn't kill both.
2. Each run checks: does the SSH key entry still exist (delegate to the manifest/watch logic rather than duplicating it); does the other trigger's registration still exist. Read the crontab file and the systemd unit file directly rather than shelling to `crontab -l` or `systemctl status`, to avoid trusting a binary that could be altered. Re-create whichever is missing.
3. Keep each run short-lived and quiet: minimal log output outside the audit trail, and naming that matches whatever conventions already exist on the box rather than something generic.
4. Also keeps a hidden spare copy of the binary itself in sync (`cmd/warden/registrations.go`'s `binary-backup` registration). `watch`/`sentinel-check`/`retrieve` are all *inside* the binary — none of them can run to restore it if the binary file itself is deleted, only if a registration pointing at it is. The cron trigger's command line checks for the binary and restores it from the spare using only `test`/`cp`/`chmod` before invoking the binary at all, so recovery doesn't depend on the thing being recovered.

## Component: restore Package

Purpose: the human-triggered "fix this now" path, separate from the automatic watch loop.

Design steps:

1. `warden restore <target> [--snapshot <id>] [--dry-run]`. Default to the latest snapshot, but allow an older one, since the most recent snapshot can already contain the bad state.
2. Dry-run shows a diff (old hash vs. current disk state) without touching anything. Make this the default when invoked through the opmenu's restore command, requiring an explicit `--apply` flag or confirmation to actually write.
3. On apply: stop the affected service if one maps to the target, pull content from the store, write it, reverify the hash post-write, restart the service, and log the whole sequence to the audit log.

## Component: Active Response (opt-in)

Purpose: react to a guarded (ConfirmFirst) path changing by identifying and firewalling the responsible IP, instead of only flagging it for a human to notice later. Still purely defensive — it blocks an IP from reaching *this* box, the same as fail2ban; it never touches red team's own infrastructure, which would be a materially different (and, under most competitions' rules, likely disallowed) kind of action. See "Rules of Engagement Note" above — this component specifically should be confirmed as allowed before enabling it, since actively firewalling a source IP is a more assertive posture than the rest of Warden's designed-to-be-inert persistence and backup mechanisms.

The hard problem this component exists to solve carefully: `watch` only knows a file's *content* changed, never *who* changed it. Getting attribution wrong is worse than doing nothing — banning the scoring engine's own checker, or a teammate on an unlisted connection, is a self-inflicted outage that looks exactly like red team caused it (the same failure mode `docs/DEPLOYMENT.md`'s "Don't let Warden fight the scoring engine" note already warns about for auto-restore). So the design leans hard toward "no evidence → no ban":

Design steps:

1. `internal/attribution`: parse sshd's own auth log (`/var/log/auth.log` or `/var/log/secure` — whichever exists; not `last`/`who`/`w`, which read the same class of accounting file sshd's own log already is, without the benefit of being what sshd itself wrote) for `Accepted`/`Disconnected` line pairs, and answer "which IPs had a session open at time T." A log line it can't parse, or no log file at all, produces no evidence — never a guess.
2. `internal/autoban`: a small persisted ban list plus a `Firewall` interface (`iptables -I INPUT -s <ip> -j DROP`, idempotent) — kept as its own package specifically so the ban/unban/reconcile logic is unit-testable against a fake firewall, never a real one, in CI.
3. The decision logic (`cmd/warden/react.go`, not `internal/watch`, to keep the pure integrity-check package free of network/firewall concerns) fires only for `ConfirmFirst`-classified changes — the paths a legitimate teammate almost never has a reason to touch directly — and only bans when **all** of the following hold:
   - An auth log was found and parsed.
   - Exactly one root-authenticated SSH session was open at the changed file's mtime.
   - That session's source IP is not `TEAM_FROM_IP` (exact match or, if `TEAM_FROM_IP` is a CIDR, containment) — this is the "double check it isn't blue" gate. Sessions authenticating as any account other than root (e.g. a replication peer's `warden-backup`) are excluded before this check even runs, since that account is `command="/usr/bin/false"` restricted and could never have written the file regardless of timing.
   - Ambiguous evidence (zero or more than one candidate foreign IP) also means no ban — a coin flip between two plausible suspects isn't a decision Warden gets to make unsupervised.
4. Every reaction — banned or not — writes one `react`/`alert` audit entry recording the path, the attributed IP/account if any, and, if attribution came up empty or ambiguous, *why*. This is what `warden alerts` (below) surfaces.
5. A ban lasts `autobanDuration` (1 hour) before `sentinel-check`'s call to `autoban.Reconcile` lifts it — long enough to matter, short enough that a wrong ban self-heals rather than requiring a human to notice. `sentinel-check` also re-applies every still-active ban's firewall rule on every pass, the same "reassert desired state" pattern it already uses for its own registrations, in case the rule was flushed (a reboot, or red team running `iptables -F`). A human can also `warden ban <ip>`/`warden unban <ip>` directly at any time.
6. **Deliberately not wired into `opmenu`**: `ban`/`unban`/`accept`/`alerts` are plain local CLI commands, reachable via `opmenu shell` (already TOTP-gated) rather than added as their own opmenu whitelist entries. There was no case for a fourth write path when the shell already gets the team there.
7. **Alerts are pull-based, never broadcast.** The obvious way to "tell the team something happened" is a system-wide `wall` message — deliberately not used, since it would reach every session on the box, including one red team might have through some entirely different foothold, handing them free confirmation they've been noticed. `warden alerts` instead tails the audit log's `react` entries in whatever shell a teammate chooses to run it in, opt-in and local to that session only.
8. **`warden accept <path> <totp-code>`** is the sanctioned way to land a deliberate change to one watched path (landing a real hardening edit, for instance) without triggering the flag/alert/ban path for it and without a blanket `warden snapshot`, which would also silently re-baseline every *other* watched path against whatever's currently on disk — masking any real, unrelated, still-unresolved drift elsewhere. `accept` requires a live TOTP code, the same second factor `opmenu`'s `restore`/`shell` require, even though reaching a local shell in production already implies that check passed once — a second check here means a change can't be laundered into "known good" by whatever got the shell in the first place, only by someone currently holding a valid code.

## Build and Deployment

Warden reaches the box by push, during the team's own initial setup window, not by pull from the box itself.

### No Clean Window: Assume Compromise

There is no guaranteed clean setup window, only an informal grace period at the start of the competition. The working assumption from here on is that red team may already have a foothold (beacons, keyloggers, altered binaries) from the moment the competition starts, not after some later point. That changes deployment order: enumerate and eliminate whatever's already there before pushing or installing anything sensitive, since installing Warden's key material onto a box that still has an active implant risks that implant capturing it.

### Delivery Mechanism

For the built *binary*, ruled out:

- `git clone` on the target: needs outbound access the box may not have, leaves the clone URL and a `.git` directory as an obvious artifact, and depends on the box's own git binary being intact, which the whole threat model assumes it might not be.
- `curl`/`wget` on the target: same egress and history problems, plus depends on curl/wget being present and un-tampered.

Instead: `scp` (or the team's own jump host, if the competition provides one) pushes the built binary onto each box once, during whatever grace period exists at the start of the competition, and only after the sweep above has confirmed the box is clean, not before.

### Build Location Contingency

The plan above assumes there's some machine the team controls and has permission to build on, even if it isn't literally a laptop issued for the competition — a personal machine or a home lab box, not necessarily team-owned equipment. That covers most cases (SECCDC-style events, where teams typically do have their own laptops alongside whatever the competition provides), but not all of them: some events (PCDC-style) issue a laptop with no permission to install anything on it at all, and that's the only machine the team has.

For that case, `scripts/build-and-install.sh` builds directly on the target box and installs immediately — see `docs/DEPLOYMENT.md`'s "Alternative: build directly on the target box" for the actual steps. Design notes on why it's structured the way it is:

- It needs the whole source tree on the box, not just a binary — the "ruled out" reasoning above was specifically about a target box pulling a finished, secret-laden artifact over the network when it didn't need to; here, the source has to arrive somehow regardless, so `scp` from a machine that already has it checked out is still the preferred transport (needs nothing the team doesn't already have — the SSH access to the box itself), with `git clone` directly on the box, or a USB drive for a fully air-gapped transfer, as fallbacks.
- Building this way means the per-competition secrets get passed to `go build -ldflags -X ...`, which puts them briefly into this box's own process list (`ps`/`/proc/<pid>/cmdline`) for the few seconds the build runs — a real, if narrow, exposure a machine red team has never touched doesn't have. The mitigation is timing (build during the clean-first sweep, before the box has been exposed to anything untrusted), not elimination — there's no way to pass `-ldflags -X` values without them being literal command-line arguments.
- A vendored module cache (`make vendor`, run once on any internet-connected machine, brought along as part of the tree) lets the build run with zero network access from the target box at all; without it, `go build` needs the box itself to reach Go's module proxy or a configured mirror.
- The whole source tree (source, vendored dependencies, `.git` if cloned, build artifacts) is a much bigger, more identifiable footprint than the finished-binary plan leaves — `build-and-install.sh` deletes the entire checkout once installation succeeds, the same reasoning `install.sh` already applies to itself and its own template directory. Removing your own working files after a build is ordinary software hygiene, not evidence-scrubbing, so it doesn't carry the same red-flag risk as wiping shell history does (see "Footprint and Evidence Policy" below).
- If the box has no Go toolchain and no way to get one (no internet, no local mirror, no package already staged), this path isn't available at all — that's a real limitation worth testing for ahead of the competition rather than discovering it mid-event.

### Configuration

Per-competition values (the team's public key, the off-host replication target, the TOTP seed, the `from=` IP restriction) are baked into the binary at build time with `-ldflags -X`, not stored in a separate config file on disk.

Why: a config file is itself a discoverable artifact, plaintext or not, sitting in a predictable path with a name that gives away what it's for. Baking values in at compile time means the only thing left on the box is the binary and the systemd/cron entries it installs, both named to blend in.

Tradeoff worth naming: a value change (a new TOTP seed, say) requires a rebuild and redeploy, not just editing a file. Given how rarely these values should change mid-competition, that's an acceptable cost for the smaller footprint.

### Install Sequence

One script, run once, does the entire setup:

1. Confirm the box is clean of known beacons, keyloggers, and altered binaries. Assume compromise by default, not a clean starting point, and eliminate anything found before continuing.
2. Place the binary at a path and name that match conventions already on that box (check what's there before choosing).
3. Set restrictive permissions (0700, root-owned).
4. Write the systemd timer and unit files for the watch loop and the sentinel pair, and the cron entry for the sentinel's second trigger.
5. Create the dedicated, low-privilege account the access layer uses (same name as the binary), append the restricted authorized_keys line to its own `authorized_keys`, and grant it a `visudo`-validated `NOPASSWD` sudo rule scoped to exactly this binary.
6. Generate the initial manifest and take the first snapshot.
7. Generate a static second factor (`warden rotate-secret`, no value given) by default, printed once for the operator to save — an alternative to TOTP for competitions where phones/authenticator apps aren't available at all.
8. Verify by calling `warden opmenu status` once over loopback, confirming the access layer works before walking away from the box.
9. Delete the install script itself. It's a one-time-use file, and leaving it behind leaves a trace for red to find.

### Footprint and Evidence Policy

Direct answer to whether this auto-deletes evidence: no, not in the sense of scrubbing shell history or logs. Wholesale history wiping is itself a red flag. An empty or truncated `.bash_history` right after the setup window looks exactly like what red team does after gaining access, and white team can't tell "blue team cleaned up after themselves" from "attacker covered their tracks." That's a real way to get penalized for the same reason this whole system needs the rules-of-engagement check from earlier in these notes.

The actual answer is to minimize footprint at the source rather than erase it afterward: one script, run once, referencing no external URLs, deleting only itself. Whatever command history the install leaves behind (the `scp`, the one script execution) should look like exactly what it is: a sysadmin pushing and running a setup script during a maintenance window, which is normal and doesn't need hiding.

## Verification Plan

1. Unit tests per package: manifest hash round-trip, store put/get with dedup, watch diff correctness, TOTP against known RFC 6238 test vectors.
2. Integration test in a VM mirroring the actual target distro: install, kill the sentinel and confirm it respawns, edit a watched config and confirm it reverts, delete the SSH key and confirm it comes back.
3. Adversarial test before the real competition: have a teammate try to find and kill this on a box with no knowledge of where to look, timed, so the team knows its actual survival window rather than assuming one.
