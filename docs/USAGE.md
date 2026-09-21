# Usage

What Warden does, command by command, once it's installed on a box. For *getting* it installed, see [DEPLOYMENT.md](DEPLOYMENT.md); for *why* it's built this way, see [DESIGN.md](DESIGN.md).

Every command below reads and writes fixed paths under `/var/lib/<binary-name>` (e.g. `/var/lib/svchelper` if that's what `install.sh`'s `INSTALL_PATH` named it — see below) and a handful of other fixed system paths — there is no config file and no flag to point them elsewhere. See "On-disk layout" below and DESIGN.md's "Configuration" section for why.

## On-disk layout

```
/var/lib/<binary-name>/       named after the installed binary, not "warden" —
                               a literal /var/lib/warden would give away exactly
                               what it is to anyone browsing /var/lib
  manifest-config.json        live pointer to the config tier's last snapshot
  manifests-config/           archived config-tier generations: manifest-<n>.json
  manifest-data.json          live pointer to the data tier's last snapshot
  manifests-data/             archived data-tier generations
  objects/                    content-addressed, gzip-compressed file contents
                               (objects/<hash prefix>/<hash>), shared by both tiers
  audit.log                   append-only JSON-lines log of every action taken

/home/<binary-name>/.ssh/authorized_keys   the team's forced-command entry (sentinel-checked)
/etc/sudoers.d/<binary-name>                grants that account NOPASSWD sudo for this binary only
/etc/systemd/system/                        watch/sentinel/snapshot/replicate timer + service units
```

All of the above is derived at runtime from the binary's own install path (`cmd/warden/config.go`'s `loadPaths`/`units.go`'s `binaryName`), the same way the systemd unit names and cron entry are — so the one naming decision made in `install.sh` (`INSTALL_PATH`) is the only one anyone has to make.

The config and data tiers are kept completely separate on disk — each has its own manifest lineage — specifically so that snapshotting one tier can never clobber the other's baseline. `watch` only ever reads the config tier; it never writes either manifest.

## Command reference

### `warden snapshot [--tier config|data]`

Takes a backup snapshot: hashes every path in the chosen tier, stores any new content in `objects/`, and writes a new manifest generation. Config tier is the default — it's also what `watch` and `restore` operate against. The data tier is for larger service data that doesn't need checking as often.

```
warden snapshot                 # config tier (default)
warden snapshot --tier data     # data tier
```

Each run also prunes `objects/` down to what's referenced by the last 10 archived generations of *either* tier (`retainGenerations` in `cmd/warden/config.go`).

Deployed as two systemd timers (`*-snap-cfg`, every 5 min; `*-snap-data`, hourly) rather than run by hand in normal operation.

### `warden watch`

Runs one integrity check pass over the config tier: generates a fresh manifest, diffs it against the last snapshot, and acts on what changed —

- **`safe-auto-restore`** paths (most config files): reverted immediately from `objects/` **if armed** (see `warden arm`/`warden disarm` above), logged as `auto-restored`. While disarmed, the same drift is left untouched and logged as `drift-suppressed` instead — nothing is lost, it's just not acted on until the box is armed.
- **`confirm-first`** paths (keys, `passwd`, `sudoers`, `sshd_config` — see `cmd/warden/config.go`'s `confirmFirstPaths`): never touched, armed or not. Logged as `flagged`, and it'll be flagged again on every subsequent run for as long as the drift is unresolved — `watch` never updates its own baseline, so nothing makes the alert go away except a human fixing it and running `snapshot` again to accept the new state.
- **Unexpected new paths**: flagged, not restored — there's no known-good content to restore from.

Not a daemon; invoked by a jittered systemd timer (`*-watch`, every 5 min ± up to 90s).

```
warden watch
# armed: true, auto-restored: 1, suppressed: 0, flagged: 0
```

### `warden restore <target> [--snapshot <generation>] [--apply]`

The human-triggered "fix this now" path for one specific config-tier path.

```
warden restore /etc/nginx/nginx.conf                     # dry run against the latest snapshot
warden restore /etc/nginx/nginx.conf --snapshot 4         # dry run against an older generation
warden restore /etc/nginx/nginx.conf --apply              # actually restore
```

Dry run (the default) prints current vs. target hash for the path and does nothing else. `--apply` stops the mapped systemd unit if one exists (`serviceForPath` in `config.go`), writes the known-good content, reverifies the hash, and restarts the unit — logging every step. A restore across multiple paths isn't supported in one invocation; run it once per path.

### `warden replicate`

Pushes both tiers, anything new since the last replication, to **every** peer baked in at build time (`REPLICATE_TARGETS` — one or more `ssh://` or `file://` targets; see DEPLOYMENT.md's "Replication topology" for running a mesh across several boxes). Additive-only on every destination: existing objects and manifest generations there are never touched, so a compromised source box can add junk but can't destroy prior backups. One peer being unreachable doesn't stop the push to the others — errors are collected and reported together.

```
warden replicate
```

Fails immediately if no `REPLICATE_TARGETS` were baked in, or (for an `ssh://` target) if `REPLICATE_KEY` wasn't or that target has no pinned host key. Scheduled by `install.sh` as a systemd timer (`*-replicate`, every 15 min ± 3 min) whenever `REPLICATE_TARGETS` is configured — and, in that case, `sentinel-check` also verifies and respawns that timer's registration, the same way it protects its own.

### `warden retrieve <peer-url> [--tier config|data] [--generation N] [--apply]`

The reverse of `replicate`: pulls a box's own backups back from a peer that holds a copy, for recovering a box that's been wiped and rebuilt. `<peer-url>` must be one of the URLs already baked into this build's `REPLICATE_TARGETS` — its pinned host key comes from there, not a flag, so recovery can't be tricked into trusting an unpinned location.

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1                    # dry run, latest generation
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply # actually recover the data tier
```

Dry run (the default) fetches the manifest and reports what's available without touching local state. `--apply` also fetches every object the manifest references into the local store and adopts the manifest as the local live baseline for that tier — after which `warden watch`/`warden restore` work normally again. See DEPLOYMENT.md's "Recovery" section for the full rebuild-and-recover workflow.

### `warden detect`

Read-only, two parts. First, every entry in `configTierPaths`/`dataTierPaths` that actually exists on **this** box right now — a plain answer to "what is Warden actually protecting here," as opposed to the full lists in `cmd/warden/config.go`, most of which won't apply to any single box. Second, a scan of the box's processes and on-disk config paths against a table of services common on CCDC-style images (web, database, mail, DNS, file transfer, DHCP, SSH — see `internal/detect`), reporting anything found that isn't in the first part yet. Changes nothing; it's meant to answer "what should the watch list actually cover" before relying on it (`docs/PLAN.md` Phase 1).

```
warden detect
==> Currently protected on this box
  /etc/passwd                              config  confirm-first
  /etc/ssh/sshd_config                     config  confirm-first
  /etc/nginx/nginx.conf                    config  auto-restore

==> Scan: services found on this box vs. what's watched
nginx            running
  /etc/nginx/nginx.conf                   watched
MySQL/MariaDB    configured, not running
  /etc/mysql/my.cnf                       NOT in watch list
```

### `warden arm` / `warden disarm`

Gates `watch`'s auto-restore. A box comes up **disarmed** right after `install.sh` — `watch` still runs on schedule and still flags `ConfirmFirst` drift, but a `SafeAutoRestore` path that changed is reported as suppressed rather than overwritten. That's deliberate: the team is usually still hardening the box (locking down `sshd_config`, `nginx.conf`, etc.) in this window, and armed auto-restore would just revert that hardening back to the pre-install state every few minutes.

```
warden arm      # snapshot the current (hardened) state, then turn auto-restore on
warden disarm   # turn auto-restore back off, e.g. ahead of a planned maintenance window
```

`arm` takes a fresh config-tier snapshot immediately before flipping the switch, so whatever's on disk at that moment — not a stale pre-hardening snapshot — becomes the enforced baseline. Both log to `audit.log`; `status` (below) reports the current armed state.

### `warden uninstall <code> [--force] [--yes]`

Reverses `install.sh`: stops and deletes every systemd timer it created, the cron fallback entry, the sudoers rule, the dedicated access-layer account, the installed binary and its hidden spare, and all local state under `/var/lib/<name>` (manifests, the backup store, the audit log, the static secret). Off-box replicas already pushed to a peer box are untouched.

```
warden uninstall <totp-or-static-code>              # asks for a typed 'yes', then removes it
warden uninstall <code> --force                     # also removes it even if the box is armed
warden uninstall <code> --yes                        # skip the interactive confirmation (scripted use)
```

There's no fully transactional install that rolls back automatically on any mid-setup failure — that would need every step of `install.sh` kept in exact lockstep with a reverse for it forever. This is the more honest version: one explicit command that undoes everything, for when setup went wrong and the cleanest fix is starting over.

This is also the single most dangerous thing this binary can do, and it runs locally as root with no opmenu round-trip — so it requires the same proof of authorization `restore`/`shell`/`accept` do (a valid TOTP code or the static secret), not just a root shell. Without that check, anyone who got root through some completely unrelated route (a vulnerable service, not opmenu at all) could strip out every persistence mechanism Warden has in one command. It also asks for a typed `yes` on top of that, so a leaked or shoulder-surfed code alone can't wipe a box unattended — pass `--yes` to skip that specific prompt for scripted testing, but the code check always still applies.

It refuses on an armed box without `--force`, since arming means the team's actual hardening is presumably riding on this box staying defended — before that point, nothing here is load-bearing yet, so it's a plain "start over" button. Deletes its own binary last; safe on Linux (the running process keeps executing from the file it already has open), but leaves nothing named `warden` on the box afterward.

### `warden rotate-secret [value]`

Sets (or replaces) a static, non-TOTP passphrase opmenu accepts as an alternative second factor — for competitions where phones/authenticator apps aren't available at all (PCDC-style events), where TOTP simply isn't usable. Generates a random value if none is given. `install.sh` already runs this once, by default, during setup — this is for rotating it later (e.g. after a leak), not first-time setup.

```
warden rotate-secret
# Static second factor set. Save this somewhere secure — it will not be printed again:
#   ABCDEFGHIJKLMNOPQRSTUVWX
```

Takes effect immediately — opmenu reads this from disk fresh on every check, nothing is baked into the binary — so rotating it (e.g. after a leak) needs no rebuild or redeploy, just running this again with a new value. Purely additive: setting this doesn't disable TOTP, `restore`/`shell` accept either. `status` reports whether one is currently set.

### `warden accept <path> <totp-code>`

The sanctioned way to land one deliberate change to a single watched path — say, a real hardening edit to `sshd_config` — without it perpetually flagging (`ConfirmFirst`) or getting reverted next tick (`SafeAutoRestore`, once armed), and without a blanket `warden snapshot`, which re-baselines *every* watched path and would silently swallow any other real, unrelated drift along with the one you meant to accept.

```
warden accept /etc/ssh/sshd_config 123456
# accepted: its current content is now known-good for /etc/ssh/sshd_config (generation 7)
```

Requires the current TOTP code, the same second factor `restore`/`shell` require over opmenu — reaching a shell at all already implied that check passed once, but a second one here means a change can't be quietly laundered into "known good" by whatever got the shell in the first place.

### `warden ban <ip>` / `warden unban <ip>` / `warden alerts`

See DESIGN.md's "Active Response" section for the full design and the "double check it isn't blue" attribution logic behind this. In short: when a `ConfirmFirst` path changes, Warden tries to identify which IP had a root SSH session open at that moment (parsing sshd's own auth log — never `last`/`who`), and — **only if `AUTOBAN_ENABLED` was set at build time**, and only if that IP is neither the team's own (`TEAM_FROM_IP`) nor ambiguous — bans it at the firewall for an hour. Every reaction is logged whether or not a ban happened.

```
warden ban 198.51.100.6 --reason "manual, saw it in the logs"   # --duration to override the default 1h
warden unban 198.51.100.6                                       # lift a ban immediately, e.g. a false positive
warden alerts                                                   # tail react's alert/ban entries, this shell only
```

`ban`/`unban`/`alerts` are plain CLI commands, not opmenu whitelist entries — reach them via `opmenu shell` like any other maintenance command. `alerts` is deliberately pull-based rather than a system-wide broadcast (`wall`): a broadcast would just as readily reach a shell red team has on the box through some other route, telling them they've been noticed. Run it in its own sidecar session over `opmenu shell` if you want a live feed.

`sentinel-check` re-applies every still-active ban's firewall rule on each pass (in case it was flushed) and lifts anything past its expiry — see DESIGN.md.

### `warden sentinel-check`

Verifies three things sentinel is responsible for keeping alive, and recreates whichever is missing: the `authorized_keys` forced-command entry, its own systemd timer (service file, timer file, and the `timers.target.wants` enabled symlink), and its own cron entry. Every check reads the relevant file directly — never `systemctl status` or `crontab -l` — since either could be lying if red team has altered them.

```
warden sentinel-check
# recreated: [authorized_keys systemd-timer cron-entry]
```

Registered two independent ways (a systemd timer *and* a cron entry, both calling this same command) so killing one registration doesn't kill both — see DESIGN.md's sentinel section.

### `warden opmenu`

Never invoked directly. This is what `authorized_keys`' `command="..."` forces every SSH session from the team's key to run instead of a shell, reading the operator's real request from `$SSH_ORIGINAL_COMMAND` (the one thing a forced command can't let the client override). See "Operating over SSH" below for what an operator actually types.

### `warden debug-config`

A build-time diagnostic, not something you run on a deployed box — build a native binary right after `make build` and run this against it to confirm `-ldflags -X` actually captured what you intended. Prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. See DEPLOYMENT.md step 3.

## Operating over SSH

Once installed, the team connects with:

```
ssh -i <team private key> <opmenu-user>@<box>
```

`<opmenu-user>` is `INSTALL_PATH`'s basename (`docs/DESIGN.md`'s opmenu section) — not root.

`authorized_keys`' forced command means whatever you'd normally type as a remote command becomes `$SSH_ORIGINAL_COMMAND`, parsed as `<command> [totp-code] [args...]`:

| You run | opmenu sees | Needs TOTP? |
| --- | --- | --- |
| `ssh <opmenu-user>@<box> status` | manifest generation, last snapshot time, last `watch`/`sentinel-check` pass | No |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf"` | dry-run restore of that path | Yes |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf apply"` | actually restores it (same as `restore --apply`) | Yes |
| `ssh <opmenu-user>@<box> "shell <code>"` | drops into `/bin/bash` as root — the only path that leaves the Go binary | Yes |

`<code>` is the current 6-digit TOTP code from the seed baked in at build time. Anything else — an unrecognized command, a missing/wrong code on `restore`/`shell` — is rejected and logged to `audit.log` either way, along with the source IP (already constrained by `authorized_keys`' `from=` before opmenu ever runs).

`status` deliberately needs no second factor, so it stays a safe, cheap way to check in without spending a TOTP window. It now also reports whether the box is armed (see `warden arm`/`warden disarm` above).

`arm`/`disarm`/`detect` aren't opmenu commands — there was no compelling reason to add a third TOTP-gated write path when `shell` already gets the team a real shell to run any CLI command from, including these.

`shell`'s bash runs over a `no-pty` channel, which bash treats as non-interactive — confirmed directly, a non-interactive bash never writes a history file at all, so nothing typed there lands in `~/.bash_history`. That's incidental, not something Warden arranges on purpose, so don't assume it holds if `no-pty` is ever dropped. Any *other* interactive root shell on the box (physical console, or an admin path outside opmenu) records history normally — see `docs/DEPLOYMENT.md`'s "A note on shell history" for why that's the one place a stray `<disguised-path> disarm` line actually matters.

## Audit log

`/var/lib/warden/audit.log` is JSON-lines, one entry per action:

```json
{"time":"2026-09-20T17:47:41Z","component":"watch","action":"auto-restored","fields":{"kind":"modified","path":"/etc/nginx/nginx.conf"}}
```

`component` is which part of Warden logged it (`snapshot`, `watch`, `restore`, `replicate`, `sentinel`, `opmenu`, `arm`, `accept`, `react`); `fields` is action-specific detail. This file, kept current, is the team's evidence of exactly what Warden did if a judge asks.

## Known limitations

- `restore` only operates on the config tier — there's no CLI path to restore an individual data-tier file today. `retrieve` does cover both tiers.
- `configTierPaths`/`dataTierPaths`/`classifyPath`/`serviceForPath` in `cmd/warden/config.go` ship with a broad multi-distro default (see `warden detect`), not this season's actual scored image — see `docs/PLAN.md` Phase 1.
- `detect` only recognizes the services in `internal/detect.KnownServices`; a scored service outside that list won't show up and needs adding to `configTierPaths` by hand.
- Active response (auto-ban) requires a plaintext sshd auth log (`/var/log/auth.log` or `/var/log/secure`). A box running journald with no rsyslog and neither file present has no attribution evidence to work from — auto-ban simply never fires (the change still gets flagged, just never banned); confirm which logging setup the target image actually has before relying on this.
- Auto-ban never touches red team's own infrastructure and never blocks an IP the team's own key was using — it's purely defensive, the same as fail2ban. See `docs/DESIGN.md`'s "Active Response" section and `docs/EXPLAINER.md`'s "What Warden deliberately does NOT do".

See `docs/PLAN.md` for the full phased build history and what's still open.
