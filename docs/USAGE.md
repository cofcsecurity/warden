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

Pushes both tiers, the audit log, and this box's heartbeat, anything new since the last replication, to **every** peer baked in at build time (`REPLICATE_TARGETS` — one or more `ssh://` or `file://` targets; see DEPLOYMENT.md's "Replication topology" for running a mesh across several boxes). Additive-only on every destination: existing objects and manifest generations there are never touched, so a compromised source box can add junk but can't destroy prior backups. One peer being unreachable doesn't stop the push to the others — errors are collected and reported together.

```
warden replicate
```

Each push also leaves a heartbeat on every peer — a small record of this box being alive and how it was doing (see `warden fleet` above). It's the one signal that survives the box itself going dark, since its absence is what gets noticed.

The audit log travels the same way as everything else — additive-only, as one immutable segment per push holding whatever was appended since that peer last heard from this box. That's what makes the evidence trail survive a box being wiped or someone with root deleting `audit.log` outright; `warden retrieve <peer> --audit` brings it back. Each entry carries its own `host` field, so several boxes replicating into one root give you a single combined, SIEM-ingestible JSON-lines log with no extra agent running anywhere.

Fails immediately if no `REPLICATE_TARGETS` were baked in, or (for an `ssh://` target) if `REPLICATE_KEY` wasn't or that target has no pinned host key. Scheduled by `install.sh` as a systemd timer (`*-replicate`, every 15 min ± 3 min) whenever `REPLICATE_TARGETS` is configured — and, in that case, `sentinel-check` also verifies and respawns that timer's registration, the same way it protects every other timer on the box. Logs a `replicate`/`pass` audit entry every run, success or failure, so `status` can tell a healthy peer push from a dead timer.

### `warden retrieve <peer-url> [--tier config|data] [--generation N] [--apply] [--audit <file>]`

The reverse of `replicate`: pulls a box's own backups back from a peer that holds a copy, for recovering a box that's been wiped and rebuilt. `<peer-url>` must be one of the URLs already baked into this build's `REPLICATE_TARGETS` — its pinned host key comes from there, not a flag, so recovery can't be tricked into trusting an unpinned location.

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1                    # dry run, latest generation
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply # actually recover the data tier
```

Dry run (the default) fetches the manifest and reports what's available without touching local state. `--apply` also fetches every object the manifest references into the local store and adopts the manifest as the local live baseline for that tier — after which `warden watch`/`warden restore` work normally again. See DEPLOYMENT.md's "Recovery" section for the full rebuild-and-recover workflow.

`--audit <file>` is the separate recovery path for the evidence trail rather than the backups: it reassembles every audit-log segment that peer holds, in order, into the file you name (`-` for stdout), and ignores the tier/generation flags. Use it when the local `audit.log` was deleted, or when you want one combined log across every box that replicates into that peer.

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --audit ./recovered-audit.log
```

It writes where you tell it and never over the live local `audit.log`, so a peer's copy can't get mixed into the record this box is still appending to.

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
warden arm        # review what changed, snapshot the current state, turn auto-restore on
warden arm --yes  # same, without being prompted (the review is still printed and logged)
warden disarm     # turn auto-restore back off, e.g. ahead of a planned maintenance window
```

`arm` takes a fresh config-tier snapshot immediately before flipping the switch, so whatever's on disk at that moment — not a stale pre-hardening snapshot — becomes the enforced baseline. Both log to `audit.log`; `status` (below) reports the current armed state.

**Before it snapshots anything, `arm` lists every watched path that changed since the last baseline** and asks you to confirm:

```
==> 3 watched path(s) changed since the baseline taken 47m0s ago (generation 1):

  modified  confirm-first /etc/ssh/sshd_config
  modified  auto-restore  /etc/nginx/nginx.conf
  added     auto-restore  /etc/redis/redis.conf

    Arm with these 3 change(s) as the new known-good state? [y/N]
```

Everything between installing and arming happens with auto-restore off, so that diff is the team's own hardening *and* anything else that landed in the same window. Arming makes all of it the enforced known-good state, so anything on the list you didn't do is worth fixing before answering. Confirm-first paths (accounts, sudo, SSH, PAM, firewall rules — what an attacker changes) sort to the top for that reason.

Over `opmenu`'s `shell` there's no terminal to answer the prompt, so `arm` refuses and tells you to re-run with `--yes` once you've read the list — `--yes` skips the question, not the review, and the full list goes to `audit.log` as an `arm`/`pre-arm-review` entry either way.

Both orders of work are supported and `arm` behaves identically in each. If the box was hardened **before** Warden was installed, the review normally lists nothing, which confirms nothing moved between install and arm. If it was hardened **after** and the review still lists nothing, that's a coverage gap rather than an all-clear — what you edited isn't in a watched path — and `arm` says exactly that instead of leaving you to spot it.

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

### `warden scan`

Six bounded checks `watch` structurally can't cover, since `watch` only ever knows a *watched path's content* changed: new **or modified** local user/group accounts (plus new domain/Active-Directory-backed accounts, flagged separately — see below), new **or replaced-in-place** setuid/setgid binaries, cron tampering for any account, `authorized_keys` tampering for any account, new listening TCP ports, and newly installed packages. Not a SIEM replacement — see `docs/PLAN.md` Phase 9 and DESIGN.md's "Anomaly Detection and Account Lockout" section for the full design.

The two "modified" halves matter as much as the "new" ones and are easy to overlook: giving an *existing* account UID 0, handing a service account a login shell, adding someone to `sudo`/`wheel`, or swapping the contents of an already-known setuid binary are all privilege escalation that creates no new name and no new file.

```
warden scan
scan: 2 finding(s), 1 account(s) locked, 0 IP(s) banned. See 'warden alerts' for detail.
```

Always flags and logs every finding (`warden alerts` surfaces them, same as guarded-file alerts above), and always writes a `scan`/`pass` audit entry even when it finds nothing — so a clean run is distinguishable from a scan timer that died days ago, which `status` reports. Once armed, and only if built with `AUTOLOCK_ENABLED`/`AUTOBAN_ENABLED`, also reacts: locks the responsible local account (and kills its sessions) when a finding is unambiguously attributable to one, and separately tries to ban the source IP the same way a guarded-file change already does. **Both reactions additionally require the box to be armed** — unlike the guarded-file ban above, since a new cron job or a teammate's key is something a team plausibly adds routinely while still setting up, not something inherently suspicious the moment it happens.

A domain-backed account (Active Directory via sssd/winbind, LDAP, ...) never appears in the raw `/etc/passwd` file at all — NSS resolves it dynamically — so a new one is detected via `getent passwd` instead, and reported with no culprit: `accountlock`'s lock is nothing but `passwd`/`usermod` against local files, which does nothing meaningful against a domain account. The finding itself says to lock it down in Active Directory instead.

Refuses to ever lock root or the opmenu account itself (no override), an account that isn't genuinely local (same reason as above, no override), or an account on the configured `SAFE_ACCOUNTS` list (override with `--force` on the manual command only — the automatic reaction never overrides this).

### `warden lock-account <user> [--duration] [--reason] [--force]` / `warden unlock-account <user>`

The manual override for `scan`'s automatic account-lock reaction — the same relationship `ban`/`unban` have to the automatic IP ban.

```
warden lock-account alovelace --reason "new SUID binary owned by this account"   # --duration to override the default 1h
warden unlock-account alovelace                                                  # lift a lock immediately, e.g. a false positive
```

Disables password auth and interactive shell access, and best-effort kills the account's current sessions. Goes through the exact same refusal checks `scan`'s own reaction does (see above) — `--force` only overrides the `SAFE_ACCOUNTS` tier, never root/opmenu or a non-local account. `sentinel-check` doesn't re-apply active locks the way it re-applies IP bans (locking is a one-time state change, not something that needs reasserting every pass), but it does lift anything past its expiry via the same `Reconcile` pattern. `warden uninstall` also unlocks everything still active before removing local state, so nothing stays locked out with no record after Warden itself is gone.

### `warden status`

Read-only summary of this box: armed state, whether a static second factor is set, the manifest generation and when it was taken, and the last recorded pass of `watch`, `sentinel-check`, `scan` and `replicate`.

```
warden status
armed: yes (auto-restore is on)
static second factor: set (in addition to TOTP — run 'rotate-secret' to change it)
manifest generation: 12
last snapshot: 2026-09-21T14:05:11Z
last watch pass: 2026-09-21T14:07:02Z (pass) map[armed:true auto_restored:0 flagged:0 suppressed:0]
last sentinel check: 2026-09-21T14:06:40Z (pass) map[ok:10 recreated:0]
last anomaly scan: 2026-09-21T14:02:18Z (pass) map[armed:true banned:0 findings:0 locked:0]
last replication: 2026-09-21T13:58:03Z (pass) map[audit_bytes_pushed:2048 failed:0 peers:2]
```

A stale timestamp on any of those lines is the thing to act on: it means that component's timer has stopped firing, which looks exactly like a quiet box from every other angle. This is the same report `opmenu`'s `status` returns over SSH — one shared implementation, so the local and remote answers can't disagree.

### `warden fleet [--from <dir>]`

The same question, asked about every box at once. Prints this box's own state, then every peer that replicates *to* this box, oldest heartbeat flagged.

```
warden fleet
==> This box
  box1                     armed     gen 12   bans 1   locks 0   just now
    last: watch=1m2s  sentinel=3m40s  scan=7m11s  replicate=4m9s

==> Peers reporting to this box
  box2                     armed     gen 9    bans 0   locks 0   4m1s ago
    last: watch=2m3s  sentinel=5m1s  scan=9m8s  replicate=4m1s
! box6                     armed     gen 5    bans 0   locks 2   3h0m1s ago  ** OVERDUE **
    last: watch=3h0m1s  sentinel=never  scan=never  replicate=never
```

A box that has gone completely dark can't tell anyone — so what appears here is the *absence* of its heartbeat. Every `replicate` push leaves one on each peer (see DESIGN.md's heartbeat section); `sentinel-check` also logs an alert for any peer that goes past its own declared interval plus grace, so the same finding reaches `warden alerts` without anyone running this by hand.

Which boxes appear depends on the topology: in the documented ring, each box sees its two neighbours. For one box that sees everything, add it to every other box's `REPLICATE_TARGETS` and run this there — no other change. `--from` points at the directory holding the peers' replication roots, for a receiving account that isn't in the usual place, or a `file://` target on removable media.

Nothing here is authenticated: a heartbeat is written by whatever account receives replication, so anyone able to write in that directory can forge one. It's a report for a human, never an input to an automatic reaction.

### `warden sentinel-check`

Verifies everything sentinel is responsible for keeping alive, and recreates whatever is missing: the `authorized_keys` forced-command entry, the sudoers rule it depends on, the hidden spare copy of the binary, its own cron entry, and **every timer on the box** — `watch`, both snapshot tiers, `scan`, its own, and `replicate` when one is configured. Each timer counts as present only if its service file, timer file, *and* `timers.target.wants` symlink all exist, since a timer missing that symlink never fires. Every check reads the relevant file directly — never `systemctl status` or `crontab -l` — since either could be lying if red team has altered them.

Covering all the timers, not just sentinel's own, is the point: each one carries a whole capability, so a timer nobody watches can be disabled and deleted once, and auto-restore, backups, or anomaly detection quietly stop for the rest of the competition on a box that still looks armed.

```
warden sentinel-check
# recreated: [authorized_keys systemd-timer cron-entry watch-timer scan-timer]
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
| `ssh <opmenu-user>@<box> status` | the same report `warden status` prints locally: armed state, manifest generation, last snapshot, last `watch`/`sentinel-check`/`scan`/`replicate` pass | No |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf"` | dry-run restore of that path | Yes |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf apply"` | actually restores it (same as `restore --apply`) | Yes |
| `ssh <opmenu-user>@<box> "shell <code>"` | drops into `/bin/bash` as root — the only path that leaves the Go binary | Yes |

`<code>` is the current 6-digit TOTP code from the seed baked in at build time. **Each code works exactly once**, across every entry point that asks for one (`restore`/`shell` here, and `accept`/`uninstall` locally — they share one spent-code record, so a code used in one place can't be replayed into another) — a used one is refused for the rest of its validity window, so a dry-run restore and the follow-up `apply` need two different codes. That's deliberate: without it, a code someone observed stays good for up to ~90 seconds in anyone's hands. (The static second factor, being a standing passphrase, is reusable until rotated — see `warden rotate-secret`.) Anything else — an unrecognized command, a missing, wrong, or already-used code on `restore`/`shell` — is rejected and logged to `audit.log` either way, along with the source IP (already constrained by `authorized_keys`' `from=` before opmenu ever runs).

`status` deliberately needs no second factor, so it stays a safe, cheap way to check in without spending a TOTP window. It also reports whether the box is armed (see `warden arm`/`warden disarm` above), and the last pass of every periodic component — `watch`, `sentinel-check`, `scan`, and `replicate` — so a timer that stopped firing is visible as a stale timestamp rather than looking like a quiet box.

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
