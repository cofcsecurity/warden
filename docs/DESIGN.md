# Design

Warden keeps a defended competition box alive and recoverable. Red wants to destroy things and lock the team out; nobody needs to prove later who did what. So Warden keeps only what keeps hosts alive and recoverable: access, restores, and off-box backups. There is no second factor, no approval step, no attribution, no signed history, and no heartbeat reporting.

## Goals and limits

- Keep the team's access working through deliberate lockout attempts, repairing within a minute or two.
- Put protected files back to exactly what the team armed, and reload their service.
- Keep enough backups on other boxes that losing one box loses nothing.
- Install on a bare box from a clone in minutes, with no laptop-side tooling and no secrets in the repo.
- Never change how any other account logs in, and never invent settings.

Root on the box still beats Warden. The defense is redundancy and repair speed, not stealth: red can find every unit and file, but has to clear all of them inside one repair window.

## Architecture (Phase 1 Rework)

Warden now uses process masquerading for persistence instead of overt systemd units and cron jobs. This replaces the previous architecture with more resilient techniques that resist detection and elimination.

### Process Replacement

Warden replaces legitimate long-running processes via `exec()`. The PID stays the same; `/proc/<pid>/exe` points to the original path; running code is Warden. Primary replacement targets include:

- `/usr/lib/systemd/systemd-logind` — Always running, handles logins, low suspicion
- `/usr/sbin/sshd` — Runs constantly on competition boxes, expected network activity

The `warden masq replace [target]` command initiates process replacement for a specified target. Warden embeds its sentinel logic within the replaced process, performing checks at randomized intervals (30 seconds to 2 minutes) while maintaining the appearance of the original service.

### LD_PRELOAD Hooking

Warden injects a shared library (`warden_hook.so`) into running processes via `LD_PRELOAD` to intercept system calls and hide its presence from inspection tools. The library hooks common commands such as `ps`, `ls`, `top`, and `kill` to filter out Warden processes, files, and network connections from output.

Hidden PIDs are configured via the `WARDEN_HIDE_PIDS` environment variable (comma-separated list). The hooking library intercepts:
- `/proc/<pid>` directory listings to hide replaced process entries
- `system()` calls targeting kill commands for hidden PIDs
- `getcwd()` calls to hide Warden directories

### Mutual Revival Strategy

Multiple components monitor each other using PIDs, signals, and Unix process groups. If one dies, another revives it within seconds. Component roles:

```
Component A (systemd-logind replacement) → monitors B, C via PID tracking
Component B (sshd replacement)          → monitors A, C; handles network checks
Component C (apt-daemon replacement)    → monitors A, B; runs integrity checks
```

Revival mechanics use randomized intervals to avoid patterns. Each component can rebuild others from stored configuration embedded elsewhere on the system.

### Configuration Storage

Critical configuration is stored in existing structures rather than dedicated files:

| Location | What It Stores |
|----------|---------------|
| SSH authorized_keys comments | Payload hash, revival config |
| Systemd environment variables | Component PIDs, check intervals |
| Extended attributes (`setfattr`) | Config on legitimate files |
| `/dev/shm` | Temporary storage (RAM-based) |

No dedicated `/var/lib/warden` or `/usr/lib/warden` directories are used.

## Access

One team SSH key. Its public half is in the runtime config; its private half stays on the laptops. The key line in each access account's `authorized_keys` carries `from="<team network>"` and a forced command, `sudo <binary> opmenu`. opmenu reads `$SSH_ORIGINAL_COMMAND`: empty or `shell` opens a root login shell, a warden subcommand runs in-process, anything else is refused. The pty is allowed so `ssh -t` gives a usable shell.

The access accounts are never root, so `PermitRootLogin no` does not disable them. Their shell is a real shell (sshd runs the forced command through it), their password field is `*` (key login only, not locked), and their home and key file are root-owned so the account itself cannot swap them.

### The access chain

Sentinel checks every link between the key and a root shell as an invariant with a repair:

| Link | Check | Repair |
| --- | --- | --- |
| Account | exists, has a shadow line, unlocked, unexpired, real shell listed in `/etc/shells`, expected home | `useradd`/`usermod`; append our own shadow line if watch restored passwd without it |
| Key file | exact content, not a symlink, not shadowed by a mount | rewrite atomically, `chattr -i`, `umount -l`, `restorecon` |
| sshd config | `sshd -T -C user=<us>,addr=<team ip>`: pubkey on, our key file read, a key alone is enough, not denied, no foreign `ForceCommand` | our `Match User` drop-in, validated with `sshd -t`, then reload |
| sshd | unit not masked, service or socket active | unmask, start |
| sudo | our rule exact (`visudo -cf`), sudo present and setuid, sudoers valid and includes `sudoers.d` | rewrite our rule; the rest is flagged |
| Firewall | our ACCEPT for the team network leads INPUT | delete stray copies, insert at the top |
| Preload | `/etc/ld.so.preload` empty | flagged (sudo is dynamic) |
| Warden | binary, two spares, two config copies | copy back |

The sshd drop-in (`/etc/ssh/sshd_config.d/00-<name>.conf`) is a `Match User <name>` block: `PubkeyAuthentication yes`, `AuthorizedKeysFile <our file>`, `AuthenticationMethods publickey`, `AllowUsers <name>`, `PermitTTY yes`. sshd accumulates `AllowUsers` rather than replacing it, so this admits our account without admitting anyone else; every other keyword applies only inside the Match. If `sshd -t` rejects the full form, a minimal one is tried, and if that fails too the drop-in is removed. The e2e tests compare a bystander account's `sshd -T` before and after every scenario.

### Break-glass

A second account with its own home (`/var/lib/<bg>`), key file outside `/home` (`/usr/lib/<bg>/keys`, pinned by its own drop-in), sudoers file, timer and `/etc/cron.d` entry that restores the binary from the second spare. One deletion cannot take both doors. Every trigger runs the same full sentinel pass, so each path repairs the other. Break-glass uses the same key and the same team network.

### Triggers

| Trigger | When |
| --- | --- |
| `<name>-refresh.timer` | every minute |
| `<name>-refresh.path` | the instant a key file, sudoers rule, sshd config, passwd or shadow changes |
| root's crontab | every two minutes, restoring the binary from `/var/lib/<name>/.spare` first |
| sshd drop-in `ExecStartPre=-systemctl start --no-block <name>-refresh` | whenever sshd (re)starts; fail-open and non-blocking |
| `<bg>-refresh.timer` | every 90 seconds |
| `/etc/cron.d/<bg>` | every two minutes, restoring the binary from `/usr/lib/<name>/` |

Each check reads files directly; systemctl is trusted only for "is this unit running", since a stopped timer still has all its files. Units are compared by content, so a mask (a symlink to `/dev/null`) counts as missing. Services set `StartLimitIntervalSec=0` so a burst of path events cannot rate-limit them into a failed state. A resident inotify watcher was considered and deferred: a minute or two is an acceptable repair latency.

Hooks into scored daemons, `pam_exec`, `/etc/profile.d`, package-manager hooks and process injection are out: Warden never changes a resident process's behavior.

### Names

Units, accounts and paths use a chosen name such as `netmgr`, with neutral suffixes (`-refresh`, `-verify`, `-cache`, `-archive`, `-audit`, `-sync`). No `warden` string appears on the box. This is a speed bump; it is not the defense.

## Protecting files

`arm` snapshots the watched files and turns on auto-restore. The team's configuration at arm time is the approved state; Warden restores toward it and never toward anything else.

Profile entries are exact paths, single-level globs, or `/**` trees. The defaults follow the team's hardening sheet (see `cmd/warden/config.go`). Two classes:

- **auto-restore:** drift is restored and the owning service reloaded (`systemctl reload-or-restart`, once per unit per pass, retried later on failure). A file that appears under an auto-restore glob (`sshd_config.d`, `sudoers.d`, `pam.d`, `cron.d`, ...) is copied to `quarantine/` and removed. A new exact path is only flagged: a newly installed service's config is not a backdoor.
- **confirm-first (flag only):** drift is reported and left alone. Shadow, firewall state, units, per-user crontabs and other accounts' `authorized_keys`, which the team changes while hardening. `accept --flagged` re-baselines them.

Warden's own files are excluded from the watch list: sentinel holds them, and two components holding one file would fight whenever pairing or a rekey legitimately changed it. A symlink is never written through; a watched path that became a link is flagged. A symlink to a non-file (a unit masked to `/dev/null`) is recorded by its target, so masking or retargeting is drift.

While armed, the config baseline is frozen: scheduled snapshots cannot absorb drift, only `arm` and `accept` move it. The data tier (`/var/www/**` by default, files over 64 MiB skipped) keeps taking snapshots and is restored by hand.

Each flagged change triggers the response logic once, not on every pass.

## Backups

The store is content-addressed (SHA-256, gzip) with numbered manifest generations per tier. Hashes are checked on every restore and recovery, because corrupt backups restore badly; there are no signatures, because there is no provenance goal.

Each box pushes both tiers to its peers over SSH. On the peer, the source's key runs a forced command, `receive --source <name>`, that serves one JSON request into `/var/lib/<peer>-peers/<name>/`: get, has, list, put. There is no delete, rename or shell, existing objects and generations are write-once, and a per-source quota refuses new uploads once full instead of evicting old ones.

**Push or pull.** Pull (the peer holds the key and fetches) protects old copies from a compromised source. The receiver above gives the same property for push: a compromised source can only add copies, never remove the good ones it sent earlier, and cannot flood them out. Push needs only the source's key on the peer, which `pair accept` installs from one line of output, so push is the default and the transport stays behind `replicate.Target` if pull is wanted later.

**Pairing.** `pair key` makes the box's backup key on first use and prints its public half; `pair accept` on the peer authorizes it and prints the peer's URL and pinned host key; `pair add` records it. Chaining the three over the team key runs the exchange from a laptop with only ssh, and no private key leaves its box.

**Recovery.** A missing object or manifest is recovered from local archives first, then peers, and verified before use. After a rebuild, re-accepting the box under the same source name keeps its stored backups for `retrieve`.

## Responses

IP bans and account locks have three modes: `off`, `flag` (default: log "would ban 10.0.0.9" and change nothing), and `act`. Root, Warden's accounts, the team network and `safe_accounts` are always exempt, and locks only ever apply to the account tied to a flagged event. The IP for a ban comes from SSH session overlap in the auth log or journal; ambiguous evidence means no automatic ban, only a shortlist in `alerts`.

## Runtime config

Everything that used to be compiled in lives in `/var/lib/<name>/config.json`, mirrored to `/usr/lib/<name>/config.json` so deleting the state directory does not lose the key. It is written by `install`, `rekey`, `config set` and `pair`, and read on every invocation. A damaged primary falls back to the mirror. Sentinel keeps both copies in step.

## Seer

Separate binaries, loosely coupled. Seer reads `warden status --json` (the stable contract: fields may be added, never renamed or removed) and can call `disarm`, `arm` and `accept` directly since there is no approval step. Seer should warn before editing files Warden watches. Moving `scan` and `detect` into seer, and an on-box `seer warden profile`, are planned there.

## Windows (later)

Not built. The plan: Server 2016 floor; access over the OpenSSH server (installed as an optional feature or downloaded) with the same restricted key and forced command; triggers as a scheduled task and a service with failure actions; ACLs and owner instead of POSIX mode in the manifest. The Linux-specific pieces (accounts, sshd, sudo, systemd, cron, iptables) are confined to `cmd/warden/access.go`, `registrations.go` and `units.go`, which is where a Windows backend would plug in.