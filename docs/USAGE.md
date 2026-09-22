# Usage

Command reference. See [DEPLOYMENT.md](DEPLOYMENT.md) for installation and [DESIGN.md](DESIGN.md) for implementation details.

Local state is stored under `/var/lib/<binary-name>`, with registrations in system paths. `/etc/warden/profile.json` can configure watched files, classifications, and service mappings; it does not relocate the state directory.

## On-disk layout

```
/var/lib/<binary-name>/       state directory named after the installed binary
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

`loadPaths` and `binaryName` derive these names from `INSTALL_PATH`.

Each tier has separate live and archived manifests. `watch` uses the config baseline. If its live manifest is missing, it recovers an existing generation from local archives or configured replicas. It does not approve changed files as a new baseline.

## Command reference

### `warden snapshot [--tier config|data]`

Hashes each file in the selected tier, stores new content in `objects/`, and writes a manifest generation. Config is the default tier. While armed, config snapshots preserve the approved baseline; data snapshots continue to capture changes.

```
warden snapshot                 # config tier (default)
warden snapshot --tier data     # data tier
```

Each run also prunes `objects/` down to what's referenced by the last 10 archived generations of *either* tier (`retainGenerations` in `cmd/warden/config.go`).

Deployed as two systemd timers (`*-snap-cfg`, every 5 min; `*-snap-data`, hourly) rather than run by hand in normal operation.

### `warden watch`

Compares the configured files with the config baseline and handles each change by class:

- **`safe-auto-restore`**: restored from `objects/` when armed and logged as `auto-restored`. While disarmed, drift is left in place and logged as `drift-suppressed`.
- **`confirm-first`**: left in place and logged as `flagged` on each pass until resolved. Default examples are `/etc/shadow`, `/etc/gshadow`, and saved firewall rules. Use `accept` to approve an intended change.
- **Unexpected new paths**: flagged because no baseline content exists to restore.

Not a daemon; invoked by a jittered systemd timer (`*-watch`, every 5 min ± up to 90s).

```
warden watch
# armed: true, auto-restored: 1, suppressed: 0, flagged: 0
```

After restoring a service config, `watch` calls `systemctl reload-or-restart` once per installed unit per pass. Reload failures are reported and logged; remaining paths are still processed.

### `warden restore <target> [--tier config|data] [--snapshot <generation>] [--apply]`

Restores one file from the config or data tier. Config is the default; use `--tier data` for service data.

```
warden restore /etc/nginx/nginx.conf                     # dry run against the latest snapshot
warden restore /etc/nginx/nginx.conf --snapshot 4         # dry run against an older generation
warden restore /etc/nginx/nginx.conf --apply              # restore
```

Dry run prints the current and target hashes. `--apply` stops the mapped service if installed, writes the saved content, verifies its hash, and restarts the service. Each step is logged. Run the command separately for each file.

**On an armed box the config baseline is frozen.** A config-tier snapshot keeps the existing record for any path that drifted, was deleted, or appeared since, logs which paths it declined, and writes no new generation when nothing moved. Only `warden accept` (one path) and `warden arm` (all of them) move the baseline while armed.

Freezing the config baseline prevents scheduled snapshots from accepting an unreviewed edit before `watch` can restore it. Data-tier snapshots continue normally.

### `warden replicate`

Pushes new objects, manifests from both tiers, audit segments, and a heartbeat to each `REPLICATE_TARGETS` peer. Destinations use `ssh://` or `file://` URLs. The client preserves existing objects and manifest generations. SSH server permissions must separately protect them from a compromised source key. Failures are collected so an unreachable peer does not stop pushes to the others.

```
warden replicate
```

Each heartbeat records the host state and recent checks. Receiving peers can report an overdue heartbeat through `warden fleet` and alerts.

Audit entries are sent as immutable segments containing new entries since the previous push to that peer. `warden retrieve <peer> --audit` recovers them. Entries include a `host` field and use JSON lines for combined logs and external analysis.

Requires configured replication targets and, for SSH targets, a replication key and pinned host key. The installer schedules replication every 15 minutes with up to 3 minutes of jitter. Sentinel verifies the timer registration. Each run logs a `replicate`/`pass` entry, including failures.

### `warden retrieve [peer-url] [--tier config|data] [--generation N] [--apply] [--audit <file>]`

Recovers local backup state after a rebuild. An optional peer URL selects the first source to try and must match a configured `REPLICATE_TARGETS` entry. With no URL, Warden uses local metadata or searches the configured replicas. SSH sources use pinned host keys.

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1                    # dry run, latest generation
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply # recover the data tier
```

Dry run reports the available generation without copying objects or adopting a baseline. `--apply` verifies every required object, recovers missing copies, then adopts the manifest for the selected tier. A manifest and its objects can come from different configured replicas. Audit retrieval still requires a peer URL.

`--audit <file>` reassembles the peer's audit segments into the specified file (`-` for stdout). It ignores tier and generation flags.

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --audit ./recovered-audit.log
```

Audit recovery refuses to overwrite the live local `audit.log`.

### `warden detect`

Reports configured paths present on the host, recognized services and their config coverage, and unknown running process names. It makes no changes. Add required paths and custom service metadata to the host profile.

```
warden detect
==> Currently protected on this box
  /etc/passwd                              config  auto-restore
  /etc/ssh/sshd_config                     config  auto-restore
  /etc/nginx/nginx.conf                    config  auto-restore

==> Scan: services found on this box vs. what's watched
nginx            running
  /etc/nginx/nginx.conf                   watched
MySQL/MariaDB    configured, not running
  /etc/mysql/my.cnf                       NOT in watch list
```

### `warden arm` / `warden disarm`

Enables or disables automatic config restoration. Installation leaves the host disarmed. Monitoring continues while disarmed, but files are not overwritten.

```
warden arm        # review what changed, snapshot the current state, turn auto-restore on
warden arm --yes  # same, without being prompted (the review is still printed and logged)
warden disarm     # turn auto-restore back off, e.g. ahead of a planned maintenance window
```

After review, `arm` snapshots the current config files and enables auto-restore. Both commands log their actions; `status` reports armed state.

`arm` first prints the watched paths, second-factor and replication configuration, active-response settings, and account exclusions:

```
==> This box's configuration
  watched here:       23 config-tier path(s) present, 8 of them confirm-first
  data tier:          nothing configured, no service data is being backed up
  access from:        203.0.113.0/24
  second factor:      TOTP and a static secret
  replication:        2 peer(s)
                      ssh://warden-backup@box2/home/warden-backup/from-box1
                      ssh://warden-backup@box6/home/warden-backup/from-box1
  auto-ban IPs:       on
  auto-lock accounts: off (flag and log only)
```

Check these settings before arming. Build-time settings require a rebuild to change.

`arm` then lists changes since the previous baseline and asks for confirmation:

```
==> 3 watched path(s) changed since the baseline taken 47m0s ago (generation 1):

  modified  confirm-first /etc/ssh/sshd_config
  modified  auto-restore  /etc/nginx/nginx.conf
  added     auto-restore  /etc/redis/redis.conf

    Arm with these 3 change(s) as the new known-good state? [y/N]
```

The review includes all changes during the disarmed window, including possible tampering. Resolve unexplained changes before confirming. Confirm-first paths are listed first.

If no interactive input is available, use `arm --yes` after reviewing the printed changes. The review is logged as `arm`/`pre-arm-review` in either case.

If hardening preceded installation, the review may be empty. If hardening followed installation and no changes appear, verify that the edited files are watched.

### `warden uninstall <code> [--force] [--yes]`

Reverses `install.sh`: stops and deletes every systemd timer it created, the cron fallback entry, the sudoers rule, the dedicated access-layer account, the installed binary and its hidden spare, and all local state under `/var/lib/<name>` (manifests, the backup store, the audit log, the static secret). Off-box replicas already pushed to a peer box are untouched.

```
warden uninstall <totp-or-static-code>              # asks for a typed 'yes', then removes it
warden uninstall <code> --force                     # also removes it even if the box is armed
warden uninstall <code> --yes                        # skip the interactive confirmation (scripted use)
```

Installation does not roll back automatically on failure. Use uninstall to remove a failed or unwanted setup.

Uninstall requires a valid second factor and a typed `yes`. `--yes` skips only the confirmation prompt.

An armed host requires `--force` for uninstall. The binary is deleted last.

### `warden rotate-secret [value]`

Sets the static passphrase accepted as an alternative second factor. With no value, generates a random passphrase. The installer creates one during setup; use this command to rotate it.

```
warden rotate-secret
# Static second factor set. Save this somewhere secure: it will not be printed again:
#   ABCDEFGHIJKLMNOPQRSTUVWX
```

Rotation takes effect on the next check because the passphrase is read from disk. TOTP remains enabled when configured, and `status` reports whether the static factor is set.

### `warden accept <path> <totp-code>`

Approves the current contents of one watched file as its baseline. Other files remain unchanged.

```
warden accept /etc/ssh/sshd_config 123456
# accepted: its current content is now known-good for /etc/ssh/sshd_config (generation 7)
```

Requires a valid second factor, even when invoked from a shell that was already authenticated.

### `warden ban <ip>` / `warden unban <ip>` / `warden alerts`

With `AUTOBAN_ENABLED`, a `ConfirmFirst` change can trigger an IP ban when SSH logs identify one non-team root IP overlapping the change. The configured team IP or CIDR and logged team-key addresses are excluded. Bans default to indefinite. Every attribution result is logged; see DESIGN.md's "Active Response" section.

```
warden ban 198.51.100.6 --reason "manual, saw it in the logs"   # --duration 1h for a timed ban; default: indefinite
warden unban 198.51.100.6                                       # lift a ban immediately, e.g. a false positive
warden alerts                                                   # tail react's alert/ban entries, this shell only
```

Run these local commands through `opmenu shell` when operating remotely. `alerts` displays events only in the calling session and does not broadcast them to other users.

`sentinel-check` re-applies every still-active ban's firewall rule on each pass (in case it was flushed) and lifts anything past its expiry, see DESIGN.md.

### `warden scan`

Checks for new or modified local users and groups, new domain accounts, new or changed SUID/SGID binaries, cron and SSH-key changes across accounts, new listening TCP ports, and newly installed packages. See DESIGN.md's anomaly detection section.

Modification checks cover changes that create no new name, such as assigning UID 0 to an existing account, adding a group member, or replacing a known SUID binary.

```
warden scan
scan: 2 finding(s), 1 account(s) locked, 0 IP(s) banned. See 'warden alerts' for detail.
```

Findings are logged and displayed by `warden alerts`. Every scan records a `pass` entry, including scans with no findings. Once armed, `AUTOLOCK_ENABLED` permits account locks and `AUTOBAN_ENABLED` permits IP bans when attribution supports them. Both scan reactions require armed state; guarded-file IP response does not.

Domain accounts are detected by comparing `getent passwd` with the raw `/etc/passwd` file. They are reported without a local culprit because `passwd` and `usermod` cannot lock a directory-managed account. Manage those accounts in the directory service.

Account locks exclude root, the opmenu account, non-local accounts, and `SAFE_ACCOUNTS`. Only a manual `--force` can override `SAFE_ACCOUNTS`; the other exclusions cannot be overridden.

### `warden lock-account <user> [--duration] [--reason] [--force]` / `warden unlock-account <user>`

Manually applies or removes a local account lock.

```
warden lock-account alovelace --reason "new SUID binary owned by this account"   # --duration 1h for a timed lock; default: indefinite
warden unlock-account alovelace                                                  # lift a lock immediately, e.g. a false positive
```

Disables password authentication and interactive shell access, then attempts to terminate the account's sessions. The same account exclusions apply as for `scan`. Sentinel expires timed locks but does not reapply active account locks. `uninstall` unlocks recorded accounts before removing local state.

### `warden status`

Read-only summary of this box: armed state, whether a static second factor is set, the manifest generation and when it was taken, and the last recorded pass of `watch`, `sentinel-check`, `scan` and `replicate`.

```
warden status
armed: yes (auto-restore is on)
static second factor: set (in addition to TOTP, run 'rotate-secret' to change it)
manifest generation: 12
last snapshot: 2026-09-21T14:05:11Z
last watch pass: 2026-09-21T14:07:02Z (pass) map[armed:true auto_restored:0 flagged:0 suppressed:0]
last sentinel check: 2026-09-21T14:06:40Z (pass) map[ok:10 recreated:0]
last anomaly scan: 2026-09-21T14:02:18Z (pass) map[armed:true banned:0 findings:0 locked:0]
last replication: 2026-09-21T13:58:03Z (pass) map[audit_bytes_pushed:2048 failed:0 peers:2]
```

A stale timestamp indicates that a component has not recorded a recent pass. Local and SSH status use the same report.

### `warden fleet [--from <dir>]`

Shows local state and the latest heartbeat from each peer reporting to this host. Overdue heartbeats are marked.

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

Replication writes a heartbeat to each peer. Sentinel reports it as overdue after the sender's declared interval and grace period, and logs the finding for `warden alerts`.

In the ring topology, each host sees its two neighbors. For a fleet-wide view, add one host to every other host's replication targets. `--from` selects a different directory containing the peers' replication roots.

Anyone with write access to the receiving directory can forge a heartbeat. Heartbeats are reports for operator review and do not trigger automatic response.

### `warden sentinel-check`

Repairs missing registrations: the forced-command key, sudoers rule, spare binary, cron entry, and Warden timers for watch, snapshots, scan, sentinel, and configured replication. A timer needs its service file, timer file, and enabled symlink. Checks read these files directly.

Each timer is checked so disabling one cannot permanently stop its scheduled function while sentinel continues running.

```
warden sentinel-check
# recreated: [authorized_keys systemd-timer cron-entry watch-timer scan-timer]
```

A systemd timer and a separate cron entry invoke this command. Either can restore the other's missing registration.

### `warden opmenu`

Invoked by the SSH key's forced command. It reads the requested operation from `$SSH_ORIGINAL_COMMAND`; see the SSH examples below.

### `warden debug-config`

Checks baked-in configuration on the build machine. It prints configured values except the TOTP secret and replication private key, which are reported only as set or unset. Use a native build; see DEPLOYMENT.md step 3.

## Operating over SSH

Once installed, the team connects with:

```
ssh -i <team private key> <opmenu-user>@<box>
```

`<opmenu-user>` is the basename of `INSTALL_PATH`, not root.

`authorized_keys`' forced command means whatever you'd normally type as a remote command becomes `$SSH_ORIGINAL_COMMAND`, parsed as `<command> [totp-code] [args...]`:

| You run | opmenu sees | Needs TOTP? |
| --- | --- | --- |
| `ssh <opmenu-user>@<box> status` | the same report `warden status` prints locally: armed state, manifest generation, last snapshot, last `watch`/`sentinel-check`/`scan`/`replicate` pass | No |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf"` | dry-run restore of that path | Yes |
| `ssh <opmenu-user>@<box> "restore <code> /etc/nginx/nginx.conf apply"` | restores it (same as `restore --apply`) | Yes |
| `ssh <opmenu-user>@<box> "shell <code>"` | drops into `/bin/bash` as root, the only path that leaves the Go binary | Yes |

`<code>` is a current six-digit TOTP code or the configured static second factor. TOTP codes are single-use across restore, shell, accept, and uninstall. A dry run and its apply therefore need separate TOTP codes. The static passphrase is reusable until rotated. Invalid requests are rejected and logged with the source IP.

`status` needs no second factor and reports armed state and the latest pass of each periodic component.

Run `arm`, `disarm`, and `detect` through `opmenu shell`; they are not separate opmenu commands.

`shell` runs Bash over a `no-pty` channel. In this non-interactive mode, Bash does not normally write command history. This changes if a PTY is added or the shell is configured differently. Other interactive shells record history normally; see DEPLOYMENT.md.

## Audit log

`/var/lib/warden/audit.log` is JSON-lines, one entry per action:

```json
{"time":"2026-09-20T17:47:41Z","component":"watch","action":"auto-restored","fields":{"kind":"modified","path":"/etc/nginx/nginx.conf"}}
```

`component` identifies the subsystem that logged the event; `fields` contains event-specific data.

## Backup recovery

Restore, watch, and replication use the local object store first. If an object is missing or corrupt, Warden checks configured `file://` replicas, then SSH peers in configuration order. Failed connections and invalid copies are skipped. Each recovered object must match the SHA-256 recorded in the manifest before it is cached or restored. Recovery records the source in `audit.log`.

A missing live manifest is recovered from local archives or configured peers. Warden selects the newest valid generation it can read. An explicit `--snapshot` or `--generation` requires that exact generation; it never substitutes an older one. If every copy is gone, the operation fails with the attempted sources instead of creating an empty replacement baseline.

```sh
warden retrieve --tier config                 # inspect available metadata
warden retrieve --tier config --apply         # recover objects and adopt the baseline
warden restore /srv/example/score.dat --tier data --apply
```

Recovery uses existing replication targets. SSH connection and handshake attempts have ten-second limits; session opening and commands have fifteen-second limits. A timed-out peer is closed so another can be tried. Object hashes detect damaged or mismatched content; manifests still rely on trusted local state and configured peers, without a separate signature.

## Known limitations

- `restore --tier data <path>` restores individual data-tier files, with `--snapshot <generation>` and `--apply` available for either tier. The default tier and opmenu restore remain config. `retrieve` covers both tiers.
- Without `/etc/warden/profile.json`, the built-in multi-distro defaults still apply. Warden cannot infer this season's scored files or credentials; supply the host profile described below before taking the baseline.
- `detect` reports unknown running process names as well as known services. Unknown processes are inventory leads, not proof of a scored service; their config paths need explicit profile entries. A stopped unknown service with no profile entry cannot be discovered this way.
- Auto-ban prefers a plaintext sshd auth log and falls back to `journalctl` when neither file exists. Journal reads have a ten-second timeout and start 24 hours before the change; older sessions or missing/rotated/unreadable logs can still leave insufficient evidence. No usable evidence means an alert without a ban. Verify the target's journal access and retention.
- Auto-ban acts at this host's firewall. It excludes `TEAM_FROM_IP` and IPs associated with the team's key fingerprint in the available SSH logs; missing key fingerprints cannot establish that extra exclusion.

IP bans and account locks default to no expiry. `--duration 0` explicitly selects indefinite; a positive duration (for example `--duration 1h`) schedules expiry, and negative durations are rejected. Existing timed records retain their saved expiry. Use `unban` or `unlock-account` for immediate removal.

## Host-specific protection profile

Create `/etc/warden/profile.json` as a root-owned file (mode `0600`, in a root-owned directory). Every CLI invocation, including timers and cron, loads it. An absent file keeps the built-in defaults; an invalid file stops the command with an error. A present profile **replaces** the built-in watched paths, classifications, and service mappings, so include every file this host needs. Paths are individual absolute file paths; service names omit `.service`.

```json
{
  "paths": [
    {"path": "/etc/example/server.conf", "tier": "config", "class": "auto-restore", "services": ["example"]},
    {"path": "/srv/example/score.dat", "tier": "data", "class": "confirm-first", "services": ["example"]}
  ],
  "services": [
    {"Name": "Example", "ProcessNames": ["example"], "ConfigPaths": ["/etc/example/server.conf"]}
  ]
}
```

`services` extends detection; it does not add watched paths. Use `confirm-first` for files that should only be flagged, and `auto-restore` for files to enforce when armed. Data-tier files are snapshotted but never watched automatically. Disarm before changing the profile, inspect `warden detect`, and take fresh snapshots of both tiers before arming the reviewed config baseline. No rebuild is required.

```sh
warden restore /srv/example/score.dat --tier data                 # preview latest data snapshot
warden restore /srv/example/score.dat --tier data --snapshot 7 --apply
```

See `docs/PLAN.md` for the full phased build history and what's still open.

## Backup verification and restore checks

```sh
warden verify-backups
warden verify-backups --record
warden verify-backups --repair
warden restore /etc/nginx/nginx.conf --preflight
warden profile validate --strict
warden arm --strict
```

Verification covers active and retained generations across local storage and configured replicas. It reports missing, corrupt, unreadable, and unreachable copies separately. `--repair` caches verified remote objects locally; it does not replace remote copies or silently adopt another generation. `--record` saves the latest result for status. Without either flag, verification makes no filesystem changes.

Restore preflight checks object availability, destination types, parent directories, and write access without writing files. Apply stages all files before stopping services. It preserves which services were running, publishes all files, checks content and modes, and runs configured validators before starting those services. On a write or validation failure it restores the previous files before restarting. If rollback itself fails, the error identifies that services need operator recovery.

Watch applies recorded account locks to the expected passwd/shadow content without changing approved archives. It finishes repairs before reloading services and retries pending reloads on later successful armed passes. Explicit unlock restores the recorded original shell. Zero-duration bans and locks remain indefinite.

`status` shows the last recorded backup verification, usable replica count, pending reload count, and unavailable local objects in each active snapshot. Reports are timestamped; they are not a guarantee that a previously verified peer is still available.

Mutating commands share a process lock. An overlapping timer or manual command returns a busy error and can be retried. Archived generation numbers are not reused after rollback. Pruning retains active-baseline objects in both tiers in addition to the newest ten generations.

When adopting backups, `retrieve --allow-rollback` is required if the selected generation is older than recorded history or some lineage checks cannot complete. Automatic recovery refuses a known rollback. See DEPLOYMENT.md for `ssh+receiver://` targets and signed manifests.
