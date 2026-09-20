# Usage

What Warden does, command by command, once it's installed on a box. For *getting* it installed, see [DEPLOYMENT.md](DEPLOYMENT.md); for *why* it's built this way, see [DESIGN.md](DESIGN.md).

Every command below reads and writes fixed paths under `/var/lib/warden` and a handful of other fixed system paths — there is no config file and no flag to point them elsewhere. See "On-disk layout" below and DESIGN.md's "Configuration" section for why.

## On-disk layout

```
/var/lib/warden/
  manifest-config.json       live pointer to the config tier's last snapshot
  manifests-config/          archived config-tier generations: manifest-<n>.json
  manifest-data.json         live pointer to the data tier's last snapshot
  manifests-data/            archived data-tier generations
  objects/                   content-addressed, gzip-compressed file contents
                              (objects/<hash prefix>/<hash>), shared by both tiers
  audit.log                  append-only JSON-lines log of every action taken

/root/.ssh/authorized_keys   the team's forced-command entry (sentinel-checked)
/etc/systemd/system/         watch/sentinel/snapshot timer + service units
```

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

- **`safe-auto-restore`** paths (most config files): reverted immediately from `objects/`, logged as `auto-restored`.
- **`confirm-first`** paths (keys, `passwd`, `sudoers`, `sshd_config` — see `cmd/warden/config.go`'s `confirmFirstPaths`): never touched. Logged as `flagged`, and it'll be flagged again on every subsequent run for as long as the drift is unresolved — `watch` never updates its own baseline, so nothing makes the alert go away except a human fixing it and running `snapshot` again to accept the new state.
- **Unexpected new paths**: flagged, not restored — there's no known-good content to restore from.

Not a daemon; invoked by a jittered systemd timer (`*-watch`, every 5 min ± up to 90s).

```
warden watch
# auto-restored: 1, flagged: 0
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

Pushes anything new since the last replication to the off-host target baked in at build time (`REPLICATE_URL` — `ssh://` or `file://`). Additive-only on the destination: existing objects and manifest generations there are never touched, so a compromised source box can add junk but can't destroy prior backups.

```
warden replicate
```

Fails immediately if no `REPLICATE_URL` was baked in, or (for `ssh://`) if `REPLICATE_KEY`/`REPLICATE_HOST_KEY` weren't. Not scheduled by `install.sh` — the design doc leaves the cadence to the team; add a systemd timer for it the same way as the others if you want it automatic.

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
ssh -i <team private key> root@<box>
```

`authorized_keys`' forced command means whatever you'd normally type as a remote command becomes `$SSH_ORIGINAL_COMMAND`, parsed as `<command> [totp-code] [args...]`:

| You run | opmenu sees | Needs TOTP? |
| --- | --- | --- |
| `ssh <box> status` | manifest generation, last snapshot time, last `watch`/`sentinel-check` pass | No |
| `ssh <box> "restore <code> /etc/nginx/nginx.conf"` | dry-run restore of that path | Yes |
| `ssh <box> "restore <code> /etc/nginx/nginx.conf apply"` | actually restores it (same as `restore --apply`) | Yes |
| `ssh <box> "shell <code>"` | drops into `/bin/bash` — the only path that leaves the Go binary | Yes |

`<code>` is the current 6-digit TOTP code from the seed baked in at build time. Anything else — an unrecognized command, a missing/wrong code on `restore`/`shell` — is rejected and logged to `audit.log` either way, along with the source IP (already constrained by `authorized_keys`' `from=` before opmenu ever runs).

`status` deliberately needs no second factor, so it stays a safe, cheap way to check in without spending a TOTP window.

## Audit log

`/var/lib/warden/audit.log` is JSON-lines, one entry per action:

```json
{"time":"2026-09-20T17:47:41Z","component":"watch","action":"auto-restored","fields":{"kind":"modified","path":"/etc/nginx/nginx.conf"}}
```

`component` is which part of Warden logged it (`snapshot`, `watch`, `restore`, `replicate`, `sentinel`, `opmenu`); `fields` is action-specific detail. This file, kept current, is the team's evidence of exactly what Warden did if a judge asks — see DESIGN.md's Rules of Engagement note.

## Known limitations

- `restore` only operates on the config tier — there's no CLI path to restore an individual data-tier file today.
- `replicate` isn't scheduled by `install.sh`; it's a manual/cron-it-yourself step.
- `configTierPaths`/`dataTierPaths`/`classifyPath`/`serviceForPath` in `cmd/warden/config.go` are a worked example (common CCDC services), not this season's actual scored image — see `docs/PLAN.md` Phase 1.

See `docs/PLAN.md` for the full phased build history and what's still open.
