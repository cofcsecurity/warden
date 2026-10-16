# Usage

Command reference. See [DEPLOYMENT.md](DEPLOYMENT.md) for installation and [DESIGN.md](DESIGN.md) for how it works. Every command accepts `--quiet` (print only errors) and `--verbose`.

## Over the team key

`<name>` is the access account `install` printed. Anything after the host becomes the warden command; nothing opens a root shell.

```bash
ssh -t -i team <name>@<box>                  # root shell
ssh -i team <name>@<box> status
ssh -i team <name>@<box> restore /etc/nginx/nginx.conf --apply
ssh -t -i team <break-glass>@<box>           # second door, same key
```

There is no code to type and no command whitelist beyond "is it a warden command": the key, from the team network, is the whole check. Unknown commands are refused rather than run through a shell.

## On-disk layout

```
/usr/local/sbin/<name>              the binary
/var/lib/<name>/                    state (root only)
  config.json                       runtime config (team key, network, modes, peers)
  profile.json                      optional host profile
  manifest-config.json, manifests-config/   config-tier baseline and generations
  manifest-data.json, manifests-data/       data-tier snapshots
  objects/                          content-addressed backups
  audit.log                         plain local log of what Warden did
  quarantine/                       files removed from watched drop-in directories
  peer_key                          this box's backup key (never leaves the box)
  .spare                            spare binary
/usr/lib/<name>/                    second spare binary and config copy
/var/lib/<name>-peers/<source>/     backups other boxes keep here
/home/<name>/.ssh/authorized_keys   team key (and paired sources' upload keys)
/usr/lib/<break-glass>/keys         break-glass key file
/etc/sudoers.d/<name>, /etc/sudoers.d/<break-glass>
/etc/ssh/sshd_config.d/00-<name>.conf, 01-<break-glass>.conf
/etc/systemd/system/<name>-{refresh,verify,cache,archive,audit,sync}.*
```

## Setup

### `install --key <pubkey|@file|https://url> [--from cidrs|any] [--yes]`

Installs this binary under a chosen name, writes the runtime config, creates both access accounts, every trigger and timer, and the first snapshots. Re-running on an installed box updates it in place. Options: `--name`, `--no-break-glass`, `--ban`, `--lock`, `--safe-accounts`. Normally run through `./install.sh`.

### `rekey <pubkey|@file|https://url> [--from cidrs]`

Replaces the team key (and optionally the network) on this box. The old key stops working at once.

### `config show` / `config set <key> <value>`

Runtime settings, no rebuild: `allow_from`, `ban` and `lock` (`off`, `flag`, `act`), `safe_accounts` (comma-separated), `peer_quota_mb`.

### `uninstall [--force] [--yes]`

Stops every trigger first, then removes units, cron entries, sshd hooks and drop-ins, the firewall rule, sudoers rules, both accounts, the binary, spares and state. Copies on peers stay. Refuses on an armed box without `--force`.

## Protect

### `arm` / `disarm`

`arm` snapshots every watched file as it is and turns on auto-restore. It lists what changed since the last snapshot so you can spot anything that was not you, then never prompts. `disarm` turns auto-restore off; watch still flags. Arming again after a disarm re-baselines.

### `watch`

One pass, run by a timer every two minutes. While armed: drifted auto-restore files are restored and their service reloaded; new files in auto-restore directories are quarantined; flag-only drift is reported. Disarmed: everything is only reported.

### `accept <path>... | --flagged`

Makes the current state of the named watched paths their baseline. `--flagged` does it for every drifted flag-only path, the usual follow-up after changing passwords or firewall rules while armed.

### `restore <path> [--tier config|data] [--snapshot N] [--apply] [--preflight]`

Restores one file from a snapshot. Dry run by default. `--apply` stages the file, stops the owning service, writes, verifies the hash, and starts it again, rolling back on failure.

### `snapshot [--tier config|data]`

Run by timers (config every 5 minutes, data hourly). While armed, the config baseline is frozen: only `arm` and `accept` move it.

### `sentinel-check`

Checks and repairs every link of the access chain and every trigger. Run by several triggers; safe to run by hand any time.

### `status [--json]`

Armed state, team network, response modes, peers, snapshot generations, the last pass of each job, pending reloads, quarantined files. `--json` is the stable form seer reads.

### `alerts [--follow]`

What Warden restored, quarantined, repaired and flagged, plus bans and locks (or what flag mode would have done). Only the calling session sees it.

## Backups

### `pair key` / `pair accept <source> <key>` / `pair add <url> <hostkey>`

```bash
ssh -i team <a>@A pair add $(ssh -i team <b>@B pair accept $(ssh -i team <a>@A pair key))
```

`pair key` prints this box's name and backup public key (generating the key on first use). `pair accept` on the peer authorizes it for uploads only and prints the URL and host key to push to. `pair add` records the peer and pushes once. `pair list` and `pair remove <url|source>` manage them. Re-accepting a rebuilt source keeps its stored backups.

### `replicate`

Pushes both tiers to every peer (timer every 15 minutes). Peers keep every generation; when a source's quota is full they refuse new uploads instead of deleting.

### `retrieve [peer-url] [--tier config|data] [--generation N] [--apply]`

Pulls this box's own backups back after it lost them: dry run by default, `--apply` adopts the baseline. After a full rebuild, re-run `install`, `pair accept` the new key on the peer (same source name), `pair add`, then `retrieve --apply`.

### `verify-backups [--record] [--repair]`

Checks every retained generation's objects locally and on peers.

## Respond

### `ban <ip>` / `unban <ip>` / `lock-account <user>` / `unlock-account <user>`

Manual responses. Automatic ones follow the `ban` and `lock` modes: `flag` logs "would ban 10.0.0.9" and changes nothing; `act` does it. Root, Warden's accounts, the team network and `safe_accounts` are always exempt.

### `scan`, `detect`, `account-edit`, `profile validate`

`scan` looks for new accounts, SUID binaries, cron jobs, keys, ports and packages. `detect` lists which watched paths exist here and which running services are not covered. `account-edit` runs `passwd` or `gpasswd` and accepts exactly that change (see [ACCOUNT-MAINTENANCE.md](ACCOUNT-MAINTENANCE.md)). `profile validate` checks coverage, mapped services and peers.

## Host profile

`/var/lib/<name>/profile.json` extends the defaults. Its entries are checked first, so it can reclassify a default path. Paths may be exact, single-level globs, or `/**` trees.

```json
{
  "exclude": ["/etc/hostname"],
  "paths": [
    {"path": "/etc/scored/app.conf", "tier": "config", "class": "auto-restore", "services": ["scored"]},
    {"path": "/etc/scored/conf.d/*", "tier": "config", "class": "auto-restore"},
    {"path": "/srv/scored/**", "tier": "data", "class": "confirm-first"}
  ]
}
```

`"replace": true` drops the defaults. A broken profile stops profile-dependent commands but never the access shell, `status` or `disarm`.
