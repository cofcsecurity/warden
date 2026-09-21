# What Warden Does

Warden helps a CCDC defense team retain access to its servers
and recover damaged configuration files and service data. This page explains
the main features. See [USAGE.md](USAGE.md) for commands and
[DESIGN.md](DESIGN.md) for implementation details.

Your team inherits servers running services such as web, mail, and databases.
Red team attempts to compromise them while the scoring engine checks that
services remain available and work correctly. Warden backs up selected files,
restores approved configurations, and maintains a restricted SSH access path.

## Access, backups, and file monitoring

Warden installs a team SSH key in a dedicated account. The key is restricted
by source IP and a forced command. Status is read-only; restore and shell
access require a second factor. Scheduled checks restore the key entry and
its supporting registrations if they are removed.

Config files are snapshotted every few minutes. Larger service data is
snapshotted hourly. When replication is configured, Warden copies backups to
other team-controlled hosts or removable media so recovery does not depend
on the source host's local disk.

`watch` compares configured files against the approved baseline. When armed,
it restores files classified as `auto-restore` and reloads their owning
services. The default list includes `sshd_config`, `/etc/passwd`,
`/etc/group`, `/etc/sudoers`, and PAM files because changes to these can
prevent the team from logging in to repair the host.

Files classified as `confirm-first` are flagged for review and left in place.
The defaults include password hashes and saved firewall rules: restoring
these could undo a password rotation or a firewall change made by the team.
Restoring a saved firewall file also does not update the live ruleset.

While armed, scheduled snapshots cannot accept changed config files as the
new baseline. Use `warden accept` to approve one file or `warden arm` to
review and approve the full config tier. Data-tier snapshots continue to
capture changing service data.

## Setup

Auto-restore starts disabled so Warden does not undo the team's initial
hardening. Monitoring still runs and reports changes.

Run `warden detect` to review existing protected paths, recognized services,
and unknown running processes. Configure the files, classifications, and
service mappings for this host in `/etc/warden/profile.json`. Warden cannot
infer which files the scoring engine needs; see [USAGE.md](USAGE.md)'s
host-profile section.

After hardening, run:

```sh
warden arm
```

`arm` prints the host configuration and every watched file added, modified,
or removed since the previous baseline. Review that list before confirming.
It can contain both your changes and changes made by an attacker during
setup. After confirmation, Warden snapshots the reviewed files and enables
auto-restore.

You can also harden before installing. In that case, the review may contain
no changes. If you hardened after installation but the review is empty,
check that the files you edited are in the watch list.

For later maintenance, run `warden disarm`, make the changes, then run
`warden arm` and review the new baseline. Over a non-interactive connection,
`arm --yes` skips the confirmation prompt but still prints the review.

## Response

When a `confirm-first` file changes, Warden checks SSH session records for
root sessions that overlapped the change. It reads a plaintext auth log, or
falls back to the system journal when neither supported log file exists.

Automatic IP bans require `AUTOBAN_ENABLED` at build time. Attribution must
identify one non-team root IP. Warden excludes the configured team IP or CIDR
and addresses associated with the team's key fingerprint in the available
logs. Missing evidence or multiple candidate IPs produce an alert without a
ban. The audit entry includes candidate IPs when attribution is ambiguous.

IP bans are indefinite by default. Use `warden unban <ip>` to remove one, or
`warden ban <ip> --duration 1h` for a manual ban that expires. The firewall
rule applies only on the defended host.

Use `warden accept <path> <code>` to approve an intentional edit to one
watched file. It requires a valid second factor and updates only that file's
baseline.

`warden alerts` displays events in the session where it runs. It does not
broadcast to other logged-in users. For a live view, open another
`opmenu shell` session and leave `warden alerts` running there.

`warden scan` checks for:

- New or modified local user and group accounts, and new domain accounts.
- New SUID/SGID binaries or changed contents of known ones.
- Changes to cron jobs or `authorized_keys` files across accounts.
- New listening TCP ports.
- Newly installed packages.

The first run establishes a baseline. Later findings are logged and shown
by `warden alerts`. Each run also records its completion so `warden status`
can show when the scanner last ran.

When armed and built with `AUTOLOCK_ENABLED`, Warden can lock an account
associated with a finding and attempt to terminate its sessions. Account
locks are indefinite by default. Use `warden unlock-account <user>` to
remove a lock, or supply a positive `--duration` when locking manually to
set an expiry.

Root, the opmenu account, non-local accounts, and accounts in `SAFE_ACCOUNTS`
are excluded from automatic locks. A manual `--force` can override only the
`SAFE_ACCOUNTS` exclusion. Domain accounts must be managed through their
directory service. With `AUTOBAN_ENABLED`, scan can also attempt IP
attribution using the same SSH evidence checks as guarded-file changes.

## Monitoring and recovery

Each replication push writes a heartbeat to its peers, recording the host's
armed state, manifest generation, and recent checks. A peer reports a
heartbeat as overdue after the sender's declared interval and grace period.
`sentinel-check` logs one alert when a peer becomes overdue and another when
it returns.

`warden fleet` shows the local host and peers that report to it. In the
bidirectional ring setup, each host sees its two neighbors. To collect a
full fleet view on one host, add it to every other host's replication targets.

Heartbeats require human review. A late heartbeat may indicate a reboot or
network failure, and anyone with write access to the receiving directory can
forge one. Heartbeats do not trigger bans or account locks.

Warden runs short commands from systemd timers and cron. The sentinel timer
and a separate cron entry both invoke `sentinel-check`, which repairs missing
registrations, including the SSH key entry, sudoers rule, and Warden timers.
If one trigger is removed, the other can restore it on its next run. Removing
both stops those checks until a trigger is restored.

A spare binary is kept under `/var/lib/<name>/.spare`. The cron command can
copy it back if the installed binary is deleted, using `test`, `cp`, and
`chmod` before invoking Warden. This handles deletion; it does not verify a
running binary against an independent trusted copy.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the registration and recovery diagrams.

1. About every five minutes: check watched configs and restore or flag changes.
2. About every five minutes: snapshot the config tier, preserving the approved
   baseline while armed.
3. Hourly: snapshot the data tier.
4. About every fifteen minutes: replicate backups to configured peers.
5. About every ten minutes: check and repair persistence registrations.

Operators review detection results, harden and arm each host, monitor status
and alerts, approve intended changes, and restore files as needed. After a
host is rebuilt, `warden retrieve` recovers its backup history from a peer.

## Limits

- SSH access requires the team key and configured source address. Restore
  and shell commands also require a second factor.
- Warden checks selected files and a fixed set of anomalies. It does not
  provide general malware detection or network traffic analysis.
- Warden uses the existing SSH service and does not open a new listening port.
- Bans and account locks affect the defended host only.
- Actions are recorded in the audit log, which is copied to peers when
  replication is configured. Local log retention is bounded.
- Installation does not enable auto-restore. An operator must review the
  baseline and run `arm`.
- Scored paths, service mappings, safe accounts, and credentials need to be
  configured for the competition. Missing or incomplete SSH logs can prevent
  attribution and automatic bans.

## Reference

- [DEPLOYMENT.md](DEPLOYMENT.md): setup, verification, and arming.
- [USAGE.md](USAGE.md): command reference.
- [DESIGN.md](DESIGN.md): implementation and design decisions.
- [ARCHITECTURE.md](ARCHITECTURE.md): component diagrams.
- [PLAN.md](PLAN.md): completed work and remaining verification.
