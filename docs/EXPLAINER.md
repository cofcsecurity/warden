# What Warden Does

Warden runs on a competition box after the team has hardened it. Red wants to destroy things and lock the team out; Warden keeps the team's way in open, puts protected files back, and keeps backups on other boxes. It does not keep an audit trail, prove who did what, or ask for approval: anyone holding the team key can do anything.

See [DEPLOYMENT.md](DEPLOYMENT.md) for setup, [USAGE.md](USAGE.md) for commands, and [DESIGN.md](DESIGN.md) for how it works.

## Access that survives

The team has one SSH key. Its public half is the only input to `warden install`. On each box Warden creates an account that accepts that key, from the team network only, with a forced command: no command opens a root shell, anything else runs that warden command.

Red locks people out by breaking one link of the chain between the key and a root shell. Sentinel checks each link and repairs it:

| Link | Red's move | Warden's repair |
| --- | --- | --- |
| Key file | delete, edit, `chattr +i`, bind-mount over `.ssh` | rewrite it, clear the flag, unmount |
| Account | delete, lock, expire, `nologin` shell | recreate and unlock it |
| sshd config | `DenyUsers`, `AllowUsers`, `PubkeyAuthentication no`, a hostile drop-in | our own `Match User` drop-in pins our key file; watch restores sshd's files; drop-ins red adds are quarantined |
| sshd | stop, mask | unmask and start |
| sudo | delete our rule | rewrite it (validated with `visudo`) |
| Firewall | DROP the team network above our rule | put our ACCEPT back at the top of INPUT |
| Warden itself | delete the binary, kill the timers | restore from spares; every trigger rebuilds the others |

Repairs run from several independent triggers: a systemd timer, a path unit that fires the moment an access file changes, root's crontab, a hook on sshd's own start, and the break-glass account's own timer and `/etc/cron.d` entry. Red has to clear all of them inside a minute or two.

The **break-glass** account is a second door with a different account, home, key file (outside `/home`), sudoers file and sshd drop-in, so one deletion cannot take both.

Nothing here changes how anyone else logs in. The sshd drop-ins apply only to Warden's accounts; the firewall rule only accepts the team network.

## Files that go back

`arm` snapshots the watched files as they are and turns on auto-restore. The default list follows the team's hardening sheet:

- **Restored:** sshd config and drop-ins, PAM, `/etc/security`, sudoers and drop-ins, passwd and group, cron, plus common service configs (nginx, Apache, MySQL, Postfix, Samba, ...). The owning service is reloaded after a restore.
- **Quarantined:** a new file in a restored directory (`sshd_config.d`, `sudoers.d`, `pam.d`, `cron.d`, ...) is copied to the state directory and removed.
- **Flagged only:** shadow and gshadow, firewall rules, systemd units, per-user crontabs, every account's `authorized_keys`. The team changes these while hardening, so Warden reports drift and leaves it. `accept --flagged` makes the current state the new baseline.

Web roots (`/var/www`) are snapshotted hourly and restored by hand.

Arm after hardening, once scoring works: whatever is on disk at arm time is what Warden holds the box to. To change a protected file later: `disarm`, change it, check, `arm`.

## Backups on other boxes

Each box keeps content-addressed backups locally and pushes them to paired peers. A peer stores them under a directory only that source's key can write to, through a forced command with no shell and no delete. When the peer's quota for a source is full it refuses new uploads rather than dropping old ones, so a compromised source cannot flood out its good backups. Pair boxes in a ring so every box has at least one peer.

## Responses

Warden can ban an IP or lock an account tied to a flagged change. Each response is `off`, `flag` (the default: log what it would have done) or `act`, set at runtime with `config set`. Root, Warden's accounts, the team network and safe-listed accounts are never touched.
