# warden

Keeps a defended competition box alive and recoverable. Built for the CofC Cybersecurity Club's SECCDC/PCDC defense team.

Red's goal is to lock us out and destroy things. Warden's job is narrow:

- **Keep the team's access alive.** One team SSH key, from the team network, gets a root shell or runs any warden command. Sentinel checks every link between that key and a root shell (account, key file, sshd's effective config, sshd itself, sudo, the firewall) and repairs what red breaks. A second break-glass account, with its own key file, sudoers rule and triggers, keeps a door open if the main one falls. Each path repairs the other.
- **Put files back.** Once armed, files red edits to lock us out or backdoor the box (sshd, PAM, sudoers, passwd, cron) go straight back and their service reloads. New files dropped into those directories are quarantined. Files the team changes on purpose (shadow, firewall rules, units, user keys) are only flagged.
- **Keep backups somewhere else.** Every box snapshots its own files and pushes them to a peer box that keeps several generations and cannot be told to delete them.

There is no second factor, no approval step and no attribution trail. Holding the team key is the whole check. See [EXPLAINER.md](docs/EXPLAINER.md).

## Install on a box

Nothing is prepared on a laptop and nothing secret is in this repo. Make the team key once, on any laptop, with the `ssh-keygen` it already has:

```bash
ssh-keygen -t ed25519 -f team -C team
```

Then on each box, as root:

```bash
git clone https://github.com/cofcsecurity/warden.git && cd warden
sudo ./install.sh --key "$(cat team.pub)"
```

`install.sh` builds with Go (fetching a verified toolchain if the box has none) or, with `--release vX.Y.Z`, downloads a release binary and checks it against the release's `SHA256SUMS`. The only question it asks is the team network, defaulting to the /24 you are connected from. Auto-restore is off until you arm.

## Use it

```bash
ssh -t -i team <name>@<box>                 # root shell
ssh -i team <name>@<box> status             # any warden command
ssh -i team <name>@<box> arm                # after hardening, once scoring works
ssh -i team <name>@<box> pair add $(ssh -i team <peer-name>@<peer> pair accept $(ssh -i team <name>@<box> pair key))
```

`<name>` is printed by install. To change a protected file later: `disarm`, change it, check scoring, `arm`.

Docs: [deployment](docs/DEPLOYMENT.md), [commands](docs/USAGE.md), [design](docs/DESIGN.md), [architecture](docs/ARCHITECTURE.md).

## Layout

```
cmd/warden/    CLI: install, arm/disarm, watch, restore, sentinel-check, pair, opmenu, ...
internal/      manifest, store, watch, restore, replicate, sentinel, opmenu, anomaly, ...
test/e2e/      container end-to-end tests (Ubuntu and Rocky boxes, a laptop with only ssh)
install.sh     build or fetch, verify, then `warden install`
```

## Testing

```bash
make test        # unit tests
make e2e         # containers: install, tamper, lockout attempts, break-glass, pairing (needs Docker)
```
