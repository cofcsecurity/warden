# Deployment Checklist

Prepare credentials and replication targets, then build, install, verify, harden, and arm each host.

If no separate build machine is available, use [the on-host build procedure](#alternative-build-directly-on-the-target-box). It replaces the build and installation steps.

## Quick reference

**Part A, once per competition, build machine only:**
- **Step 0, 1, 2**: [decide what to watch without fighting the scoring engine](#0-dont-let-warden-fight-the-scoring-engine), [generate secrets](#1-generate-per-competition-secrets) (`generate-keys.sh`), [plan replication topology](#2-replication-topology) if defending multiple boxes.
- **Step 3**: [build](#3-build) one binary per box (`make build`), and verify it with `debug-config` before trusting it. *(No build machine? See [the alternative](#alternative-build-directly-on-the-target-box) instead.)*

**Part B, once per box:**
- **Step 4, 5**: [fill in `install.sh`'s per-box values](#4-confirm-installshs-per-box-values) and [deploy](#5-deploy-to-each-box) (`scp` + `sudo ./install.sh`, which now prints its own next-steps summary when it finishes).
- **Step 6**: [verify](#6-verify) the access layer and replication both work.
- **Step 6.5**: [harden the box, then arm it](#65-harden-then-arm) (`warden detect` + `warden scan` → harden → `warden arm`). **The box is unprotected against config drift until this step, a fresh install is not the same as a defended box.**
- **Step 7, 8**: keep [recovery](#7-recovery-pulling-a-boxs-own-backups-back) in mind for if a box gets wiped later, and repeat steps 3–6.5 [per box](#8-repeat-per-box).

## 0. Don't let Warden fight the scoring engine

Identify the scoring engine's accounts and credentials before configuring watched paths. Do not auto-restore credentials that the scoring engine rotates. If they need monitoring, use `ConfirmFirst`.

Include the team's local operating accounts and the scoring account in `SAFE_ACCOUNTS`. IP exclusions do not protect these accounts from the separate account-lock response.

## 1. Generate per-competition secrets

For a single box:

```
./scripts/generate-keys.sh
```

For multiple boxes (see step 2 if defending several), pass a distinct output directory per box instead, **each box should get its own replication keypair**, not a shared one:

```
./scripts/generate-keys.sh secrets/box1
./scripts/generate-keys.sh secrets/box2
```

Either way it writes (gitignored): a replication-only SSH keypair (`replicate_key`/`replicate_key.pub`) and a TOTP seed (`totp_secret`). None of this belongs in this repo or anywhere else public. Distribute each TOTP seed to teammates who'll need to generate opmenu codes, out-of-band (e.g. a QR code shown once, not pasted into Slack).

This does **not** generate the team's own login keypair (`TEAM_PUBKEY`), use whatever key a team member already holds the private half of, or generate one now, **on your own machine, never on a target box**:

```
./scripts/generate-team-key.sh
```

Prints the public key to use as `TEAM_PUBKEY`. Generate this once per competition, not once per box, every box uses the same value, and every teammate who'll operate a box needs a copy of the private half, shared out-of-band.

If a separate machine is unavailable, generate the team key on a host with:

```
./scripts/generate-team-key.sh --on-box
```

This generates the keypair on the host and guides you through saving the private key elsewhere before removing its local file. Share it with authorized teammates through a private channel. Reuse the team key across hosts. The build-and-install script offers this step and removes the leftover public-key file after building.

## 2. Replication topology

For multiple hosts, configure a bidirectional ring. Each host replicates to its two neighbors and receives backups from them. For six hosts:

```
box1 ⇄ box2 ⇄ box3 ⇄ box4 ⇄ box5 ⇄ box6 ⇄ box1
```

Each connection requires a target entry in both directions. Each host then has three copies of its backups: one local and two on peers.

Set each host's `REPLICATE_TARGETS` to its two neighbors.

### Per-box secrets

Generate a separate replication keypair for each host so a stolen key grants access only to that host's configured peers:

```
./scripts/generate-keys.sh secrets/box1
./scripts/generate-keys.sh secrets/box2
# ... one per box
```

(Each run also writes a fresh `totp_secret`; reuse one across boxes or generate per-box ones, see step 3's note.)

`warden fleet` shows hosts that replicate to the current host. To collect a full fleet view, add one host as a third target for every other host. The ring's backup copies remain in place.

### Set up each box's receiving side

The current SSH transport executes shell commands on the receiver. It requires a dedicated account with a working shell. A `nologin` shell or `command="/usr/bin/false"` in authorized_keys blocks replication.

```sh
useradd -m -s /bin/sh warden-backup
install -d -o warden-backup -g warden-backup -m 700 /home/warden-backup/.ssh
install -o warden-backup -g warden-backup -m 600 /dev/null /home/warden-backup/.ssh/authorized_keys
```

Use the file-creation command only for a new account; it replaces an existing authorized_keys file. Append the allowed peers' public keys, restricting each to that peer's address:

```text
from="<box2 IP>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <box2 replication public key>
from="<box6 IP>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <box6 replication public key>
```

These options disable PTYs and forwarding, but still allow commands as the receiving account. Warden's client avoids overwriting existing backups; the server does not enforce that policy. A stolen replication key can modify or delete anything writable by that account. For stronger isolation, use a separate receiving account per source and backup snapshots or storage retention that those accounts cannot alter. A restricted receiver protocol is not implemented yet.

Inspect and verify the receiving host's public key through a trusted channel before pinning it. `ssh-keyscan` collects a candidate key but does not authenticate it:

```
box1$ ssh-keyscan -t ed25519 box2   # run this from box1, to pin box2's key in box1's own build
```

**Path matters**: use a path under `/home/warden-backup/`, e.g. `/home/warden-backup/from-box1`, an absolute root-level path like `/from-box1` will fail with a permission error, since the receiving account isn't root and can't create directories outside its own home.

## 3. Build

Each box's `REPLICATE_TARGETS` lists both neighbors, `<url>||<hostkey>` pairs separated by `;;`:

```
make build \
  TEAM_PUBKEY="<team login pubkey>" \
  TEAM_FROM_IP="<team's public IP or CIDR>" \
  TOTP_SECRET="$(cat secrets/box1/totp_secret)" \
  REPLICATE_KEY="$(base64 < secrets/box1/replicate_key | tr -d '\n')" \
  REPLICATE_TARGETS="ssh://warden-backup@box2/home/warden-backup/from-box1||$(ssh box1 ssh-keyscan -t ed25519 box2 2>/dev/null | cut -d' ' -f2-);;ssh://warden-backup@box6/home/warden-backup/from-box1||$(ssh box1 ssh-keyscan -t ed25519 box6 2>/dev/null | cut -d' ' -f2-)"
```

Repeat once per box, substituting that box's own two neighbors, its own `secrets/<box>/` keys, and `from-<box>` as the path segment (so each box's backups land in their own subdirectory on each neighbor, never mixed with the neighbor's own local data or its *other* neighbor's backups).

If there's no realistic second box this season at all, `REPLICATE_TARGETS` can instead be a single `file:///path||` entry (empty host key) pointing at removable media, see `docs/PLAN.md` Phase 2.

Add `AUTOBAN_ENABLED=1` to the same `make build` invocation to enable auto-banning an attacker's IP, see `docs/DESIGN.md`'s "Active Response" section. It's off (unset) by default; leaving it off still gets you the flagging and `warden alerts` visibility, just not the automatic firewall block.

Add `AUTOLOCK_ENABLED=1` the same way to enable `warden scan`'s separate account-lock reaction (see `docs/DESIGN.md`'s "Anomaly Detection and Account Lockout" section), off by default too, same reasoning. If it's on, also set `SAFE_ACCOUNTS="<your team's own account>,<scoring's account if it has one>"`, see step 0 above for why this can't be skipped the way `TEAM_FROM_IP` alone protects `AUTOBAN_ENABLED`.

Produces `bin/warden`, a stripped, static binary with everything above baked in. Verify it captured the right values before going further, on a native build since `bin/warden` is cross-compiled for the target's `linux/amd64` and won't run here:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this, it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before deploying.

## Alternative: build directly on the target box

For events with no separate build machine (e.g. PCDC-style, a locked-down provided laptop with no permission to install a toolchain). `scripts/build-and-install.sh` builds Warden directly on the box being defended and installs it in the same run, **replacing steps 3 through 5 below entirely.** Steps 0, 6, 6.5, 7, and 8 still apply as written; come back to step 6 once this is done.

Read the tradeoff at the top of that script's own comments first: per-competition secrets get passed to `go build` as command-line flags, so they're briefly visible in this box's own process list (`ps`) while the build runs. Do this as early as possible in the box's clean-first window (the script asks you to confirm that, same as `install.sh`).

If Go is missing, `build-and-install.sh` offers to download the upstream release to `/usr/local/go`. This requires HTTPS access to go.dev.

The script uses `apt-get`, `dnf`, or `yum` to install missing dependencies where possible. Optional tools such as `qrencode` have fallbacks. The standalone installer also checks for cron and sudo.

The script does not install `python3`. If Python is unavailable for TOTP generation, provide an existing seed or use the static second factor.

### Step 1: get the source code onto the box

This needs the whole repository on the target box, not just the finished binary.

The examples use `~/build`. The checkout remains on disk during installation and is removed after success unless `KEEP_SOURCE=1` is set.

**A. Copy it from a machine that already has it checked out (recommended)**

Copy over SSH using the account provided for the host. The target needs no internet access if dependencies are vendored:

```bash
# from the machine that has this repo, at ./warden:
scp -r ./warden <user>@<box>:~/build
```

For zero internet access on the target box, run this once first, on whatever machine you're copying *from*:

```bash
make vendor   # downloads every dependency into ./vendor, once, on a machine with internet
```

**B. Clone it directly on the box**

Needs `git` already present on the box (`command -v git`) and outbound access to wherever this repo is hosted. If either isn't true, use option A or C instead:

```bash
ssh <user>@<box>
git clone https://github.com/cofcsecurity/warden.git ~/build
cd ~/build
```

If the repo is private, cloning needs credentials (a deploy key or access token) on the box temporarily, treat those like any other secret. `build-and-install.sh`'s cleanup step removes the whole checkout, credentials included, once installation succeeds.

**C. USB drive (no network needed on the box at all)**

```bash
# on your own machine, with this repo at ./warden:
tar czf build.tar.gz --exclude=.git -C . warden
# copy build.tar.gz to a USB drive, plug it into the box's console, then on the box:
mkdir ~/build && tar xzf build.tar.gz -C ~/build --strip-components=1
```

**D. One-line setup (`scripts/bootstrap.sh`)**

Combines fetching the repo and running `build-and-install.sh` into one command, if the box can reach GitHub directly:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/cofcsecurity/warden/main/scripts/bootstrap.sh)"
```

Use `bash -c` so Bash receives the script as an argument and leaves stdin available for prompts. Piping the script into Bash can consume the input needed by those prompts. Private repositories still require credentials on the target.

### Step 2: run it

```bash
cd ~/build   # wherever it landed
sudo ./scripts/build-and-install.sh
```

The wizard collects team key, team IP, and install path, and offers TOTP and replication-key generation. It suggests a `/24` based on the connected client shown by `who`; verify this, especially when using a jump host. Export `TEAM_PUBKEY`, `TEAM_FROM_IP`, `INSTALL_PATH`, `TOTP_SECRET`, `REPLICATE_TARGETS`, `REPLICATE_KEY`, `AUTOBAN_ENABLED`, `AUTOLOCK_ENABLED`, or `SAFE_ACCOUNTS` to supply those values without prompts.

The script builds, checks `debug-config`, and invokes `install.sh`. After success it removes the source tree unless `KEEP_SOURCE=1` is set.

Continue with step 6.

## 4. Confirm `install.sh`'s per-box values

Set `TEAM_PUBKEY` and `TEAM_FROM_IP`. Leave `INSTALL_PATH` empty for automatic selection or set it explicitly. Automatic selection checks for collisions with binaries, accounts, units, and sudoers files. The account and sudoers rule use the selected name. Unfilled team placeholders or a missing binary stop installation.

Also set `REPLICATE_TARGETS` to any non-empty value (e.g. `"1"`) if this box's binary was built with real replication targets, that's just the switch this script uses to decide whether to schedule the replication timer; the real target list lives in the binary, not here.

## 5. Deploy to each box

Once the box has been swept clean of any existing compromise (see `docs/DESIGN.md`'s "No Clean Window: Assume Compromise"). Log in as whatever account the competition gave you, not root:

```
scp bin/warden deploy/install.sh -r deploy/systemd <user>@<box>:~/
ssh <user>@<box> 'sudo ./install.sh'
```

Once the access-layer verification prompt near the end passes, `install.sh` deletes the leftover `~/warden` source binary, the `~/systemd/` template directory, and finally itself. If verification fails, none of that cleanup runs, so those stay in place for debugging.

`install.sh` also prints a "what's next" summary before it deletes itself, the same detect → harden → arm sequence as step 6.5 below.

## 6. Verify

- `ssh -i <team's own login private key> <opmenu-user>@<box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes. `<opmenu-user>` is `INSTALL_PATH`'s basename (`docs/DESIGN.md`'s opmenu section). This is the team's own key from step 3/`TEAM_PUBKEY`, not a `secrets/<box>/replicate_key`, which authenticates the *box* to its replication peers, not an operator to the box.
- Run `warden replicate` by hand once (don't wait for the timer) and confirm objects landed on **both** neighbors: `ssh <neighbor> 'find /home/warden-backup/from-<box> -type f'` should show `manifests-config/`, `manifests-data/`, and `objects/`.

Save the static second factor printed during installation. Restore and shell accept it as an alternative to TOTP. Run `<INSTALL_PATH> rotate-secret` from an existing shell to replace it.

## 6.5. Harden, then arm

Both setup orders are supported:

| Order | What it buys | What to watch for |
| --- | --- | --- |
| **Harden → install → arm** | The initial snapshot contains the hardened files. | Run detect and scan after installation, then review before arming. |
| **Install → harden → arm** | Detection is available during hardening. | Review all changes made while auto-restore was disabled. |

If you hardened after installing but arm reports no changes, verify that the edited paths are watched.

Installation leaves auto-restore disabled. Open a shell with `ssh <opmenu-user>@<box> "shell <code>"` and:

1. Run `warden detect` and configure scored paths, tiers, classes, service mappings, and custom detection entries in `/etc/warden/profile.json`.
2. Review the host's accounts, SUID binaries, cron jobs, SSH keys, ports, and packages.
3. Harden the host and run `warden scan` to establish the anomaly baseline before arming.
4. Run `warden arm`, review the changes, then confirm the new baseline.

   Resolve unexplained changes before confirming. Arming accepts the current files, including any tampering that occurred during setup.

   With no interactive input, use `arm --yes` after reading the review. The review is still printed and logged.

The installer leaves arming to the operator. Check armed state with `warden status`.

Use `warden fleet` to view local state and reporting peers. Sentinel logs overdue heartbeats.

For later maintenance, disarm first and re-arm after reviewing the changes. Use `warden accept <path> <code>` to approve one config file.

For response events, run `warden alerts` in a separate authenticated shell.

### A note on shell history

`opmenu`'s `shell` command execs bash over a `no-pty` SSH channel, which bash treats as non-interactive. A non-interactive bash never writes a history file, so commands typed there (`arm`, `disarm`, `ban`, `accept`, ...) leave nothing in `~/.bash_history` regardless of any setting. Don't rely on this holding if `no-pty` is ever dropped from the authorized_keys entry.

Any *other* interactive root shell on the box, physical console, or an admin path outside opmenu, records history normally, and a line like `svchelper disarm` reveals both the disguised binary's path and how to turn off its protection. Set `HISTCONTROL=ignorespace` for root there (check `root`'s `.bashrc`) and prefix sensitive commands with a leading space.

## 7. Recovery: pulling a box's own backups back

After a rebuild, use the previous credentials and pinned replication targets to recover from a peer. Restore the host profile as well. Without a baseline, watch cannot restore saved content:

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier config --apply
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply
```

The optional peer URL must match a configured replication target. Omit it to use automatic source selection: `warden retrieve --tier config --apply`. Missing objects are searched across local storage and all configured replicas. Run without `--apply` to inspect the generation first.

Recover the audit trail separately:

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --audit ./recovered-audit.log
```

The destination must differ from the live audit log. Recovered entries retain their `host` fields and JSON-lines format.

## 8. Repeat per box

Each box gets its own install, its own replication keypair, and (per the ring topology above) its own pair of `REPLICATE_TARGETS` entries; only the team's login key is shared across all of them.
