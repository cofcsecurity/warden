# Deployment Checklist

Warden is deployed during incident response on hosts with known active incursions. The IR team locks down each box to a sufficient state, reviews its baseline, and then arms Warden to help maintain that state and buy time for continued response and threat hunting.

Build and install directly on the affected box. A team laptop with a build toolchain is rarely available. Installation can precede hardening; arming follows the team's review.

## Quick reference

1. Triage the incident and contain known malicious access where practical. Assume the host may still be compromised.
2. [Choose watched paths and account exclusions](#0-dont-let-warden-fight-the-scoring-engine). Review [credentials](#1-generate-per-competition-secrets) and [replication targets](#2-replication-topology).
3. [Build and install on the affected host](#build-directly-on-the-target-box). The wizard collects configuration and can generate the required keys. Manual build and transfer steps are optional alternatives.
4. [Verify access and replication](#6-verify), then [repair and review the baseline before arming](#65-harden-then-arm). Initial snapshots may contain attacker changes; installation leaves automatic restore disarmed.
5. Repeat for each affected host. Use [peer recovery](#7-recovery-pulling-a-boxs-own-backups-back) when local backups are lost.

## 0. Don't let Warden fight the scoring engine

Identify the scoring engine's accounts and credentials before configuring watched paths. Do not auto-restore credentials that the scoring engine rotates. If they need monitoring, use `ConfirmFirst`.

Include the team's local operating accounts and the scoring account in `SAFE_ACCOUNTS`. IP exclusions do not protect these accounts from the separate account-lock response.

## Build directly on the target box

`scripts/build-and-install.sh` builds Warden on the affected box and installs it in the same run. This is the primary deployment path. It handles the manual build and install steps 3 through 5; continue with verification in step 6 afterward.

The host may still be compromised. Compiled secrets appear in linker arguments during the build, and privileged malware may capture them. The script asks you to acknowledge this exposure and review known compromise before proceeding; it does not certify the host as clean. Leave automatic restore disarmed until the selected baseline has been repaired and reviewed.

If Go is missing, `build-and-install.sh` offers to download the upstream release to `/usr/local/go`. This requires HTTPS access to go.dev.

The script uses `apt-get`, `dnf`, or `yum` to install missing dependencies where possible. Optional tools such as `qrencode` have fallbacks. The standalone installer also checks for cron and sudo.

The script does not install `python3`. If Python is unavailable for TOTP generation, provide an existing seed or use the static second factor.

### Step 1: get the source code onto the box

This needs the whole repository on the target box, not just the finished binary.

The examples use `~/build`. The checkout remains on disk during installation and is removed after success unless `KEEP_SOURCE=1` is set.

**Clone directly on the box**

Needs `git` already present on the box (`command -v git`) and outbound access to wherever this repo is hosted. If either isn't true, copy a source bundle from another host or use removable media instead:

```bash
ssh <user>@<box>
git clone https://github.com/cofcsecurity/warden.git ~/build
cd ~/build
```

If the repo is private, cloning needs credentials (a deploy key or access token) on the box temporarily, treat those like any other secret. `build-and-install.sh`'s cleanup step removes the whole checkout, credentials included, once installation succeeds.

**Copy from another accessible host**

Copy over SSH using the account provided for the host. The target needs no internet access if Go is already available and dependencies are vendored:

```bash
# from the machine that has this repo, at ./warden:
scp -r ./warden <user>@<box>:~/build
```

For zero internet access on the target box, run this once first, on whatever machine you're copying *from*:

```bash
make vendor   # downloads every dependency into ./vendor, once, on a machine with internet
```

**Removable media**

```bash
# on your own machine, with this repo at ./warden:
tar czf build.tar.gz --exclude=.git -C . warden
# copy build.tar.gz to a USB drive, plug it into the box's console, then on the box:
mkdir ~/build && tar xzf build.tar.gz -C ~/build --strip-components=1
```

**One-line setup (`scripts/bootstrap.sh`)**

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

The script builds in a private workspace, checks `debug-config`, and invokes `install.sh` with the private executable path. Build output and Go build/temporary files are removed on exit, including failed builds or installs. `KEEP_SOURCE=1` retains the source checkout after success, but does not retain the private build workspace.

Older versions wrote `deploy/warden` into the checkout. Remove any leftover copy from an earlier build. If its credentials may have been exposed, replace those credentials; a private rebuild cannot revoke an already copied key.

Continue with step 6.

## 1. Generate per-competition secrets

The on-host wizard offers secret generation. For manual setup on a single box:

```
./scripts/generate-keys.sh
```

For multiple boxes (see step 2 if defending several), pass a distinct output directory per box instead, **each box should get its own replication keypair**, not a shared one:

```
./scripts/generate-keys.sh secrets/box1
./scripts/generate-keys.sh secrets/box2
```

Either way it writes (gitignored): a replication-only SSH keypair (`replicate_key`/`replicate_key.pub`) and a TOTP seed (`totp_secret`). None of this belongs in this repo or anywhere else public. Distribute each TOTP seed to teammates who'll need to generate opmenu codes, out-of-band (e.g. a QR code shown once, not pasted into Slack).

The team's login key (`TEAM_PUBKEY`) is separate from replication credentials. Reuse an existing team key when available. Otherwise the on-host wizard offers:

```bash
./scripts/generate-team-key.sh --on-box
```

Save the private key in the team's SSH client and share it only with authorized teammates before the script removes its host copy. Reuse the team login key across hosts. If a separate machine is available, `./scripts/generate-team-key.sh` can generate it there instead. Neither removing the host copy nor later cleanup reverses exposure to malware already on the host.

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

Use a separate receiving account and directory for each source. The account needs a working shell because sshd uses it to start the forced command, but the replication key must be restricted to `warden receive`.

```sh
useradd -m -s /bin/sh warden-backup-box2
chown root:root /home/warden-backup-box2
install -d -o warden-backup-box2 -g warden-backup-box2 -m 700 /home/warden-backup-box2/from-box2
install -d -o root -g root -m 755 /home/warden-backup-box2/.ssh
```

Create a root-owned `authorized_keys` file with mode 644 in that `.ssh` directory. Keep the account's home owned by root as well so the receiving account cannot replace `.ssh`. Build a separate receiver binary without host credentials. The main installed binary is mode 0700 and cannot be executed by this account; changing its mode would also expose its compiled credentials.

On the receiving host, from the source checkout:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o warden-receiver ./cmd/warden
```

Do not pass the main build's secret-bearing linker flags. Install the resulting binary on that receiving host:

```sh
install -d -o root -g root -m 755 /usr/local/libexec
install -o root -g root -m 755 warden-receiver /usr/local/libexec/warden-receiver
```

 For a source with manifest signing enabled, use this key entry, replacing the placeholders:

```text
restrict,from="<box2 IP>",command="/usr/local/libexec/warden-receiver receive --root /home/warden-backup-box2/from-box2 --source box2 --public-key <base64 manifest public key>" <box2 replication SSH public key>
```

Configure the source target as `ssh+receiver://warden-backup-box2@box1/from-box2`, with the receiver's pinned SSH host key. The forced command chooses the storage root; the URL path does not choose or change it. Each source needs its own account/key restriction and root. The receiver permits verified object writes, immutable manifest writes, audit segments, heartbeats, and reads. It exposes no shell, delete, rename, or retention operation. Requests are limited to 256 MiB of JSON, including base64 overhead. Large individual data files need a different backup method until chunked transfers are supported.

The receiving host's administrator controls storage quotas and retention. Keep manifest files to preserve generation history, including after removing old objects. Sources cannot request pruning. A receiver administrator or a compromised receiving host can still delete backups, so keep copies on multiple hosts.

Existing `ssh://` targets retain the shell transport for compatibility. They do not enforce server-side immutability. Migrate the authorized key and URL together; a forced receiver rejects legacy shell commands. For unsigned existing builds, omit `--source` and `--public-key` temporarily, then enable signing as described below.

Inspect and verify the receiving host's public key through a trusted channel before pinning it. `ssh-keyscan` collects a candidate key but does not authenticate it:

```
box1$ ssh-keyscan -t ed25519 box2   # run this from box1, to pin box2's key in box1's own build
```

**Path matters**: use a path under `/home/warden-backup/`, e.g. `/home/warden-backup/from-box1`, an absolute root-level path like `/from-box1` will fail with a permission error, since the receiving account isn't root and can't create directories outside its own home.

## 3. Manual build (optional)

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

Produces `bin/warden`, targeting Linux amd64 by default. When building on a different operating system or architecture, use a native build to inspect configuration:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this, it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before deploying.

## 4. Manual installer configuration (optional)

Set `TEAM_PUBKEY` and `TEAM_FROM_IP`. Leave `INSTALL_PATH` empty for automatic selection or set it explicitly. Automatic selection checks for collisions with binaries, accounts, units, and sudoers files. The account and sudoers rule use the selected name. Unfilled team placeholders or a missing binary stop installation.

Also set `REPLICATE_TARGETS` to any non-empty value (e.g. `"1"`) if this box's binary was built with real replication targets, that's just the switch this script uses to decide whether to schedule the replication timer; the real target list lives in the binary, not here.

## 5. Transfer a prebuilt binary (optional)

Use this path when a separate machine is available to build the binary. Log in with the team's existing response account:

```
scp bin/warden deploy/install.sh -r deploy/systemd <user>@<box>:~/
ssh <user>@<box> 'sudo ./install.sh'
```

Once the access-layer verification prompt near the end passes, `install.sh` deletes the leftover `~/warden` source binary, the `~/systemd/` template directory, and finally itself. If verification fails, none of that cleanup runs, so those stay in place for debugging.

`install.sh` also prints a "what's next" summary before it deletes itself, the same detect → harden → arm sequence as step 6.5 below.

## 6. Verify

- `ssh -i <team's own login private key> <opmenu-user>@<box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes. `<opmenu-user>` is `INSTALL_PATH`'s basename (`docs/DESIGN.md`'s opmenu section). This is the team's own key from step 3/`TEAM_PUBKEY`, not a `secrets/<box>/replicate_key`, which authenticates the *box* to its replication peers, not an operator to the box.
- Run `warden replicate` by hand once (don't wait for the timer) and confirm objects landed on **both** neighbors: `ssh <neighbor> 'find /home/warden-backup/from-<box> -type f'` should show `manifests-config/`, `manifests-data/`, and `objects/`.

The dedicated operator account uses `/bin/sh` so sshd can execute its forced command. Its home and `.ssh` directory are root-owned mode 0755, and `authorized_keys` is root-owned mode 0644. The file contains only the configured team key; installation and sentinel repair replace extra entries. The public key is readable, but the account cannot edit it. The sudo rule permits only `<INSTALL_PATH> opmenu` and preserves the two SSH request variables used by that handler. User SSH startup scripts are disabled on the managed key.

For existing installations, replacing the binary does not migrate the account shell or directory ownership. From an existing trusted root session, set the dedicated account's shell to `/bin/sh`, apply the ownership and modes above, and run `sentinel-check` to update the key and sudo rules. Verify `status`, rejection of an incorrect second factor, and authenticated `shell` from the allowed team address before closing that session. Review effective sshd configuration for alternate key files, certificate authorities, password authentication, and account restrictions. Those host-wide settings remain administrator-controlled. Do not grant the dedicated account broader sudo privileges through another rule or group.

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
3. Lock down the host to a state the IR team judges sufficient to preserve. Run `warden scan` to establish the anomaly baseline before arming.
4. Run `warden arm`, review the changes, then confirm the new baseline.

   Resolve unexplained changes before confirming. Warden preserves the reviewed bytes and rejects arming if file contents, modes, or the selected path set changed during review. Changes after that check remain drift against the approved baseline.

   With no interactive input, use `arm --yes` after reading the review. The review is still printed and logged.

A malformed host profile does not block authenticated operator shell access, status, or disarming. Restore and other protection operations still reject it. Use the shell to repair the profile.

The installer leaves arming to the operator. Check armed state with `warden status`. Continue threat hunting, containment, and blue-team operations after arming. Warden buys time by maintaining the selected state; it does not finish the incident response.

Use `warden fleet` to view local state and reporting peers. Sentinel logs overdue heartbeats.

For local password or group membership changes, use `warden account-edit passwd USER` or `warden account-edit gpasswd -a/-d USER GROUP`. See [account maintenance](ACCOUNT-MAINTENANCE.md) for requirements and failure handling. For other planned config edits, use `warden accept <path> <code>` after review. Disarming stops automatic restoration, but does not disable every active-response path; it is not a general maintenance exemption.

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

### Sign manifests

Generate one manifest key pair per source during host setup:

```sh
umask 077
warden manifest-keygen > box2-manifest-key.json
```

Supply the JSON's `private_key` and `public_key` as `MANIFEST_KEY` and `MANIFEST_PUBLIC_KEY`, and use a stable source name such as `MANIFEST_SOURCE=box2` when building with Make or the build-and-install script. These are separate from SSH replication keys. Put only the public key and source name in the receiver's forced command. Keep the private key out of receiving accounts and version control.

With a public key configured, recovered manifests must have a valid signature for that source and tier. Existing unsigned archives are not accepted under the new pin. During a controlled migration, disarm and take a new approved snapshot with the signing-enabled binary, replicate it, verify the backups, then arm. Keep older unsigned backups available separately if needed.

The source binary contains the signing key. Its signature authenticates manifests against modification on a replica; it cannot prove that a compromised source approved honest content. The receiver retains immutable generation files outside the source host. Recovery checks their highest generation and requires `retrieve --allow-rollback` to adopt an older generation or override an incomplete lineage check. Losing every independently held copy also loses that external history.

### Validate deployment

Run `warden profile validate` for coverage, unit mappings, attribution logs, and replica connectivity. `--strict` returns failure for reported issues, and `warden arm --strict` makes the same checks a prerequisite. The broad default profile includes paths absent on many hosts; tailor it before expecting strict validation to pass. The optional `ignored_processes` array acknowledges unknown process names that do not need service coverage, such as local desktop utilities. It only suppresses those unknown-process findings; it does not suppress missing watched files or known service coverage failures.

Configure service validators in the profile as argument arrays, for example `"validators": {"nginx": ["/usr/sbin/nginx", "-t"], "sshd": ["/usr/sbin/sshd", "-t"]}`. Use the actual unit names from the profile. Commands run without a shell, with a 15-second limit, after all files are published and before service restart or reload. A failed explicit restore validation rolls the files back. Units without a configured validator receive content and mode verification only.

Use `warden verify-backups --record` to save a verification report for `status`. Use `--repair` to recover local objects from verified copies. The default command only reads and prints JSON; it does not save a report. A successful heartbeat is independent of backup health.
