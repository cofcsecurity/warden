# Deployment Checklist

The step-by-step version of `docs/PLAN.md`'s Phase 5. Two phases: **Part A**, once per competition on the team's own build machine, produces one binary per box; **Part B**, once per box, gets it installed, verified, hardened, and armed.

**No separate build machine available** (e.g. PCDC-style events where the only laptop you get is locked down, with no permission to install a toolchain on it)? Skip to [Alternative: build directly on the target box](#alternative-build-directly-on-the-target-box) — it replaces Part A and steps 3–5 of Part B with one script run on the box itself, at the cost of a real tradeoff spelled out there. Otherwise, the normal flow below is the safer default.

## Quick reference

Section numbers below match the headers exactly. Skip to any of them for full detail.

**Part A — once per competition, build machine only:**
- **Step 0, 1, 2** — [decide what to watch without fighting the scoring engine](#0-dont-let-warden-fight-the-scoring-engine), [generate secrets](#1-generate-per-competition-secrets) (`generate-keys.sh`), [plan replication topology](#2-replication-topology) if defending multiple boxes.
- **Step 3** — [build](#3-build) one binary per box (`make build`), and verify it with `debug-config` before trusting it. *(No build machine? See [the alternative](#alternative-build-directly-on-the-target-box) instead.)*

**Part B — once per box:**
- **Step 4, 5** — [fill in `install.sh`'s per-box values](#4-confirm-installshs-per-box-values) and [deploy](#5-deploy-to-each-box) (`scp` + `sudo ./install.sh`, which now prints its own next-steps summary when it finishes).
- **Step 6** — [verify](#6-verify) the access layer and replication both actually work.
- **Step 6.5** — [harden the box, then arm it](#65-harden-then-arm) (`warden detect` → harden → `warden arm`). **The box is unprotected against config drift until this step — a fresh install is not the same as a defended box.**
- **Step 7, 8** — keep [recovery](#7-recovery-pulling-a-boxs-own-backups-back) in mind for if a box gets wiped later, and repeat steps 3–6.5 [per box](#8-repeat-per-box).

## 0. Don't let Warden fight the scoring engine

Before filling in `cmd/warden/config.go`'s watch list (Phase 1 of `docs/PLAN.md`), identify every account and credential the scoring engine itself uses to check the box — including its own SSH access. Never classify one of those as `SafeAutoRestore`: if the scoring engine rotates its own key or password and `watch` reverts it back to a stale snapshot, that's Warden causing a scoring outage that looks exactly like red team did it. If it needs watching at all, use `ConfirmFirst` (flag, never auto-revert) — see the warning comment above `configTierPaths` in `config.go`. This also means: don't add the scoring engine's own login path to `configTierPaths` at all unless there's a real reason to — watching something you never intend to act on just adds noise.

## 1. Generate per-competition secrets

For a single box:

```
./scripts/generate-keys.sh
```

For multiple boxes (see step 2 if defending several), pass a distinct output directory per box instead — **each box should get its own replication keypair**, not a shared one:

```
./scripts/generate-keys.sh secrets/box1
./scripts/generate-keys.sh secrets/box2
```

Either way it writes (gitignored): a replication-only SSH keypair (`replicate_key`/`replicate_key.pub`) and a TOTP seed (`totp_secret`). None of this belongs in this repo or anywhere else public. Distribute each TOTP seed to teammates who'll need to generate opmenu codes — out-of-band (e.g. a QR code shown once, not pasted into Slack).

This does **not** generate the team's own login keypair (`TEAM_PUBKEY`) — use whatever key a team member already holds the private half of, or generate one now, **on your own machine, never on a target box**:

```
./scripts/generate-team-key.sh
```

Prints the public key to use as `TEAM_PUBKEY`. Generate this once per competition, not once per box — every box uses the same value, and every teammate who'll operate a box needs a copy of the private half, shared out-of-band.

**No machine outside the competition network exists at all** (e.g. some PCDC-style events — every device you've been handed is itself in scope, not just the boxes you're defending)? There's no way around the key briefly existing on a machine you're defending in that case, so the goal shifts to minimizing the window instead of avoiding it:

```
./scripts/generate-team-key.sh --on-box
```

Generates the same keypair, but on this box, and walks through getting the private half off it before shredding it from disk here. The simplest way: you're already operating this box through your own terminal, over your own SSH session — copy the private key straight out of your terminal's scrollback the same as any other remote output, save it locally, then hand it to any other teammate the same out-of-band way this always recommended (read aloud, handwritten, a competition channel red team can't see), just person-to-person instead of box-to-person. No box is any safer than another in this situation, so there's no reason to single one out just for key generation — do it as part of installing to whichever box you're setting up first (`scripts/build-and-install.sh`'s own wizard offers to run it inline, see below, and cleans up the leftover public-key file on this box once it's baked into the build). The same key gets reused for every other box after that, so this exposure only has to happen once, not once per box.

## 2. Replication topology

With 6–8 boxes to defend, don't just pick one box as everyone's backup destination — that box becomes a single point of failure for every other box's recovery path, and it's one more thing red team can go after. Instead, arrange the boxes in a **bidirectional ring**: each box replicates to both of its neighbors, and receives from both of them in turn. For 6 boxes (`box1`…`box6`) in a ring:

```
box1 ⇄ box2 ⇄ box3 ⇄ box4 ⇄ box5 ⇄ box6 ⇄ box1
```

Every arrow is two `REPLICATE_TARGETS` entries (one per direction) baked into each box's binary. This gives every box's backups **3 total copies** — itself plus its two neighbors — and every replication relationship is mutual, so losing any single box, or even two *non-adjacent* boxes, never costs another box its only remaining copy. (Losing two *adjacent* boxes at once does cost the box between them one of its two off-box copies, not all of them — it still has the other neighbor.)

This is genuinely just configuration, not new code: `replicate`'s push is already additive-only and target-agnostic, so "mesh" here means nothing more than pointing each box's `REPLICATE_TARGETS` at two peers instead of one.

### Per-box secrets

Generate a **distinct** replication keypair per box, not one shared team-wide key — if a box is compromised, that limits the blast radius to the (at most 2) peers that specific box's key can write to, not the whole mesh:

```
./scripts/generate-keys.sh secrets/box1
./scripts/generate-keys.sh secrets/box2
# ... one per box
```

(Each run also writes a fresh `totp_secret`; reuse one across boxes or generate per-box ones — see step 3's note.)

### Set up each box's receiving side

On **every** box, before building anything, create a dedicated low-privilege account that only exists to receive backups — never the team's login account, never root:

```
useradd -m -s "$(command -v nologin || echo /usr/sbin/nologin)" warden-backup
mkdir -p /home/warden-backup/.ssh
chmod 700 /home/warden-backup/.ssh
```

(`/usr/sbin/nologin` covers most current Debian- and RHEL-family boxes; the `command -v nologin` check is only there for the rare older or minimal image where it lives somewhere else.)

Then append **both neighbors'** `secrets/<box>/replicate_key.pub` to that account's `authorized_keys` (one line each) and lock each down the same way as any other automated key:

```
command="/usr/bin/false",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <box2's replicate pubkey>
command="/usr/bin/false",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <box6's replicate pubkey>
```

`command="/usr/bin/false"` matters: `SSHTarget` only ever runs plain shell one-liners (`mkdir`/`test`/`cat`/`mv`) over the *session* channel, not by executing whatever the client requests, so a forced no-op command here doesn't break replication — it just means a stolen replication key can't be used to get an interactive shell on the receiving box, only to run the specific commands `SSHTarget` sends over an already-open session (additive file writes under the given root). Get each box's host key from its neighbors' perspective — **not from the box itself**, since the exact bytes the client sees on connection are what matters:

```
box1$ ssh-keyscan -t ed25519 box2   # run this from box1, to pin box2's key in box1's own build
```

**Path matters**: use a path under `/home/warden-backup/`, e.g. `/home/warden-backup/from-box1` — an absolute root-level path like `/from-box1` will fail with a permission error, since the receiving account isn't root and can't create directories outside its own home.

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

If there's no realistic second box this season at all, `REPLICATE_TARGETS` can instead be a single `file:///path||` entry (empty host key) pointing at removable media — see `docs/PLAN.md` Phase 2.

Add `AUTOBAN_ENABLED=1` to the same `make build` invocation to enable auto-banning an attacker's IP — see `docs/DESIGN.md`'s "Active Response" section. It's off (unset) by default; leaving it off still gets you the flagging and `warden alerts` visibility, just not the automatic firewall block.

Produces `bin/warden` — a stripped, static binary with everything above baked in. Verify it actually captured the right values before going further, on a native build since `bin/warden` is cross-compiled for the target's `linux/amd64` and won't run here:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this — it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before actually deploying.

## Alternative: build directly on the target box

For events with no separate build machine (e.g. PCDC-style, a locked-down provided laptop with no permission to install a toolchain). `scripts/build-and-install.sh` builds Warden directly on the box being defended and installs it in the same run — **replacing steps 3 through 5 below entirely.** Steps 0, 6, 6.5, 7, and 8 still apply as written; come back to step 6 once this is done.

Read the tradeoff at the top of that script's own comments first: per-competition secrets get passed to `go build` as command-line flags, so they're briefly visible in this box's own process list (`ps`) while the build runs. Do this as early as possible in the box's clean-first window (the script asks you to confirm that, same as `install.sh`).

No Go toolchain on the box either? `build-and-install.sh` offers to download the official release from go.dev and install it to `/usr/local/go` — needs this box to reach go.dev over HTTPS. It never tries a distro package (names for Go vary by distro and are often outdated, e.g. Debian/Ubuntu call it `golang-go`, not `go`).

### Step 1: get the source code onto the box

This needs the whole repository on the target box, not just the finished binary.

**Name the destination something inconspicuous, not literally `warden`** — it's deleted automatically once install succeeds (see step 2 below), but it exists on disk for the whole build+install window until then. The examples below use `~/build`.

**A. Copy it from a machine that already has it checked out (recommended)**

Needs nothing beyond the SSH access you're about to use anyway (log in as whatever account the competition gave you, not root), and no internet access on the target box:

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

If the repo is private, cloning needs credentials (a deploy key or access token) on the box temporarily — treat those like any other secret. `build-and-install.sh`'s cleanup step removes the whole checkout, credentials included, once installation succeeds.

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

**Use this exact form, not `curl ... | sudo bash`.** Piping into bash makes bash read its own script *from stdin* — which then also has to serve every interactive prompt further down, and the two conflict. `bash -c "$(curl ...)"` fetches the script into a string first and hands it to bash as an argument instead, so stdin is never touched and stays attached to your actual terminal the whole time. Same requirements as option B (needs `git`, `curl`, or `wget` on the box, and — if the repo is private — credentials already configured there). Skips straight to step 2 below; there's no separate directory to `cd` into first.

### Step 2: run it

```bash
cd ~/build   # wherever it landed
sudo ./scripts/build-and-install.sh
```

Asks for the same things `install.sh` normally needs (team pubkey, team IP, install path), plus offers to generate a TOTP seed and, if wanted, a replication keypair. Set any of `TEAM_PUBKEY`, `TEAM_FROM_IP`, `INSTALL_PATH`, `TOTP_SECRET`, `REPLICATE_TARGETS`, `REPLICATE_KEY`, `AUTOBAN_ENABLED` as environment variables beforehand to skip that prompt.

Builds, self-verifies with `debug-config`, hands off to the normal `install.sh`, and — once that succeeds — deletes the entire source tree it ran from. Set `KEEP_SOURCE=1` beforehand to keep the checkout instead.

From here, pick back up at step 6 (Verify) below.

## 4. Confirm `install.sh`'s per-box values

Open `deploy/install.sh` and fill in `TEAM_PUBKEY`/`TEAM_FROM_IP`. Leave `INSTALL_PATH` empty (its default) — `install.sh` auto-selects a name from a large combination of plausible service-sounding words, checks it against what's actually on the box (existing binaries, accounts, units, sudoers files) in random order, and uses the first one with no collision. Set `INSTALL_PATH` explicitly only if a specific name is wanted. The access layer's dedicated account (`OPMENU_USER`) and its `sudoers.d` rule both derive from whatever name is chosen. The script refuses to run (`require_filled_in`) if either `TEAM_*` value is still a `CHANGE-ME` placeholder or the binary hasn't been built yet.

Also set `REPLICATE_TARGETS` to any non-empty value (e.g. `"1"`) if this box's binary was actually built with real replication targets — that's just the switch this script uses to decide whether to schedule the replication timer; the real target list lives in the binary, not here.

## 5. Deploy to each box

Once the box has been swept clean of any existing compromise (see `docs/DESIGN.md`'s "No Clean Window: Assume Compromise"). Log in as whatever account the competition gave you, not root:

```
scp bin/warden deploy/install.sh -r deploy/systemd <user>@<box>:~/
ssh <user>@<box> 'sudo ./install.sh'
```

Once the access-layer verification prompt near the end passes, `install.sh` deletes the leftover `~/warden` source binary, the `~/systemd/` template directory, and finally itself. If verification fails, none of that cleanup runs, so those stay in place for debugging.

`install.sh` also prints a "what's next" summary before it deletes itself — the same detect → harden → arm sequence as step 6.5 below.

## 6. Verify

- `ssh -i <team's own login private key> <opmenu-user>@<box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes. `<opmenu-user>` is `INSTALL_PATH`'s basename (`docs/DESIGN.md`'s opmenu section). This is the team's own key from step 3/`TEAM_PUBKEY` — not a `secrets/<box>/replicate_key`, which authenticates the *box* to its replication peers, not an operator to the box.
- Run `warden replicate` by hand once (don't wait for the timer) and confirm objects landed on **both** neighbors: `ssh <neighbor> 'find /home/warden-backup/from-<box> -type f'` should show `manifests-config/`, `manifests-data/`, and `objects/`.

`install.sh` already generated a static second factor during setup (printed to the terminal — scroll back if you missed it) — `restore`/`shell` accept it exactly like a TOTP code, no phone or authenticator app needed, which is what makes step 6.5 below possible at competitions where phones aren't allowed at all (PCDC-style). Make sure that value got saved somewhere secure; `<INSTALL_PATH> rotate-secret` (from a shell you already have) changes it later, e.g. if it leaks.

## 6.5. Harden, then arm

The box comes up **disarmed**: `watch` runs on schedule and flags sensitive drift, but won't auto-revert anything yet. That's the window for the team's actual hardening work — get a shell (`ssh <opmenu-user>@<box> "shell <code>"` over opmenu, TOTP required) and:

1. Run `warden detect` to see what's actually running on this box and which of its config files aren't yet in `configTierPaths` — add the ones that matter for this competition's scoring to `cmd/warden/config.go` and rebuild/redeploy if anything's missing (steps 3–5 again for just this box).
2. Do the actual hardening: lock down `sshd_config`, tighten service configs, rotate anything default, whatever this box needs.
3. Once that's done: `warden arm`. This snapshots the box's current (hardened) state and turns on auto-restore — from here on, drift in a watched file gets reverted, not just flagged.

Don't skip straight to step 3 before steps 1–2: arming locks in whatever's on disk *at that moment* as "known good," so arming before hardening just means watch will keep enforcing the pre-hardening state instead. If a later maintenance window needs to touch a watched file without watch fighting it, `warden disarm` first and `warden arm` again when done. If a specific hardening edit needs to land on a `ConfirmFirst` path (which is never auto-reverted anyway, armed or not) without perpetually flagging, `warden accept <path> <totp-code>` marks just that one file's current state as known-good.

If this build has `AUTOBAN_ENABLED` set, open a second SSH session now (`ssh <opmenu-user>@<box> "shell <code>"`) and leave `warden alerts` running in it — see `docs/DESIGN.md`'s "Active Response" section.

### A note on shell history

`opmenu`'s `shell` command execs bash over a `no-pty` SSH channel, which bash treats as non-interactive. A non-interactive bash never writes a history file, so commands typed there (`arm`, `disarm`, `ban`, `accept`, ...) leave nothing in `~/.bash_history` regardless of any setting. Don't rely on this holding if `no-pty` is ever dropped from the authorized_keys entry.

Any *other* interactive root shell on the box — physical console, or an admin path outside opmenu — records history normally, and a line like `svchelper disarm` reveals both the disguised binary's path and how to turn off its protection. Set `HISTCONTROL=ignorespace` for root there (check `root`'s `.bashrc`) and prefix sensitive commands with a leading space.

## 7. Recovery: pulling a box's own backups back

If a box is wiped and rebuilt (rebuild it with the **same** `TEAM_PUBKEY`/`TOTP_SECRET`/`REPLICATE_TARGETS`/`REPLICATE_KEY` it had before — recovery assumes the rebuilt binary can still authenticate to the same peers), it starts with no local manifest and `watch` will flag everything as unexpected rather than restore anything, since it has no baseline to restore from. Pull its own prior backups back from either neighbor:

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier config --apply
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply
```

The peer URL must be one of the box's own configured `REPLICATE_TARGETS` entries — `retrieve` looks up its pinned host key from there rather than taking one on trust from a flag, so recovery can't be tricked into pulling from (and trusting the host key of) an unpinned location. Run without `--apply` first to see what generation and record count is available before committing to it. Once applied, `warden watch`/`warden restore` pick the recovered baseline straight back up — verified end-to-end in a test rig: wipe `/var/lib/<box>`'s warden data entirely, `retrieve --apply` both tiers from a peer, then tamper a file and confirm `watch` auto-restores it again.

## 8. Repeat per box

Each box gets its own install, its own replication keypair, and (per the ring topology above) its own pair of `REPLICATE_TARGETS` entries; only the team's login key is shared across all of them.
