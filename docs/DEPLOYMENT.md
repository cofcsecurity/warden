# Deployment Checklist

The step-by-step version of `docs/PLAN.md`'s Phase 5. Two phases: **Part A**, once per competition on the team's own build machine, produces one binary per box; **Part B**, once per box, gets it installed, verified, hardened, and armed.

**No separate build machine available** (e.g. PCDC-style events where the only laptop you get is locked down, with no permission to install a toolchain on it)? Skip to [Alternative: build directly on the target box](#alternative-build-directly-on-the-target-box) — it replaces Part A and steps 3–5 of Part B with one script run on the box itself, at the cost of a real tradeoff spelled out there. Otherwise, the normal flow below is the safer default.

## Quick reference

Section numbers below match the headers exactly. Skip to any of them for full detail.

**Part A — once per competition, build machine only:**
- **Step 0** — [confirm rules of engagement](#0-rules-of-engagement-do-this-first-not-last) with organizers, before anything else.
- **Step 0.5, 1, 2** — [decide what to watch without fighting the scoring engine](#05-dont-let-warden-fight-the-scoring-engine), [generate secrets](#1-generate-per-competition-secrets) (`generate-keys.sh`), [plan replication topology](#2-replication-topology) if defending multiple boxes.
- **Step 3** — [build](#3-build) one binary per box (`make build`), and verify it with `debug-config` before trusting it. *(No build machine? See [the alternative](#alternative-build-directly-on-the-target-box) instead.)*

**Part B — once per box:**
- **Step 4, 5** — [fill in `install.sh`'s per-box values](#4-confirm-installshs-per-box-values) and [deploy](#5-deploy-to-each-box) (`scp` + `sudo ./install.sh`, which now prints its own next-steps summary when it finishes).
- **Step 6** — [verify](#6-verify) the access layer and replication both actually work.
- **Step 6.5** — [harden the box, then arm it](#65-harden-then-arm) (`warden detect` → harden → `warden arm`). **The box is unprotected against config drift until this step — a fresh install is not the same as a defended box.**
- **Step 7, 8** — keep [recovery](#7-recovery-pulling-a-boxs-own-backups-back) in mind for if a box gets wiped later, and repeat steps 3–6.5 [per box](#8-repeat-per-box).

## 0. Rules of engagement (do this first, not last)

Confirm with organizers/advisors that a forced-command SSH channel with auto-revert is permitted under this competition's rules. See [DESIGN.md](DESIGN.md)'s "Rules of Engagement Note". If it's ambiguous, ask before the competition starts. Don't let "the code is ready" substitute for this.

## 0.5. Don't let Warden fight the scoring engine

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

This does **not** generate the team's own login keypair (`TEAM_PUBKEY`) — that should already exist; use whatever key a team member actually holds the private half of.

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
useradd -m -s /usr/sbin/nologin warden-backup
mkdir -p /home/warden-backup/.ssh
chmod 700 /home/warden-backup/.ssh
```

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

Add `AUTOBAN_ENABLED=1` to the same `make build` invocation only after confirming with organizers that auto-banning an attacker's IP is allowed under this competition's rules of engagement — see `docs/DESIGN.md`'s "Active Response" section. It's off (unset) by default; leaving it off still gets you the flagging and `warden alerts` visibility, just not the automatic firewall block.

Produces `bin/warden` — a stripped, static binary with everything above baked in. Verify it actually captured the right values before going further, on a native build since `bin/warden` is cross-compiled for the target's `linux/amd64` and won't run here:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this — it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before actually deploying.

## Alternative: build directly on the target box

Everything above assumes a separate machine the team controls, with Go installed, to build on — normally someone's personal laptop, not whatever the competition issues you (see the note at the top of this doc if that's not available at all: some events genuinely only hand out a locked-down laptop with no permission to install anything on it, e.g. PCDC). If that's your situation, or a separate build machine is just more coordination than it's worth for how many boxes there are, `scripts/build-and-install.sh` builds Warden **directly on the box being defended** and installs it in the same run instead — **replacing steps 3 through 5 below entirely.** Steps 0, 0.5, 6, 6.5, 7, and 8 still apply exactly as written; come back to step 6 once this is done.

Read the tradeoff spelled out at the top of that script's own comments first: because the per-competition secrets get passed to `go build` as command-line flags, they're briefly visible in this box's own process list (`ps`) while the build runs — a real, if narrow, exposure the normal path doesn't have, since a machine red team has never touched never sees them at all. Doing this as early as possible in the box's clean-first window (the script still asks you to confirm that, same as `install.sh`) is the mitigation.

### Step 1: get the source code onto the box

Unlike the normal path (which only ever needs the one finished binary), this needs the whole repository on the target box. A few ways to get it there, in order of preference:

**A. Copy it from a machine that already has it checked out (recommended)**

If you or a teammate already have this repo cloned somewhere, `scp` it straight to the box — this needs nothing beyond the SSH access you're about to use anyway, and no internet access on the target box at all:

```bash
# from the machine that has this repo, at ./warden:
scp -r ./warden root@<box>:~/warden
```

For a build that needs **zero internet access** on the target box (the safer default — see `docs/DESIGN.md`'s threat model), do this once first, on whatever machine you're copying *from*, before the `scp` above:

```bash
make vendor   # downloads every dependency into ./vendor, once, on a machine with internet
```

**B. Clone it directly on the box**

Only if the box itself already has outbound access to wherever this repo is hosted, and you're comfortable with that — `docs/DESIGN.md`'s original "Delivery Mechanism" section steers away from `git clone` on a target box for the plain-binary path specifically because of this egress dependency; here, needing the source there at all means that tradeoff is at least a deliberate one:

```bash
ssh root@<box>
git clone https://github.com/cofcsecurity/warden.git ~/warden
cd ~/warden
```

If the repo is private, cloning needs credentials (a deploy key or access token) on the box temporarily — treat those like any other secret. `build-and-install.sh`'s cleanup step removes the whole checkout, credentials included, once installation succeeds.

**C. USB drive (no network needed on the box at all)**

```bash
# on your own machine, with this repo at ./warden:
tar czf warden.tar.gz --exclude=.git -C . warden
# copy warden.tar.gz to a USB drive, plug it into the box's console, then on the box:
tar xzf warden.tar.gz -C ~/
```

### Step 2: run it

```bash
cd ~/warden   # wherever it landed
sudo ./scripts/build-and-install.sh
```

It asks for the same things `install.sh` normally needs (team pubkey, team IP, install path), plus offers to generate a TOTP seed — and, if you want replication, a replication keypair — right there on the spot. Set any of `TEAM_PUBKEY`, `TEAM_FROM_IP`, `INSTALL_PATH`, `TOTP_SECRET`, `REPLICATE_TARGETS`, `REPLICATE_KEY`, `AUTOBAN_ENABLED` as environment variables beforehand to skip that particular prompt.

It builds, self-verifies with `debug-config`, hands off to the normal `install.sh` (so you still get its own "confirm access works" prompt and next-steps summary), and — once that succeeds — **deletes the entire source tree it just ran from**, converging back to the same minimal footprint the off-box path leaves behind. Set `KEEP_SOURCE=1` beforehand if you have a real reason to keep the checkout around instead.

From here, pick back up at step 6 (Verify) below.

## 4. Confirm `install.sh`'s per-box values

Open `deploy/install.sh` and fill in the `CHANGE-ME` block: `INSTALL_PATH` (matching this box's naming conventions — check what's already there first), `TEAM_PUBKEY`, `TEAM_FROM_IP`. The script now refuses to run (`require_filled_in`) if either `TEAM_*` value is still a `CHANGE-ME` placeholder or the binary hasn't been built yet, but it can't know whether `INSTALL_PATH` genuinely blends in — that's a judgment call about the specific box.

Also set `REPLICATE_TARGETS` to any non-empty value (e.g. `"1"`) if this box's binary was actually built with real replication targets — that's just the switch this script uses to decide whether to schedule the replication timer; the real target list lives in the binary, not here.

## 5. Deploy to each box

Once the box has been swept clean of any existing compromise (see `docs/DESIGN.md`'s "No Clean Window: Assume Compromise"):

```
scp bin/warden deploy/install.sh -r deploy/systemd <box>:~/
ssh <box> 'sudo ./install.sh'
```

Once the access-layer verification prompt near the end passes, `install.sh` cleans up after itself and deletes itself: the leftover `~/warden` source binary (its literal, un-disguised filename would otherwise sit right next to the disguised one at `$INSTALL_PATH`, giving the game away to anyone who runs `ls ~`), the `~/systemd/` template directory (same problem — its filenames spell out exactly what each unit is for), and finally the script itself. Nothing manual needed here anymore; if verification fails, none of this cleanup runs, so the templates and source binary stay in place for debugging.

`install.sh` also prints a "what's next" summary before it deletes itself — the same detect → harden → arm sequence from step 6.5 below — so it doesn't rely on whoever's running it remembering to come back to this doc.

## 6. Verify

- `ssh -i <team's own login private key> <box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes. This is the team's own key from step 3/`TEAM_PUBKEY` — not a `secrets/<box>/replicate_key`, which authenticates the *box* to its replication peers, not an operator to the box.
- Run `warden replicate` by hand once (don't wait for the timer) and confirm objects landed on **both** neighbors: `ssh <neighbor> 'find /home/warden-backup/from-<box> -type f'` should show `manifests-config/`, `manifests-data/`, and `objects/`.

## 6.5. Harden, then arm

The box comes up **disarmed**: `watch` runs on schedule and flags sensitive drift, but won't auto-revert anything yet. That's the window for the team's actual hardening work — get a shell (`ssh <box> "shell <code>"` over opmenu, TOTP required) and:

1. Run `warden detect` to see what's actually running on this box and which of its config files aren't yet in `configTierPaths` — add the ones that matter for this competition's scoring to `cmd/warden/config.go` and rebuild/redeploy if anything's missing (steps 3–5 again for just this box).
2. Do the actual hardening: lock down `sshd_config`, tighten service configs, rotate anything default, whatever this box needs.
3. Once that's done: `warden arm`. This snapshots the box's current (hardened) state and turns on auto-restore — from here on, drift in a watched file gets reverted, not just flagged.

Don't skip straight to step 3 before steps 1–2: arming locks in whatever's on disk *at that moment* as "known good," so arming before hardening just means watch will keep enforcing the pre-hardening state instead. If a later maintenance window needs to touch a watched file without watch fighting it, `warden disarm` first and `warden arm` again when done. If a specific hardening edit needs to land on a `ConfirmFirst` path (which is never auto-reverted anyway, armed or not) without perpetually flagging, `warden accept <path> <totp-code>` marks just that one file's current state as known-good.

If this build has `AUTOBAN_ENABLED` set, open a second SSH session now (`ssh <box> "shell <code>"`) and leave `warden alerts` running in it — that's the only way anyone sees a guarded-path alert as it happens, by design (see `docs/DESIGN.md`'s "Active Response" section on why it's pull-based instead of a broadcast).

### A note on shell history

`opmenu`'s `shell` command execs bash over a `no-pty` SSH channel, which bash treats as non-interactive — verified directly: a non-interactive bash never writes a history file at all, so commands typed there (`arm`, `disarm`, `ban`, `accept`, ...) leave nothing in `~/.bash_history` regardless of any setting. That's not something Warden arranges deliberately, just a side effect of `no-pty` already being there for other reasons (see `docs/DESIGN.md`'s opmenu section) — don't rely on it if that restriction ever changes.

The real exposure is any *other* interactive root shell on the box — physical console access, or any admin path outside opmenu — where history is recorded normally, and a line like `svchelper disarm` hands anyone who later reads that file both the disguised binary's real path and how to turn off its protection. If your team has that kind of access to a box, set `HISTCONTROL=ignorespace` for root there (most distros support it; check `root`'s `.bashrc`, since it isn't always on by default) and prefix sensitive commands with a leading space — a normal, unremarkable sysadmin habit, not something that needs explaining to a judge, unlike editing a history file after the fact would be.

## 7. Recovery: pulling a box's own backups back

If a box is wiped and rebuilt (rebuild it with the **same** `TEAM_PUBKEY`/`TOTP_SECRET`/`REPLICATE_TARGETS`/`REPLICATE_KEY` it had before — recovery assumes the rebuilt binary can still authenticate to the same peers), it starts with no local manifest and `watch` will flag everything as unexpected rather than restore anything, since it has no baseline to restore from. Pull its own prior backups back from either neighbor:

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier config --apply
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply
```

The peer URL must be one of the box's own configured `REPLICATE_TARGETS` entries — `retrieve` looks up its pinned host key from there rather than taking one on trust from a flag, so recovery can't be tricked into pulling from (and trusting the host key of) an unpinned location. Run without `--apply` first to see what generation and record count is available before committing to it. Once applied, `warden watch`/`warden restore` pick the recovered baseline straight back up — verified end-to-end in a test rig: wipe `/var/lib/<box>`'s warden data entirely, `retrieve --apply` both tiers from a peer, then tamper a file and confirm `watch` auto-restores it again.

## 8. Repeat per box

Each box gets its own install, its own replication keypair, and (per the ring topology above) its own pair of `REPLICATE_TARGETS` entries; only the team's login key and RoE confirmation are shared across all of them.
