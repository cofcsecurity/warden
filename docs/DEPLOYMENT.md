# Deployment Checklist

The step-by-step version of `docs/PLAN.md`'s Phase 5. Work through this once per competition, on the team's own build machine — never on a target box.

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

Produces `bin/warden` — a stripped, static binary with everything above baked in. Verify it actually captured the right values before going further, on a native build since `bin/warden` is cross-compiled for the target's `linux/amd64` and won't run here:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this — it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before actually deploying.

## 4. Confirm `install.sh`'s per-box values

Open `deploy/install.sh` and fill in the `CHANGE-ME` block: `INSTALL_PATH` (matching this box's naming conventions — check what's already there first), `TEAM_PUBKEY`, `TEAM_FROM_IP`. The script now refuses to run (`require_filled_in`) if either `TEAM_*` value is still a `CHANGE-ME` placeholder or the binary hasn't been built yet, but it can't know whether `INSTALL_PATH` genuinely blends in — that's a judgment call about the specific box.

Also set `REPLICATE_TARGETS` to any non-empty value (e.g. `"1"`) if this box's binary was actually built with real replication targets — that's just the switch this script uses to decide whether to schedule the replication timer; the real target list lives in the binary, not here.

## 5. Deploy to each box

Once the box has been swept clean of any existing compromise (see `docs/DESIGN.md`'s "No Clean Window: Assume Compromise"):

```
scp bin/warden deploy/install.sh -r deploy/systemd <box>:~/
ssh <box> 'sudo ./install.sh'
```

`install.sh` deletes itself on success. It does **not** delete `deploy/systemd/` — do that by hand after confirming the units came up, since leaving the template directory behind is exactly the kind of artifact `docs/DESIGN.md`'s footprint policy warns about:

```
ssh <box> 'rm -rf ~/systemd'
```

## 6. Verify

- `ssh -i <team's own login private key> <box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes. This is the team's own key from step 3/`TEAM_PUBKEY` — not a `secrets/<box>/replicate_key`, which authenticates the *box* to its replication peers, not an operator to the box.
- Run `warden replicate` by hand once (don't wait for the timer) and confirm objects landed on **both** neighbors: `ssh <neighbor> 'find /home/warden-backup/from-<box> -type f'` should show `manifests-config/`, `manifests-data/`, and `objects/`.

## 7. Recovery: pulling a box's own backups back

If a box is wiped and rebuilt (rebuild it with the **same** `TEAM_PUBKEY`/`TOTP_SECRET`/`REPLICATE_TARGETS`/`REPLICATE_KEY` it had before — recovery assumes the rebuilt binary can still authenticate to the same peers), it starts with no local manifest and `watch` will flag everything as unexpected rather than restore anything, since it has no baseline to restore from. Pull its own prior backups back from either neighbor:

```
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier config --apply
warden retrieve ssh://warden-backup@box2/home/warden-backup/from-box1 --tier data --apply
```

The peer URL must be one of the box's own configured `REPLICATE_TARGETS` entries — `retrieve` looks up its pinned host key from there rather than taking one on trust from a flag, so recovery can't be tricked into pulling from (and trusting the host key of) an unpinned location. Run without `--apply` first to see what generation and record count is available before committing to it. Once applied, `warden watch`/`warden restore` pick the recovered baseline straight back up — verified end-to-end in a test rig: wipe `/var/lib/<box>`'s warden data entirely, `retrieve --apply` both tiers from a peer, then tamper a file and confirm `watch` auto-restores it again.

## 8. Repeat per box

Each box gets its own install, its own replication keypair, and (per the ring topology above) its own pair of `REPLICATE_TARGETS` entries; only the team's login key and RoE confirmation are shared across all of them.
