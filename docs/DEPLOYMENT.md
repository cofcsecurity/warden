# Deployment Checklist

The step-by-step version of `docs/PLAN.md`'s Phase 5. Work through this once per competition, on the team's own build machine — never on a target box.

## 0. Rules of engagement (do this first, not last)

Confirm with organizers/advisors that a forced-command SSH channel with auto-revert is permitted under this competition's rules. See [DESIGN.md](DESIGN.md)'s "Rules of Engagement Note". If it's ambiguous, ask before the competition starts. Don't let "the code is ready" substitute for this.

## 1. Generate per-competition secrets

```
./scripts/generate-keys.sh
```

Writes to `secrets/` (gitignored): a replication-only SSH keypair (`replicate_key`/`replicate_key.pub`) and a TOTP seed (`totp_secret`). Neither belongs in this repo or anywhere else public. Distribute the TOTP seed to teammates who'll need to generate opmenu codes — out-of-band (e.g. a QR code shown once, not pasted into Slack).

This does **not** generate the team's own login keypair (`TEAM_PUBKEY`) — that should already exist; use whatever key a team member actually holds the private half of.

## 2. Decide the replication target

Per `docs/PLAN.md` Phase 2: is there an actual second team-controlled box this season, or does `replicate` point at removable media instead?

- **Second box**: note its address, add `secrets/replicate_key.pub` to *that* box's `authorized_keys` (restricted the same way as any other automated key — a `command=` forcing a receive-only script is worth considering, though `SSHTarget`'s additive-only design already limits the blast radius of a stolen key to spamming junk objects), and get its host key with `ssh-keyscan -t ed25519 <backup-box>`.
- **Removable media**: skip this section; `REPLICATE_URL` will be `file:///path` and `REPLICATE_KEY`/`REPLICATE_HOST_KEY` aren't needed.

## 3. Build

```
make build \
  TEAM_PUBKEY="<team login pubkey>" \
  TEAM_FROM_IP="<team's public IP or CIDR>" \
  TOTP_SECRET="$(cat secrets/totp_secret)" \
  REPLICATE_URL="ssh://warden@<backup-box>/warden" \
  REPLICATE_KEY="$(base64 < secrets/replicate_key | tr -d '\n')" \
  REPLICATE_HOST_KEY="<output of ssh-keyscan above>"
```

(Drop the last three flags, or set `REPLICATE_URL=file:///path`, for the removable-media case.)

Produces `bin/warden` — a stripped, static binary with everything above baked in. Verify it actually captured the right values before going further, on a native build since `bin/warden` is cross-compiled for the target's `linux/amd64` and won't run here:

```
GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) make build TEAM_PUBKEY=... TOTP_SECRET=... ...   # same args as above
./bin/warden debug-config
```

`debug-config` is a hidden command (not shown in `--help`) meant for exactly this — it prints every baked-in value except the TOTP secret and replication private key, which it only reports as set/not-set. Rebuild for `linux/amd64` (drop the `GOOS`/`GOARCH` override) before actually deploying.

## 4. Confirm `install.sh`'s per-box values

Open `deploy/install.sh` and fill in the `CHANGE-ME` block: `INSTALL_PATH` (matching this box's naming conventions — check what's already there first), `TEAM_PUBKEY`, `TEAM_FROM_IP`. The script now refuses to run (`require_filled_in`) if either `TEAM_*` value is still a `CHANGE-ME` placeholder or the binary hasn't been built yet, but it can't know whether `INSTALL_PATH` genuinely blends in — that's a judgment call about the specific box.

## 5. Deploy to each box

Once the box has been swept clean with `seer` (see `docs/DESIGN.md`'s "No Clean Window: Assume Compromise"):

```
scp bin/warden deploy/install.sh -r deploy/systemd <box>:~/
ssh <box> 'sudo ./install.sh'
```

`install.sh` deletes itself on success. It does **not** delete `deploy/systemd/` — do that by hand after confirming the units came up, since leaving the template directory behind is exactly the kind of artifact `docs/DESIGN.md`'s footprint policy warns about:

```
ssh <box> 'rm -rf ~/systemd'
```

## 6. Verify

- `ssh -i secrets/replicate_key <box> status` (over the opmenu forced command) reports a manifest generation and recent watch/sentinel passes.
- If using a second box for replication, confirm `warden replicate` on the target actually lands objects there.

## 7. Repeat per box

Each box gets its own install; nothing here is shared between boxes except the team's login key, the TOTP seed (unless you'd rather generate a distinct seed per box — more secure, more to distribute), and the replication target.
