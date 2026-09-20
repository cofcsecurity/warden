# warden

Persistence and backup/restore for a host under active attack, built for the CofC Cybersecurity Club's SECCDC/PCDC defense team.

Read [docs/DESIGN.md](docs/DESIGN.md) for the full design and rationale, [docs/USAGE.md](docs/USAGE.md) for every command and what it does, [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the step-by-step checklist to stand this up ahead of a competition, and [docs/PLAN.md](docs/PLAN.md) for what's built versus what's left, phased.

**Before deploying any of this against a real box, confirm it's allowed under that competition's rules of engagement.** See DESIGN.md's "Rules of Engagement Note".

## Layout

```
cmd/warden/    Cobra CLI: snapshot, replicate, watch, restore, sentinel-check, opmenu
internal/      manifest, store, replicate, watch, restore, audit, opmenu, sentinel, totp
deploy/        systemd unit/timer templates, install.sh
scripts/       generate-keys.sh — one-time per-competition secret generation
docs/          design notes, usage reference, deployment checklist, implementation plan
```

## Building

```
./scripts/generate-keys.sh   # once per competition; writes to ./secrets/ (gitignored)

make build TEAM_PUBKEY="ssh-ed25519 AAAA... team@ccdc" TEAM_FROM_IP=203.0.113.10 \
           TOTP_SECRET=$(cat secrets/totp_secret) REPLICATE_URL=ssh://warden@backup-box/warden \
           REPLICATE_KEY=$(base64 < secrets/replicate_key | tr -d '\n') \
           REPLICATE_HOST_KEY="$(ssh-keyscan -t ed25519 backup-box 2>/dev/null | cut -d' ' -f2-)"
```

`REPLICATE_URL` can be `file:///path` instead (removable media) if there's no second team-controlled box; in that case `REPLICATE_KEY`/`REPLICATE_HOST_KEY` aren't needed.

Produces a stripped, static `bin/warden` for `linux/amd64` with no build-time config file — see DESIGN.md's "Configuration" section for why.

## Testing

```
make test
```
