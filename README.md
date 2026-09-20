# warden

Persistence and backup/restore for a host under active attack, built for the CofC Cybersecurity Club's SECCDC/PCDC defense team. Companion tool to [seer](https://github.com/cofcsecurity/seer).

Read [docs/DESIGN.md](docs/DESIGN.md) for the full design and rationale, and [docs/PLAN.md](docs/PLAN.md) for what's built versus what's left, phased.

**Before deploying any of this against a real box, confirm it's allowed under that competition's rules of engagement.** See DESIGN.md's "Rules of Engagement Note".

## Layout

```
cmd/warden/    Cobra CLI: snapshot, replicate, watch, restore, sentinel-check, opmenu
internal/      manifest, store, replicate, watch, restore, audit, opmenu, sentinel, totp
deploy/        systemd unit/timer templates, install.sh
docs/          design notes and implementation plan
```

## Building

```
make build TEAM_PUBKEY="ssh-ed25519 AAAA... team@ccdc" TEAM_FROM_IP=203.0.113.10 \
           TOTP_SECRET=<base32 seed> REPLICATE_URL=ssh://backup-box/warden
```

Produces a stripped, static `bin/warden` for `linux/amd64` with no build-time config file — see DESIGN.md's "Configuration" section for why.

## Testing

```
make test
```
