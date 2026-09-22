# warden

Incident-response tooling for hosts with known active incursions, built for the CofC Cybersecurity Club's SECCDC/PCDC defense team.

The IR team locks down a box to a sufficient state, reviews its baseline, then arms Warden to help keep it in that state. Warden maintains repair access, restores approved files, and keeps recovery copies available to buy responders time when time is scarce. Blue-team operations and threat hunting continue alongside it. Its setup and operational overhead make it impractical for routine use outside an active incident.

[EXPLAINER.md](docs/EXPLAINER.md) covers the main features.

Documentation: [design](docs/DESIGN.md), [commands](docs/USAGE.md), [deployment](docs/DEPLOYMENT.md), [architecture](docs/ARCHITECTURE.md), and [implementation history](docs/PLAN.md).

## Layout

```
cmd/warden/    Cobra CLI: snapshot, replicate, watch, restore, sentinel-check, opmenu
internal/      manifest, store, replicate, watch, restore, audit, opmenu, sentinel, totp
deploy/        systemd unit/timer templates, install.sh
scripts/       generate-keys.sh, one-time per-competition secret generation
docs/          design notes, usage reference, deployment checklist, implementation plan
```

## Deploy on the affected host

Build and install directly on the box being defended. A separate build laptop is rarely available and is not required for the normal workflow.

```bash
git clone https://github.com/cofcsecurity/warden.git ~/build
cd ~/build
sudo ./scripts/build-and-install.sh
```

The script collects host configuration, builds Warden, and runs the installer. See [deployment](docs/DEPLOYMENT.md) for bootstrap, offline source delivery, credentials, and replication setup. A separate-machine build is an optional alternative when available.

Assume the host may still be compromised. Review the incident and contain what you can before introducing credentials. Installation leaves automatic restore disarmed: inspect the host profile, repair the selected files, and approve that baseline before arming. An initial snapshot is not proof of a clean host.

## Testing

```
make test
```
