#!/usr/bin/env bash
# Run this on your OWN machine — never on a target box. Generates (or
# reuses) the team's login keypair: the ONE key used across every box
# this competition, not a new one per box (see docs/DEPLOYMENT.md step 8).
# The public half is TEAM_PUBKEY; the private half is what every teammate
# operating a box needs a copy of.
#
# Different from scripts/generate-keys.sh, which generates per-box
# replication/TOTP material — never something you log in with.

set -euo pipefail

KEY_PATH="${1:-$HOME/.ssh/warden_team_key}"

if [[ -e "$KEY_PATH" ]]; then
	echo "==> ${KEY_PATH} already exists — reusing it rather than generating a new one."
else
	echo "==> Generating a new team login keypair at ${KEY_PATH}"
	ssh-keygen -t ed25519 -N "" -C "team@ccdc" -f "$KEY_PATH"
fi

cat <<EOF

Done.

Private key — keep this secret. Share it only with teammates who'll
operate these boxes, out-of-band (not Slack/Discord). Never commit it,
never put it on a target box:
  ${KEY_PATH}

Public key — this is TEAM_PUBKEY. Use this exact value for every box you
set up this competition, not a new one per box:
  $(cat "${KEY_PATH}.pub")

To connect once a box is set up (see docs/USAGE.md's "Operating over SSH"):
  ssh -i ${KEY_PATH} <opmenu-user>@<box> status
EOF
