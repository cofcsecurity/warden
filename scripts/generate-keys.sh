#!/usr/bin/env bash
# Generates the per-competition secrets that get baked into the binary at
# build time (see docs/DESIGN.md's "Configuration" section): the
# replication-only SSH keypair and the opmenu TOTP seed. Run this once on
# the team's own build machine, ahead of the competition — never on a
# target box.
#
# Output goes to ./secrets/ (gitignored) as separate files rather than
# straight into a `make build` invocation, so they can be reviewed,
# distributed to teammates who need to generate TOTP codes, and reused for
# a rebuild without regenerating everything.
#
# This does NOT generate the team's own login pubkey (TEAM_PUBKEY) — that
# should already be a real keypair a team member holds the private half of.

set -euo pipefail

OUT_DIR="${1:-secrets}"
mkdir -p "$OUT_DIR"

if [[ -e "$OUT_DIR/replicate_key" ]]; then
	echo "generate-keys.sh: $OUT_DIR/replicate_key already exists; remove it first if you really want to regenerate (this would orphan any replica already trusting the old key)." >&2
	exit 1
fi

echo "==> Generating replication-only SSH keypair"
ssh-keygen -t ed25519 -N "" -C "warden-replicate" -f "$OUT_DIR/replicate_key" >/dev/null
chmod 600 "$OUT_DIR/replicate_key"

echo "==> Generating TOTP seed"
if ! command -v python3 >/dev/null; then
	echo "generate-keys.sh: needs python3 to base32-encode the TOTP seed" >&2
	exit 1
fi
TOTP_SECRET="$(python3 -c 'import secrets, base64; print(base64.b32encode(secrets.token_bytes(20)).decode())')"
printf '%s\n' "$TOTP_SECRET" > "$OUT_DIR/totp_secret"
chmod 600 "$OUT_DIR/totp_secret"

OTPAUTH_URI="otpauth://totp/Warden:${OUT_DIR}?secret=${TOTP_SECRET}&issuer=Warden&digits=6&period=30"
echo "==> Two-factor setup — scan this in an authenticator app (Google Authenticator, Authy, 1Password, ...)"
if command -v qrencode >/dev/null 2>&1; then
	qrencode -t ANSIUTF8 "$OTPAUTH_URI"
else
	echo "    (install 'qrencode' to render this as a scannable QR code here instead of typing it in)"
fi
echo "    Or add it manually — most apps have an 'enter setup key' option:"
echo "      secret: $TOTP_SECRET"

cat <<EOF

Done. Wrote to $OUT_DIR/ (gitignored, do not commit):
  replicate_key      - private key; stays on the box that pushes replication
  replicate_key.pub  - public key; add to the backup box's authorized_keys
  totp_secret        - base32 seed; re-run this script's QR code (above) for
                        each teammate who needs it, out-of-band (not Slack)

Still needed before building, that this script can't generate for you:
  - TEAM_PUBKEY:         the team's own login public key (not this script's output)
  - TEAM_FROM_IP:        the IP(s) opmenu will accept connections from
  - REPLICATE_TARGETS:   "<url>||<hostkey>" pairs separated by ";;", one per
                         replication peer (see docs/DEPLOYMENT.md's
                         "Replication topology" for a multi-box mesh).
                         <hostkey> is empty for a file:// target. Get a
                         peer's host key with, e.g.:
                           ssh-keyscan -t ed25519 <peer>

Example build against a single peer, once the above is known:
  make build \\
    TEAM_PUBKEY="<team login pubkey>" \\
    TEAM_FROM_IP="<team IP>" \\
    TOTP_SECRET="$TOTP_SECRET" \\
    REPLICATE_KEY="\$(base64 < $OUT_DIR/replicate_key | tr -d '\\n')" \\
    REPLICATE_TARGETS="ssh://warden-backup@peer/from-thisbox||<peer's host key>"
EOF
