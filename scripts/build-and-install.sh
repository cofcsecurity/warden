#!/usr/bin/env bash
# The single-box path: build Warden directly on the box being defended,
# then install it immediately — for when there's no separate machine
# available to build on first (PCDC-style events with only a locked-down
# provided laptop and no permission to install a toolchain on it), or
# when there is one but coordinating a separate build-then-transfer dance
# is more overhead than it's worth for how many boxes there are.
#
# The normal path (build on a machine the team controls, transfer just
# the finished binary — see docs/DEPLOYMENT.md steps 1-5) stays the
# default recommendation when it's available: it never exposes
# per-competition secrets to the target box's own process table, and
# never puts the source tree anywhere red team might reach it first. This
# script exists for when that path genuinely isn't practical, not as a
# universal replacement for it.
#
# Read before running:
#
# 1. Secrets appear briefly in this box's own process list. `go build
#    -ldflags -X ...` passes the TOTP seed and replication key as literal
#    command-line arguments to the linker, visible via `ps`/
#    /proc/<pid>/cmdline to anyone who can already read root's process
#    table on this box for the few seconds the build runs. That's a
#    materially different exposure than building on a machine red team
#    has never touched. Run this as early as possible in the box's
#    clean-first window (step_confirm_clean, below, still runs first,
#    same as install.sh's own) to minimize who's in a position to see it.
# 2. This needs a Go toolchain already on this box (go.mod's version or
#    newer). If there isn't one and there's no way to get one (no
#    internet, no local mirror, no package already staged), this path
#    isn't available — fall back to docs/DEPLOYMENT.md's normal one.
# 3. Fully offline needs a pre-vendored module cache: run `make vendor`
#    on any internet-connected machine first and bring the whole tree
#    here (including the resulting vendor/ directory), or this script
#    falls back to a normal `go build`, which needs this box to reach
#    Go's module proxy (or a configured mirror) itself.
# 4. This deletes the entire source tree (this script's own parent
#    checkout) after a successful install, the same reasoning as
#    install.sh deleting itself: a full repo checkout sitting on the box
#    is a far bigger, more identifiable footprint than the three files
#    the normal path leaves behind, and none of it is needed once the
#    binary is running from INSTALL_PATH. Set KEEP_SOURCE=1 to skip that
#    if there's a real reason to keep it around.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

require_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		echo "build-and-install.sh: must run as root" >&2
		exit 1
	fi
}

step_confirm_clean() {
	echo "==> Confirm this box is clean before continuing."
	echo "    Enumerate it for beacons, keyloggers, and altered binaries, and eliminate anything found first."
	echo "    (install.sh will ask this again in a moment — that's its own gate, not a bug.)"
	read -r -p "    Box confirmed clean? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborting"; exit 1; }
}

require_go() {
	if ! command -v go >/dev/null 2>&1; then
		cat >&2 <<'EOF'
build-and-install.sh: no `go` toolchain found on this box.

This path needs one here. If there's genuinely no way to get one (no
internet, no local mirror, no package already staged), use the normal
path instead: build on any other machine the team controls and transfer
just the finished binary — see docs/DEPLOYMENT.md steps 1-5, and
docs/DESIGN.md's "Build Location Contingency" for the full reasoning.
EOF
		exit 1
	fi
}

prompt_if_unset() {
	# Sets $1 (a variable name) to its current value if already exported
	# and non-empty; otherwise prompts for it. Never echoes an empty
	# default back as if it were acceptable — required values stay
	# required either way.
	local var="$1" label="$2"
	if [[ -z "${!var:-}" ]]; then
		read -r -p "$label: " "$var"
	fi
}

collect_config() {
	echo "==> Per-box configuration (set as env vars beforehand to skip these prompts)"
	prompt_if_unset TEAM_PUBKEY "Team's login public key (e.g. 'ssh-ed25519 AAAA... team@ccdc')"
	prompt_if_unset TEAM_FROM_IP "Team's source IP or CIDR opmenu will accept connections from"
	INSTALL_PATH="${INSTALL_PATH:-}"
	if [[ -z "$INSTALL_PATH" ]]; then
		read -r -p "Install path, matching this box's naming conventions (default: /usr/local/sbin/svchelper): " INSTALL_PATH
		INSTALL_PATH="${INSTALL_PATH:-/usr/local/sbin/svchelper}"
	fi

	TOTP_SECRET="${TOTP_SECRET:-}"
	if [[ -z "$TOTP_SECRET" ]]; then
		read -r -p "Generate a fresh TOTP seed right here now? [Y/n] " ans
		if [[ -z "$ans" || "$ans" == "y" || "$ans" == "Y" ]]; then
			if ! command -v python3 >/dev/null; then
				echo "build-and-install.sh: needs python3 to generate a TOTP seed (or set TOTP_SECRET yourself)" >&2
				exit 1
			fi
			TOTP_SECRET="$(python3 -c 'import secrets, base64; print(base64.b32encode(secrets.token_bytes(20)).decode())')"
			echo "    Generated. Distribute it to teammates out-of-band (e.g. a QR code) so they can generate opmenu codes — it will not be printed again."
		else
			prompt_if_unset TOTP_SECRET "TOTP seed (base32)"
		fi
	fi

	REPLICATE_TARGETS="${REPLICATE_TARGETS:-}"
	REPLICATE_KEY="${REPLICATE_KEY:-}"
	if [[ -z "$REPLICATE_TARGETS" ]]; then
		read -r -p "Set up replication to a peer now? [y/N] " ans
		if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
			echo "    See docs/DEPLOYMENT.md's 'Replication topology' — this needs a peer already reachable"
			echo "    and its receiving account already set up. Skipping for now if that's not true yet;"
			echo "    rebuild and rerun later once it is."
			read -r -p "    REPLICATE_TARGETS (\"<url>||<hostkey>\" pairs, ';;'-separated, blank to skip): " REPLICATE_TARGETS
			if [[ -n "$REPLICATE_TARGETS" ]]; then
				if [[ -z "$REPLICATE_KEY" && ! -f secrets/replicate_key ]]; then
					./scripts/generate-keys.sh >/dev/null
					echo "    Generated a fresh replication keypair at ./secrets/. Its PUBLIC half"
					echo "    (./secrets/replicate_key.pub) still needs adding to each peer's authorized_keys"
					echo "    before replicate will actually work — see docs/DEPLOYMENT.md."
				fi
				REPLICATE_KEY="${REPLICATE_KEY:-$(base64 < secrets/replicate_key | tr -d '\n')}"
			fi
		fi
	fi

	AUTOBAN_ENABLED="${AUTOBAN_ENABLED:-}"
	if [[ -z "$AUTOBAN_ENABLED" ]]; then
		echo "    Auto-ban (docs/DESIGN.md's 'Active Response') actively firewalls an attacker IP —"
		echo "    only enable this after confirming with organizers it's allowed under this"
		echo "    competition's rules of engagement."
		read -r -p "    Enable it? [y/N] " ans
		[[ "$ans" == "y" || "$ans" == "Y" ]] && AUTOBAN_ENABLED=1
	fi
}

build() {
	local mod_flag=""
	if [[ -d vendor ]]; then
		echo "==> Building with the vendored module cache (offline, -mod=vendor)"
		mod_flag="-mod=vendor"
	else
		echo "==> No ./vendor found — building normally, which needs this box to reach Go's module proxy"
	fi

	CGO_ENABLED=0 go build $mod_flag -ldflags="-s -w \
		-X 'main.buildTeamPubKey=${TEAM_PUBKEY}' \
		-X 'main.buildTeamFromIP=${TEAM_FROM_IP}' \
		-X 'main.buildTOTPSecret=${TOTP_SECRET}' \
		-X 'main.buildReplicateTargets=${REPLICATE_TARGETS}' \
		-X 'main.buildReplicateKey=${REPLICATE_KEY}' \
		-X 'main.buildAutobanEnabled=${AUTOBAN_ENABLED}'" \
		-o deploy/warden ./cmd/warden

	echo "==> Verifying what actually got baked in"
	./deploy/warden debug-config
}

step_cleanup_repo() {
	if [[ -n "${KEEP_SOURCE:-}" ]]; then
		echo "==> KEEP_SOURCE is set — leaving $REPO_ROOT in place"
		return
	fi
	echo "==> Removing the source tree ($REPO_ROOT) — nothing here is needed once the binary is installed"
	cd /
	rm -rf -- "$REPO_ROOT"
}

main() {
	require_root
	require_go
	step_confirm_clean
	collect_config
	build

	export WARDEN_BIN_SRC="./warden"
	export INSTALL_PATH TEAM_PUBKEY TEAM_FROM_IP REPLICATE_TARGETS

	echo "==> Handing off to install.sh"
	(cd deploy && bash ./install.sh)

	step_cleanup_repo
}

main "$@"
