#!/usr/bin/env bash
# One-shot deploy script for a single box. Run once, during the team's
# setup window, after confirming the box is clean of any existing
# compromise. See docs/DESIGN.md ("Install Sequence", "Footprint and
# Evidence Policy") for the reasoning behind each step.
#
# This is a template: fill in the CHANGE-ME values for the target box
# before running it, then delete it (step 8 does this automatically on
# success).

set -euo pipefail

# --- CHANGE-ME: per-box values -----------------------------------------
WARDEN_BIN_SRC="./warden"                # binary built by `make build`
INSTALL_PATH="/usr/local/sbin/svchelper" # match this box's naming conventions
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
TEAM_PUBKEY="CHANGE-ME ssh-ed25519 AAAA... team@ccdc"
TEAM_FROM_IP="CHANGE-ME 203.0.113.10"

# Unit names are derived from INSTALL_PATH's basename, not chosen
# separately: sentinel-check re-derives these same names at runtime from
# its own binary path (see cmd/warden/units.go), so there's exactly one
# place that decides what this box's units are called.
BINARY_NAME="$(basename "$INSTALL_PATH")"
WATCH_UNIT_NAME="${BINARY_NAME}-watch"
SENTINEL_UNIT_NAME="${BINARY_NAME}-sentinel"
SNAPSHOT_CONFIG_UNIT_NAME="${BINARY_NAME}-snap-cfg"
SNAPSHOT_DATA_UNIT_NAME="${BINARY_NAME}-snap-data"

WATCH_INTERVAL="5min"
WATCH_JITTER="90"
SENTINEL_INTERVAL="10min"
SENTINEL_JITTER="120"
SNAPSHOT_CONFIG_INTERVAL="5min"
SNAPSHOT_CONFIG_JITTER="60"
SNAPSHOT_DATA_INTERVAL="1h"
SNAPSHOT_DATA_JITTER="300"
# -------------------------------------------------------------------------

require_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		echo "install.sh: must run as root" >&2
		exit 1
	fi
}

require_filled_in() {
	local unfilled=()
	for var in TEAM_PUBKEY TEAM_FROM_IP; do
		if [[ "${!var}" == CHANGE-ME* ]]; then
			unfilled+=("$var")
		fi
	done
	if [[ ! -f "$WARDEN_BIN_SRC" ]]; then
		echo "install.sh: WARDEN_BIN_SRC ($WARDEN_BIN_SRC) doesn't exist — build it first with 'make build'" >&2
		exit 1
	fi
	if [[ ${#unfilled[@]} -gt 0 ]]; then
		echo "install.sh: still has placeholder CHANGE-ME values for: ${unfilled[*]}" >&2
		echo "            edit the per-box values at the top of this script before running it." >&2
		exit 1
	fi
}

step_confirm_clean() {
	echo "==> Confirm this box is clean before continuing."
	echo "    Enumerate it for beacons, keyloggers, and altered binaries, and eliminate anything found first."
	read -r -p "    Box confirmed clean? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborting"; exit 1; }
}

step_place_binary() {
	echo "==> Installing binary to $INSTALL_PATH"
	install -o root -g root -m 0700 "$WARDEN_BIN_SRC" "$INSTALL_PATH"
}

step_install_systemd_units() {
	echo "==> Installing systemd timer units"
	local unit_dir="/etc/systemd/system"

	sed -e "s#%NAME_ON_BOX%#${WATCH_UNIT_NAME}#g" \
	    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
	    systemd/warden-watch.service.template > "${unit_dir}/${WATCH_UNIT_NAME}.service"
	sed -e "s#%NAME_ON_BOX%#${WATCH_UNIT_NAME}#g" \
	    -e "s#%WATCH_INTERVAL%#${WATCH_INTERVAL}#g" \
	    -e "s#%WATCH_JITTER%#${WATCH_JITTER}#g" \
	    systemd/warden-watch.timer.template > "${unit_dir}/${WATCH_UNIT_NAME}.timer"

	sed -e "s#%SENTINEL_NAME_ON_BOX%#${SENTINEL_UNIT_NAME}#g" \
	    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
	    systemd/warden-sentinel.service.template > "${unit_dir}/${SENTINEL_UNIT_NAME}.service"
	sed -e "s#%SENTINEL_NAME_ON_BOX%#${SENTINEL_UNIT_NAME}#g" \
	    -e "s#%SENTINEL_INTERVAL%#${SENTINEL_INTERVAL}#g" \
	    -e "s#%SENTINEL_JITTER%#${SENTINEL_JITTER}#g" \
	    systemd/warden-sentinel.timer.template > "${unit_dir}/${SENTINEL_UNIT_NAME}.timer"

	sed -e "s#%SNAPSHOT_CONFIG_NAME_ON_BOX%#${SNAPSHOT_CONFIG_UNIT_NAME}#g" \
	    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
	    systemd/warden-snapshot-config.service.template > "${unit_dir}/${SNAPSHOT_CONFIG_UNIT_NAME}.service"
	sed -e "s#%SNAPSHOT_CONFIG_NAME_ON_BOX%#${SNAPSHOT_CONFIG_UNIT_NAME}#g" \
	    -e "s#%SNAPSHOT_CONFIG_INTERVAL%#${SNAPSHOT_CONFIG_INTERVAL}#g" \
	    -e "s#%SNAPSHOT_CONFIG_JITTER%#${SNAPSHOT_CONFIG_JITTER}#g" \
	    systemd/warden-snapshot-config.timer.template > "${unit_dir}/${SNAPSHOT_CONFIG_UNIT_NAME}.timer"

	sed -e "s#%SNAPSHOT_DATA_NAME_ON_BOX%#${SNAPSHOT_DATA_UNIT_NAME}#g" \
	    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
	    systemd/warden-snapshot-data.service.template > "${unit_dir}/${SNAPSHOT_DATA_UNIT_NAME}.service"
	sed -e "s#%SNAPSHOT_DATA_NAME_ON_BOX%#${SNAPSHOT_DATA_UNIT_NAME}#g" \
	    -e "s#%SNAPSHOT_DATA_INTERVAL%#${SNAPSHOT_DATA_INTERVAL}#g" \
	    -e "s#%SNAPSHOT_DATA_JITTER%#${SNAPSHOT_DATA_JITTER}#g" \
	    systemd/warden-snapshot-data.timer.template > "${unit_dir}/${SNAPSHOT_DATA_UNIT_NAME}.timer"

	systemctl daemon-reload
	systemctl enable --now \
		"${WATCH_UNIT_NAME}.timer" \
		"${SENTINEL_UNIT_NAME}.timer" \
		"${SNAPSHOT_CONFIG_UNIT_NAME}.timer" \
		"${SNAPSHOT_DATA_UNIT_NAME}.timer"
}

step_install_cron_entry() {
	echo "==> Installing sentinel's second, independent trigger"
	local marker="# ${SENTINEL_UNIT_NAME}"
	local line="*/10 * * * * ${INSTALL_PATH} sentinel-check ${marker}"
	# `|| true` matters here: on a box with no crontab yet (a fresh box is
	# exactly this case), `crontab -l` prints nothing and grep -v on empty
	# input exits 1, which under `set -e`/pipefail would otherwise abort
	# this whole subshell before `echo "$line"` ever runs.
	( { crontab -l 2>/dev/null | grep -vF "$marker" || true; }; echo "$line" ) | crontab -
}

step_authorize_key() {
	echo "==> Appending restricted authorized_keys entry"
	mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
	touch "$AUTHORIZED_KEYS"
	chmod 700 "$(dirname "$AUTHORIZED_KEYS")"
	chmod 600 "$AUTHORIZED_KEYS"

	local entry="command=\"${INSTALL_PATH} opmenu\",from=\"${TEAM_FROM_IP}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${TEAM_PUBKEY}"
	if ! grep -qF "$TEAM_PUBKEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
		echo "$entry" >> "$AUTHORIZED_KEYS"
	fi
}

step_initial_snapshot() {
	echo "==> Generating initial manifest and taking the first snapshots"
	"$INSTALL_PATH" snapshot --tier config
	"$INSTALL_PATH" snapshot --tier data
}

step_self_delete() {
	echo "==> Removing this install script"
	rm -- "$0"
}

main() {
	require_root
	require_filled_in
	step_confirm_clean
	step_place_binary
	step_install_systemd_units
	step_install_cron_entry
	step_authorize_key
	step_initial_snapshot

	echo "==> Before deleting this script, verify the access layer works:"
	echo "    ssh -i <team's own login private key, matching TEAM_PUBKEY above> root@127.0.0.1 status"
	read -r -p "    Verified? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "not deleting install.sh; re-run once verified"; exit 1; }

	step_self_delete
}

main "$@"
