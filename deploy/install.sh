#!/usr/bin/env bash
# One-shot deploy script for a single box. Run once, during the team's
# setup window, after confirming with seer that the box is clean. See
# docs/DESIGN.md ("Install Sequence", "Footprint and Evidence Policy") for
# the reasoning behind each step.
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

WATCH_UNIT_NAME="svchelper-watch"
SENTINEL_UNIT_NAME="svchelper-sentinel"
WATCH_INTERVAL="5min"
WATCH_JITTER="90"
SENTINEL_INTERVAL="10min"
SENTINEL_JITTER="120"
# -------------------------------------------------------------------------

require_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		echo "install.sh: must run as root" >&2
		exit 1
	fi
}

step_confirm_clean() {
	echo "==> Confirm this box is clean before continuing."
	echo "    Run seer against it and eliminate anything found first."
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

	systemctl daemon-reload
	systemctl enable --now "${WATCH_UNIT_NAME}.timer" "${SENTINEL_UNIT_NAME}.timer"
}

step_install_cron_entry() {
	echo "==> Installing sentinel's second, independent trigger"
	local marker="# ${SENTINEL_UNIT_NAME}"
	local line="*/10 * * * * ${INSTALL_PATH} sentinel-check ${marker}"
	( crontab -l 2>/dev/null | grep -vF "$marker"; echo "$line" ) | crontab -
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
	echo "==> Generating initial manifest and taking the first snapshot"
	"$INSTALL_PATH" snapshot
}

step_self_delete() {
	echo "==> Removing this install script"
	rm -- "$0"
}

main() {
	require_root
	step_confirm_clean
	step_place_binary
	step_install_systemd_units
	step_install_cron_entry
	step_authorize_key
	step_initial_snapshot

	echo "==> Before deleting this script, verify the access layer works:"
	echo "    ssh -i <team replication key> root@127.0.0.1 status"
	read -r -p "    Verified? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "not deleting install.sh; re-run once verified"; exit 1; }

	step_self_delete
}

main "$@"
