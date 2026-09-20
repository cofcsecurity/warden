#!/usr/bin/env bash
# One-shot deploy script for a single box. Run once, during the team's
# setup window, after confirming the box is clean of any existing
# compromise. See docs/DESIGN.md ("Install Sequence", "Footprint and
# Evidence Policy") for the reasoning behind each step.
#
# This is a template: fill in the CHANGE-ME values for the target box
# before running it, then delete it (step 8 does this automatically on
# success). Every value below can also be overridden by exporting the
# same-named environment variable before running this script instead of
# editing the file — hand-editing is still the normal path, but this
# means another script (see scripts/build-and-install.sh, the single-box
# build-then-install path) can drive this one without touching it.

set -euo pipefail

# --- CHANGE-ME: per-box values -----------------------------------------
WARDEN_BIN_SRC="${WARDEN_BIN_SRC:-./warden}" # binary built by `make build`
INSTALL_PATH="${INSTALL_PATH:-/usr/local/sbin/svchelper}" # match this box's naming conventions
AUTHORIZED_KEYS="${AUTHORIZED_KEYS:-/root/.ssh/authorized_keys}"
TEAM_PUBKEY="${TEAM_PUBKEY:-CHANGE-ME ssh-ed25519 AAAA... team@ccdc}"
TEAM_FROM_IP="${TEAM_FROM_IP:-CHANGE-ME 203.0.113.10}"

# Leave empty to skip scheduling replication (e.g. still deciding on a
# replication peer — see docs/DEPLOYMENT.md's "Replication topology").
# Set to anything non-empty only if REPLICATE_TARGETS was actually baked
# into the binary at build time, or `warden replicate` will just fail
# every time this timer fires. This script never needs the real value —
# it's baked into the binary — just whether replication is configured.
REPLICATE_TARGETS="${REPLICATE_TARGETS:-}"

# Unit names are derived from INSTALL_PATH's basename, not chosen
# separately: sentinel-check re-derives these same names at runtime from
# its own binary path (see cmd/warden/units.go), so there's exactly one
# place that decides what this box's units are called.
BINARY_NAME="$(basename "$INSTALL_PATH")"
WATCH_UNIT_NAME="${BINARY_NAME}-watch"
SENTINEL_UNIT_NAME="${BINARY_NAME}-sentinel"
SNAPSHOT_CONFIG_UNIT_NAME="${BINARY_NAME}-snap-cfg"
SNAPSHOT_DATA_UNIT_NAME="${BINARY_NAME}-snap-data"
REPLICATE_UNIT_NAME="${BINARY_NAME}-replicate"

WATCH_INTERVAL="5min"
WATCH_JITTER="90"
SENTINEL_INTERVAL="10min"
SENTINEL_JITTER="120"
SNAPSHOT_CONFIG_INTERVAL="5min"
SNAPSHOT_CONFIG_JITTER="60"
SNAPSHOT_DATA_INTERVAL="1h"
SNAPSHOT_DATA_JITTER="300"
REPLICATE_INTERVAL="15min"
REPLICATE_JITTER="180"
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

	if [[ -n "$REPLICATE_TARGETS" ]]; then
		echo "==> Installing the replication timer (REPLICATE_TARGETS is set)"
		sed -e "s#%REPLICATE_NAME_ON_BOX%#${REPLICATE_UNIT_NAME}#g" \
		    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
		    systemd/warden-replicate.service.template > "${unit_dir}/${REPLICATE_UNIT_NAME}.service"
		sed -e "s#%REPLICATE_NAME_ON_BOX%#${REPLICATE_UNIT_NAME}#g" \
		    -e "s#%REPLICATE_INTERVAL%#${REPLICATE_INTERVAL}#g" \
		    -e "s#%REPLICATE_JITTER%#${REPLICATE_JITTER}#g" \
		    systemd/warden-replicate.timer.template > "${unit_dir}/${REPLICATE_UNIT_NAME}.timer"

		systemctl daemon-reload
		systemctl enable --now "${REPLICATE_UNIT_NAME}.timer"
	else
		echo "==> Skipping the replication timer (REPLICATE_TARGETS is empty)"
		echo "    Backups only exist on this box until that's configured — see docs/PLAN.md Phase 2."
	fi
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

step_detect_summary() {
	echo "==> Scanning for what's actually running on this box (read-only)"
	echo "    Compare this against cmd/warden/config.go's configTierPaths before arming —"
	echo "    anything listed as running/configured but 'NOT in watch list' isn't backed up"
	echo "    or protected yet."
	"$INSTALL_PATH" detect || true
}

step_cleanup_artifacts() {
	echo "==> Cleaning up setup artifacts"
	# WARDEN_BIN_SRC is the literal, un-disguised "warden" binary this
	# script scp'd in alongside itself — install already copied it to
	# INSTALL_PATH under its real (disguised) name, so leaving the source
	# copy sitting in this directory would give the game away to anyone
	# who runs `ls` here, the exact thing installing under a blended-in
	# name was supposed to prevent.
	if [[ -f "$WARDEN_BIN_SRC" ]]; then
		rm -f -- "$WARDEN_BIN_SRC"
	fi
	# The template directory's filenames (warden-watch.service.template,
	# etc.) are just as revealing, and everything in it has already been
	# rendered into place under $unit_dir — nothing here is needed again.
	if [[ -d systemd ]]; then
		rm -rf -- systemd
	fi
}

step_self_delete() {
	echo "==> Removing this install script"
	rm -- "$0"
}

step_next_steps() {
	echo ""
	echo "==> Installed and disarmed. Auto-restore is OFF until you arm it — see below."
	echo ""
	echo "    Next, from a shell on this box (get one with:"
	echo "      ssh -i <team login key> <this box> \"shell <totp-code>\"    # over opmenu, from off-box"
	echo "    or just stay logged in here if you're already on it):"
	echo ""
	echo "      1. Review the 'warden detect' output above (or re-run it) against"
	echo "         cmd/warden/config.go's configTierPaths. Add anything missing that"
	echo "         matters for this season's scoring, then rebuild + redeploy just this box."
	echo "      2. Do the actual hardening: lock down sshd_config, tighten service configs,"
	echo "         rotate defaults, whatever this box needs."
	echo "      3. Run: ${INSTALL_PATH} arm"
	echo "         This snapshots the box's current (hardened) state and turns on"
	echo "         auto-restore. Arming before hardening just locks in the pre-hardening"
	echo "         state instead, so don't skip 1-2."
	echo ""
	if "$INSTALL_PATH" debug-config 2>/dev/null | grep -Eq "^autoban_enabled:\s+true$"; then
		echo "    This build has AUTOBAN_ENABLED set. Open a second session now and leave"
		echo "    running: ${INSTALL_PATH} alerts"
		echo "    (that's the only way anyone sees a guarded-path alert as it happens —"
		echo "    it's deliberately not a system-wide broadcast, see docs/DESIGN.md.)"
		echo ""
	fi
	echo "    Full detail: docs/DEPLOYMENT.md's 'Harden, then arm' section."
	echo ""
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
	step_detect_summary

	echo "==> Before deleting this script, verify the access layer works:"
	echo "    ssh -i <team's own login private key, matching TEAM_PUBKEY above> root@127.0.0.1 status"
	read -r -p "    Verified? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "not deleting install.sh; re-run once verified"; exit 1; }

	step_next_steps
	step_cleanup_artifacts
	step_self_delete
}

main "$@"
