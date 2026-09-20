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
INSTALL_PATH="${INSTALL_PATH:-}" # leave empty to auto-select an unused, inconspicuous name
TEAM_PUBKEY="${TEAM_PUBKEY:-CHANGE-ME ssh-ed25519 AAAA... team@ccdc}"
TEAM_FROM_IP="${TEAM_FROM_IP:-CHANGE-ME 203.0.113.10}"

# Leave empty to skip scheduling replication (e.g. still deciding on a
# replication peer — see docs/DEPLOYMENT.md's "Replication topology").
# Set to anything non-empty only if REPLICATE_TARGETS was actually baked
# into the binary at build time, or `warden replicate` will just fail
# every time this timer fires. This script never needs the real value —
# it's baked into the binary — just whether replication is configured.
REPLICATE_TARGETS="${REPLICATE_TARGETS:-}"

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

# warn_if_already_installed catches the case where this script (or
# scripts/build-and-install.sh) already ran on this box once: INSTALL_PATH
# isn't remembered between runs, so a second run would otherwise just pick
# a different unused name via choose_install_path and set up a completely
# separate second installation — not update the first, and not obviously
# so, since the two would look unrelated. /var/lib/<name>/.spare only
# exists once install_spare_binary has run, so pairing it with audit.log
# is a reasonably specific signal without needing a second, more
# obviously-named marker file.
warn_if_already_installed() {
	local dir name
	for dir in /var/lib/*/; do
		[[ -f "${dir}audit.log" && -f "${dir}.spare" ]] || continue
		name="$(basename "$dir")"
		echo "==> Warden already appears to be installed on this box as '${name}'"
		echo "    (found ${dir}audit.log). Continuing installs a SEPARATE, second copy"
		echo "    under a different name — it does not update or replace this one."
		echo "    To check on the existing install instead: ssh <team key> ${name}@<box> status"
		read -r -p "    Install a second copy anyway? [y/N] " ans
		[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborting"; exit 1; }
		return
	done
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

# NAME_PREFIXES x NAME_SUFFIXES combine into a couple hundred
# plausible-looking service names, checked in random order — not a short,
# easily enumerated list. Name obscurity here is a secondary layer, not
# the actual defense; that's the self-healing registrations and off-box
# backups. It only has to raise the cost of a casual look, not survive
# someone who has this source and is willing to check every combination.
NAME_PREFIXES=(net sys log cron disk mem pkg ssl dns ntp udev acpi irq pci usb mount fsck swap kernel proc)
NAME_SUFFIXES=(mgr helper agent watch sync relay proxy check monitor collector reporter handler)

name_collides() {
	local name="$1"
	[[ -e "/usr/local/sbin/$name" ]] && return 0
	[[ -e "/usr/sbin/$name" ]] && return 0
	[[ -e "/usr/bin/$name" ]] && return 0
	command -v "$name" >/dev/null 2>&1 && return 0
	id "$name" >/dev/null 2>&1 && return 0
	[[ -e "/etc/systemd/system/${name}-sentinel.service" ]] && return 0
	[[ -e "/etc/sudoers.d/$name" ]] && return 0
	return 1
}

choose_install_path() {
	local prefix suffix name candidates=() ordered
	for prefix in "${NAME_PREFIXES[@]}"; do
		for suffix in "${NAME_SUFFIXES[@]}"; do
			candidates+=("${prefix}${suffix}")
		done
	done
	if command -v shuf >/dev/null 2>&1; then
		ordered="$(printf '%s\n' "${candidates[@]}" | shuf)"
	else
		ordered="$(printf '%s\n' "${candidates[@]}")"
	fi
	while IFS= read -r name; do
		if ! name_collides "$name"; then
			echo "/usr/local/sbin/$name"
			return 0
		fi
	done <<< "$ordered"
	echo "install.sh: every candidate name collided with something already on this box — set INSTALL_PATH explicitly" >&2
	return 1
}

# resolve_install_path fills in INSTALL_PATH (auto-selecting one if it
# wasn't set) and derives every name that depends on it — unit names,
# the access-layer account, its authorized_keys path, and its sudoers
# rule. Kept as one step run early in main(), rather than plain top-level
# assignments, since it needs INSTALL_PATH finalized first.
resolve_install_path() {
	if [[ -z "$INSTALL_PATH" ]]; then
		INSTALL_PATH="$(choose_install_path)" || exit 1
		echo "==> Auto-selected an install path: $INSTALL_PATH"
	fi

	BINARY_NAME="$(basename "$INSTALL_PATH")"
	WATCH_UNIT_NAME="${BINARY_NAME}-watch"
	SENTINEL_UNIT_NAME="${BINARY_NAME}-sentinel"
	SNAPSHOT_CONFIG_UNIT_NAME="${BINARY_NAME}-snap-cfg"
	SNAPSHOT_DATA_UNIT_NAME="${BINARY_NAME}-snap-data"
	REPLICATE_UNIT_NAME="${BINARY_NAME}-replicate"

	# OPMENU_USER holds the team's forced-command SSH key — deliberately
	# not root, since PermitRootLogin no (independent of Warden, some
	# teams' standard practice) would make an entry in root's own
	# authorized_keys inert. Reuses BINARY_NAME: cmd/warden/units.go's
	# opmenuUser() derives the identical name at runtime, so there's one
	# place this decision is made.
	OPMENU_USER="$BINARY_NAME"
	OPMENU_USER_HOME="/home/${OPMENU_USER}"
	AUTHORIZED_KEYS="${AUTHORIZED_KEYS:-${OPMENU_USER_HOME}/.ssh/authorized_keys}"
	SUDOERS_PATH="/etc/sudoers.d/${OPMENU_USER}"
	# SPARE_BINARY_PATH is a hidden second copy of the binary — see
	# step_install_spare_binary and cronLine: watch/sentinel-check/retrieve
	# are all *inside* the binary, so if the binary file itself is deleted,
	# none of them can run to restore it. The cron trigger below checks
	# for and restores from this copy using only test/cp/chmod, never the
	# Go binary, so it still works even when the binary doesn't exist.
	SPARE_BINARY_PATH="/var/lib/${BINARY_NAME}/.spare"
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

step_install_spare_binary() {
	echo "==> Stashing a hidden recovery copy of the binary"
	mkdir -p "$(dirname "$SPARE_BINARY_PATH")"
	install -o root -g root -m 0700 "$INSTALL_PATH" "$SPARE_BINARY_PATH"
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
	# The "test -x ... || { cp; chmod; }" prefix restores the binary
	# itself from the hidden spare copy before doing anything else, using
	# only test/cp/chmod — never the Go binary — since watch/sentinel-check
	# are both *inside* that binary and can't run to fix its own absence.
	# cmd/warden/units.go's cronLine builds the identical line so
	# sentinel-check's own recreation never drifts from this.
	local line="*/10 * * * * test -x ${INSTALL_PATH} || { cp ${SPARE_BINARY_PATH} ${INSTALL_PATH}; chmod 0700 ${INSTALL_PATH}; }; ${INSTALL_PATH} sentinel-check ${marker}"
	# `|| true` matters here: on a box with no crontab yet (a fresh box is
	# exactly this case), `crontab -l` prints nothing and grep -v on empty
	# input exits 1, which under `set -e`/pipefail would otherwise abort
	# this whole subshell before `echo "$line"` ever runs.
	( { crontab -l 2>/dev/null | grep -vF "$marker" || true; }; echo "$line" ) | crontab -
}

# nologin_shell finds whatever this distro actually calls its no-login
# shell — /usr/sbin/nologin covers most current Debian- and RHEL-family
# boxes (usrmerge means /sbin/nologin is the same file), but older or
# minimal images can differ, so check rather than assume.
nologin_shell() {
	local candidate
	for candidate in /usr/sbin/nologin /sbin/nologin; do
		[[ -x "$candidate" ]] && { echo "$candidate"; return; }
	done
	command -v nologin 2>/dev/null && return
	echo "/bin/false"
}

step_create_opmenu_user() {
	echo "==> Creating the dedicated account for the access layer ($OPMENU_USER)"
	if id "$OPMENU_USER" >/dev/null 2>&1; then
		echo "    $OPMENU_USER already exists — leaving it as-is"
		return
	fi
	useradd -r -m -d "$OPMENU_USER_HOME" -s "$(nologin_shell)" "$OPMENU_USER"
}

step_authorize_key() {
	echo "==> Appending restricted authorized_keys entry"
	mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
	touch "$AUTHORIZED_KEYS"
	chmod 700 "$(dirname "$AUTHORIZED_KEYS")"
	chmod 600 "$AUTHORIZED_KEYS"

	# The forced command runs through sudo, not directly — this key lives
	# in OPMENU_USER's own authorized_keys, not root's, so it needs
	# step_configure_sudoers' rule to actually reach root-level access.
	local entry="command=\"sudo ${INSTALL_PATH} opmenu\",from=\"${TEAM_FROM_IP}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${TEAM_PUBKEY}"
	if ! grep -qF "$TEAM_PUBKEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
		echo "$entry" >> "$AUTHORIZED_KEYS"
	fi
}

step_configure_sudoers() {
	echo "==> Granting $OPMENU_USER passwordless sudo for exactly this binary"
	local tmp="${SUDOERS_PATH}.install-tmp"
	{
		echo "Defaults:${OPMENU_USER} !requiretty"
		echo "${OPMENU_USER} ALL=(root) NOPASSWD: ${INSTALL_PATH}"
	} > "$tmp"
	chmod 0440 "$tmp"
	# Never trust a hand-generated sudoers file without checking it first —
	# a malformed one can break sudo box-wide, for every account, not just
	# this one. visudo -cf validates without installing.
	if ! visudo -cf "$tmp" >/dev/null; then
		echo "install.sh: generated sudoers content failed validation — not installing it" >&2
		rm -f "$tmp"
		exit 1
	fi
	mv -f "$tmp" "$SUDOERS_PATH"
}

step_initial_snapshot() {
	echo "==> Generating initial manifest and taking the first snapshots"
	"$INSTALL_PATH" snapshot --tier config
	"$INSTALL_PATH" snapshot --tier data
}

# step_generate_static_secret runs by default, for every install, not just
# PCDC-style ones with no phones: it's an alternative to TOTP, not a
# replacement, so there's no downside to always having one ready — a team
# that ends up not needing it just doesn't use it. Doing this here means
# nobody has to remember a separate manual step for it later.
step_generate_static_secret() {
	echo "==> Generating a static second factor (works without TOTP or a phone at all)"
	"$INSTALL_PATH" rotate-secret
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
	echo "    A static second factor was generated above (scroll up if you missed it) —"
	echo "    restore/shell accept it exactly like a TOTP code, no phone or authenticator"
	echo "    app needed. Works whether or not TOTP is also usable at this competition."
	echo "    Save that value now; run '${INSTALL_PATH} rotate-secret' any time to change it."
	echo ""
	echo "    Next, from a shell on this box (get one with:"
	echo "      ssh -i <team login key> ${OPMENU_USER}@<this box> \"shell <totp-code>\"    # over opmenu, from off-box"
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
	warn_if_already_installed
	resolve_install_path
	step_confirm_clean
	step_place_binary
	step_install_spare_binary
	step_install_systemd_units
	step_install_cron_entry
	step_create_opmenu_user
	step_authorize_key
	step_configure_sudoers
	step_initial_snapshot
	step_generate_static_secret
	step_detect_summary

	echo "==> Before deleting this script, verify the access layer works:"
	echo "    ssh -i <team's own login private key, matching TEAM_PUBKEY above> ${OPMENU_USER}@127.0.0.1 status"
	read -r -p "    Verified? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "not deleting install.sh; re-run once verified"; exit 1; }

	step_next_steps
	step_cleanup_artifacts
	step_self_delete
}

# See scripts/build-and-install.sh's identical block for the full reasoning:
# redirecting fd 0 any earlier than this risks bash trying to read its own
# not-yet-executed script text from the terminal instead of the pipe it
# was actually invoked from, if this is ever piped directly rather than
# run as a file (its documented invocations always run it as a file, where
# this wouldn't actually be at risk, but there's no reason to depend on
# that). The fd-3 probe never touches fd 0, so it's always safe.
if exec 3</dev/tty 2>/dev/null; then
	exec 3<&-
	main "$@" < /dev/tty
else
	main "$@"
fi
