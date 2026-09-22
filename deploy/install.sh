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
SCAN_INTERVAL="10min"
SCAN_JITTER="120"
# -------------------------------------------------------------------------

require_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		echo "install.sh: must run as root" >&2
		exit 1
	fi
}

# PKG_MANAGER/PKG_UPDATED back ensure_deps below — set once, on first use.
PKG_MANAGER=""
PKG_UPDATED=0

detect_pkg_manager() {
	if command -v apt-get >/dev/null 2>&1; then
		PKG_MANAGER=apt-get
	elif command -v dnf >/dev/null 2>&1; then
		PKG_MANAGER=dnf
	elif command -v yum >/dev/null 2>&1; then
		PKG_MANAGER=yum
	fi
}

pkg_name_for() {
	case "$1" in
	cron)
		[[ "$PKG_MANAGER" == "apt-get" ]] && echo cron || echo cronie
		;;
	*)
		echo "$1"
		;;
	esac
}

# pkg_install mirrors scripts/build-and-install.sh's identical helper —
# see its comment for why `set -e` is suspended around the actual
# package-manager call and why a failure here is reported, not fatal.
pkg_install() {
	local check_cmd="$1" logical="$2" pkg
	command -v "$check_cmd" >/dev/null 2>&1 && return 0
	if [[ -z "$PKG_MANAGER" ]]; then
		echo "    No apt-get/dnf/yum found — install ${logical} (for ${check_cmd}) manually if this box needs it." >&2
		return 1
	fi
	pkg="$(pkg_name_for "$logical")"
	echo "==> Installing ${pkg} (${check_cmd} not found)"

	set +e
	case "$PKG_MANAGER" in
	apt-get)
		if [[ "$PKG_UPDATED" -eq 0 ]]; then
			apt-get update -qq && PKG_UPDATED=1
		fi
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
		;;
	dnf|yum)
		"$PKG_MANAGER" install -y -q "$pkg"
		;;
	esac
	set -e

	if ! command -v "$check_cmd" >/dev/null 2>&1; then
		echo "    Failed to install ${pkg} — install it manually if this box actually needs it." >&2
		return 1
	fi
}

# ensure_deps installs, best-effort, the two things this script shells
# out to directly that a minimal competition image might genuinely be
# missing: cron (step_install_cron_entry's crontab) and sudo (
# step_configure_sudoers' visudo). Neither failure is fatal here — it's
# reported and this keeps going, since the step that actually needs it
# will fail with a much clearer error at that point if it's still
# missing than a bare "command not found" would.
ensure_deps() {
	detect_pkg_manager
	if [[ -z "$PKG_MANAGER" ]]; then
		return
	fi
	pkg_install crontab cron || true
	pkg_install visudo sudo || true
}

# ask prints $1 as a prompt and reads a line into the variable named by
# $2, always from the controlling terminal directly (/dev/tty) rather
# than whatever fd 0 currently is — see scripts/build-and-install.sh's
# identical helper for the full reasoning, including why the prompt is
# printed separately with printf instead of via `read -p`, and why the
# trailing `return 0` matters (read's own EOF failure must never become
# ask's exit status — silently fatal under `set -e` for a bare caller).
# Falls back to fd 0 if there's genuinely no controlling terminal (e.g.
# `ssh box 'cmd'` without -t).
ask() {
	local prompt="$1" var="$2"
	printf '%s' "$prompt"
	if exec 3</dev/tty 2>/dev/null; then
		read -r "$var" <&3
		exec 3<&-
	else
		read -r "$var"
	fi
	return 0
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
		ask "    Install a second copy anyway? [y/N] " ans
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
	SCAN_UNIT_NAME="${BINARY_NAME}-scan"

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
	ask "    Box confirmed clean? [y/N] " ans
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

	# Installed unconditionally, same as watch/sentinel/snapshot above:
	# scan always flags and logs regardless of AUTOLOCK_ENABLED/
	# AUTOBAN_ENABLED — only the reaction to what it finds is opt-in, not
	# the detection itself.
	sed -e "s#%SCAN_NAME_ON_BOX%#${SCAN_UNIT_NAME}#g" \
	    -e "s#%INSTALL_PATH%#${INSTALL_PATH}#g" \
	    systemd/warden-scan.service.template > "${unit_dir}/${SCAN_UNIT_NAME}.service"
	sed -e "s#%SCAN_NAME_ON_BOX%#${SCAN_UNIT_NAME}#g" \
	    -e "s#%SCAN_INTERVAL%#${SCAN_INTERVAL}#g" \
	    -e "s#%SCAN_JITTER%#${SCAN_JITTER}#g" \
	    systemd/warden-scan.timer.template > "${unit_dir}/${SCAN_UNIT_NAME}.timer"

	systemctl daemon-reload
	systemctl enable --now \
		"${WATCH_UNIT_NAME}.timer" \
		"${SENTINEL_UNIT_NAME}.timer" \
		"${SNAPSHOT_CONFIG_UNIT_NAME}.timer" \
		"${SNAPSHOT_DATA_UNIT_NAME}.timer" \
		"${SCAN_UNIT_NAME}.timer"

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

step_create_opmenu_user() {
	echo "==> Creating the dedicated account for the access layer ($OPMENU_USER)"
	if id "$OPMENU_USER" >/dev/null 2>&1; then
		echo "    $OPMENU_USER already exists — leaving it as-is"
		return
	fi
	useradd -r -m -d "$OPMENU_USER_HOME" -s /bin/sh "$OPMENU_USER"
}

step_authorize_key() {
	echo "==> Installing the dedicated account's restricted authorized_keys entry"
	if [[ -L "$OPMENU_USER_HOME" || -L "$(dirname "$AUTHORIZED_KEYS")" || -L "$AUTHORIZED_KEYS" ]]; then
		echo "install.sh: refusing symlink in operator access paths" >&2
		exit 1
	fi
	mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
	chown root:root "$OPMENU_USER_HOME" "$(dirname "$AUTHORIZED_KEYS")"
	chmod 755 "$OPMENU_USER_HOME"
	chmod 755 "$(dirname "$AUTHORIZED_KEYS")"

	# The forced command runs through sudo, not directly — this key lives
	# in OPMENU_USER's own authorized_keys, not root's, so it needs
	# step_configure_sudoers' rule to actually reach root-level access.
	local entry="command=\"sudo ${INSTALL_PATH} opmenu\",from=\"${TEAM_FROM_IP}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc,no-pty ${TEAM_PUBKEY}"
	local key_tmp
	key_tmp="$(mktemp "${AUTHORIZED_KEYS}.XXXXXX")"
	printf '%s\n' "$entry" > "$key_tmp"
	chown root:root "$key_tmp"
	chmod 644 "$key_tmp"
	mv -f "$key_tmp" "$AUTHORIZED_KEYS"
}

step_configure_sudoers() {
	echo "==> Granting $OPMENU_USER passwordless sudo for the second-factor gate"
	local tmp="${SUDOERS_PATH}.install-tmp"
	{
		echo "Defaults:${OPMENU_USER} !requiretty"
		echo "Defaults:${OPMENU_USER} env_keep += \"SSH_ORIGINAL_COMMAND SSH_CLIENT\""
		echo "${OPMENU_USER} ALL=(root) NOPASSWD: ${INSTALL_PATH} opmenu"
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

# step_next_steps deliberately ends with the box NOT armed, and says so
# first. Installing and arming in one go would bake whatever state the box
# happens to be in right now — pre-hardening, still carrying whatever red
# team may already have left — in as the enforced "known good", which is
# the one outcome worse than not being armed at all. So this prints the
# command instead of running it, with the customization worth doing first
# spelled out as commands rather than as advice.
step_next_steps() {
	echo ""
	echo "==> Installed, and deliberately NOT armed."
	echo ""
	echo "    Nothing gets auto-restored yet. 'watch' is already running on its timer and"
	echo "    will flag drift, and 'scan' is already looking for tampering — but nothing is"
	echo "    reverted until you arm, which is a command you run, not something this script"
	echo "    did for you. Arming now would lock in this box exactly as it is, before you've"
	echo "    hardened it."
	echo ""
	echo "    A static second factor was generated above (scroll up if you missed it) —"
	echo "    restore/shell accept it exactly like a TOTP code, no phone or authenticator"
	echo "    app needed. Works whether or not TOTP is also usable at this competition."
	echo "    Save that value now; run '${INSTALL_PATH} rotate-secret' any time to change it."
	echo ""
	echo "    Everything below runs on this box. You're already here; from off-box, get a"
	echo "    shell with:"
	echo "      ssh -i <team login key> ${OPMENU_USER}@<this box> \"shell <totp-code>\""
	echo ""
	echo "    1. See what is and isn't covered:"
	echo "         ${INSTALL_PATH} detect        # what's protected here, plus what's running that isn't"
	echo "         ${INSTALL_PATH} status        # armed state, manifest generation, last pass of each timer"
	echo ""
	echo "       Anything 'NOT in watch list' that matters for this season's scoring needs"
	echo "       adding to cmd/warden/config.go's configTierPaths, then a rebuild and"
	if [[ -n "${WARDEN_BIN_SRC:-}" ]]; then
		echo "       redeploy of this box. Note the source tree is being removed from this box"
		echo "       at the end of this run — make that edit wherever you build, not here."
	else
		echo "       redeploy of this box (steps 3-5 of docs/DEPLOYMENT.md, for this box only)."
	fi
	echo ""
	echo "    2. Harden the box for real: lock down sshd_config, tighten service configs,"
	echo "       rotate default credentials, remove what shouldn't be running. Do this"
	echo "       BEFORE arming, not after — arm is what turns the current state into the"
	echo "       baseline everything is held to."
	echo ""
	echo "       Already hardened this box before installing? Then there's nothing to do"
	echo "       here, and step 4's review should list no changes — that's the"
	echo "       confirmation nothing moved between install and arm. Still run step 1:"
	echo "       if it lists changes you didn't make, or lists nothing when you DID"
	echo "       harden after installing, both are worth knowing before you arm."
	echo ""
	echo "    3. Worth setting up while you're here (each takes effect immediately, no"
	echo "       rebuild needed):"
	echo "         ${INSTALL_PATH} rotate-secret # set a second factor your team picked"
	echo "         ${INSTALL_PATH} scan          # bootstrap the anomaly baselines on the HARDENED box"
	echo "         ${INSTALL_PATH} fleet         # this box plus any peers replicating to it"
	echo "         ${INSTALL_PATH} alerts        # live alert feed; leave running in a second session"
	echo ""
	echo "       Run 'scan' after hardening, not before: its first run records whatever it"
	echo "       finds as normal for this box, exactly like the first snapshot does."
	echo ""
	echo "    4. Then, and only then, turn it on:"
	echo ""
	echo "         ${INSTALL_PATH} arm"
	echo ""
	echo "       It first lists every watched file that changed since this install, then"
	echo "       snapshots that state and switches auto-restore on. READ THAT LIST: this"
	echo "       window is unprotected, so anything else that changed a watched file is"
	echo "       in it too, and arming makes all of it the enforced known-good state."
	echo "       Until arm runs, this box is monitored but not defended."
	echo ""
	echo "    After arming:"
	echo "      ${INSTALL_PATH} accept <path> <code>   # land a deliberate change without tripping an alert"
	echo "      ${INSTALL_PATH} disarm                 # ahead of a planned maintenance window"
	echo "      ${INSTALL_PATH} arm                    # again afterwards, re-baselining on the way"
	echo ""
	echo "    Something about this setup wrong? '${INSTALL_PATH} uninstall <code>' removes"
	echo "    everything above (timers, cron entry, sudoers rule, the ${OPMENU_USER}"
	echo "    account, the binary itself) and starts clean — <code> is a live TOTP code"
	echo "    or the static secret, same as restore/shell/accept. It refuses once armed"
	echo "    (--force overrides) — before that, nothing here is load-bearing yet."
	echo ""
	if [[ -n "${REPLICATE_TARGETS:-}" ]]; then
		echo "    This box replicates to a peer, so it also leaves a heartbeat there every"
		echo "    push. If it's ever taken down deliberately, expect its peers to report it"
		echo "    as silent within the hour ('warden fleet' / 'warden alerts' there) — that's"
		echo "    the dead-man's switch working, not a second problem."
		echo ""
	fi
	if "$INSTALL_PATH" debug-config 2>/dev/null | grep -Eq "^(autoban|autolock)_enabled:\s+true$"; then
		echo "    This build has AUTOBAN_ENABLED and/or AUTOLOCK_ENABLED set. Open a second"
		echo "    session now and leave running: ${INSTALL_PATH} alerts"
		echo "    (that's the only way anyone sees a guarded-path or scan alert as it"
		echo "    happens — it's deliberately not a system-wide broadcast, see docs/DESIGN.md.)"
		echo ""
	fi
	echo "    Full detail: docs/DEPLOYMENT.md's 'Harden, then arm' section."
	echo ""
}

main() {
	require_root
	ensure_deps
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
	ask "    Verified? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "not deleting install.sh; re-run once verified"; exit 1; }

	step_next_steps
	step_cleanup_artifacts
	step_self_delete
}

main "$@"
