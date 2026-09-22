#!/usr/bin/env bash
# Primary deployment path: build and install directly on the affected host
# during incident response. A separate build machine is optional.
#
# Read before running:
#
# 1. Secrets appear briefly in this box's own process list. `go build
#    -ldflags -X ...` passes the TOTP seed and replication key as literal
#    command-line arguments to the linker, visible via `ps`/
#    /proc/<pid>/cmdline to anyone who can already read root's process
#    table while the build runs. Review known compromise and contain what
#    you can; the confirmation does not certify a clean host.
# 2. If there's no Go toolchain on this box, this offers to download the
#    official upstream release from go.dev (not a distro package — those
#    vary in name and are often outdated or absent) and install it to
#    /usr/local/go. Needs this box to reach go.dev over HTTPS; if it
#    can't, and there's no toolchain already staged some other way, this
#    path isn't available — supply a toolchain or use a separate-machine build.
# 3. Fully offline needs a pre-vendored module cache: run `make vendor`
#    on any internet-connected machine first and bring the whole tree
#    here (including the resulting vendor/ directory), or this script
#    falls back to a normal `go build`, which needs this box to reach
#    Go's module proxy (or a configured mirror) itself.
# 4. This deletes the entire source tree (this script's own parent
#    checkout) after a successful install, the same reasoning as
#    install.sh deleting itself: a full repo checkout sitting on the box
#    is a far bigger, more identifiable footprint than the three files
#    a separate-machine build leaves behind, and none of it is needed once the
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

# ask prints $1 as a prompt and reads a line into the variable named by
# $2, always from the controlling terminal directly (/dev/tty) rather
# than whatever fd 0 currently is -- fd 0 can be all sorts of things
# depending on how this script was invoked (piped into bash, a
# command-substitution argument to bash -c, the SSH channel from a
# remote command, ...), and at least one of those forms has repeatedly
# proven unreliable for interactive input in live testing. /dev/tty
# sidesteps all of that by talking directly to the terminal device.
#
# The prompt is printed with a plain printf, not `read -p`: bash only
# ever displays a `read -p` prompt when the fd read() is consuming from
# is itself a terminal, and silently swallows it otherwise. That
# silent-swallow is exactly what every failed test showed — the prompt
# text never appeared at all, in any invocation form, right before an
# instant "aborting" with no visible question. Printing it ourselves to
# stdout means it always shows, independent of what fd read() ends up
# using.
#
# Falls back to fd 0 if there's genuinely no controlling terminal (e.g.
# `ssh box 'cmd'` without -t).
#
# The explicit `return 0` matters: `read` returns non-zero on EOF, and
# without it, `ask`'s own exit status would be that failure — silently
# fatal under `set -e` for any caller that happens to be the last thing
# its own function runs (bare `ask "..." var` with no `||`, which is
# most of them). An empty/EOF'd answer should behave like an empty
# answer, not kill the whole script with no message.
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

step_confirm_clean() {
	echo "==> Review the incident before deploying Warden."
	echo "    Contain known malicious access where practical. This host may still capture credentials."
	echo "    Installation leaves auto-restore disarmed; review and repair the baseline before arming."
	ask "    Incident reviewed; proceed on this potentially compromised host? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborting"; exit 1; }
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

# pkg_name_for translates a logical dependency name to the package name
# this distro family actually calls it, for the handful where it differs.
# Everything else passes through unchanged (git, curl, qrencode, sudo are
# all named the same across apt/dnf/yum).
pkg_name_for() {
	case "$1" in
	cron)
		[[ "$PKG_MANAGER" == "apt-get" ]] && echo cron || echo cronie
		;;
	ssh-client)
		[[ "$PKG_MANAGER" == "apt-get" ]] && echo openssh-client || echo openssh-clients
		;;
	*)
		echo "$1"
		;;
	esac
}

# pkg_install installs the package that provides $2 (a logical name, e.g.
# "cron") if $1 (the command it should leave on PATH, e.g. "crontab")
# isn't already there. Never aborts the script over a failed install —
# `set -e` is deliberately suspended around the actual package-manager
# call, since a missing repo (e.g. qrencode needing EPEL on some RHEL
# images) is exactly the kind of failure this should report and move
# past, not treat as fatal. Callers that actually require the result
# check for it themselves afterward (ensure_go already does this for go
# itself; nothing here is as hard a requirement as that one).
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

# ensure_deps installs, best-effort, everything this script and the ones
# it hands off to (install.sh, generate-team-key.sh) shell out to that a
# locked-down or minimal box might not already have — the same situation
# ensure_go below already handles for the Go toolchain specifically.
# Nothing here is fatal on its own: a box missing one of these still
# works for whatever doesn't need it (no cron package just means the
# systemd timer is sentinel's only trigger instead of two independent
# ones; no qrencode just means the TOTP secret prints as text instead of
# a QR code). ensure_go's own requirement is checked separately, right
# after this, since Go genuinely has no fallback.
#
# Deliberately never installs python3, even though the TOTP-seed
# generation below can use it if it's already there: python3 is also
# what tools like Ansible run on, and installing it as a side effect of
# setting up Warden would hand a defended box a capability it might not
# have had otherwise — one red team's own tooling could take advantage
# of just as easily. If it's missing, the TOTP prompt below just steps
# aside instead of trying to fix that.
ensure_deps() {
	detect_pkg_manager
	if [[ -z "$PKG_MANAGER" ]]; then
		echo "==> No apt-get/dnf/yum found — skipping automatic dependency install."
		echo "    If a step below fails over a missing command, install it yourself first."
		return
	fi
	echo "==> Checking for git, curl, cron, sudo, qrencode, ssh-keygen"
	pkg_install git git || true
	pkg_install curl curl || true
	pkg_install crontab cron || true
	pkg_install visudo sudo || true
	pkg_install qrencode qrencode || true
	pkg_install ssh-keygen ssh-client || true
}

# ensure_go finds a usable `go`, or offers to download the official
# upstream tarball (go.dev, not a distro package — distro package names
# for Go vary and are frequently outdated or absent, e.g. Debian/Ubuntu
# ship it as `golang-go`, not `go`) and installs it to /usr/local/go. This
# needs the box to reach go.dev over HTTPS; if it can't, there's no way
# around needing a toolchain from somewhere — use the normal
# build-elsewhere path instead (docs/DEPLOYMENT.md steps 1-5).
ensure_go() {
	if command -v go >/dev/null 2>&1; then
		return
	fi

	echo "==> No Go toolchain found on this box."
	local version arch url tmp
	# `|| true`: under pipefail, grep finding no matching line would make
	# this whole assignment non-zero — a bare statement that would abort
	# the script right here under set -e, before the explicit "couldn't
	# read" check below ever gets a chance to run and explain why.
	version="$(grep -E '^go [0-9]' go.mod | awk '{print $2}')" || true
	if [[ -z "$version" ]]; then
		echo "build-and-install.sh: couldn't read the required Go version from go.mod" >&2
		exit 1
	fi
	case "$(uname -m)" in
		x86_64) arch=amd64 ;;
		aarch64) arch=arm64 ;;
		*)
			echo "build-and-install.sh: no auto-download for $(uname -m) — install Go manually or use the normal build-elsewhere path" >&2
			exit 1
			;;
	esac
	if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
		echo "build-and-install.sh: no curl or wget on this box to download Go — install one of them, install Go manually, or use the normal build-elsewhere path" >&2
		exit 1
	fi

	url="https://go.dev/dl/go${version}.linux-${arch}.tar.gz"
	ask "    Download and install Go ${version} from go.dev now? [y/N] " ans
	[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborting — install a Go toolchain yourself, or use the normal build-elsewhere path"; exit 1; }

	tmp="$(mktemp -d)"
	echo "==> Downloading ${url}"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "${tmp}/go.tar.gz"
	else
		wget -qO "${tmp}/go.tar.gz" "$url"
	fi
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "${tmp}/go.tar.gz"
	rm -rf "$tmp"
	export PATH="/usr/local/go/bin:${PATH}"

	if ! command -v go >/dev/null 2>&1; then
		echo "build-and-install.sh: installed Go to /usr/local/go but it's still not on PATH — add /usr/local/go/bin to PATH and re-run" >&2
		exit 1
	fi
	echo "==> Go installed: $(go version)"
}

prompt_if_unset() {
	# Sets $1 (a variable name) to its current value if already exported
	# and non-empty; otherwise prompts for it. Never echoes an empty
	# default back as if it were acceptable — required values stay
	# required either way.
	local var="$1" label="$2"
	if [[ -z "${!var:-}" ]]; then
		ask "$label: " "$var"
	fi
}

# detect_client_ip finds the IP of whoever is running this script over
# SSH, from the OS's own login record (`who`) rather than SSH_CONNECTION/
# SSH_CLIENT — those are ordinary environment variables, and sudo resets
# the environment by default on virtually every distro, so they're
# usually gone by the time a `sudo bash -c "..."` invocation gets here.
# `who` reads utmp directly, independent of that. Empty output (not a
# real interactive SSH session, or the box doesn't record it) just means
# no guess is offered — falls back to asking outright.
#
# The trailing `|| true` matters: under `pipefail`, grep finding no match
# (the normal outcome whenever detection isn't possible) makes the whole
# pipeline return non-zero, and the caller assigns this straight into a
# plain variable (`detected_ip="$(detect_client_ip)"`) — a bare statement
# that would silently abort the entire script under `set -e` on exactly
# the common "couldn't detect anything" case, before the caller's own
# `[[ -n "$detected_ip" ]]` check ever runs.
detect_client_ip() {
	who -m 2>/dev/null | grep -oE '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' | tr -d '()' | head -n1 || true
}

# guess_subnet turns a detected IP into a /24 guess — the common case for
# a competition's team VLAN, not a certainty. It's a starting point to
# confirm or correct, not applied unconfirmed: this value becomes the
# network-level ACL on the entire access layer (TEAM_FROM_IP, baked into
# both the binary and the authorized_keys `from=` restriction), so
# guessing wrong in the wrong direction — too broad — is a real
# regression, not just an inconvenience. It's also wrong outright if
# there's a jump host between the operator and this box: `who` sees
# whatever directly dialed in, which is the jump host's IP, not the
# laptop behind it, in that case.
guess_subnet() {
	local ip="$1"
	[[ "$ip" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}$ ]] || return 1
	echo "${BASH_REMATCH[1]}.0/24"
}

collect_config() {
	echo "==> Per-box configuration (set as env vars beforehand to skip these prompts)"
	if [[ -z "${TEAM_PUBKEY:-}" ]]; then
		echo "    TEAM_PUBKEY is the team's own login key — the SAME one across every box"
		echo "    this competition, not a new one per box."
		if [[ -f "$HOME/.ssh/warden_team_key.pub" ]]; then
			echo "    Found an existing one at ~/.ssh/warden_team_key.pub — reusing it."
			TEAM_PUBKEY="$(cat "$HOME/.ssh/warden_team_key.pub")"
		else
			echo "    Have a machine outside the competition network? Generate it THERE,"
			echo "    never here, with scripts/generate-team-key.sh, then paste the public"
			echo "    key it prints below."
			echo "    No such machine exists (e.g. PCDC, every box provided is in scope)?"
			echo "    Then there's no separate machine to gain by using — generating it"
			echo "    right here, on this same box, is next:"
			ask "    Generate the team login keypair on this box now? [y/N] " ans
			if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
				./scripts/generate-team-key.sh --on-box
				TEAM_PUBKEY="$(cat "$HOME/.ssh/warden_team_key.pub")"
				GENERATED_TEAM_KEY_ON_BOX=1
			fi
		fi
	fi
	prompt_if_unset TEAM_PUBKEY "Team's login public key (e.g. 'ssh-ed25519 AAAA... team@ccdc')"

	if [[ -z "${TEAM_FROM_IP:-}" ]]; then
		local detected_ip guessed_cidr
		detected_ip="$(detect_client_ip)"
		if [[ -n "$detected_ip" ]] && guessed_cidr="$(guess_subnet "$detected_ip")"; then
			echo "    Detected this session connecting from ${detected_ip} — since your team's"
			echo "    laptops share one subnet this competition, guessing ${guessed_cidr} (a /24)."
			echo "    Wrong if there's a jump host between you and this box (this would be its"
			echo "    IP, not your laptop's) or your team's subnet isn't a /24 — check it."
			ask "    TEAM_FROM_IP [${guessed_cidr}]: " TEAM_FROM_IP
			TEAM_FROM_IP="${TEAM_FROM_IP:-$guessed_cidr}"
		fi
	fi
	prompt_if_unset TEAM_FROM_IP "Team's source IP or CIDR opmenu will accept connections from"
	# Left empty on purpose: install.sh auto-selects an unused,
	# inconspicuous name itself (see its resolve_install_path) unless
	# INSTALL_PATH is already set here.
	INSTALL_PATH="${INSTALL_PATH:-}"

	TOTP_SECRET="${TOTP_SECRET:-}"
	if [[ -z "$TOTP_SECRET" ]]; then
		if ! command -v python3 >/dev/null 2>&1; then
			echo "    No python3 on this box, and it's deliberately not auto-installed (see"
			echo "    ensure_deps above) — it's also what tools like Ansible run on, not"
			echo "    something worth handing a defended box just to generate a TOTP seed."
			echo "    Paste an existing seed below, or leave this blank to skip TOTP entirely"
			echo "    and rely on the static secret alone (generated next either way — it's"
			echo "    part of this binary, not python3)."
			ask "TOTP seed (base32, or blank to skip): " TOTP_SECRET
		else
			ask "Generate a fresh TOTP seed right here now? [Y/n] " ans
			if [[ -z "$ans" || "$ans" == "y" || "$ans" == "Y" ]]; then
				TOTP_SECRET="$(python3 -c 'import secrets, base64; print(base64.b32encode(secrets.token_bytes(20)).decode())')"
				local otpauth_uri="otpauth://totp/Warden?secret=${TOTP_SECRET}&issuer=Warden&digits=6&period=30"
				echo "==> Generated — scan this in an authenticator app (Google Authenticator, Authy, 1Password, ...)"
				if command -v qrencode >/dev/null 2>&1; then
					qrencode -t ANSIUTF8 "$otpauth_uri"
				else
					echo "    (install 'qrencode' to render this as a scannable QR code here instead of typing it in)"
				fi
				echo "    Or add it manually — most apps have an 'enter setup key' option:"
				echo "      secret: $TOTP_SECRET"
				echo "    Distribute this to every teammate who needs to generate opmenu codes,"
				echo "    out-of-band (not Slack/Discord) — it will not be printed again."
			else
				prompt_if_unset TOTP_SECRET "TOTP seed (base32, or blank to skip)"
			fi
		fi
	fi

	REPLICATE_TARGETS="${REPLICATE_TARGETS:-}"
	REPLICATE_KEY="${REPLICATE_KEY:-}"
	if [[ -z "$REPLICATE_TARGETS" ]]; then
		echo "    Off-box backups (optional, but recommended — without this, backups only"
		echo "    exist on this one box). Three options:"
		echo "      1. Skip for now — no second box, no removable media. No keypair needed;"
		echo "         you can rebuild and rerun later once you have one of the other two."
		echo "      2. A peer box also running Warden, over SSH — needs a replication keypair"
		echo "         (generated below) and that peer's receiving account already set up,"
		echo "         see docs/DEPLOYMENT.md's 'Replication topology'."
		echo "      3. A mounted USB drive / removable media on this box — no keypair needed"
		echo "         at all, just a local path."
		ask "    Choice [1/2/3, default 1]: " choice
		case "$choice" in
		2)
			ask "    REPLICATE_TARGETS (\"<url>||<hostkey>\" pairs, ';;'-separated): " REPLICATE_TARGETS
			if [[ -n "$REPLICATE_TARGETS" ]]; then
				if [[ -z "$REPLICATE_KEY" && ! -f secrets/replicate_key ]]; then
					./scripts/generate-keys.sh >/dev/null
					echo "    Generated a fresh replication keypair at ./secrets/. Its PUBLIC half"
					echo "    (./secrets/replicate_key.pub) still needs adding to each peer's authorized_keys"
					echo "    before replicate will actually work — see docs/DEPLOYMENT.md."
				fi
				REPLICATE_KEY="${REPLICATE_KEY:-$(base64 < secrets/replicate_key | tr -d '\n')}"
			fi
			;;
		3)
			ask "    Path to the mounted media (e.g. /mnt/usb): " media_path
			if [[ -n "$media_path" ]]; then
				REPLICATE_TARGETS="file://${media_path}||"
			fi
			;;
		*)
			: # skip — REPLICATE_TARGETS/REPLICATE_KEY stay empty
			;;
		esac
	fi

	AUTOBAN_ENABLED="${AUTOBAN_ENABLED:-}"
	if [[ -z "$AUTOBAN_ENABLED" ]]; then
		echo "    Auto-ban (docs/DESIGN.md's 'Active Response') actively firewalls an attacker IP."
		ask "    Enable it? [y/N] " ans
		# Deliberately a full if, not a bare `[[ ]] && ...`: this is
		# collect_config's last statement, so ITS exit status is whatever
		# this line's is. `[[ false ]] && cmd` as a standalone statement
		# returns non-zero (the failed test) when the answer isn't y/Y —
		# which is the common case, since this defaults to declining —
		# and under `set -e`, a bare `collect_config` call in main()
		# would then abort the entire script right here, silently, before
		# build() ever runs. That's exactly what happened during testing:
		# answering "N" here killed the whole install with zero output
		# and no error, immediately after this prompt.
		if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
			AUTOBAN_ENABLED=1
		fi
	fi

	AUTOLOCK_ENABLED="${AUTOLOCK_ENABLED:-}"
	if [[ -z "$AUTOLOCK_ENABLED" ]]; then
		echo "    Account-lock ('warden scan', docs/DESIGN.md's 'Active Response') locks"
		echo "    a local account and kills its sessions the instant a scan finding"
		echo "    attributes suspicious activity to it. A different risk than auto-ban"
		echo "    above: a false positive here can lock out a legitimate teammate's own"
		echo "    account, where auto-ban structurally can't hit the team's own IP."
		ask "    Enable it? [y/N] " ans
		if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
			AUTOLOCK_ENABLED=1
		fi
	fi

	SAFE_ACCOUNTS="${SAFE_ACCOUNTS:-}"
	if [[ -z "$SAFE_ACCOUNTS" ]]; then
		echo "    Account name(s) that must NEVER be auto-locked — your team's own"
		echo "    operating account on this box, and the scoring engine's account if"
		echo "    it uses one. (root and the opmenu account itself are already excluded"
		echo "    automatically, always, no need to list them.)"
		ask "    Comma-separated, or leave blank for none: " SAFE_ACCOUNTS
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
		-X 'main.buildAutobanEnabled=${AUTOBAN_ENABLED}' \
		-X 'main.buildAutolockEnabled=${AUTOLOCK_ENABLED}' \
		-X 'main.buildSafeAccounts=${SAFE_ACCOUNTS}' \
		-X 'main.buildManifestKey=${MANIFEST_KEY:-}' \
		-X 'main.buildManifestPublicKey=${MANIFEST_PUBLIC_KEY:-}' \
		-X 'main.buildManifestSource=${MANIFEST_SOURCE:-}'" \
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

# step_cleanup_team_key removes the on-box-generated public key file once
# it's actually baked into the built binary (build() already ran by the
# time this is called) — it has no further purpose here, and unlike a
# normal ~/.ssh key, its name (warden_team_key.pub) itself is a footprint:
# it tells anyone with box access that this was set up, which is exactly
# what install.sh's inconspicuous naming is otherwise trying to avoid. The
# private half is already gone — generate-team-key.sh --on-box shreds it
# before this function ever runs. Only relevant when the key was actually
# generated on this box (GENERATED_TEAM_KEY_ON_BOX); a TEAM_PUBKEY passed
# in some other way never created this file to begin with.
step_cleanup_team_key() {
	[[ -n "${GENERATED_TEAM_KEY_ON_BOX:-}" ]] || return
	echo "==> Removing the leftover team public key file (already baked into the binary)"
	rm -f "$HOME/.ssh/warden_team_key.pub"
}

main() {
	require_root
	ensure_deps
	ensure_go
	step_confirm_clean
	collect_config
	build
	step_cleanup_team_key

	export WARDEN_BIN_SRC="./warden"
	export INSTALL_PATH TEAM_PUBKEY TEAM_FROM_IP REPLICATE_TARGETS

	echo "==> Handing off to install.sh"
	(cd deploy && bash ./install.sh)

	step_cleanup_repo
	step_final_reminder
}

# step_final_reminder runs after the source tree is gone, so the last
# thing on screen is what to do next rather than a cleanup line. The
# detail is all in install.sh's own next-steps output above; this exists
# because that output has scrolled by the time this finishes, and the one
# thing nobody should walk away without knowing is that the box isn't
# armed yet.
step_final_reminder() {
	echo ""
	echo "==> Done — and this box is NOT armed yet."
	echo ""
	echo "    Harden it first, then:"
	echo "      ${INSTALL_PATH} detect        # what's protected, and what's running that isn't"
	echo "      ${INSTALL_PATH} status        # armed state and the last run of every timer"
	echo "      ${INSTALL_PATH} scan          # bootstrap anomaly baselines, AFTER hardening"
	echo "      ${INSTALL_PATH} arm           # turn auto-restore on"
	echo ""
	echo "    Scroll up for the full checklist, or see docs/DEPLOYMENT.md's"
	echo "    'Harden, then arm' section."
	echo ""
}

main "$@"
