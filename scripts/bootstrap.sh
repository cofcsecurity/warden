#!/usr/bin/env bash
# The one-line entry point for the single-box path: fetches this
# repository onto the box it's run on, then hands off to
# scripts/build-and-install.sh. Meant to be run as:
#
#   sudo bash -c "$(curl -fsSL <raw-url-to-this-file>)"
#
# Prefer that form over `curl ... | sudo bash`: piping into bash makes
# bash read its own script from stdin, which is a real hazard in general
# (a script that redirects fd 0 mid-execution can end up racing its own
# not-yet-executed source). It turned out not to be why the interactive
# prompts further down this chain were failing, though — that was
# `read -p` silently swallowing its own prompt text whenever the fd it
# reads from isn't a terminal (see build-and-install.sh's `ask` helper).
# Both scripts read every prompt from /dev/tty directly now, so either
# invocation form works; `bash -c` is still the one documented here since
# it avoids the stdin-racing hazard too, for free.
#
# Needs this box to reach wherever the repo is hosted. If the repo is
# private, that means git credentials (a deploy key or token) already
# configured on this box — same requirement as cloning it by hand; see
# docs/DEPLOYMENT.md's "Clone it directly on the box". The normal path
# (build on a machine the team controls, transfer just the finished
# binary) stays the default recommendation when a separate build machine
# is available — this exists for when it isn't.

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/cofcsecurity/warden.git}"
REPO_TARBALL_URL="${REPO_TARBALL_URL:-https://github.com/cofcsecurity/warden/archive/refs/heads/main.tar.gz}"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "bootstrap.sh: must run as root (e.g. 'sudo bash -c \"\$(curl -fsSL ...)\"')" >&2
	exit 1
fi

# A directory literally named "warden" would undo the point of everything
# else here trying not to look like what it is — mktemp's random suffix
# is also less guessable than a human-chosen name. build-and-install.sh
# deletes this entirely once install succeeds either way.
DEST="$(mktemp -d)"

echo "==> Fetching warden into ${DEST}"
if command -v git >/dev/null 2>&1; then
	git clone --depth 1 "$REPO_URL" "$DEST"
elif command -v curl >/dev/null 2>&1; then
	curl -fsSL "$REPO_TARBALL_URL" | tar xz -C "$DEST" --strip-components=1
elif command -v wget >/dev/null 2>&1; then
	wget -qO- "$REPO_TARBALL_URL" | tar xz -C "$DEST" --strip-components=1
else
	echo "bootstrap.sh: need git, curl, or wget on this box to fetch the repo" >&2
	exit 1
fi

cd "$DEST"
exec ./scripts/build-and-install.sh
