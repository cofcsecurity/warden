#!/usr/bin/env bash
# The one-line entry point for the single-box path: fetches this
# repository onto the box it's run on, then hands off to
# scripts/build-and-install.sh. Meant to be run as:
#
#   curl -fsSL <raw-url-to-this-file> | sudo bash
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
	echo "bootstrap.sh: must run as root (e.g. 'curl ... | sudo bash')" >&2
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
