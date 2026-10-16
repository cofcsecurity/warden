#!/usr/bin/env bash
# Install Warden on the box this runs on, from a fresh clone:
#
#   git clone https://github.com/cofcsecurity/warden.git && cd warden
#   sudo ./install.sh --key "ssh-ed25519 AAAA... team"
#
# The repository holds no secrets, so the clone and the build are safe to
# leave lying around; the only input is the team's public key. Every other
# flag is passed to `warden install` (see `warden install --help`):
#
#   --from 10.0.0.0/24    team network (default: the /24 you SSHed in from)
#   --yes                 do not ask anything
#
# How the binary is obtained, in order:
#   --release vX.Y.Z      download that GitHub release and verify it against
#                         the release's SHA256SUMS (and --sha256 if given)
#   otherwise             build here with Go; if Go is missing, download the
#                         official toolchain from dl.google.com and verify it
set -euo pipefail

REPO="${WARDEN_REPO:-cofcsecurity/warden}"
GO_VERSION="$(awk '/^go /{print $2}' "$(dirname "$0")/go.mod" 2>/dev/null || true)"
GO_VERSION="${GO_VERSION:-1.26.0}"

release=""
pin=""
args=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--release) release="$2"; shift 2 ;;
	--release=*) release="${1#*=}"; shift ;;
	--sha256) pin="$2"; shift 2 ;;
	--sha256=*) pin="${1#*=}"; shift ;;
	*) args+=("$1"); shift ;;
	esac
done

die() { echo "install.sh: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./install.sh ...)"
[[ "$(uname -s)" == Linux ]] || die "Linux only"

case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

fetch() { # fetch URL DEST
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "need curl or wget to download $1"
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
bin="$work/warden"

if [[ -n "$release" ]]; then
	base="https://github.com/$REPO/releases/download/$release"
	echo "==> Downloading warden $release for linux/$arch"
	fetch "$base/warden-linux-$arch" "$bin"
	fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
	want="$(awk -v f="warden-linux-$arch" '$2 == f || $2 == "*"f {print $1}' "$work/SHA256SUMS")"
	got="$(sha256_of "$bin")"
	[[ -n "$want" && "$got" == "$want" ]] || die "checksum mismatch for warden-linux-$arch (got $got, release says $want)"
	if [[ -n "$pin" && "$got" != "$pin" ]]; then
		die "checksum $got does not match the pinned --sha256 $pin"
	fi
	chmod 700 "$bin"
else
	cd "$(dirname "$0")"
	[[ -f go.mod && -d cmd/warden ]] || die "run from the root of a warden clone, or pass --release"
	go_bin="$(command -v go || true)"
	if [[ -z "$go_bin" ]]; then
		tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
		echo "==> Go not found; downloading $tarball"
		fetch "https://dl.google.com/go/$tarball" "$work/$tarball"
		fetch "https://dl.google.com/go/$tarball.sha256" "$work/$tarball.sha256"
		want="$(tr -d ' \n' < "$work/$tarball.sha256")"
		got="$(sha256_of "$work/$tarball")"
		[[ "$got" == "$want" ]] || die "Go toolchain checksum mismatch (got $got, want $want)"
		tar -C "$work" -xzf "$work/$tarball"
		go_bin="$work/go/bin/go"
	fi
	echo "==> Building warden"
	# Caches go to the throwaway work dir, not root's home. GOTOOLCHAIN=auto
	# lets an older installed Go fetch the version go.mod asks for, verified
	# against the Go checksum database.
	GOPATH="$work/gopath" GOCACHE="$work/cache" GOTOOLCHAIN=auto GOFLAGS=-modcacherw \
		CGO_ENABLED=0 "$go_bin" build -trimpath -ldflags="-s -w" -o "$bin" ./cmd/warden
fi

"$bin" install "${args[@]}"
