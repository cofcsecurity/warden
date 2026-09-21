#!/usr/bin/env bash
# Generates (or reuses) the team's login keypair: the ONE key used across
# every box this competition, not a new one per box (see
# docs/DEPLOYMENT.md step 1). The public half is TEAM_PUBKEY; the private
# half is what every teammate operating a box needs a copy of.
#
# Different from scripts/generate-keys.sh, which generates per-box
# replication/TOTP material — never something you log in with.
#
# Run this on your own machine — never on a target box — UNLESS there
# genuinely isn't one (see --on-box below).
#
# Usage:
#   generate-team-key.sh [key-path]              # normal path, own machine
#   generate-team-key.sh --on-box [key-path]      # no separate machine exists

set -euo pipefail

# ask prints $1 as a prompt and reads a line into the variable named by
# $2, from /dev/tty directly — see scripts/build-and-install.sh's
# identical helper for why: `read -p` silently drops its own prompt
# whenever the fd it reads from isn't a terminal, which matters here
# since this script can now run through the same curl/bootstrap chain as
# everything else, not just a plain interactive shell. The trailing
# `return 0` matters too: `read`'s own EOF failure must never become
# ask's exit status, which would be silently fatal under `set -e` for a
# bare caller.
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

ON_BOX=0
if [[ "${1:-}" == "--on-box" ]]; then
	ON_BOX=1
	shift
fi

KEY_PATH="${1:-$HOME/.ssh/warden_team_key}"

if [[ "$ON_BOX" -eq 1 ]]; then
	cat <<'EOF'
==> --on-box mode: generating the team login key on THIS machine.

This is only for when there is genuinely no separate machine outside the
competition network to generate it on instead — e.g. PCDC-style events
where every box provided is in scope. That's a real, different exposure
than the normal path: the private key briefly touches a machine you're
defending, not one red team has never had a chance to reach.

To keep the window as small as possible, this:
  1. Generates the keypair here.
  2. Prints the private key to THIS screen. The simplest safe way to get
     it off this box: you're already operating it through your OWN
     terminal, over your OWN SSH session — just select and copy the
     private key text straight out of your terminal's scrollback, the
     same as copying any other remote output, and paste it into a new
     file on your own machine (e.g. ~/.ssh/warden_team_key), then
     `chmod 600` it there. That never touches the network beyond the
     session you're already in. Getting it to any OTHER teammate from
     there is the same out-of-band sharing this script always
     recommended (read aloud, handwritten, a channel red team can't
     see) — just person-to-person instead of box-to-person.

     Before running this: if this session is being recorded anywhere —
     tmux/screen logging, a bastion's session capture, a cloud
     console's session replay — the private key printed here ends up
     wherever that recording lives too. Check for that first, and clear
     or rotate the recording afterward if you can't avoid it.
  3. Shreds the private key file from this box once you confirm every
     teammate who needs it has their own copy. Only the public key
     (never sensitive) is left behind. Note `shred` overwrites-then-
     deletes, which is not a hard guarantee on SSDs, journaling/
     copy-on-write filesystems, or most cloud block storage — treat
     step 2 (getting it off this box) as the real control, this as
     defense in depth on top of it, not instead of it.

Since no box is any safer than another here, there's nothing to gain by
picking a special one just for this — do it as part of installing to
whichever box you're setting up first. This same key gets reused for
every other box after that, so it only has to happen once.

EOF
fi

if [[ -e "$KEY_PATH" ]]; then
	echo "==> ${KEY_PATH} already exists — reusing it rather than generating a new one."
else
	echo "==> Generating a new team login keypair at ${KEY_PATH}"
	ssh-keygen -t ed25519 -N "" -C "team@ccdc" -f "$KEY_PATH"
fi

PRIVATE_KEY="$(cat "$KEY_PATH")"
PUBLIC_KEY="$(cat "${KEY_PATH}.pub")"

if [[ "$ON_BOX" -eq 0 ]]; then
	cat <<EOF

Done.

Private key — keep this secret. Share it only with teammates who'll
operate these boxes, out-of-band (not Slack/Discord). Never commit it,
never put it on a target box:
  ${KEY_PATH}

Public key — this is TEAM_PUBKEY. Use this exact value for every box you
set up this competition, not a new one per box:
  ${PUBLIC_KEY}

Each teammate who receives the private key needs it saved on their OWN
laptop before they can connect with it — it's already there for you
(${KEY_PATH}). For anyone else, on their own laptop:
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  nano ~/.ssh/warden_team_key
Paste the private key block above (everything from "-----BEGIN" to
"-----END", both lines included) into the editor, save, exit, then:
  chmod 600 ~/.ssh/warden_team_key
(any editor works — nano, vim, whatever's there; a text editor is safer
to paste multi-line key material into by hand than a shell heredoc,
which breaks if the paste doesn't land exactly as typed)

To connect once a box is set up (see docs/USAGE.md's "Operating over SSH"):
  ssh -i ${KEY_PATH} <opmenu-user>@<box> status
EOF
	exit 0
fi

cat <<EOF

==> Generated. Copy BOTH of these out now, before continuing.

Public key — this is TEAM_PUBKEY. Use this exact value for every box you
set up this competition, not a new one per box:

${PUBLIC_KEY}

Private key — every teammate who'll operate a box needs their OWN copy of
this, saved on their own device, before it's deleted from this box. Copy
everything from "-----BEGIN" to "-----END" below, both lines included:

${PRIVATE_KEY}

On your own laptop (or whichever machine you'll actually run \`ssh\` from):
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  nano ~/.ssh/warden_team_key
Paste the block above into the editor, save, exit, then:
  chmod 600 ~/.ssh/warden_team_key
(any editor works; a text editor is safer to paste multi-line key
material into by hand than a shell heredoc, which breaks if the paste
doesn't land exactly as typed)

Get the same block to every other teammate who needs it, out-of-band,
and have them do the same on their own laptop.

EOF

ask "Copied the private key to every teammate who needs it, off this box? [y/N] " ans
if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
	echo "Not deleting anything yet. Re-run this script (it'll reuse the same key) once it's actually copied out — leaving the private key on this box any longer than necessary defeats the point."
	exit 1
fi

echo "==> Removing the private key from this box"
if command -v shred >/dev/null 2>&1; then
	shred -u "$KEY_PATH"
else
	rm -f "$KEY_PATH"
fi
echo "    Done. Only the public key (${KEY_PATH}.pub, not sensitive) is left here."
echo ""
echo "    One more thing this script can't do for you: it ran as its own"
echo "    process, so it can't clear YOUR shell's own history. If your shell"
echo "    keeps a history file, run 'history -c' (bash/zsh) now in the shell"
echo "    you're typing in, so the private key text printed above doesn't"
echo "    end up sitting in it or in HISTFILE on disk."
echo ""
echo "    Once TEAM_PUBKEY above is actually baked into a build (scripts/"
echo "    build-and-install.sh's own wizard does this for you automatically"
echo "    if you got here through it), also remove ${KEY_PATH}.pub — it has"
echo "    no further purpose on this box, and its name alone tells anyone"
echo "    with access here that this was set up."
