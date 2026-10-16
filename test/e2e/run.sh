#!/usr/bin/env bash
# End-to-end tests in containers: two defended boxes (Ubuntu and Rocky, real
# systemd, sshd, sudo, cron, iptables) and a "laptop" that has only ssh.
#
#   ./test/e2e/run.sh            all scenarios
#   KEEP=1 ./test/e2e/run.sh     leave the containers running afterwards
#   FROM_CLONE=1 ...             also time a full ./install.sh from a clone
#
# Each scenario plays red against one link of the access chain, then checks
# that the team key works again within the repair window and that a
# bystander account's sshd configuration and login never changed.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"
NET=warden-e2e
SUBNET=172.30.77.0/24
A_IP=172.30.77.10
B_IP=172.30.77.11
LAPTOP_IP=172.30.77.50
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
	if [[ -z "${KEEP:-}" ]]; then
		docker rm -f w-a w-b w-laptop w-clone >/dev/null 2>&1 || true
		docker network rm "$NET" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
# run_cmd runs a command, or evaluates "sh -c STRING" here so it can use
# the helper functions below.
run_cmd() {
	if [[ "$1" == sh && "$2" == -c ]]; then
		eval "$3"
	else
		"$@"
	fi
}
check() { # check "description" cmd...
	local what="$1"
	shift
	if run_cmd "$@" >"$WORK/out" 2>&1; then ok "$what"; else bad "$what"; sed 's/^/       /' "$WORK/out" | tail -20; fi
}
# eventually SECONDS "description" cmd...: retry until it passes.
eventually() {
	local limit="$1" what="$2" start=$SECONDS
	shift 2
	while ((SECONDS - start < limit)); do
		if run_cmd "$@" >"$WORK/out" 2>&1; then
			ok "$what ($((SECONDS - start))s)"
			return 0
		fi
		sleep 3
	done
	bad "$what (not within ${limit}s)"
	sed 's/^/       /' "$WORK/out" | tail -20
	return 0
}

box() { docker exec "$@"; }
ssh_opts=(-i /root/team -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
lap() { docker exec -i w-laptop ssh "${ssh_opts[@]}" "$@"; }
# root_shell USER IP: the team key's shell answers as root.
root_shell() { echo 'id -u' | lap "$1@$2" | grep -qx 0; }

start_box() { # name image ip hostname
	docker run -d --name "$1" --hostname "$4" --network "$NET" --ip "$3" \
		--privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock "$2" >/dev/null
	for _ in $(seq 1 60); do
		state="$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)"
		[[ "$state" == running || "$state" == degraded ]] && return 0
		sleep 1
	done
	echo "systemd did not come up in $1" >&2
	return 1
}

log "Building images and the linux binary"
arch="$(docker info --format '{{.Architecture}}')"
case "$arch" in aarch64 | arm64) goarch=arm64 ;; *) goarch=amd64 ;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "$WORK/warden" ./cmd/warden
docker build -q -t w-ubuntu -f test/e2e/Dockerfile.ubuntu test/e2e >/dev/null
docker build -q -t w-rocky -f test/e2e/Dockerfile.rocky test/e2e >/dev/null
docker build -q -t w-laptop -f test/e2e/Dockerfile.laptop test/e2e >/dev/null
docker rm -f w-a w-b w-laptop w-clone >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET" "$NET" >/dev/null
start_box w-a w-ubuntu "$A_IP" boxa
start_box w-b w-rocky "$B_IP" boxb
docker run -d --name w-laptop --network "$NET" --ip "$LAPTOP_IP" w-laptop >/dev/null

# The team key is made on the laptop with stock ssh-keygen; only the public
# half ever reaches a box.
ssh-keygen -q -t ed25519 -N '' -C team -f "$WORK/team"
ssh-keygen -q -t ed25519 -N '' -C alice -f "$WORK/alice"
docker cp "$WORK/team" w-laptop:/root/team
docker cp "$WORK/alice" w-laptop:/root/alice
for b in w-a w-b; do
	docker cp "$WORK/warden" "$b:/tmp/warden"
	docker cp "$WORK/team.pub" "$b:/tmp/team.pub"
	# A bystander with a password and a key, whose access must never change.
	box "$b" sh -c 'useradd -m -s /bin/bash alice && echo alice:hunter2 | chpasswd && mkdir -p /home/alice/.ssh'
	docker cp "$WORK/alice.pub" "$b:/home/alice/.ssh/authorized_keys"
	box "$b" sh -c 'chown -R alice:alice /home/alice/.ssh && chmod 700 /home/alice/.ssh && chmod 600 /home/alice/.ssh/authorized_keys'
	box "$b" sh -c "sshd -T -C user=alice,host=x,addr=$LAPTOP_IP | sort" >"$WORK/$b.alice.before"
done
alice_ok() { # box ip
	docker exec -i w-laptop ssh -i /root/alice -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR "alice@$2" true &&
		box "$1" sh -c "sshd -T -C user=alice,host=x,addr=$LAPTOP_IP | sort" | diff "$WORK/$1.alice.before" -
}

log "Install (key only, nothing prepared on the laptop)"
start=$SECONDS
check "install on Ubuntu" box w-a /tmp/warden install --key @/tmp/team.pub --from "$SUBNET" --yes
check "install on Rocky" box w-b /tmp/warden install --key @/tmp/team.pub --from "$SUBNET" --yes
echo "  install took $((SECONDS - start))s for both boxes"
NA="$(box w-a sh -c 'basename "$(dirname "$(ls /var/lib/*/config.json)")"')"
NB="$(box w-b sh -c 'basename "$(dirname "$(ls /var/lib/*/config.json)")"')"
BGA="$(box w-a sh -c "grep -o '\"break_glass_user\": \"[^\"]*' /var/lib/$NA/config.json | cut -d'\"' -f4")"
BIN_A="/usr/local/sbin/$NA"
BIN_B="/usr/local/sbin/$NB"
echo "  box A: $NA (break-glass $BGA)   box B: $NB"
check "no 'warden' string in unit names" box w-a sh -c '! ls /etc/systemd/system | grep -i warden'
check "the clone binary is not what runs" box w-a test -x "$BIN_A"
check "install again updates in place" box w-a /tmp/warden install --yes
check "still one install" box w-a sh -c '[ "$(ls /var/lib/*/config.json | wc -l)" = 1 ]'

log "Access over the team key"
check "status over ssh" sh -c "lap $NA@$A_IP status | grep -q 'armed: NO'"
check "status --json over ssh" sh -c "lap $NA@$A_IP status --json | grep -q '\"armed\": false'"
check "root shell over ssh" root_shell "$NA" "$A_IP"
check "break-glass root shell" root_shell "$BGA" "$A_IP"
check "Rocky root shell" root_shell "$NB" "$B_IP"
check "unknown commands refused" sh -c "! lap $NA@$A_IP 'rm -rf /'"
check "alice unaffected by install (Ubuntu)" alice_ok w-a "$A_IP"
check "alice unaffected by install (Rocky)" alice_ok w-b "$B_IP"
check "team key limited to the team network" box w-a grep -q "from=\"$SUBNET\"" "/home/$NA/.ssh/authorized_keys"

log "Arm, then tamper"
check "arm over ssh" sh -c "lap $NA@$A_IP arm | grep -q 'armed: holding'"
check "arm over ssh (Rocky)" sh -c "lap $NB@$B_IP arm | grep -q 'armed: holding'"
box w-a sh -c 'echo "PermitRootLogin yes" >> /etc/ssh/sshd_config'
box w-a sh -c 'echo "red ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/zz-red && chmod 440 /etc/sudoers.d/zz-red'
box w-a sh -c 'echo "auth sufficient pam_permit.so" > /etc/pam.d/evil'
box w-a sh -c 'echo "* * * * * root /tmp/beacon" > /etc/cron.d/beacon'
box w-a sh -c 'echo "red:x:0:0::/root:/bin/bash" >> /etc/passwd'
check "watch pass" box w-a "$BIN_A" watch
check "sshd_config restored" sh -c "! box w-a grep -q 'PermitRootLogin yes' /etc/ssh/sshd_config"
check "passwd restored" sh -c "! box w-a grep -q '^red:' /etc/passwd"
check "new sudoers.d file quarantined" sh -c "! box w-a test -e /etc/sudoers.d/zz-red && box w-a sh -c 'ls /var/lib/$NA/quarantine | grep -q zz-red'"
check "new pam.d file quarantined" sh -c "! box w-a test -e /etc/pam.d/evil"
check "new cron.d file quarantined" sh -c "! box w-a test -e /etc/cron.d/beacon"
check "Warden's own drop-ins left alone" box w-a test -e "/etc/sudoers.d/$NA"
check "alerts show the quarantine" sh -c "lap $NA@$A_IP alerts | grep -q 'quarantined /etc/sudoers.d/zz-red'"
box w-a sh -c 'echo alice:newpass | chpasswd'
check "a password change is flagged, never reverted" sh -c "box w-a $BIN_A watch | grep -q 'flagged: [1-9]' && box w-a $BIN_A watch && box w-a $BIN_A status >/dev/null"
check "accept --flagged takes it as the new baseline" sh -c "box w-a $BIN_A accept --flagged | grep -q /etc/shadow && box w-a $BIN_A watch | grep -q 'flagged: 0'"
check "disarm, change, arm keeps the change" sh -c "lap $NA@$A_IP disarm && box w-a sh -c 'echo \"# team edit\" >> /etc/ssh/sshd_config' && lap $NA@$A_IP arm && box w-a $BIN_A watch && box w-a grep -q 'team edit' /etc/ssh/sshd_config"
box w-a sh -c 'echo "PermitRootLogin yes" >> /etc/ssh/sshd_config'
eventually 200 "the watch timer reverts drift by itself" sh -c "! box w-a grep -q 'PermitRootLogin yes' /etc/ssh/sshd_config"

log "Lockout attempts (repair within two minutes, bystander untouched)"
box w-a rm -f "/home/$NA/.ssh/authorized_keys"
eventually 30 "deleted key restored by the path unit" root_shell "$NA" "$A_IP"
box w-a sh -c "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGarbageGarbageGarbageGarbageGarbageGarbage red' > /home/$NA/.ssh/authorized_keys && chattr +i /home/$NA/.ssh/authorized_keys 2>/dev/null || true"
eventually 120 "replaced key restored" root_shell "$NA" "$A_IP"
box w-a usermod -L -s /usr/sbin/nologin -e 1 "$NA"
eventually 120 "locked, expired, nologin account repaired" root_shell "$NA" "$A_IP"
box w-a sh -c "printf 'Match User $NA\n\tPubkeyAuthentication no\n' > /etc/ssh/sshd_config.d/00-0red.conf && (systemctl reload ssh || systemctl reload sshd || true)"
eventually 180 "sshd drop-in that sorts before ours undone" root_shell "$NA" "$A_IP"
box w-a sh -c "echo 'AllowUsers alice' >> /etc/ssh/sshd_config && (systemctl reload ssh || systemctl reload sshd)"
eventually 180 "AllowUsers lockout survived" root_shell "$NA" "$A_IP"
box w-a rm -f "/etc/sudoers.d/$NA"
eventually 120 "sudoers rule restored" root_shell "$NA" "$A_IP"
box w-a iptables -I INPUT 1 -s "$SUBNET" -p tcp --dport 22 -j DROP
eventually 120 "firewall DROP above the team rule undone" root_shell "$NA" "$A_IP"
box w-a iptables -D INPUT -s "$SUBNET" -p tcp --dport 22 -j DROP || true
# The AllowUsers edit above was red's change to sshd_config; armed, watch
# puts the file back, after which alice must be exactly as before.
check "watch reverts red's sshd_config edits" sh -c "box w-a $BIN_A watch && ! box w-a grep -q 'AllowUsers alice' /etc/ssh/sshd_config"
check "alice unaffected by repairs (Ubuntu)" alice_ok w-a "$A_IP"

log "Kill the triggers"
box w-b sh -c "systemctl disable --now $NB-refresh.timer $NB-refresh.path && rm -f /etc/systemd/system/$NB-refresh.* && systemctl daemon-reload"
eventually 200 "sentinel units rebuilt by the other triggers (Rocky)" box w-b test -f "/etc/systemd/system/$NB-refresh.timer"
box w-b sh -c "systemctl mask --now sshd"
eventually 150 "masked and stopped sshd brought back (Rocky)" root_shell "$NB" "$B_IP"
box w-b rm -f "$BIN_B" "/var/lib/$NB/.spare"
eventually 200 "deleted binary restored from a spare (Rocky)" box w-b test -x "$BIN_B"

log "Break-glass: remove the main path entirely"
box w-a sh -c "systemctl disable --now $NA-refresh.timer $NA-refresh.path; rm -f /etc/systemd/system/$NA-refresh.*; crontab -l | grep -v $NA-refresh | crontab -; rm -f /etc/sudoers.d/$NA; userdel $NA; rm -rf /home/$NA; systemctl daemon-reload"
check "break-glass still gets a root shell" root_shell "$BGA" "$A_IP"
eventually 200 "main path rebuilt by break-glass triggers" root_shell "$NA" "$A_IP"
check "alice unaffected throughout (Ubuntu)" alice_ok w-a "$A_IP"
check "alice unaffected throughout (Rocky)" alice_ok w-b "$B_IP"

log "A broken profile never blocks access"
box w-a sh -c "echo '{broken' > /var/lib/$NA/profile.json"
check "shell works with a broken profile" root_shell "$NA" "$A_IP"
check "disarm works with a broken profile" lap "$NA@$A_IP" disarm
check "profile-dependent commands refuse" sh -c "! lap $NA@$A_IP watch"
box w-a rm -f "/var/lib/$NA/profile.json"
check "re-arm" lap "$NA@$A_IP" arm

log "Peer backups"
check "pair A -> B from the laptop" sh -c "docker exec w-laptop sh -c 'ssh ${ssh_opts[*]} $NA@$A_IP pair add \$(ssh ${ssh_opts[*]} $NB@$B_IP pair accept \$(ssh ${ssh_opts[*]} $NA@$A_IP pair key))'"
check "B holds A's backups" sh -c "box w-b sh -c 'ls /var/lib/$NB-peers/boxa/manifests-config/ | grep -q manifest-'"
check "A's backup key cannot get a shell on B" sh -c "! box w-a sh -c 'ssh -i /var/lib/$NA/peer_key -o StrictHostKeyChecking=no -o BatchMode=yes $NB@$B_IP id' 2>&1 | grep -q uid="
box w-a sh -c "rm -rf /var/lib/$NA/manifest-config.json /var/lib/$NA/manifests-config /var/lib/$NA/objects"
check "retrieve A's baseline back from B" box w-a "$BIN_A" retrieve --tier config --apply
check "restores work again after retrieve" box w-a "$BIN_A" restore /etc/ssh/sshd_config --preflight

log "Uninstall"
check "uninstall Rocky" box w-b "$BIN_B" uninstall --force --yes
check "no units left" sh -c "! box w-b sh -c 'ls /etc/systemd/system | grep -q $NB'"
check "no account left" sh -c "! box w-b id $NB"
check "alice unaffected by uninstall" alice_ok w-b "$B_IP"

if [[ -n "${FROM_CLONE:-}" ]]; then
	log "Fresh clone to armed (install.sh, Go fetched if missing)"
	start_box w-clone w-ubuntu 172.30.77.12 boxc
	tar -C "$ROOT" --exclude .git --exclude bin --exclude dist -cf "$WORK/src.tar" .
	docker cp "$WORK/src.tar" w-clone:/root/src.tar
	docker cp "$WORK/team.pub" w-clone:/tmp/team.pub
	start=$SECONDS
	check "install.sh from a clone" box w-clone sh -c 'mkdir -p /root/warden && tar -C /root/warden -xf /root/src.tar && cd /root/warden && ./install.sh --key @/tmp/team.pub --from 172.30.77.0/24 --yes'
	NC="$(box w-clone sh -c 'basename "$(dirname "$(ls /var/lib/*/config.json)")"')"
	check "arm" lap "$NC@172.30.77.12" arm
	echo "  fresh clone to armed: $((SECONDS - start))s"
fi

log "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
