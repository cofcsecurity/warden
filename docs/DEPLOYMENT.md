# Deployment

Bare box to armed in a few minutes, with nothing installed or prepared on the laptops. Every step runs on the defended box or uses only the `ssh` and `ssh-keygen` that ship with the laptops (Linux, macOS, Windows 10/11).

## 0. Once per competition: the team key

On any team laptop:

```bash
ssh-keygen -t ed25519 -f team -C team
```

Share `team` (private) among the team the way you share any secret, and never put it on a defended box. `team.pub` is public; paste it, or host it somewhere reachable over https.

## 1. Per box: install

```bash
git clone https://github.com/cofcsecurity/warden.git && cd warden
sudo ./install.sh --key "ssh-ed25519 AAAA... team"
```

- The repo contains no secrets, so the clone and the build are harmless. The binary has nothing compiled in.
- With Go on the box it builds from the clone. Without Go it fetches the official toolchain from `dl.google.com` and checks its SHA-256 first. `GOTOOLCHAIN=auto` upgrades an older Go the same verified way.
- No Go and no wish to build: `sudo ./install.sh --release vX.Y.Z --key ...` downloads the release binary and checks it against that release's `SHA256SUMS`. Add `--sha256 <hex>` to pin the exact binary you expect.
- The only question is the team network, defaulting to the /24 of the SSH session you are installing from. Pass `--from 10.0.0.0/24` (comma-separated CIDRs, or `any` for key-only) and `--yes` to skip it.

Install picks an inconspicuous name (`netmgr`, `diskcheck`, ...) and prints it with the commands to connect. It creates:

- the access account and a break-glass account, both accepting only the team key from the team network
- sshd drop-ins that apply only to those two accounts
- the triggers and timers (sentinel, watch, snapshots, scan)
- the first snapshots

Auto-restore stays **off**. Running install again on the same box updates it in place.

## 2. Check you can get in

From the team network:

```bash
ssh -i team <name>@<box> status
ssh -t -i team <name>@<box>                 # root shell
ssh -t -i team <break-glass>@<box>          # second door
```

## 3. Harden, then arm

Follow the hardening sheet. Check that services and scoring still work. Then:

```bash
ssh -i team <name>@<box> arm
```

Whatever is on disk now is what Warden holds the box to. `arm` lists the files that changed since the install snapshot; glance over it for anything that was not you.

After arming:

- `disarm`, change, check, `arm` to change a protected file on purpose.
- Password and firewall changes are only flagged; run `accept --flagged` afterwards.
- `alerts` (or `alerts --follow` in a spare session) shows what Warden restored, quarantined and repaired.

If the box has scored files Warden does not know about, add them to `/var/lib/<name>/profile.json` (see [USAGE.md](USAGE.md#host-profile)) before arming.

## 4. Pair the boxes

Each box should push its backups to at least one other box. From a laptop, for boxes A and B:

```bash
ssh -i team <a>@A pair add $(ssh -i team <b>@B pair accept $(ssh -i team <a>@A pair key))
ssh -i team <b>@B pair add $(ssh -i team <a>@A pair accept $(ssh -i team <b>@B pair key))
```

The same line works in bash and PowerShell. With more boxes, pair in a ring (A to B, B to C, C to A). Private keys never leave the box that made them; B only learns A's public key, and A's key can only upload into its own directory on B.

## 5. Responses

IP bans and account locks default to `flag`: Warden logs what it would have done. To let it act:

```bash
ssh -i team <name>@<box> config set safe_accounts scorer,alice
ssh -i team <name>@<box> config set ban act
```

## Recovering a box

- **Locked out of the main account:** use break-glass; sentinel rebuilds the main path within a couple of minutes either way.
- **Warden's files deleted:** the spares, the config mirror and the triggers bring it back. If everything is gone, reinstall.
- **Box wiped:** reinstall, then on the peer `pair accept <same source name> <new key>` (stored backups are kept), `pair add` on the rebuilt box, and `retrieve --apply` for each tier.
- **Rotate the team key:** `rekey <new pub>` on each box.

If all else fails, the console and the original admin credentials still work: Warden never changes other accounts.

## Remove

```bash
ssh -t -i team <name>@<box>
/usr/local/sbin/<name> uninstall --force
```
