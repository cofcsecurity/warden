# What Warden Is, In Plain English

This is the "start here if you're new" doc. If you already know what a CCDC-style
competition is and just want commands or design rationale, skip to
[USAGE.md](USAGE.md) or [DESIGN.md](DESIGN.md) instead — this page deliberately
repeats a few things they also cover, in plainer language, and skips a lot of
detail they include.

## The situation this is built for

In a CCDC/SECCDC/PCDC-style competition, your team ("blue team") is handed a
handful of servers that are already set up and already running real services
(a web server, a mail server, a database, whatever). Two things happen to
those servers for the rest of the competition:

- **Red team** actively tries to break in, change things, and lock you out —
  deleting your SSH access, corrupting configs, planting their own backdoors.
- **White team/scoring** periodically checks that your services are still up
  and behaving correctly, and that's your score.

So you're defending boxes you didn't build, against people actively trying to
kick you out of them, while also needing to keep proving the services on them
still work. Warden exists to make two specific parts of that easier: **staying
able to get back in**, and **not losing your data when something gets broken
or deleted**.

## What Warden actually does, in three pieces

**1. It gets you back in, even after red team kicks you out.**

Normally, if red team deletes your SSH key or firewalls you off, you're locked
out until you can get physical/console access — which you often can't during
a live competition. Warden sets up an extra way in ahead of time: a special
SSH key that only your team holds, restricted so it can only run a small
menu of safe commands (never a general shell, unless a one-time code proves
it's really you). If red team deletes this entry, Warden notices within
minutes and puts it back — see "How it survives being killed" below.

**2. It backs up your configs and service data automatically, off the box.**

Every few minutes, Warden takes a snapshot of the files you've told it matter
(configs like `nginx.conf`, `sshd_config`, and so on) and copies the actual
service data less often (hourly, since it's bigger). It keeps a copy of that
backup on at least one *other* box your team controls, not just the one being
attacked — so if a box gets root-compromised or wiped, the backup isn't gone
with it.

**3. It watches for tampering and reacts differently depending on what changed.**

Every few minutes, Warden checks: does anything on disk not match the last
known-good snapshot? If a config file changed in a way that's safe to just
fix automatically (like someone tweaking `nginx.conf`), Warden reverts it
immediately, no human needed. If something more sensitive changed — the
password file, `sudoers`, `sshd_config`, or the credentials scoring itself
depends on — Warden deliberately does **not** touch it. It just flags it,
loudly, and keeps flagging it every single check until a human looks at it.
The reasoning: silently "fixing" a credential file could just as easily undo
something your own teammate meant to change, or paper over exactly the thing
a judge needs to see. Some decisions need a person.

## Turning auto-restore on: arm and disarm

There's a wrinkle in "reverts it immediately": right after Warden is
installed, your team is usually still actively *hardening* the box —
tightening `sshd_config`, locking down `nginx.conf`, and so on. Those are
exactly the same files watch would otherwise consider "drift" and revert.
Without something to stop it, watch would undo your own hardening work
every few minutes, back to whatever the box looked like the moment Warden
was installed.

So auto-restore starts **off**. Right after install, watch still runs on
its normal schedule and still flags the sensitive stuff (passwd, sudoers,
etc.), it just doesn't overwrite anything — it reports what it *would* have
reverted and leaves it alone. Once your team is done hardening, run:

```
warden arm
```

This takes one more snapshot of exactly what's on disk right now — locking
in your hardened state as the new "known good" — and turns auto-restore on.
From that point forward, watch behaves the way "What Warden actually does"
above describes. If you need to do more maintenance later (patching a
service, say) without watch fighting you, `warden disarm` turns auto-restore
back off first; run `arm` again when you're done.

Detecting *what* to watch and harden in the first place is its own step —
run `warden detect` to scan the box for common CCDC services (web, database,
mail, DNS, file transfer, DHCP) already running or configured, and see which
of their config files are and aren't already in Warden's watch list.

## Reacting to a guarded file being touched (opt-in)

The most sensitive files Warden watches — `passwd`, `shadow`, `sudoers`,
`sshd_config` and the like — never get auto-reverted, only flagged (see
"What actually changed" above). Optionally, Warden can go a step further:
when one of those files changes, it tries to figure out *whose* SSH session
was open at that exact moment, and if it's confident that's an outside
party rather than your own team, it blocks that IP at the firewall for an
hour — the same thing a tool like fail2ban does.

That confidence check matters more than the blocking itself. Warden reads
this straight out of `sshd`'s own connection log, and only acts when the
evidence is genuinely clear:

- If nothing in the log overlaps the moment the file changed (say, it was
  edited from the physical console instead), nothing gets banned — just
  flagged, same as always.
- If the *only* session that overlaps is coming from your team's own known
  IP, nothing gets banned. This is the important part if you're worried
  about a teammate accidentally editing a guarded file without disarming
  first: since your team's real access is already restricted to one known
  IP by the forced-command SSH setup, a session from that IP is never
  treated as a suspect, full stop.
- If more than one outside IP overlaps, it's too ambiguous to single one
  out, so nothing gets banned either — a coin flip isn't a decision Warden
  makes unsupervised.
- Only when there's exactly one session, from exactly one IP that isn't
  your team's own, does a ban actually happen.

Every one of those outcomes — banned or not — gets written to the audit
log and to `warden alerts`, described next. This is opt-in at build time
(`AUTOBAN_ENABLED`) and off by default, the same way replication targets
are.

If your team does need to make a deliberate change to one of these
sensitive files — a real hardening edit, not an attack — `warden accept
<path> <code>` (with a live TOTP code) marks that one file's current state
as the new known-good, without needing to touch anything else Warden is
watching.

### Getting the alert without tipping off red team

The obvious way to tell everyone on the team "hey, something just
happened" is a system-wide broadcast message. Warden deliberately doesn't
do that: if red team has a shell on the box through some completely
different route, a broadcast message would reach them too, and now they
know they've been noticed. Instead, `warden alerts` is something a
teammate chooses to run, in their own SSH session, and only that session
sees what it prints. Open a second connection just for this
(`ssh <opmenu-user>@<box> "shell <code>"`, then run `warden alerts` inside
it) and leave it running if you want a live feed while you work.

## How it survives being killed

This is the part that makes Warden more than "a backup script." There's no
single process to kill — nothing you could find with `ps` and `kill -9` and
be done with. There are three things involved — a scheduled timer, a
separate `cron` entry, and the SSH key entry itself — but only two of them,
the timer and the cron entry, can actually *trigger* anything. Every few
minutes, whichever of those two fires checks that all three still exist and
rebuilds whichever one is missing, including, if it comes to that, the other
trigger.

Think of it less like three equal peers and more like two guards who each,
independently, patrol and repair all three things — the SSH key line itself
never patrols anything, it's just one of the things getting checked. So
killing any one or two of the three doesn't matter: whichever guard is still
standing puts the rest back on its next round. Red team would have to take
out *both* guards (the timer and the cron entry) in the exact same instant
to stop the patrols entirely — and even then, your existing SSH access
wouldn't vanish on its own, it would just stop being defended going forward.
Meanwhile, your watched config files are still getting auto-reverted (once
armed — see "Turning auto-restore on" above) by the piece described earlier,
so *those* changes don't stick either.

See [ARCHITECTURE.md](ARCHITECTURE.md)'s "Persistence: how it survives a kill
attempt" diagram if you want to see this laid out visually.

## A day in the life, roughly

You don't run Warden by hand day-to-day — it's installed once at the start of
the competition and then runs itself on a schedule. What that looks like:

1. Every ~5 minutes: it checks your watched configs for changes. Sensitive
   ones get flagged either way; everything else gets silently fixed *only if
   armed* — otherwise it's flagged too, so nothing is lost, it's just not
   acted on yet.
2. Every ~5 minutes: it takes a fresh config-tier backup.
3. Every hour: it takes a backup of the bigger service data.
4. Every ~15 minutes: it pushes new backup data to your other team-controlled
   box(es).
5. Every ~10 minutes: it double-checks its own persistence (the timer, the
   cron entry, the SSH key) is all still in place.

The times a human actually *does* something with Warden: running `warden
detect` and hardening the box early on, running `warden arm` once that's
done, checking in on its status, telling it to actually restore something
after a flagged change, or — in the worst case — recovering a box's entire
backup history from a peer after that box got wiped and rebuilt from
scratch.

## What Warden deliberately does NOT do

This list matters as much as what it does do — a few of these are easy to
assume incorrectly:

- **It is not a general-purpose backdoor.** The special SSH access only
  accepts your team's specific key, only from your team's specific network
  address, and only runs a small fixed menu of commands — never an open
  shell without a one-time code proving it's actually your team typing.
- **It does not replace human judgment on sensitive changes.** Password
  files, `sudoers`, and similar are always flagged for a person, never
  silently auto-fixed — see "What actually changed" above.
- **It is not an intrusion detection system.** It only reacts to specific
  files changing content. It does not scan for malware, watch network
  traffic, or notice a new suspicious process on its own. (A more general
  "does anything look wrong" check is a known gap — see `docs/PLAN.md` Phase
  9 — not something Warden currently does.)
- **It does not add a new hole for red team to also use.** It piggybacks on
  a service that's already running (SSH) instead of opening a new listening
  port, and the forced-command restriction means even someone who steals the
  team's key still can't get an open shell without the second-factor code.
- **It does not fight back.** Warden can, if your team opts into it (see
  "Reacting to a guarded file being touched" below), block an IP from
  reaching *your own* box — the same thing fail2ban does. It never touches
  red team's own infrastructure, and never does anything more aggressive
  than that. "Survives an attack" here means resilience (and, optionally,
  a locked door), not retaliation.
- **It does not scrub evidence or hide what it did.** Every single action —
  a restore, a flagged file, a rejected login attempt — gets written to a
  log file your team can show a judge if asked. Trying to look invisible by
  wiping logs would itself look exactly like what an attacker does after
  breaking in, which is its own way to lose points.
- **It does not set itself up correctly for your specific competition.**
  Someone on the team still has to decide, ahead of time, which files matter
  enough to watch and back up, and generate the one-time secrets. None of
  that happens automatically — see [DEPLOYMENT.md](DEPLOYMENT.md).

One more thing worth knowing up front: getting Warden onto a box normally means building it on a machine your team controls (usually someone's own laptop) and only transferring the finished file — that machine never needs to touch the competition network at all. If your team genuinely doesn't have a machine like that available (some events only issue a locked-down laptop), there's a second path that builds and installs directly on the box itself in one step; see [DEPLOYMENT.md](DEPLOYMENT.md)'s "Alternative: build directly on the target box" if that's your situation.

## Where to go next

- Setting this up before a competition: [DEPLOYMENT.md](DEPLOYMENT.md)
- Every command and exactly what it does: [USAGE.md](USAGE.md)
- The full reasoning behind each design choice: [DESIGN.md](DESIGN.md)
- Diagrams of how the pieces connect: [ARCHITECTURE.md](ARCHITECTURE.md)
- What's built vs. still open: [PLAN.md](PLAN.md)
