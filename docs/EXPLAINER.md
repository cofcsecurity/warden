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

## How it survives being killed

This is the part that makes Warden more than "a backup script." There's no
single process to kill — nothing you could find with `ps` and `kill -9` and
be done with. Instead there are three independent things keeping each other
alive: a scheduled timer, a separate `cron` entry, and the SSH key entry
itself. Every few minutes, whichever of the timer or the cron entry fires
checks that all three still exist, and rebuilds whichever one is missing —
including, if it comes to that, whichever one just fired the check in the
first place.

Think of it like three people who each check on each other on a rotating
schedule and restore whoever's missing. Red team would have to destroy all
three in the exact same instant, before the next check runs, to actually cut
you off — and even then, your watched config files are still getting
auto-reverted in the meantime by the piece described above, so *those*
changes don't stick either.

See [ARCHITECTURE.md](ARCHITECTURE.md)'s "Persistence: how it survives a kill
attempt" diagram if you want to see this laid out visually.

## A day in the life, roughly

You don't run Warden by hand day-to-day — it's installed once at the start of
the competition and then runs itself on a schedule. What that looks like:

1. Every ~5 minutes: it checks your watched configs for changes, and either
   fixes them quietly or flags them loudly.
2. Every ~5 minutes: it takes a fresh config-tier backup.
3. Every hour: it takes a backup of the bigger service data.
4. Every ~15 minutes: it pushes new backup data to your other team-controlled
   box(es).
5. Every ~10 minutes: it double-checks its own persistence (the timer, the
   cron entry, the SSH key) is all still in place.

The only time a human actually *does* anything with Warden is: checking in on
its status, telling it to actually restore something after a flagged change,
or — in the worst case — recovering a box's entire backup history from a
peer after that box got wiped and rebuilt from scratch.

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
- **It does not scrub evidence or hide what it did.** Every single action —
  a restore, a flagged file, a rejected login attempt — gets written to a
  log file your team can show a judge if asked. Trying to look invisible by
  wiping logs would itself look exactly like what an attacker does after
  breaking in, which is its own way to lose points.
- **It does not set itself up correctly for your specific competition.**
  Someone on the team still has to decide, ahead of time, which files matter
  enough to watch and back up, generate the one-time secrets, and confirm
  with organizers that this kind of tool is even allowed under that
  competition's rules. None of that happens automatically — see
  [DEPLOYMENT.md](DEPLOYMENT.md).

## Where to go next

- Setting this up before a competition: [DEPLOYMENT.md](DEPLOYMENT.md)
- Every command and exactly what it does: [USAGE.md](USAGE.md)
- The full reasoning behind each design choice: [DESIGN.md](DESIGN.md)
- Diagrams of how the pieces connect: [ARCHITECTURE.md](ARCHITECTURE.md)
- What's built vs. still open: [PLAN.md](PLAN.md)
