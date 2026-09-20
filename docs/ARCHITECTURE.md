# Architecture Diagrams

Visual companions to [DESIGN.md](DESIGN.md) (why it's built this way) and [USAGE.md](USAGE.md) (what each command does). GitHub renders these Mermaid blocks natively.

## Component overview

What runs on one box, and how the pieces connect. Nothing here is a long-lived process — every box on the left is a systemd timer or cron entry invoking the binary briefly, then exiting.

```mermaid
flowchart TB
    subgraph Triggers["Triggers (systemd timers + cron)"]
        T_watch["*-watch.timer\nevery 5min ± 90s"]
        T_snapcfg["*-snap-cfg.timer\nevery 5min ± 60s"]
        T_snapdata["*-snap-data.timer\nevery 1h ± 5min"]
        T_sentinel["*-sentinel.timer\nevery 10min ± 2min"]
        T_cron["cron entry\nevery 10min"]
        T_replicate["*-replicate.timer\nevery 15min ± 3min"]
    end

    subgraph Binary["warden binary (one file, disguised name)"]
        watch["watch"]
        snapshot["snapshot --tier config|data"]
        sentinelcheck["sentinel-check"]
        replicate["replicate"]
        restore["restore"]
        opmenu["opmenu\n(forced command only)"]
    end

    subgraph State["/var/lib/&lt;binary-name&gt;/ (named to blend in)"]
        manifests["manifest-config.json\nmanifest-data.json\nmanifests-config/\nmanifests-data/"]
        objects["objects/\n(content-addressed, gzip)"]
        auditlog["audit.log\n(JSON lines)"]
    end

    subgraph External["Outside this box"]
        watchedfiles["Watched files\n/etc/passwd, nginx.conf, ..."]
        akeys["/root/.ssh/authorized_keys"]
        units["/etc/systemd/system/*.timer/.service"]
        peers["Replication peers\n(other boxes in the mesh)"]
        operator["Operator's SSH client\n(team key + TOTP)"]
    end

    T_watch --> watch
    T_snapcfg --> snapshot
    T_snapdata --> snapshot
    T_sentinel --> sentinelcheck
    T_cron --> sentinelcheck
    T_replicate --> replicate

    watch <-- "read only" --> manifests
    watch <-- "read for repair" --> objects
    watch --> auditlog
    watch <-- "diff / auto-restore" --> watchedfiles

    snapshot --> manifests
    snapshot --> objects
    snapshot --> auditlog
    snapshot <-- "hash + read" --> watchedfiles

    sentinelcheck <-- "check / recreate" --> akeys
    sentinelcheck <-- "check / recreate" --> units
    sentinelcheck <-- "check / recreate" --> T_cron
    sentinelcheck --> auditlog

    replicate <-- "push (additive-only)" --> peers
    replicate --> manifests
    replicate --> objects

    restore <-- "pull known-good" --> objects
    restore --> watchedfiles
    restore --> auditlog

    operator -- "ssh, key forces command=" --> opmenu
    opmenu --> restore
    opmenu -.-> sentinelcheck
    opmenu --> auditlog
```

## Persistence: how it survives a kill attempt

The actual persistence mechanism isn't a running process — there's nothing to `kill -9`. It's three independent *registrations* (a systemd timer, a cron entry, and an `authorized_keys` line) that each independently trigger `sentinel-check`, which verifies all three exist and rebuilds whichever doesn't.

```mermaid
flowchart LR
    subgraph Registrations["Three independent registrations"]
        direction TB
        R1["authorized_keys\nforced-command line"]
        R2["systemd timer\n(*-sentinel.timer)"]
        R3["cron entry\n(*/10 * * * *)"]
    end

    R2 -- "fires" --> SC["sentinel-check"]
    R3 -- "fires" --> SC

    SC -- "reads directly\n(no systemctl/crontab)" --> R1
    SC -- "reads directly" --> R2
    SC -- "reads directly" --> R3

    SC -- "missing? append-only\nrecreate" --> R1
    SC -- "missing? write unit files\n+ systemctl enable --now" --> R2
    SC -- "missing? append-only\nrecreate" --> R3

    SC --> AL["audit.log"]

    style R1 fill:#2d3748,color:#fff
    style R2 fill:#2d3748,color:#fff
    style R3 fill:#2d3748,color:#fff
```

**Why killing one doesn't kill persistence**: `sentinel-check` is triggered by *two* of the three registrations (the timer and the cron entry), so removing either trigger still leaves the other one calling `sentinel-check`, which then notices and rebuilds whatever's missing — including, if it comes to it, the trigger that just fired it. The `authorized_keys` line has no trigger of its own; it's purely a target `sentinel-check` verifies and restores. All three would have to be destroyed in the same instant, before the next timer or cron tick, to actually cut off access for good — and even then, the box's watched files are still being auto-reverted by `watch` in the meantime, so read team's edits to *those* don't stick either.

**Why this doesn't add new attack surface**: nothing here opens a new listening port. The forced-command entry piggybacks on `sshd`, which is already running (and already the thing red team would need to get past to reach a real shell anyway). `opmenu` never execs a shell itself except after a valid TOTP code, and every other path — `status`, `restore` — stays inside the Go binary.

## opmenu: what happens on a forced-command connection

```mermaid
sequenceDiagram
    participant Op as Operator
    participant sshd
    participant opmenu
    participant TOTP as internal/totp
    participant Bash as /bin/bash

    Op->>sshd: ssh -i team_key box "restore 123456 /etc/nginx/nginx.conf apply"
    sshd->>sshd: check from= against source IP
    Note over sshd: wrong source IP → connection<br/>refused before opmenu ever runs
    sshd->>opmenu: exec warden opmenu<br/>($SSH_ORIGINAL_COMMAND = the quoted string)
    opmenu->>opmenu: parse: command=restore,<br/>totp=123456, args=[path, apply]
    opmenu->>TOTP: Validate(seed, "123456", now, skew=1)
    alt valid code
        TOTP-->>opmenu: ok
        opmenu->>opmenu: restore.Plan + restore.Apply
        opmenu->>Op: plan + result
    else invalid/missing code
        TOTP-->>opmenu: rejected
        opmenu->>Op: error, nothing executed
    end
    opmenu->>opmenu: audit.Log(accepted/rejected, source IP, command)

    Note over Op,Bash: "shell <code>" is the one path that<br/>leaves the Go binary — only reached<br/>after the same TOTP check passes
```

## Watch: detect, classify, act

```mermaid
flowchart TD
    Start["watch runs\n(systemd timer, every ~5min)"] --> Gen["Generate manifest\nfrom configTierPaths right now"]
    Gen --> Diff["Diff against last snapshot\n(read-only — watch never writes it)"]
    Diff --> Changed{{"Any changes?"}}
    Changed -- no --> Exit["exit, log 'pass'"]
    Changed -- yes --> Class{{"Record's Class?"}}
    Class -- "ConfirmFirst\n(passwd, shadow, sudoers,\nsshd_config, scoring creds)" --> Flag["Flag only.\nNever touched.\nRe-flagged every run\nuntil a human fixes it\n+ re-snapshots."]
    Class -- "SafeAutoRestore\n(most service configs)" --> Restore["Pull known-good bytes\nfrom objects/, overwrite,\nlog auto-restored"]
    Flag --> AuditLog["audit.log"]
    Restore --> AuditLog
```

## Backup lineage: two tiers, never sharing a baseline

```mermaid
flowchart LR
    subgraph ConfigTier["Config tier"]
        CS["snapshot --tier config\nevery 5 min"] --> CM["manifest-config.json\n(live pointer)"]
        CM --> CA["manifests-config/\nmanifest-1.json, -2.json, ..."]
    end
    subgraph DataTier["Data tier"]
        DS["snapshot --tier data\nevery 1 hour"] --> DM["manifest-data.json\n(live pointer)"]
        DM --> DA["manifests-data/\nmanifest-1.json, -2.json, ..."]
    end
    CS --> OBJ["objects/\n(shared, content-addressed —\ndedup is safe across tiers,\nsince identical content hashes\nidentically either way)"]
    DS --> OBJ

    W["watch"] -. "reads only" .-> CM
    RS["restore"] -. "reads only" .-> CM
    RS -. "reads only" .-> CA

    style ConfigTier fill:#1a365d,color:#fff
    style DataTier fill:#1a365d,color:#fff
```

Keeping these separate is why `install.sh` running `snapshot --tier config` immediately followed by `snapshot --tier data` doesn't erase either tier's baseline — an earlier version of this shared one `manifest.json`, and the second snapshot silently wiped out what the first one had just established (see `docs/PLAN.md` Phase 6).

## Mesh replication and recovery (multiple boxes)

A bidirectional ring across N defended boxes: every box pushes to both neighbors, so every box's data has 3 total copies (itself + 2 neighbors) and every replication relationship is mutual.

```mermaid
flowchart LR
    B1((box1)) <-->|push| B2((box2))
    B2 <-->|push| B3((box3))
    B3 <-->|push| B4((box4))
    B4 <-->|push| B5((box5))
    B5 <-->|push| B6((box6))
    B6 <-->|push| B1

    style B1 fill:#22543d,color:#fff
    style B2 fill:#22543d,color:#fff
    style B3 fill:#22543d,color:#fff
    style B4 fill:#22543d,color:#fff
    style B5 fill:#22543d,color:#fff
    style B6 fill:#22543d,color:#fff
```

Each arrow is additive-only in both directions: `box2` can only ever add files under its own `from-box1` subdirectory (a restricted, non-root receiving account enforces this), never delete or overwrite what's already there — so even a fully compromised `box1` can't destroy the copy of its own data sitting on `box2`.

```mermaid
sequenceDiagram
    participant Box1 as box1 (wiped & rebuilt)
    participant Box2 as box2 (peer, holds box1's backups)

    Note over Box1: install.sh re-run with the<br/>same TEAM_PUBKEY/TOTP/REPLICATE_TARGETS
    Box1->>Box1: warden watch<br/>(no local manifest → everything flagged, nothing restored)
    Box1->>Box2: warden retrieve ssh://.../from-box1 --tier config
    Box2-->>Box1: manifest generation N (dry run: reports what's available)
    Box1->>Box2: warden retrieve ... --tier config --apply
    Box2-->>Box1: manifest + every referenced object
    Box1->>Box1: objects stored locally,<br/>manifest adopted as live config-tier baseline
    Box1->>Box2: warden retrieve ... --tier data --apply
    Box2-->>Box1: data-tier manifest + objects
    Note over Box1: warden watch / warden restore<br/>work normally again
```
