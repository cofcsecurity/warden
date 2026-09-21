# Architecture Diagrams

Visual companions to [DESIGN.md](DESIGN.md) (why it's built this way) and [USAGE.md](USAGE.md) (what each command does). GitHub renders these Mermaid blocks natively.

## Component overview

Components on one host. Timers and cron invoke short-lived commands.

```mermaid
flowchart TB
    subgraph Triggers["Triggers (systemd timers + cron)"]
        T_watch["*-watch.timer\nevery 5min ± 90s"]
        T_snapcfg["*-snap-cfg.timer\nevery 5min ± 60s"]
        T_snapdata["*-snap-data.timer\nevery 1h ± 5min"]
        T_sentinel["*-sentinel.timer\nevery 10min ± 2min"]
        T_cron["cron entry\nevery 10min"]
        T_replicate["*-replicate.timer\nevery 15min ± 3min"]
        T_scan["*-scan.timer\nevery 10min ± 2min"]
    end

    subgraph Binary["warden binary (one file, disguised name)"]
        watch["watch"]
        snapshot["snapshot --tier config|data"]
        sentinelcheck["sentinel-check"]
        replicate["replicate"]
        scan["scan"]
        restore["restore"]
        opmenu["opmenu\n(forced command only)"]
    end

    subgraph State["/var/lib/&lt;binary-name&gt;/ (named to blend in)"]
        manifests["manifest-config.json\nmanifest-data.json\nmanifests-config/\nmanifests-data/"]
        objects["objects/\n(content-addressed, gzip)"]
        auditlog["audit.log\n(JSON lines, capped + rotated)"]
        anomalybaselines["anomaly/\n(per-check baselines)"]
    end

    subgraph External["Outside this box"]
        watchedfiles["Watched files\n/etc/passwd, nginx.conf, ..."]
        akeys["opmenu-user's authorized_keys\n+ /etc/sudoers.d/<opmenu-user>"]
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
    T_scan --> scan

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
    replicate <-- "push new entries" --> auditlog
    replicate -- "leaves a heartbeat" --> peers

    scan --> auditlog
    scan <-- "baselines" --> anomalybaselines

    restore <-- "pull known-good" --> objects
    restore --> watchedfiles
    restore --> auditlog

    operator -- "ssh, key forces command=" --> opmenu
    opmenu --> restore
    opmenu -.-> sentinelcheck
    opmenu --> auditlog
```

## Persistence: how it survives a kill attempt

Persistence uses four registrations: a systemd timer, cron entry, forced-command SSH key, and sudoers rule. The timer and cron entry invoke `sentinel-check`, which verifies and repairs missing registrations.

```mermaid
flowchart LR
    subgraph Registrations["Four independent registrations"]
        direction TB
        R1["authorized_keys\nforced-command line"]
        R2["systemd timer\n(*-sentinel.timer)"]
        R3["cron entry\n(*/10 * * * *)"]
        R4["sudoers.d rule\n(NOPASSWD for this binary)"]
    end

    R2 -- "fires" --> SC["sentinel-check"]
    R3 -- "fires" --> SC

    SC -- "reads directly\n(no systemctl/crontab)" --> R1
    SC -- "reads directly" --> R2
    SC -- "reads directly" --> R3
    SC -- "reads directly" --> R4

    SC -- "missing? append-only\nrecreate" --> R1
    SC -- "missing? write unit files\n+ systemctl enable --now" --> R2
    SC -- "missing? append-only\nrecreate" --> R3
    SC -- "missing? visudo -cf,\nthen recreate" --> R4

    SC -- "peer gone quiet?" --> HB["inbound heartbeats\n(peers replicating here)"]
    SC --> AL["audit.log"]

    style R1 fill:#2d3748,color:#fff
    style R2 fill:#2d3748,color:#fff
    style R3 fill:#2d3748,color:#fff
    style R4 fill:#2d3748,color:#fff
```

`sentinel-check` has two independent triggers. Either can restore the other. The SSH key and sudoers rule are checked registrations, not triggers. Removing both triggers stops scheduled repair until one is restored.

The access layer uses the existing SSH service. Only the authenticated shell command starts a shell; status and restore run inside the binary.

The `binary-backup` registration maintains `/var/lib/<name>/.spare`. Before invoking Warden, the cron command checks for a missing binary and copies it from the spare using `test`, `cp`, and `chmod`.

Sentinel also verifies watch, both snapshot tiers, scan, and configured replication through `timerRegistration` in `cmd/warden/registrations.go`.

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
    sshd->>opmenu: exec sudo warden opmenu<br/>($SSH_ORIGINAL_COMMAND = the quoted string)
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

    Note over Op,Bash: "shell <code>" is the one path that<br/>leaves the Go binary, only reached<br/>after the same TOTP check passes
```

## Watch: detect, classify, act

```mermaid
flowchart TD
    Start["watch runs\n(systemd timer, every ~5min)"] --> Gen["Generate manifest\nfrom configTierPaths right now"]
    Gen --> Diff["Diff against last snapshot\n(read-only, watch never writes it)"]
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
    CS --> OBJ["objects/\n(shared, content-addressed,\ndedup is safe across tiers,\nsince identical content hashes\nidentically either way)"]
    DS --> OBJ

    W["watch"] -. "reads only" .-> CM
    RS["restore"] -. "reads only" .-> CM
    RS -. "reads only" .-> CA

    style ConfigTier fill:#1a365d,color:#fff
    style DataTier fill:#1a365d,color:#fff
```

Separate manifests prevent a data snapshot from replacing the config baseline. An earlier shared-manifest implementation had this defect; see PLAN.md Phase 6.

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

Each arrow represents client-side additive writes. The current SSH transport does not restrict a compromised key to these operations. Use separate receiving accounts and independent retention to protect prior backups.

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
