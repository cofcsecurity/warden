# Architecture Diagrams

Companions to [DESIGN.md](DESIGN.md) and [USAGE.md](USAGE.md). GitHub renders these Mermaid blocks natively.

## Components on one box

Short-lived commands, started by timers, a path unit, cron and an sshd hook.

```mermaid
flowchart TB
    subgraph Triggers
        T_refresh["&lt;name&gt;-refresh.timer\nevery 1 min"]
        T_path["&lt;name&gt;-refresh.path\non access-file change"]
        T_cron["root crontab\nevery 2 min"]
        T_sshd["sshd ExecStartPre hook"]
        T_bg["&lt;bg&gt;-refresh.timer + /etc/cron.d/&lt;bg&gt;"]
        T_watch["&lt;name&gt;-verify.timer\nevery 2 min"]
        T_snap["-cache / -archive timers\n5 min / 1 h"]
        T_sync["&lt;name&gt;-sync.timer\nevery 15 min"]
    end

    subgraph Binary["/usr/local/sbin/&lt;name&gt;"]
        sentinel["sentinel-check"]
        watch["watch"]
        snapshot["snapshot"]
        replicate["replicate"]
        opmenu["opmenu\n(team key's forced command)"]
        receive["receive\n(paired source's forced command)"]
    end

    subgraph State["/var/lib/&lt;name&gt;/"]
        config["config.json\n(+ mirror in /usr/lib/&lt;name&gt;)"]
        manifests["manifests + objects/"]
        log["audit.log (plain local log)"]
        quarantine["quarantine/"]
    end

    T_refresh & T_path & T_cron & T_sshd & T_bg --> sentinel
    T_watch --> watch
    T_snap --> snapshot
    T_sync --> replicate

    sentinel -- "check + repair" --> access["accounts, keys, sudoers,\nsshd drop-ins, sshd, firewall"]
    sentinel -- "check + repair" --> Triggers
    watch -- "restore / quarantine / flag" --> files["watched files"]
    snapshot --> manifests
    watch -. reads .-> manifests
    replicate -- "upload only" --> peer["peer box\n/var/lib/&lt;peer&gt;-peers/&lt;source&gt;/"]
    laptop["team laptop\n(ssh + team key)"] -- "ssh &lt;name&gt;@box [command]" --> opmenu
    opmenu --> Binary
```

## Lockout and repair

Any trigger runs the whole pass; every pass also checks every trigger.

```mermaid
sequenceDiagram
    participant Red
    participant Box as files on the box
    participant Path as refresh.path
    participant S as sentinel-check
    participant Team as team laptop

    Red->>Box: rm authorized_keys
    Box-->>Path: PathChanged fires
    Path->>S: start
    S->>Box: rewrite key file (atomic, no symlink follow)
    Team->>Box: ssh -t <name>@box   (works again within seconds)

    Red->>Box: usermod -L -s nologin, DenyUsers, iptables DROP
    Note over S: next timer tick (≤1 min)
    S->>Box: unlock account, restore shell
    S->>Box: Match User drop-in + reload sshd
    S->>Box: team ACCEPT back to top of INPUT

    Red->>Box: delete main account, sudoers, refresh units, cron line
    Team->>Box: ssh -t <break-glass>@box   (still works)
    Note over S: break-glass timer or cron.d (≤2 min)
    S->>Box: rebuild main account, key, sudoers, units, cron line
```

## Watch: restore, quarantine, flag

```mermaid
flowchart TD
    Start["watch pass"] --> Gen["files matched by the profile now\n+ baselined files still covered"]
    Gen --> Diff["diff against the armed baseline"]
    Diff --> Kind{{"change"}}
    Kind -- "flag-only class\n(shadow, firewall, units, keys)" --> Flag["flag; react once"]
    Kind -- "modified / removed,\nauto-restore" --> Armed{{"armed?"}}
    Armed -- no --> Sup["report as suppressed"]
    Armed -- yes --> Link{{"path is a symlink now?"}}
    Link -- yes --> Flag
    Link -- no --> Restore["write baseline bytes,\nreload owning service"]
    Kind -- "new file" --> Q{{"armed and under an\nauto-restore glob?"}}
    Q -- yes --> Quar["copy to quarantine/, remove,\nreload owning service"]
    Q -- no --> Flag
```

## Pairing and backups

```mermaid
sequenceDiagram
    participant L as laptop (ssh only)
    participant A as box A
    participant B as box B

    L->>A: pair key
    A-->>L: "boxa ssh-ed25519 AAAA…"   (key made on A, private half stays)
    L->>B: pair accept boxa ssh-ed25519 AAAA…
    B->>B: add upload-only line:\ncommand="sudo <b> receive --source boxa"
    B-->>L: "ssh+receiver://<b>@B/boxa ssh-ed25519 <B host key>"
    L->>A: pair add ssh+receiver://… <host key>
    A->>B: push objects + manifests (put/has only)
    Note over B: no delete; quota refuses new puts rather than evicting old ones
```

Pair in a ring so every box has at least one peer:

```mermaid
flowchart LR
    A((A)) --> B((B)) --> C((C)) --> A
```
