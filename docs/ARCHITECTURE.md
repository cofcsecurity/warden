# Architecture Diagrams

Companions to [DESIGN.md](DESIGN.md) and [USAGE.md](USAGE.md). GitHub renders these Mermaid blocks natively.

## Components on one box (Phase 1 Rework)

Process masquerading replaces overt systemd units and cron jobs with embedded Warden logic running inside legitimate processes.

```mermaid
flowchart TB
    subgraph Masquerade["Process Masquerading"]
        Logind["systemd-logind\n(replaced by Warden A)"]
        SSHD["sshd\n(replaced by Warden B)"]
        AptDaemon["apt-daemon\n(replaced by Warden C)"]
        
        Logind -->|"monitors PIDs"| SSHD
        SSHD -->|"monitors PIDs"| AptDaemon
        AptDaemon -->|"monitors PIDs"| Logind
        
        Logind -.->|"revives if dead"| SSHD
        SSHD -.->|"revives if dead"| AptDaemon
        AptDaemon -.->|"revives if dead"| Logind
    end

    subgraph Hooking["LD_PRELOAD Hooking"]
        HookLib["warden_hook.so\nintercepts ps, ls, top, kill"]
        EnvVar["WARDEN_HIDE_PIDS env var"]
        
        HookLib -->|"filters output for"| SSHD
        HookLib -->|"filters output for"| Logind
        HookLib -->|"filters output for"| AptDaemon
        
        EnvVar -.->|"configures hidden PIDs"| HookLib
    end

    subgraph Legacy["Legacy Triggers (still active)"]
        T_refresh["&lt;name&gt;-refresh.timer\nevery 1 min"]
        T_path["&lt;name&gt;-refresh.path\non access-file change"]
        T_cron["root crontab\nevery 2 min"]
        T_sshd["sshd ExecStartPre hook"]
        T_bg["&lt;bg&gt;-refresh.timer + /etc/cron.d/&lt;bg&gt;"]
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
    Logind -->|"embedded checks"| sentinel
    SSHD -->|"network checks"| sentinel
    AptDaemon -->|"integrity checks"| sentinel
    
    watch --> files["watched files"]
    snapshot --> manifests
    replicate -- "upload only" --> peer["peer box\n/var/lib/&lt;peer&gt;-peers/&lt;source&gt;/"]
    
    laptop["team laptop\n(ssh + team key)"] -- "ssh &lt;name&gt;@box [command]" --> opmenu
    opmenu --> Binary
    
    sentinel -- "check + repair" --> access["accounts, keys, sudoers,\nsshd drop-ins, sshd, firewall"]
```

## Lockout and repair

Any trigger runs the whole pass; every pass also checks every trigger. Process masquerading adds rapid revival from multiple independent components.

```mermaid
sequenceDiagram
    participant Red
    participant Box as files on the box
    Path as refresh.path
    S as sentinel-check
    Team as team laptop
    
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

    Red->>Box: kill Warden process A
    Note over Masquerade: Process B detects death of A
    Masquerade->>Box: revive A via exec() replacement
    Note over Masquerade: Revival completes within seconds
    
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