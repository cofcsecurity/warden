# Natural changes and writer attribution

Investigated `95c404d`. This is a proposed design and a bug review, not an implemented attribution feature. Three local probes reproduced attribution errors. The other findings below come from the code and upstream documentation. No firewall rules, accounts, or Linux monitoring configuration were changed.

Warden needs two separate decisions: whether a change violates the state the IR team wants to preserve, and what evidence identifies the process or session responsible. A legitimate process can make an unwanted change; a familiar account or executable can also be compromised. Neither identity nor drift alone establishes intent.

## Bugs and gaps

1. **P1: Session overlap is used as evidence of authorship.** `attributeChange` selects a lone non-team root SSH session; watch and scan can automatically ban its IP. A service, package manager, console user, or another account using sudo may have made the change. `alerts` then says that someone used that account to touch the path, which claims more than the evidence establishes. Keep overlap as a candidate lead, label its confidence, and require a direct writer/session link before an automatic attribution-based ban. Code: `cmd/warden/react.go`, `cmd/warden/scan.go`, `cmd/warden/alerts.go`.

2. **P1: Journal attribution does not authenticate the log producer.** The reader selects `--identifier=sshd` and parses `short-iso` text. It never checks trusted producer metadata. The identifier and syslog PID are client-supplied fields, so a process able to submit journal messages can potentially fabricate accepted-login or team-key evidence. Use JSON output and verify producer metadata such as `_UID`, `_EXE`, and the service context against the target's sshd installation before interpreting its messages. Account for stdout/stderr attribution to a parent process. This is a code-level finding, not a live injection test. See the [systemd journal field definitions](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.journal-fields.xml). Code: `cmd/warden/journal.go:25`.

3. **P1: Automatic locking confuses an affected account with the writer.** Account changes set `Culprit` to the modified account; authorized-key changes use the account owning the key file. Scan can lock that account and kill its sessions without identifying the process that made the change. Package installation or a legitimate administrator changing a service account can therefore disable that service account. Separate `affected_account` from `actor`. Account containment may still be appropriate for a confirmed compromised account, but it needs its own policy and evidence rather than an ownership inference. Code: `internal/anomaly/accounts.go`, `internal/anomaly/authorizedkeys.go`, `cmd/warden/scan.go:157`.

4. **P2: Mode changes are attributed using the old content modification time.** Reproduction: save a file with mtime 14:00, record a root SSH session ending at 14:01, and change permissions later. The selected suspect is that historical session because `reactToGuardedChange` uses the unchanged mtime. Deletions instead use detection time, and scan findings without an event timestamp do the same. Track the interval between the last verified observation and detection; prefer captured writer events. A ctime can help locate metadata changes but cannot identify their author. Code: `cmd/warden/react.go:31`, `cmd/warden/scan.go:85`.

5. **P2: An existing stale auth file prevents consulting the journal.** Reproduction: the file contains an accepted root login; the journal source contains its later disconnect. Attribution selects the stale file's apparently open session, and the journal callback is never invoked. Merge validated sources with deduplication, explicit coverage, boot/session boundaries, and bounded rotation handling. An unreadable or incomplete source must not silently become complete evidence. Code: `cmd/warden/journal.go:15`.

6. **P2: Some connection-ending messages leave sessions open forever.** Reproduction: an accepted login followed by `Connection closed by ...` still becomes a suspect an hour later. The parser only closes sessions on two disconnect formats. OpenSSH also emits closed, reset, and timeout messages. Extend lifecycle parsing and represent missing closure as uncertain, not proof that a session stayed open. See [OpenSSH's connection termination code](https://github.com/openssh/openssh-portable/blob/master/packet.c). Code: `internal/attribution/attribution.go`.

The three probes tested mode-only changes, stale-file precedence, and connection closure. All failed their correctness assertions; temporary test files were removed afterward. No ban was executed. These findings remain open, separately from the earlier recovery review.

## What already handles normal changes

- A timestamp-only change does not trigger manifest drift. Hash, mode, and symlink changes do.
- Data-tier files are snapshotted without automatic restoration.
- `confirm-first` paths are not overwritten, but they can still trigger attribution and automatic response. That makes this class unsuitable as a general exemption for normal churn.
- Disarming permits config edits, but guarded-file response is not gated by armed state. It is not a complete maintenance mode.
- `SAFE_ACCOUNTS` protects named accounts from automatic locking. It does not identify a file's writer or distinguish legitimate from malicious modifications.

## Implemented account maintenance

`warden account-edit` now covers explicit team password and group-membership edits. It checks all four account files against their baseline before running the native utility, validates the requested fields afterward, and publishes a new config generation. Exact group approvals are shared with scan. It does not infer the writer of arbitrary changes, approve service/package churn, or rotate passwords on a schedule. See [ACCOUNT-MAINTENANCE.md](ACCOUNT-MAINTENANCE.md). The six findings above remain open.

## Proposed natural-change policy

Keep the team's approved recovery baseline separate from the latest observed state. Repeated observation must not automatically approve a change.

| File or activity | Proposed handling |
| --- | --- |
| Stable access and service configuration | Enforce the approved content and security metadata. A direct writer event adds context; its absence does not stop policy-based restoration. |
| Generated files, leases, logs, and changing service data | Explicit observation or snapshot policy. Do not restore each ordinary content update or punish an account merely for writing it. Continue checking configured security invariants. |
| Certificates and other structured generated configuration | Validate the intended properties, such as ownership, permissions, expected identity, and permitted location. Keep prior versions for recovery; do not treat any writer with the right process name as trusted. |
| Package updates or coordinated team edits | A path-scoped maintenance window with an expiry, before/after review, and explicit acceptance. Other paths remain enforced. |
| Scoring accounts and credentials | Configure the expected rotation policy and protected account list for the actual image. Keep credential churn separate from privilege, shell, key, and group changes. |

A proposed `observe` class should record changes without auto-restore or attribution-based bans/locks for that path. It must be distinct from `confirm-first`. Scope exceptions to exact paths and permitted operations; avoid unrestricted directory or root-user exemptions.

Maintenance expiry should leave unreviewed changes pending and report them. Do not silently accept them or immediately roll an in-progress package update back. The operator should see which paths are pending and decide whether to accept or restore them. Installation, arming, maintenance, and response should share this policy rather than having separate exceptions.

For generated content, keep watching metadata and meaningful invariants. DNS-generated output, certificate rotation, or a legitimate service write should not grant permission to change file ownership, executable bits, symlink targets, account privileges, or access policy. Package activity is context, not automatic authorization for every change in its time window.

## Sources for identifying the writer

### Linux Audit: first implementation target

Collect kernel filesystem records for selected paths and parent directories, including writes, metadata changes, deletion, and replacement by rename. Join event records by their event identifier and host/boot context. Capture login UID (`auid`), effective credentials, PID/PPID, executable, session, operation, result, and path/inode details. Login UID and effective UID serve different purposes; account for unset login UID on background services. Do not filter those services out of collection when investigating natural changes. Confirm architecture-specific syscall coverage and rule installation on the target. [Audit rules](https://man7.org/linux/man-pages/man7/audit.rules.7.html), [auditctl](https://man7.org/linux/man-pages/man8/auditctl.8.html).

Use an existing auditd installation where available. Warden's short-lived commands can read persisted records, so they do not need to keep a new monitor alive just to retain writer history. Store reader checkpoints, deduplicate events, and report lost records, backlog pressure, absent rules, and missing time ranges. Gaps reduce attribution confidence. Keep Warden's rules scoped and namespaced; do not replace the host's rule set. Avoid automatic panic-on-overflow or immutable configuration changes during installation. [auditctl status and controls](https://man7.org/linux/man-pages/man8/auditctl.8.html).

A captured writer event identifies credentials and a process, not the human controlling a stolen account. Correlate its audit session with validated SSH or login records before assigning a source IP. Preserve console, sudo, service, and unknown origins instead of forcing every event into an SSH explanation.

### Other sources

| Source | Useful evidence | Practical limits |
| --- | --- | --- |
| fanotify | Writer PID and, where supported, a pidfd. | Requires an active collector. A process may exit before its event is consumed; a pidfd is not guaranteed. Kernel/filesystem support and queue loss need checking. [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html). |
| inotify | Prompt notification of path and metadata changes. | Does not report the triggering user or process. Useful to trigger a check, not to identify the writer. [inotify](https://man7.org/linux/man-pages/man7/inotify.7.html). |
| eBPF/LSM | Custom collection at kernel security hooks. | A later option requiring compatible kernels, privileges, a collector, and explicit testing of event/path coverage. [Kernel LSM BPF documentation](https://docs.kernel.org/bpf/prog_lsm.html). |
| Journal, sudo, SSH, service and package records | Session and operational context. | The log producer is not necessarily the file writer. Validate producer metadata; link context to a captured writer event where possible. [systemd journal fields](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.journal-fields.xml). |
| `/proc` inspection after detecting drift | Context for a still-running process. | Cannot reconstruct the writer after exit and risks PID reuse. Do not infer authorship from whichever process currently owns a PID or has the file open. |

## Implementation order

1. Correct session lifecycle and source handling, downgrade overlap to candidate evidence, and stop presenting affected accounts as proven writers.
2. Add explicit observation policy and scoped maintenance state so normal churn can be permitted without globally disarming the host.
3. Add a Linux Audit reader and a readiness check. Initially report actor evidence without enabling new automatic punishments.
4. Join writer events to sessions, add coverage/confidence fields, and test real service updates, sudo edits, atomic saves, package operations, deleted files, log rotation, and event loss on Linux.
5. Gate automatic actor-based response on that validated evidence and the path's policy. Keep restoration useful when attribution is unavailable.

This work uses event records to improve response decisions, not to justify the team's competition actions. The aim is fewer self-inflicted outages and less time spent chasing the wrong session. Host-root compromise can still tamper with local collection and credentials; remote copies preserve what was received but cannot prove that missing events never happened.
