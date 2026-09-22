# Incident-response workflow review

Reviewed `9e41268`. Five new findings are open. Four were reproduced locally; the installer verification issue was identified from its generated command and key restriction. No production code was changed in this review. The [six earlier recovery findings](REVIEW-2026-09-22.md) remain open separately.

## Findings

### P1: On-host builds leave a readable credential-bearing executable

The build driver writes `deploy/warden` in the source checkout without a private build directory or restrictive umask. With umask `022`, the resulting executable is mode `0755`. Any local account able to traverse the checkout can read its compiled TOTP seed, replication key, and configured signing key. Installing a separate copy as mode `0700` does not protect this intermediate artifact. Failed installation or delayed verification extends its lifetime.

Reproduction: run the existing `build()` function with a fake TOTP seed and only relocate its output to a temporary directory. The output was mode `0755`, and a normal file read found the fake seed in its bytes. No real credentials were used. A root-only bootstrap directory limits this exposure; a checkout under an accessible home directory does not.

Patch: build in a fresh root-owned directory with mode `0700`, set umask `077` before creating sensitive files, keep the output mode `0700`, and protect or remove failed-build artifacts. Check ownership of the working directory as well as file modes. This addresses local unprivileged readers; it does not remove the existing host-root exposure.

Code: [build-and-install.sh](../scripts/build-and-install.sh), `build()`, lines 456-480.

### P1: A single invalid watched file stops unrelated repairs

`Watcher.Check` generates the current manifest for all watched paths before acting on any of them. One unsupported file type or read error aborts the whole pass. An attacker able to replace one watched file with a FIFO can suppress repairs elsewhere without changing Warden's executable or state.

Reproduction: snapshot two ordinary files, replace the first with a FIFO, and modify the second. An armed check returns `unsupported file type`, returns no result, and leaves the second file's tampered bytes in place.

Patch: collect read failures per path, flag the inaccessible path, and continue checking and repairing other paths. Never interpret an unreadable file as a confirmed deletion. Return an aggregate failure after completing independent work.

Code: [watch.go](../internal/watch/watch.go), lines 107-110; [manifest.go](../internal/manifest/manifest.go), `Generate`.

### P1: Arming can approve bytes that changed after the review

`runArm` generates and displays a review, waits for confirmation, then calls `runSnapshot`, which reads the files again. The snapshot is not bound to the reviewed hashes and modes. A change made while the prompt is open becomes the enforced baseline without a new review. The operation lock excludes other Warden mutations, but it does not exclude editors, services, or attacker processes.

Reproduction: establish a baseline, make an intended hardening change, launch `arm`, and wait for its confirmation prompt. Replace the file with different bytes, then answer yes. Arming succeeds and the saved manifest hashes the replacement bytes.

Patch: retain the candidate manifest and verified objects used for review. Before publishing it, check that the selected files still match that candidate and require another review if they changed. Publish the reviewed candidate rather than generating a replacement after confirmation. Subsequent drift must remain drift against that approved state.

Code: [arm.go](../cmd/warden/arm.go), lines 105-125; [snapshot.go](../cmd/warden/snapshot.go), `runSnapshot`.

### P1: A malformed profile disables the repair shell

The root command loads `/etc/warden/profile.json` before every command except `receive`. Invalid JSON or an invalid profile therefore blocks `opmenu` before authentication or shell dispatch. It also blocks `disarm` and ordinary status commands. A configuration mistake during response can remove the access path needed to correct it.

Reproduction: with a valid profile and a valid static second factor, an `opmenu` shell executes a harmless marker command. Corrupt the profile and repeat the identical request: it exits with `host profile: invalid character` before reaching the shell. The probe relocated the profile and state directories to temporary paths using a Go build overlay; authentication and dispatch code were unchanged.

Patch: keep authenticated emergency shell access independent of the protection profile. Load and validate the profile only for operations that need its paths, mappings, or validators. Restore and watch should continue refusing invalid profiles; they should not silently fall back to broader defaults.

Code: [main.go](../cmd/warden/main.go), lines 76-83; [opmenu.go](../cmd/warden/opmenu.go), `runOpmenu`.

### P2: Installer verification uses a source address the managed key excludes

The installer asks the operator to run `ssh ... account@127.0.0.1 status`. The installed key restricts authentication to `TEAM_FROM_IP`. For a normal team address or subnet that excludes loopback, the suggested check cannot authenticate. It also assumes the team's private login key is present on the defended host. The deployment guide already describes testing from the allowed team address, but the installer and design sequence still point at loopback.

Patch: print a check to run from the team's existing SSH client against the host's reachable address. Separate local configuration checks from a real end-to-end login test. Do not add loopback to the allowed source range just to make the prompt work.

Code: [install.sh](../deploy/install.sh), lines 595-598; [units.go](../cmd/warden/units.go), `authorizedKeysLine`.

## Improvements worth implementing

| Priority | Improvement | Response benefit |
| --- | --- | --- |
| 1 | Private on-host build workspace | Keeps compiled credentials away from unprivileged accounts throughout installation, including failure paths. |
| 1 | Independent per-path watch checks | One damaged path cannot disable the rest of the box's repairs. |
| 1 | Review-bound arming with content and mode diffs | Operators can see and approve the actual state Warden will preserve. |
| 1 | Authenticated emergency access independent of profile parsing | A broken protection configuration does not remove the team's repair shell. |
| 2 | Deployment readiness command | Check effective access configuration, source restrictions, executable permissions, and peer connectivity before asking for a real login test. |
| 2 | Service-aware data snapshots | Add explicit quiesce or export hooks for databases and other changing service data; a file copy alone does not establish application consistency. |
| 2 | Unified recovery status | Show unresolved restore transactions, pending service starts, and verified backup coverage together, building on the earlier recovery review. |

## Validation

The watch reproduction used a temporary test with ordinary files and a FIFO. Its correctness assertion failed because the unrelated file remained modified. The arming and shell probes used the CLI with only profile and state paths redirected into a temporary directory. The build probe used a fake seed and relocated output. No real services, accounts, SSH policy, or production data were changed. Temporary failing tests were removed after recording the results; these cases are not fixed by the existing passing suite. The loopback finding was not tested against a deployed sshd.
