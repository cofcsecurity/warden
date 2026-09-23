# Changing passwords and group membership

Use `account-edit` from the team's authenticated root shell on the defended box. It runs the installed Linux utility and approves only the requested account-file changes. It does not generate, export, save, or display plaintext passwords.

```sh
warden account-edit passwd alice
warden account-edit gpasswd -a alice sudo
warden account-edit gpasswd -d alice sudo
warden account-edit gpasswd incident-response
```

Replace `warden` with the installed binary path if it was renamed. The last command changes a group's password. Only these forms are supported; arbitrary utility flags, alternate roots, directory accounts, and passwords supplied as arguments are rejected.

Warden prompts for its TOTP code or static second factor without echoing it. For password changes, `passwd` or `gpasswd` then prompts normally on the existing terminal. Use an interactive SSH shell with a terminal allocated. No client-side files or software are needed.

## What gets approved

Before running the utility, Warden requires an existing config snapshot covering `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow`. All four files must match the effective baseline, including any Warden account locks. Review existing drift first; this command does not approve it for you.

- `passwd USER` may update that user's shadow password hash and last-change date. It cannot approve changes to the user's UID, shell, home, expiry policy, or another account.
- `gpasswd -a/-d USER GROUP` may make exactly that membership change in both group databases. It cannot approve a changed GID or group administrator.
- `gpasswd GROUP` may change only that group's gshadow password hash.

The wrapper checks permissions, ownership, symlinks, and all other account-file content before accepting the result. Successful edits create a new config generation and preserve earlier archives. The account scan recognizes the exact approved group record, even if it has not run since the edit. Subsequent changes to that record still get checked.

A Warden-locked user must be unlocked through `unlock-account` before a password change. The opmenu account's password cannot be changed through this wrapper. Other accounts' temporary Warden locks remain temporary overlays; the wrapper does not fold them into the saved baseline.

## During the command

Warden holds its shared operation lock while the utility runs and the new baseline is published. Other mutating commands report busy; watch, scan, and sentinel timers retry on their next scheduled pass. This briefly delays checks across the host. Password entry has a five-minute command limit, and the authorization prompt has a separate two-minute limit. Finish the operation promptly.

External programs can still change files during this interval. The wrapper checks the final account files and refuses unrelated changes. Unrelated watched files keep their existing baselines and are checked when watch resumes. No persistent maintenance exemption is created.

If the utility fails, the connection closes, validation fails, or publication fails, do not assume nothing changed. Inspect the account state and Warden's reported error before retrying. A changed password may already be effective even though Warden has not accepted it. The wrapper does not automatically roll credentials back or approve a partial result. A hard kill or host crash can also leave a completed system change awaiting review.

This workflow prevents Warden from treating a validated team edit as drift. It does not protect password entry from an attacker who already controls root or the terminal. Password handling remains with the host's installed utility and PAM configuration; this is not a credential vault.

For the native commands' behavior, see [passwd](https://man7.org/linux/man-pages/man1/passwd.1.html) and [gpasswd](https://man7.org/linux/man-pages/man1/gpasswd.1.html).
