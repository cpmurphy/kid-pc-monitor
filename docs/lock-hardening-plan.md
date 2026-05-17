# Plan: Stricter lock enforcement (follow-up to cross-user install)

## Context

Today's "lock" is soft. Three weaknesses, by severity:

1. **`lock_pc()` just calls `LockWorkStation()`** (`src/pc_control.py:222`). The child re-enters their password and is back in. No account-hours restriction, no account disable, no shutdown.
2. **The main monitor loop `break`s after one lock** (`src/pc_control.py:331`). After the agent triggers one auto-lock, the time-limit thread exits; nothing re-issues the lock if the child unlocks. The separate `monitor_activity` thread (line 161) only observes lock state, it doesn't re-lock.
3. **Scheduled (bedtime) locks fire only during the exact minute** (`src/pc_control.py:305-309`: `current_time.hour == lock_time.hour and current_time.minute == lock_time.minute and current_time.second < 1`). If the agent isn't running at 21:00:00 sharp (because the child is at the logon screen) the 21:00 lock is missed; signing in at 21:01 bypasses it.

This plan combines three hardenings, chosen with the user:

- **Agent-level in-session re-lock** — no elevation, works in same-user and cross-user modes. Closes weakness #2.
- **OS-enforced bedtime via `net user /times`** — Windows-enforced logon hours, applied install-time. Closes weakness #3. Cross-user mode only (needs admin to apply).
- **Account disable when the daily usage limit hits**, with a separate SYSTEM-level helper task that re-enables at midnight. Strongest enforcement for the usage-limit path. Cross-user mode only.

Bedtime schedule updates are install-time only — to change bedtime, re-run the installer as admin. No new dynamic-config surface.

## Approach

### Part 1 — Agent-level re-lock loop (`src/pc_control.py`)

The current `run_monitor` calls `lock_pc()` once and breaks. Replace with a continuous-enforcement model:

- Define a helper `currently_in_lock_window()` that returns `(locked, reason)` based on:
  - **Bedtime windows**: for each entry in `self.lock_times`, treat `lock_time` as the start of a "locked-until-end-of-day" window (i.e., locked from `lock_time` until 24:00 of the same calendar day). This makes the check robust to the agent missing the exact minute.
  - **Usage limit**: locked if `usage_minutes >= self.usage_limit`.
- Rewrite `run_monitor` so it never breaks:

  ```python
  def run_monitor(self):
      while True:
          self.check_and_send_warnings()
          locked, reason = self.currently_in_lock_window()
          if locked and not self.check_if_locked():
              self.logger.info(f"Locking PC: {reason}")
              self.lock_pc()
          time.sleep(1)
  ```

  `check_if_locked()` already exists (line 142) and returns whether `LogonUI.exe` is present, so the loop re-locks immediately after every detected unlock while a window is active.
- Reset the warnings set (`self.warnings_sent`) when a window ends (e.g., at midnight) so the 15/5/1-minute warnings fire correctly the next day. Currently warnings_sent is only added to, never cleared.
- Remove the `should_lock` exact-minute branch in `check_time_limits` (lines 305-309); replace by delegating to `currently_in_lock_window`.

Behavioral note: this changes the "scheduled bedtime" semantics from "lock at exactly HH:MM" to "stay locked from HH:MM until midnight". That matches user intent for a bedtime curfew. Document in the README.

### Part 2 — OS-enforced bedtime (`scripts/install.py`)

In cross-user mode only, after the task is created:

- Prompt for an **allowed-hours window** (single window applied to every day, keep UX simple): default `07:00-21:00`. Validate `HH:MM-HH:MM`.
- Apply via:
  ```
  net user <kid> /times:M-Su,07:00-21:00
  ```
- Apply force-logoff so an in-session child is kicked off when hours expire:
  ```
  net accounts /forcelogoff:0
  ```
  This is a machine-wide setting; document the side effect.
- Store the chosen window in `C:\ProgramData\KidPCMonitor\install_config.json` so the removal flow can roll it back.

Skipped (out of scope): per-weekday-vs-weekend windows. A power user can re-run `net user /times:...` manually.

**Same-user mode**: skip Part 2 entirely. A non-elevated installer can't usefully apply `net user /times` against an admin-ish account anyway, and same-user mode is the "the kid is the only user, possibly with admin rights" path where OS-enforced hours don't make sense.

### Part 3 — Account disable on daily limit (`scripts/install.py` + new `enforcer.py`)

The agent is unprivileged (cross-user mode), so it can't run `net user /active:no` directly. Add a SYSTEM-level helper:

- **New file**: `src/enforcer.py`, copied to `C:\ProgramData\KidPCMonitor\enforcer.py` by the installer.
- **New scheduled task**: `KidPCMonitorEnforcer`, created by the installer in cross-user mode.
  - Principal: `SYSTEM` (`-User "NT AUTHORITY\SYSTEM"`, `-LogonType ServiceAccount`, `-RunLevel Highest`)
  - Triggers: `AtStartup` plus a `RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)`. (Set on a one-shot daily trigger; the cmdlet quirk where `-Once` is required for repetition applies.)
  - Action: `pythonw.exe C:\ProgramData\KidPCMonitor\enforcer.py <kid-username>`
- **`enforcer.py` behavior** (each invocation, runs as SYSTEM, takes the kid username as argv[1]):
  1. Read `C:\ProgramData\KidPCMonitor\state\enforce.json` (created/written by the agent).
  2. If `{ "disable_account": true }` is present: run `net user <kid> /active:no`, then run `logoff` on the kid's session via `query session` + `logoff <sessionid>` so the disable takes effect immediately (otherwise the existing session continues). Clear the flag.
  3. Read `last_reset_date` from `C:\ProgramData\KidPCMonitor\state\reset.json`. If it's not today's local date, run `net user <kid> /active:yes` and update `last_reset_date`. This handles the midnight reset without needing a separate trigger.
- **Agent changes (`src/pc_control.py`)**: when the usage-limit branch of `currently_in_lock_window` fires, also write `enforce.json` with `disable_account: true`. The agent owns nothing else about elevation — it just sets the flag and locks the screen; within ~1 minute the SYSTEM enforcer picks up the flag and disables/logoffs the account.
- **ACLs** (installer applies):
  - `C:\ProgramData\KidPCMonitor\enforcer.py` — `<kid>:R` (no execute by kid; only SYSTEM runs it).
  - `C:\ProgramData\KidPCMonitor\state\` — `<kid>:(OI)(CI)M` (modify, so the agent can write `enforce.json` and read `reset.json`).
  - The rest of the install dir stays `<kid>:(OI)(CI)RX` from the cross-user install plan.

### Part 4 — Removal flow

`remove_task()` in `scripts/install.py` currently only deletes `KidPCMonitor`. Extend it to:

- Also delete `KidPCMonitorEnforcer` (best-effort, ignore not-found).
- Read `install_config.json`; if a `net user /times` window was applied, reset with `net user <kid> /times:all`.
- Optionally restore `net accounts /forcelogoff:`. Track the previous value in `install_config.json` so removal can put it back; default to no-restore if unknown.
- Re-enable the account: `net user <kid> /active:yes` (in case removal happens while the kid is in a disabled state).

## Files touched

- `src/pc_control.py`
  - Add `currently_in_lock_window()`.
  - Rewrite `run_monitor` to re-lock continuously instead of breaking.
  - Reset `warnings_sent` at midnight rollover.
  - On usage-limit window, write `enforce.json` to `C:\ProgramData\KidPCMonitor\state\` (only when running in cross-user mode — detect via presence of the state dir).
- `src/enforcer.py` (new) — SYSTEM-level account enforcer, ~80 lines.
- `scripts/install.py`
  - Cross-user mode: prompt for allowed-hours window; apply `net user /times` and `net accounts /forcelogoff:0`; record in `install_config.json`.
  - Cross-user mode: copy `enforcer.py` to the install dir; create `state\` subdir with kid write access; register `KidPCMonitorEnforcer` SYSTEM task.
  - `remove_task()`: delete the enforcer task; roll back `net user /times`, `net user /active`, and force-logoff.
- `README.md` — document the three enforcement modes; flag the machine-wide side effect of `forcelogoff:0`; note that bedtime schedule changes require re-running the installer.
- `docs/cross-user-install.md` — append a "Hardened enforcement" section pointing at this plan.

## Edge cases and risks

- **`net accounts /forcelogoff:0` is machine-wide.** It will affect every user account on the box that has logon-hour restrictions, not just the kid. Mitigation: document this clearly; default to `0` (force immediately) but allow opt-out via installer prompt.
- **Logging the child off via `logoff <sessionid>` loses unsaved work.** The agent already sends 15/5/1-minute warnings, so the kid has notice for the usage-limit case. For the OS-enforced bedtime case the warnings still fire because the agent runs them; Windows' own forced logoff has no warning of its own.
- **`enforcer.py` running every minute as SYSTEM** is a new privileged surface. Keep it tiny, no network listen, only acts on local files in `C:\ProgramData\KidPCMonitor\state\` with strict ACLs (admins + SYSTEM full; kid modify only on `state\`; nothing else writable by kid). Code-review the parsing path carefully.
- **State dir creation across modes**: `src/pc_control.py` already writes log/state to `%LOCALAPPDATA%\KidPCMonitor` (kid's profile). The enforce.json/reset.json files live in `C:\ProgramData\KidPCMonitor\state\` so SYSTEM and the kid can share. Don't conflate the two.
- **Daylight saving / clock changes** can confuse the midnight reset in `enforcer.py`. Use local date comparison via `datetime.date.today()` rather than tracking elapsed seconds.
- **Account disable doesn't kill RDP/cached creds reliably.** This monitor only targets local interactive logons. Fine for the home-PC use case.

## Verification

On the same Windows test box used for cross-user install (`parent` admin, `kid` standard user):

1. **In-session re-lock (Part 1)**
   - Set usage limit to 2 minutes via the parent web panel.
   - Sign in as `kid`. Wait 2 minutes; confirm auto-lock.
   - Unlock with the kid's password. Confirm the agent re-locks within ~1-2 seconds. Repeat 3-5 times. The lock should persist for the rest of the session.
   - Set a bedtime lock for 2 minutes in the future. Wait past the lock minute, **then** unlock. Confirm re-lock (proves the new range check, not the old exact-minute check).
2. **OS bedtime (Part 2)**
   - Re-run installer; choose cross-user mode; enter allowed-hours `07:00-08:00` (i.e., bedtime starts at 08:00) for the test.
   - `net user kid` → confirm "Logon hours allowed" shows `M-Su 7:00 AM - 8:00 AM`.
   - Sign in as kid before 08:00. At 08:00, confirm Windows logs the kid off (`forcelogoff:0`). Try to sign back in at 08:01; expect "Your account has time restrictions that prevent you from signing in at this time."
3. **Account disable on usage limit (Part 3)**
   - Set usage limit to 1 minute. Sign in as kid. Wait for the limit.
   - Within 60-90 seconds of the limit hitting, confirm in `taskschd.msc` history that `KidPCMonitorEnforcer` fired.
   - `net user kid` → confirm "Account active = No".
   - Confirm the kid's session was logged off (Task Manager → Users on the parent side, or `query session` from elevated cmd).
   - Try to sign in as kid; expect "Your account has been disabled. Please see your system administrator."
   - Wait until just after local midnight (or temporarily set clock forward); confirm `KidPCMonitorEnforcer` re-enables the account on its next 1-minute tick.
4. **Removal (Part 4)**
   - Run installer → Remove. Confirm:
     - `schtasks /query /tn KidPCMonitor` → not found.
     - `schtasks /query /tn KidPCMonitorEnforcer` → not found.
     - `net user kid` shows "Logon hours allowed = All".
     - `net user kid` shows "Account active = Yes".
     - `net accounts` shows `Force user logoff how long after time expires?` reset (or documented as unchanged if no original-value was recorded).
5. **Same-user regression** — run installer on a single-account VM in same-user mode. Confirm Parts 2 and 3 are skipped, Part 1 is active, behavior matches the previous same-user mode otherwise.

## Out of scope (call out, don't implement)

- Per-weekday vs. per-weekend bedtime windows in the installer (use `net user /times` manually).
- Dynamic schedule updates from the web panel (would require a privileged IPC surface; intentionally deferred per scope decision).
- Force-shutdown on usage limit (rejected; data-loss risk outweighs the marginal benefit over account-disable).
- Hardening against the kid having local admin rights — the cross-user mode already assumes the kid is non-admin; same-user mode remains intentionally soft.
