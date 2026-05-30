# Install flow: design notes and Windows test plan

This document captures the design behind the unified "admin installs, the monitored account runs" install flow, and the end-to-end checks to run on a real Windows machine. The Linux dev box can syntax-check the Python, but everything below needs an actual Windows two-account setup to validate.

## Why this exists

The original `scripts/install.py` created a scheduled task pinned to whoever ran the installer — it read `os.getenv('USERNAME')` and used that account as both the task principal and (implicitly) the only user whose logon fired the trigger. So when a parent installed while signed in as their admin account, the agent never started on the child's logon.

A later revision added a second "cross-user" mode behind a top-level prompt. That prompt was confusing for first-time users, so the two modes were unified: the installer always asks for the monitored account's username and always uses the cross-user (pinned-logon, `LeastPrivilege`) task. Entering your own username is allowed as a warned, weaker self-install.

## What changed

### `src/pc_control.py`
- `pc_control.log` and `pc_control_state.json` live in `%LOCALAPPDATA%\KidPCMonitor` instead of the process CWD. This keeps the install dir (read-only for the kid) clean and gives the agent a writable home in whichever profile it runs under.

### `scripts/install.py`
- No mode prompt. The installer always asks for the monitored Windows username (`prompt_target_user`) and validates it via `Get-LocalUser`.
- Entering the current user is permitted: `warn_self_install` explains the trade-offs (the agent runs unelevated, so that account can stop the task and undo locks; recommend a separate standard account) and asks the user to confirm before proceeding.
- Python: searches for a **system-wide** `pythonw.exe` (PATH, `C:\Program Files\Python*`, `C:\Program Files (x86)\Python*`, `C:\Python*`). For a *different* user it refuses if only a per-user `%LOCALAPPDATA%\Programs\Python\…` install exists (the child's task can't reach the admin's profile). For the **self-install** case it falls back to the current interpreter (`sys.executable`) since the task runs in the same session.
- Copies the `kid_pc_monitor` package into `C:\ProgramData\KidPCMonitor` and runs `icacls … /grant <user>:(OI)(CI)RX /T` so the monitored account can read+execute but not write.
- Creates the scheduled task with both the `<Principal>` `UserId` and the `<LogonTrigger>` `UserId` pinned to `COMPUTERNAME\<user>`, `LogonType=InteractiveToken`, `RunLevel=LeastPrivilege`. There is no `AtStartup` trigger — the monitored user isn't logged in at boot.

### `README.md`
- Documents the single-prompt flow and the cross-user prerequisites under "Option A → On each kid's PC", plus the self-install warning.
- Security note: the monitored account cannot stop the task or delete the install files (unless you self-install, where it can).

## Files touched

- `src/pc_control.py` — log/state moved into `%LOCALAPPDATA%\KidPCMonitor`.
- `scripts/install.py` — unified flow; helpers `prompt_target_user`, `warn_self_install`, `validate_user_exists`, `find_system_python`, `install_to_programdata`, `find_repo_package_dir`, and a single `run_install_flow`. `create_task_with_power_settings(target_user, script_path, python_path, *, is_self=False)` and `create_task_simple_schtasks(target_user, script_path, python_path)` always emit the pinned-logon `LeastPrivilege` principal/trigger blocks.
- `README.md` — Option A install section and security notes.

## Windows test plan

Prereqs:
- A Windows 10/11 machine with two local accounts. Call them `parent` (administrator, the account running the installer) and `kid` (standard user — not an administrator). Both must have logged in at least once so `Get-LocalUser` shows them.
- Python 3.7+ installed **for all users** (so `pythonw.exe` lives under `C:\Program Files\Python…`, not `%LOCALAPPDATA%\Programs\Python\…`). Verify with `where pythonw.exe` from an admin shell.
- The repo cloned and `pip install -r requirements.txt` run.

### 1. Cross-user install (the main path)

As `parent`:

1. Open an elevated PowerShell or cmd prompt (`Run as administrator`).
2. From the repo root: `python scripts\install.py`.
3. Pick **1** at the top menu (Create/Update scheduled task).
4. Enter `kid` as the username when asked.
   - Sanity check: enter a non-existent name first (e.g., `kiid`) and confirm the installer offers a retry rather than crashing.
5. Confirm the installer prints "Using system Python: C:\Program Files\Python…\pythonw.exe". To test the refusal path, temporarily rename those folders aside and re-run with a *different* user; expect a clean exit with a message pointing to python.org "Install for all users".
7. Confirm the installer copies files to `C:\ProgramData\KidPCMonitor` and grants the kid RX:
   ```powershell
   Get-ChildItem C:\ProgramData\KidPCMonitor
   icacls C:\ProgramData\KidPCMonitor
   ```
   The ACL output should show `kid:(OI)(CI)(RX)`.
8. Open `taskschd.msc` → Task Scheduler Library → find `KidPCMonitor`. Confirm:
   - General tab: "When running the task, use the following user account: `kid`". "Run only when user is logged on". "Run with highest privileges" should be **off**.
   - Triggers tab: a single trigger, "At log on of `MACHINE\kid`".
   - Actions tab: program = the system pythonw.exe, argument = `"C:\ProgramData\KidPCMonitor\pc_control.py"`.

Sign out of `parent`, sign in as `kid`:

9. Open Task Manager → Details (or `tasklist /v`). Confirm a `pythonw.exe` is running under the `kid` user.
10. Confirm `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` exists and the first line includes `Monitoring user: kid`.
11. From the parent web panel (on the parent's PC, run `python src\web_panel.py` and browse to `http://<kid-pc-ip>:5000`), confirm the kid's PC shows up and reports username `kid`. Trigger a remote lock and confirm the kid's session locks via `LogonUI.exe`.
12. Try to delete `C:\ProgramData\KidPCMonitor\pc_control.py` while signed in as `kid`. It should fail (`Access is denied`). Try `schtasks /delete /tn KidPCMonitor /f` — also expected to fail without elevation.

### 2. Self-install (warned, weaker path)

As a user with admin rights, monitoring your own account:

1. `python scripts\install.py`, choose **1** (Create), enter **your own** username.
2. Confirm the installer prints the self-install warning (unelevated, account can stop the task / undo locks) and proceeds only after you confirm.
3. If only a per-user Python is installed, confirm the installer falls back to the current interpreter instead of refusing.
4. Sign out and back in. Confirm `pythonw.exe` is running under that user and `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` is being written.

### 3. Removal

As an administrator on each test box: `python scripts\install.py`, choose **2** (Remove). Then `schtasks /query /tn KidPCMonitor` should return "task not found".

### 4. XML fallback

The XML path (`create_task_simple_schtasks`) is only used when the PowerShell `Register-ScheduledTask` path fails. To exercise it, temporarily break the PowerShell path (e.g., introduce a syntax error in the `$action` line) and confirm the XML template produces a working task with the correct pinned principal/trigger UserId.

## Known follow-ups (not done here)

- `scripts/install_web_panel.py` was not touched. The web panel is parent-side, so cross-user install doesn't apply directly, but if someone runs the single-PC setup with a non-admin kid the web panel installer would have the same logon-trigger limitation. Worth a follow-up.
- No automated tests. The installer is interactive and Windows-only, so manual verification is the practical path for now.
