# Cross-user install mode: design notes and Windows test plan

This document captures the design behind the "admin installs, non-admin child runs" mode added on the `work-with-admin-account` branch, and the end-to-end checks to run on a real Windows machine. The Linux dev box can syntax-check the Python, but everything below needs an actual Windows two-account setup to validate.

## Why this exists

The previous `scripts/install.py` created a scheduled task pinned to whoever ran the installer — it read `os.getenv('USERNAME')` and used that account as both the task principal and (implicitly) the only user whose logon fired the trigger. So when a parent installed while signed in as their admin account, the agent never started on the child's logon. The simple "install while signed in as the kid" path still works (and is preserved); the new path lets an admin install once for a different, non-admin child account.

## What changed

### `src/pc_control.py`
- `pc_control.log` and `pc_control_state.json` now live in `%LOCALAPPDATA%\KidPCMonitor` instead of the process CWD. This keeps the install dir (read-only for the kid in cross-user mode) clean and gives the agent a writable home in whichever profile it runs under. Same-user mode benefits too — no more files written next to the repo.

### `scripts/install.py`
- New top-level prompt: install for **this account** (existing behavior) or **a different user account** (new cross-user mode).
- Same-user mode keeps the previous task semantics: principal = current user, triggers = `AtStartup` + `AtLogon`, `RunLevel=Highest`.
- Cross-user mode:
  - Validates the child's Windows account via `Get-LocalUser`.
  - Searches for a **system-wide** `pythonw.exe` (PATH, `C:\Program Files\Python*`, `C:\Program Files (x86)\Python*`, `C:\Python*`) and refuses if only a per-user `%LOCALAPPDATA%\Programs\Python\…` install exists — the child's task can't reach the admin's profile.
  - Copies `pc_control.py` into `C:\ProgramData\KidPCMonitor` and runs `icacls … /grant <kid>:(OI)(CI)RX /T` so the child can read+execute but not write.
  - Creates the scheduled task with both the `<Principal>` `UserId` and the `<LogonTrigger>` `UserId` pinned to `COMPUTERNAME\<kid>`, `LogonType=InteractiveToken`, `RunLevel=LeastPrivilege`. Drops the `AtStartup` trigger since the child isn't logged in at boot.

### `README.md`
- Documents the mode prompt and the cross-user prerequisites under "Option A → On each kid's PC".
- Updates the security note: in cross-user mode the child cannot stop the task or delete the install files.

## Files touched

- `src/pc_control.py` — log/state moved into `%LOCALAPPDATA%\KidPCMonitor`.
- `scripts/install.py` — full restructure; new helpers `prompt_install_mode`, `prompt_target_user`, `validate_user_exists`, `find_system_python`, `install_to_programdata`, `find_repo_pc_control`, and a `run_install_flow` that drives both paths. Both `create_task_with_power_settings` and `create_task_simple_schtasks` now take `(target_user, script_path, python_path, cross_user)` and switch the principal/trigger blocks based on `cross_user`.
- `README.md` — Option A install section and security notes.

## Windows test plan

Prereqs:
- A Windows 10/11 machine with two local accounts. Call them `parent` (administrator, the account running the installer) and `kid` (standard user — not an administrator). Both must have logged in at least once so `Get-LocalUser` shows them.
- Python 3.7+ installed **for all users** (so `pythonw.exe` lives under `C:\Program Files\Python…`, not `%LOCALAPPDATA%\Programs\Python\…`). Verify with `where pythonw.exe` from an admin shell.
- The repo cloned and `pip install -r requirements.txt` run.

### 1. Cross-user install (the new path)

As `parent`:

1. Open an elevated PowerShell or cmd prompt (`Run as administrator`).
2. From the repo root: `python scripts\install.py`.
3. Pick **1** at the top menu (Create/Update scheduled task).
4. At the mode prompt, pick **2** (a different user account).
5. Enter `kid` as the username.
   - Sanity check: enter a non-existent name first (e.g., `kiid`) and confirm the installer offers a retry rather than crashing.
6. Confirm the installer prints "Using system Python: C:\Program Files\Python…\pythonw.exe". To test the refusal path, temporarily rename those folders aside and re-run; expect a clean exit with a message pointing to python.org "Install for all users".
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

### 2. Same-user install (regression check)

On a separate VM/box (or after running the removal step below), as a user with admin rights:

1. `python scripts\install.py`, choose **1** (Create), pick mode **1** (this account).
2. Walk through `get_script_path()` as before.
3. Sign out and back in. Confirm `pythonw.exe pc_control.py` is running under that user.
4. Confirm `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` is being written (this is the one behavioral change in same-user mode — previously the log lived in CWD).

### 3. Removal in both modes

As an administrator on each test box: `python scripts\install.py`, choose **2** (Remove). Then `schtasks /query /tn KidPCMonitor` should return "task not found".

### 4. XML fallback

The XML path (`create_task_simple_schtasks`) is only used when the PowerShell `Register-ScheduledTask` path fails. To exercise it, temporarily break the PowerShell path (e.g., introduce a syntax error in the `$action` line) and confirm both same-user and cross-user XML templates produce a working task with the correct principal/trigger UserId.

## Known follow-ups (not done here)

- `scripts/install_web_panel.py` was not touched. The web panel is parent-side, so cross-user install doesn't apply directly, but if someone runs the single-PC setup with a non-admin kid the web panel installer would have the same logon-trigger limitation. Worth a follow-up.
- No automated tests. The installer is interactive and Windows-only, so manual verification is the practical path for now.
