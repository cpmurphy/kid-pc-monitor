# Cross-user install

An administrator installs the agent. The monitored Windows account runs it. That account does not need to be an administrator, and it cannot change the program files.

`scripts/install_agent.ps1` always asks for the monitored account's username and creates a logon task pinned to that account (`LeastPrivilege`, interactive token). Entering the account you are signed in as is allowed. The installer warns that this is weaker: the agent is not elevated, so that account can stop the task and undo locks.

## What gets installed

- `kid-pc-agent.exe`, a copy of the installer, `update.cmd`, and `version.txt` go to `C:\ProgramData\KidPCMonitor`.
- The folder's ACL is SYSTEM and Administrators (full control) and the monitored account (read and execute).
- The schedule is stored in ProgramData and in `%LOCALAPPDATA%\KidPCMonitor` under the monitored account. The log and runtime state are in that profile, not in ProgramData, so the install directory can stay read-only for the child.
- The shared secret is Fernet-encrypted, the same file format an older Python agent used. If that older agent is already installed, this installer replaces its task and removes its files (`kid_pc_monitor`, `pc_control.py`, `requirements.txt`) without asking for the schedule or secret again.

There is no separate "cross-user mode" prompt. One install path covers both a child's account and a warned self-install.

## Checking it on a Windows machine

- Two local accounts. Call them `parent` (administrator, runs the installer) and `kid` (standard user). Both have signed in at least once, so `Get-LocalUser` lists them.
- From an elevated PowerShell as `parent`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_agent.ps1
```

Enter `kid` when asked for the account, then the schedule and the shared secret.

- Confirm the scheduled task `KidPCMonitor` runs as `COMPUTERNAME\kid` at that user's logon, `LeastPrivilege`, and that its action is `C:\ProgramData\KidPCMonitor\kid-pc-agent.exe`.
- Sign in as `kid`. The agent should start without a UAC prompt. Its log is `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` in the kid's profile.
- As `kid`, changing or deleting files in `C:\ProgramData\KidPCMonitor` should fail. Stopping the scheduled task should also fail.
- Run the installer again as `parent` and enter `parent` as the account. It should explain the weaker self-install and ask you to confirm before creating the task.
