import subprocess
import os
import sys
import glob
import shutil
from pathlib import Path

TASK_NAME = "KidPCMonitor"
INSTALL_DIR_DEFAULT = r"C:\ProgramData\KidPCMonitor"
AGENT_PORT = 9999
FIREWALL_RULE_DISPLAY_NAME = "Kid PC Monitor Agent (TCP 9999)"
FIREWALL_RULE_GROUP = "Kid PC Monitor"


def get_script_path():
    """Get the path to pc_control.py from user (same-user mode)"""
    print("📁 Where is pc_control.py located?")
    print("\nOptions:")
    print("1. Current directory")
    print("2. Same directory as this installer")
    print("3. Enter custom path")

    choice = input("\nChoice (1-3): ").strip()

    if choice == "1":
        script_path = os.path.abspath("pc_control.py")
    elif choice == "2":
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pc_control.py")
    else:
        while True:
            custom_path = input("\nEnter full path to pc_control.py: ").strip()
            # Remove quotes if user copied from explorer
            custom_path = custom_path.strip('"').strip("'")

            if os.path.exists(custom_path) and custom_path.endswith('.py'):
                script_path = os.path.abspath(custom_path)
                break
            else:
                print("❌ File not found or not a .py file. Please try again.")

    # Verify the file exists
    if not os.path.exists(script_path):
        print(f"\n❌ Error: Could not find {script_path}")
        print("Please make sure pc_control.py exists in the specified location.")
        return None

    print(f"\n✅ Found: {script_path}")
    return script_path


def find_repo_pc_control():
    """Locate pc_control.py shipping alongside this installer (../src/pc_control.py)."""
    here = Path(os.path.dirname(os.path.abspath(__file__)))
    for candidate in [here / "pc_control.py", here.parent / "src" / "pc_control.py"]:
        if candidate.exists():
            return str(candidate)
    return None


def prompt_install_mode(current_user):
    """Ask whether to install for the current account or for a different user."""
    print("\n👥 Who will run the monitoring agent?")
    print(f"\n  1. This account ({current_user}) — install and run as the current user")
    print( "  2. A different user account — admin installs, a non-admin child runs")
    choice = input("\nChoice (1-2) [1]: ").strip() or "1"
    return choice == "2"


def prompt_target_user():
    """Ask for the child's Windows username and validate it exists locally."""
    while True:
        name = input("\nChild's Windows username on this PC: ").strip()
        if not name:
            print("❌ Username cannot be empty.")
            continue
        if not validate_user_exists(name):
            print(f"❌ Could not find a local Windows account named '{name}'.")
            retry = input("Try a different name? (y/n): ").strip().lower()
            if retry != "y":
                return None
            continue
        return name


def validate_user_exists(name):
    """Return True if a local Windows account with this name exists."""
    ps = (
        f"if (Get-LocalUser -Name '{name}' -ErrorAction SilentlyContinue) "
        f"{{ Write-Host 'OK' }} else {{ Write-Host 'MISSING' }}"
    )
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
            capture_output=True, text=True
        )
        return 'OK' in result.stdout
    except Exception:
        return False


def find_system_python():
    """
    Locate a system-wide pythonw.exe that a non-admin user can execute.
    Returns a path string or None if only per-user installations are found.
    """
    candidates = []

    # 1. PATH lookup
    try:
        out = subprocess.run(['where', 'pythonw.exe'], capture_output=True, text=True)
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                line = line.strip()
                if line:
                    candidates.append(line)
    except Exception:
        pass

    # 2. Conventional install dirs
    for pattern in [
        r"C:\Program Files\Python*\pythonw.exe",
        r"C:\Program Files (x86)\Python*\pythonw.exe",
        r"C:\Python*\pythonw.exe",
    ]:
        candidates.extend(glob.glob(pattern))

    # 3. Drop per-user installs — the child's task can't reach the admin's profile
    seen = set()
    for path in candidates:
        lower = path.lower()
        if r"\appdata\local" in lower:
            continue
        if lower in seen:
            continue
        if not os.path.exists(path):
            continue
        seen.add(lower)
        return path
    return None


def install_to_programdata(target_user, source_script):
    """Copy agent into C:\\ProgramData\\KidPCMonitor and grant the child read+execute."""
    dest = Path(INSTALL_DIR_DEFAULT)
    dest.mkdir(parents=True, exist_ok=True)

    shutil.copy2(source_script, dest / "pc_control.py")

    # Optional: copy requirements.txt for reference
    repo_root = Path(source_script).resolve().parent.parent
    req = repo_root / "requirements.txt"
    if req.exists():
        try:
            shutil.copy2(req, dest / "requirements.txt")
        except Exception:
            pass

    # Grant read+execute to the child, recursively
    acl_result = subprocess.run(
        ['icacls', str(dest), '/grant', f'{target_user}:(OI)(CI)RX', '/T', '/Q'],
        capture_output=True, text=True
    )
    if acl_result.returncode != 0:
        print(f"\n⚠️  icacls warning while granting access to {target_user}:")
        print(acl_result.stdout)
        print(acl_result.stderr)

    return str(dest / "pc_control.py")


def create_task_with_power_settings(target_user, script_path, python_path, cross_user):
    """Create the scheduled task via PowerShell New-ScheduledTask cmdlets."""

    task_name = TASK_NAME

    print(f"\n📋 Task Configuration:")
    print(f"   Script:     {script_path}")
    print(f"   Python:     {python_path}")
    print(f"   Task Name:  {task_name}")
    print(f"   Runs as:    {target_user}")
    print(f"   Mode:       {'cross-user (admin install / non-admin run)' if cross_user else 'same-user'}")

    confirm = input("\nProceed with these settings? (y/n): ").lower()
    if confirm != 'y':
        print("❌ Setup cancelled.")
        return False

    if cross_user:
        # Logon trigger pinned to the child's account; runs unelevated in their session.
        domain = os.environ.get('COMPUTERNAME', '.')
        triggers_block = (
            f"$triggers = @( New-ScheduledTaskTrigger -AtLogon -User '{domain}\\{target_user}' )"
        )
        principal_block = (
            f"$principal = New-ScheduledTaskPrincipal "
            f"-UserId '{domain}\\{target_user}' -LogonType Interactive -RunLevel Limited"
        )
    else:
        # Existing same-user behavior: also start at boot and on any logon, elevated if available.
        triggers_block = (
            "$triggers = @( "
            "(New-ScheduledTaskTrigger -AtStartup), "
            "(New-ScheduledTaskTrigger -AtLogon) "
            ")"
        )
        principal_block = (
            f"$principal = New-ScheduledTaskPrincipal "
            f"-UserId '{target_user}' -LogonType Interactive -RunLevel Highest"
        )

    ps_script = f'''
    $ErrorActionPreference = 'Stop'
    try {{
        $action = New-ScheduledTaskAction -Execute "{python_path}" -Argument "{script_path}" -WorkingDirectory "{os.path.dirname(script_path)}"

        {triggers_block}

        {principal_block}

        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -DontStopOnIdleEnd `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Hours 0)

        Register-ScheduledTask `
            -TaskName "{task_name}" `
            -Action $action `
            -Trigger $triggers `
            -Principal $principal `
            -Settings $settings `
            -Force

        $task = Get-ScheduledTask -TaskName "{task_name}" -ErrorAction Stop
        Write-Host "SUCCESS: Task verified in Task Scheduler"
        Write-Host "Task Path: $($task.TaskPath)"
        Write-Host "Triggers: $($task.Triggers)"
        Write-Host "Principal: $($task.Principal)"
        exit 0
    }}
    catch {{
        Write-Host "ERROR: $_"
        Write-Host "Detailed error: $($_.Exception.Message)"
        exit 1
    }}
    '''

    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True
        )

        print("\n=== PowerShell Output ===")
        print(result.stdout)
        if result.stderr:
            print("=== Errors ===")
            print(result.stderr)

        if result.returncode == 0:
            verify_cmd = f'schtasks /query /tn "{task_name}"'
            verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)

            if verify_result.returncode == 0:
                print("\n✅ Task successfully created and verified!")
                if cross_user:
                    print(f"   - Triggers: At logon of {target_user}")
                else:
                    print(f"   - Triggers: At Startup + At Logon")
                print(f"   - Running as: {target_user}")
                print("\nYou can verify in Task Scheduler (taskschd.msc)")
                return True
            else:
                print("\n❌ Task creation failed verification")
                print("Try running this script as Administrator again")
                return False
        else:
            print("\n❌ Error creating task")
            if "Access is denied" in result.stderr:
                print("Please ensure you're running as Administrator")
            return False

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False


def create_task_simple_schtasks(target_user, script_path, python_path, cross_user):
    """XML fallback for environments where the PowerShell cmdlets misbehave."""
    task_name = TASK_NAME

    print(f"\n📋 Creating task with XML method...")

    if cross_user:
        domain = os.environ.get('COMPUTERNAME', '.')
        user_id = f"{domain}\\{target_user}"
        trigger_block = f'''    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_id}</UserId>
    </LogonTrigger>'''
        principal_block = f'''    <Principal id="Author">
      <UserId>{user_id}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>'''
    else:
        trigger_block = '''    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>'''
        principal_block = '''    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>'''

    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Kid PC Monitor - Manages computer usage time</Description>
  </RegistrationInfo>
  <Triggers>
{trigger_block}
  </Triggers>
  <Principals>
{principal_block}
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{python_path}</Command>
      <Arguments>"{script_path}"</Arguments>
      <WorkingDirectory>{os.path.dirname(script_path)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''

    try:
        with open('task_config.xml', 'w', encoding='utf-16') as f:
            f.write(xml_content)

        result = subprocess.run(
            f'schtasks /create /tn "{task_name}" /xml "task_config.xml" /f',
            shell=True,
            capture_output=True,
            text=True
        )

        os.remove('task_config.xml')

        if result.returncode == 0:
            print("\n✅ Task created successfully with battery settings!")
            verify_task_settings(task_name)
            return True
        else:
            print(f"\n❌ Error: {result.stderr}")
            return False

    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False


def verify_task_settings(task_name):
    """Verify the power settings of a task"""

    query_cmd = f'schtasks /query /tn "{task_name}" /xml'
    result = subprocess.run(query_cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        xml = result.stdout
        battery_start = "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" in xml
        battery_stop = "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" in xml

        print("\n📋 Task Power Settings:")
        print(f"   ✅ Can start on battery: {battery_start}")
        print(f"   ✅ Won't stop on battery: {battery_stop}")


def check_admin():
    """Check if running as administrator"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def _escape_ps_single_quoted(value):
    """Escape a string for use inside a PowerShell single-quoted literal."""
    return value.replace("'", "''")


def prompt_allow_public_firewall():
    """
    Ask whether inbound agent traffic should be allowed on Public (untrusted) networks.

    Default is no: only Private and Domain profiles (safer on coffee-shop Wi‑Fi).
    """
    print("\n🔒 Windows Firewall — remote control port")
    print(f"\n   The agent listens on TCP {AGENT_PORT}. By default, the installer")
    print("   allows inbound connections only on Private and Domain networks")
    print("   (typical home Wi‑Fi when Windows trusts the network).")
    print("\n   Public/untrusted networks are blocked so strangers on open Wi‑Fi")
    print("   cannot reach the agent.")
    print("\n   Problem: A child can disconnect Wi‑Fi and reconnect; Windows may")
    print("   then treat your home network as Public, and you lose remote control")
    print("   until you fix the network profile or re-run this installer.")
    print("\n   Desktop PCs rarely join random networks; laptops are the main case.")
    print("   You can allow Public networks below if you accept that trade-off.")
    choice = input(
        f"\nAllow inbound TCP {AGENT_PORT} on Public networks too? (y/N): "
    ).strip().lower()
    return choice in ("y", "yes")


def add_agent_firewall_rule(python_path, *, allow_public=False):
    """
    Allow inbound TCP only on AGENT_PORT for the specific pythonw.exe used by the task.

    Restrictions: one program path, one local port, TCP only. Profile is Private+Domain
    by default; include Public when allow_public is True. Does not grant outbound or
    other ports for this executable.
    """
    python_path = os.path.normpath(os.path.abspath(python_path))
    if not os.path.isfile(python_path):
        print(f"\n⚠️  Firewall rule skipped: Python not found at {python_path}")
        return False

    ps_python = _escape_ps_single_quoted(python_path)
    ps_name = _escape_ps_single_quoted(FIREWALL_RULE_DISPLAY_NAME)
    ps_group = _escape_ps_single_quoted(FIREWALL_RULE_GROUP)
    if allow_public:
        firewall_profiles = "Private,Domain,Public"
        profile_label = "Private, Domain, and Public profiles"
    else:
        firewall_profiles = "Private,Domain"
        profile_label = "Private and Domain profiles"

    ps_script = f"""
    $ErrorActionPreference = 'Stop'
    $ruleName = '{ps_name}'
    $python = '{ps_python}'
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {{
        $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }}
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Group '{ps_group}' `
        -Description 'Kid PC Monitor agent: allow remote control only on TCP {AGENT_PORT} for the scheduled pythonw.exe' `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -Profile {firewall_profiles} `
        -Program $python `
        -Protocol TCP `
        -LocalPort {AGENT_PORT}
    Write-Host "SUCCESS: Firewall rule added for $python on TCP {AGENT_PORT} ({profile_label})"
    exit 0
    """

    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True,
        )
        print("\n=== Firewall ===")
        print(result.stdout.strip() or "(no output)")
        if result.stderr.strip():
            print(result.stderr.strip())
        if result.returncode == 0:
            return True
        print("\n⚠️  Could not add Windows Firewall rule (agent may prompt on first run).")
        return False
    except Exception as exc:
        print(f"\n⚠️  Firewall setup error: {exc}")
        return False


def remove_agent_firewall_rule():
    """Remove the inbound agent rule created by add_agent_firewall_rule."""
    ps_name = _escape_ps_single_quoted(FIREWALL_RULE_DISPLAY_NAME)
    ps_script = f"""
    $rules = Get-NetFirewallRule -DisplayName '{ps_name}' -ErrorAction SilentlyContinue
    if (-not $rules) {{
        Write-Host 'INFO: No firewall rule to remove'
        exit 0
    }}
    $rules | Remove-NetFirewallRule
    Write-Host 'SUCCESS: Firewall rule removed'
    exit 0
    """
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip():
            print(result.stdout.strip())
        return result.returncode == 0
    except Exception as exc:
        print(f"⚠️  Could not remove firewall rule: {exc}")
        return False


def remove_task():
    """Remove existing task"""
    task_name = TASK_NAME
    print(f"\n🗑️  Removing task '{task_name}'...")

    result = subprocess.run(
        f'schtasks /delete /tn "{task_name}" /f',
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("✅ Task removed successfully!")
    else:
        print("ℹ️  Task not found or already removed.")

    print("\nRemoving Windows Firewall rule...")
    remove_agent_firewall_rule()


def run_install_flow():
    """Drive the install: pick a mode, gather paths, create the task."""
    current_user = os.environ.get('USERNAME') or os.environ.get('USER') or ''
    cross_user = prompt_install_mode(current_user)

    if cross_user:
        target_user = prompt_target_user()
        if not target_user:
            print("❌ No valid user provided. Aborting.")
            return False

        python_path = find_system_python()
        if not python_path:
            print("\n❌ No system-wide Python (pythonw.exe) was found.")
            print("   The scheduled task will run in the child's session, which cannot")
            print("   reach a Python install under your user profile.")
            print("\n   Fix: reinstall Python from https://www.python.org/downloads/")
            print("   and on the first screen choose 'Install for all users'.")
            return False
        print(f"\n🐍 Using system Python: {python_path}")

        source_script = find_repo_pc_control()
        if not source_script:
            print("\n❌ Could not locate pc_control.py next to this installer.")
            print("   Expected at ../src/pc_control.py relative to scripts/install.py.")
            return False

        print(f"\n📦 Installing agent to {INSTALL_DIR_DEFAULT} ...")
        script_path = install_to_programdata(target_user, source_script)
        print(f"   Granted {target_user} read+execute on the install directory.")

    else:
        target_user = current_user
        python_path = sys.executable.replace('python.exe', 'pythonw.exe')
        script_path = get_script_path()
        if not script_path:
            return False

    if create_task_with_power_settings(target_user, script_path, python_path, cross_user):
        allow_public_firewall = prompt_allow_public_firewall()
        add_agent_firewall_rule(python_path, allow_public=allow_public_firewall)
        print("\n✅ Setup complete! Task will run even on laptops using battery.")
        return True

    print("\nTrying alternative method...")
    if create_task_simple_schtasks(target_user, script_path, python_path, cross_user):
        allow_public_firewall = prompt_allow_public_firewall()
        add_agent_firewall_rule(python_path, allow_public=allow_public_firewall)
        print("\n✅ Setup complete using XML method!")
        return True

    print("\n❌ Could not create task. Please check the error messages above.")
    return False


if __name__ == "__main__":
    print("Kid PC Monitor - Task Scheduler Setup")
    print("=" * 45)

    if not check_admin():
        print("\n❌ This script needs to run as Administrator!")
        print("   Please right-click and select 'Run as administrator'")
        input("\nPress Enter to exit...")
        sys.exit(1)

    print("\nWhat would you like to do?")
    print("1. Create/Update scheduled task")
    print("2. Remove scheduled task")
    print("3. Exit")

    choice = input("\nChoice (1-3): ").strip()

    if choice == "1":
        print("\nCreating scheduled task with battery-friendly settings...\n")
        run_install_flow()
    elif choice == "2":
        remove_task()
    else:
        print("\nExiting...")

    input("\nPress Enter to close...")
