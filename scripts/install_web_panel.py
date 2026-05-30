import subprocess
import os
import sys
from pathlib import Path

MODULE = "kid_pc_monitor.web_panel"


def ensure_package_installed():
    """pip-install the kid-pc-monitor package from the repo so imports work."""
    installer_dir = Path(__file__).resolve().parent
    repo_root = installer_dir.parent
    pyproject = repo_root / "pyproject.toml"

    if not pyproject.is_file():
        print(f"Error: could not find pyproject.toml at {pyproject}")
        print("Run this script from a git checkout of kid-pc-monitor.")
        return False

    try:
        from kid_pc_monitor.web_panel import main as _unused  # noqa: F401
        print("kid-pc-monitor package is already installed.")
        return True
    except ImportError:
        pass

    print(f"Installing kid-pc-monitor from {repo_root} ...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", str(repo_root)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("pip install failed:")
        print(result.stdout)
        print(result.stderr)
        return False

    print("Package installed successfully.")
    return True


def configure_shared_secret():
    """Prompt for and store the panel <-> agent shared secret.

    Requires the package to be importable, so call after ensure_package_installed().
    """
    try:
        from kid_pc_monitor.shared_secret import prompt_and_store_shared_secret
    except ImportError as exc:
        print(f"\nCould not load the shared-secret prompt: {exc}")
        print("Skipping shared-secret setup; you can re-run this installer later.")
        return
    prompt_and_store_shared_secret()


def create_task_with_power_settings():
    """Create scheduled task that runs even on battery power"""

    if not ensure_package_installed():
        return False

    pythonw_path = sys.executable.replace('python.exe', 'pythonw.exe')
    task_name = "KidPCMonitorWebPanel"
    current_user = os.getenv('USERNAME')

    print(f"\nTask Configuration:")
    print(f"   Command: {pythonw_path} -m {MODULE}")
    print(f"   Task Name: {task_name}")
    print(f"   User Account: {current_user}")

    confirm = input("\nProceed with these settings? (y/n): ").lower()
    if confirm != 'y':
        print("Setup cancelled.")
        return False

    ps_script = f'''
    $ErrorActionPreference = 'Stop'
    try {{
        $action = New-ScheduledTaskAction -Execute "{pythonw_path}" -Argument "-m {MODULE}"

        $triggers = @(
            (New-ScheduledTaskTrigger -AtStartup),
            (New-ScheduledTaskTrigger -AtLogon)
        )

        $principal = New-ScheduledTaskPrincipal -UserId "{current_user}" -LogonType Interactive -RunLevel Highest

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

        Start-ScheduledTask -TaskName "{task_name}"
        Write-Host "Task started."
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
                print("\nTask successfully created and verified!")
                print(f"   - Triggers: At Startup + At Logon")
                print(f"   - Running as: {current_user}")
                print("\nYou can verify in Task Scheduler (taskschd.msc)")
                return True
            else:
                print("\nTask creation failed verification")
                print("Try running this script as Administrator again")
                return False
        else:
            print("\nError creating task")
            if "Access is denied" in result.stderr:
                print("Please ensure you're running as Administrator")
            return False

    except Exception as e:
        print(f"\nUnexpected error: {e}")
        return False

def create_task_simple_schtasks():
    """Alternative using schtasks with XML template"""

    if not ensure_package_installed():
        return False

    pythonw_path = sys.executable.replace('python.exe', 'pythonw.exe')
    task_name = "KidPCMonitorWebPanel"

    print(f"\nCreating task with XML method...")

    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Kid PC Monitor Web Panel - Admin interface for managing child PC usage</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
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
      <Command>{pythonw_path}</Command>
      <Arguments>-m {MODULE}</Arguments>
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
            print("\nTask created successfully with battery settings!")
            verify_task_settings(task_name)
            subprocess.run(
                f'schtasks /run /tn "{task_name}"',
                shell=True,
                capture_output=True,
            )
            print("Task started.")
            return True
        else:
            print(f"\nError: {result.stderr}")
            return False

    except Exception as e:
        print(f"\nError: {e}")
        return False

def verify_task_settings(task_name):
    """Verify the power settings of a task"""

    query_cmd = f'schtasks /query /tn "{task_name}" /xml'
    result = subprocess.run(query_cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        xml = result.stdout
        battery_start = "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" in xml
        battery_stop = "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" in xml

        print("\nTask Power Settings:")
        print(f"   Can start on battery: {battery_start}")
        print(f"   Won't stop on battery: {battery_stop}")

def check_admin():
    """Check if running as administrator"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def remove_task():
    """Remove existing task"""
    task_name = "KidPCMonitorWebPanel"
    print(f"\nRemoving task '{task_name}'...")

    result = subprocess.run(
        f'schtasks /delete /tn "{task_name}" /f',
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("Task removed successfully!")
    else:
        print("Task not found or already removed.")

if __name__ == "__main__":
    print("Kid PC Monitor Web Panel - Task Scheduler Setup")
    print("=" * 50)

    if not check_admin():
        print("\nThis script needs to run as Administrator!")
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

        if ensure_package_installed():
            configure_shared_secret()

        if create_task_with_power_settings():
            print("\nSetup complete! Task will run even on laptops using battery.")
            print("\nAccess the web panel from any device on your network at:")
            print("   http://<this-pc-ip>:5000")
        else:
            print("\nTrying alternative method...")
            if create_task_simple_schtasks():
                print("\nSetup complete using XML method!")
                print("\nAccess the web panel from any device on your network at:")
                print("   http://<this-pc-ip>:5000")
            else:
                print("\nCould not create task. Please check the error messages above.")

    elif choice == "2":
        remove_task()

    else:
        print("\nExiting...")

    input("\nPress Enter to close...")
