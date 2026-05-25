# Kid PC Monitor

DIY parental control system for tech-savvy parents. If you know what 'pip install' means, this could be for you!

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Kids PC](https://img.shields.io/badge/kids_PC-Windows-lightgrey.svg)
![Web panel](https://img.shields.io/badge/web_panel-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)

## 🎯 Features

- **📱 Control from your phone** - Web interface works on any device
- **🔒 Remote lock/unlock detection** - See if kids' PCs are locked
- **⏰ Scheduled bedtime locks** - Automatically lock at set times
- **⏱️ Daily usage limits** - Set maximum screen time
- **💬 Send messages** - Display warnings or reminders
- **🏠 Auto-discovery** - Finds all PCs on your network
- **⏰ Grace period warnings** - 15, 5, and 1-minute warnings before locks
- **💾 Persistent settings** - Limits survive PC restarts
- **👤 User-specific restrictions** - Monitor only specific Windows accounts
- **📊 Real-time status** - See current limits and time remaining

Note: this is a fork from rookie7799's implementation.  I'd like to thank
them for all the work providing the starting point.  As it is a fork, they have no
responsibility for any problems with this version.


## ⚠️ Technical Skills Required

This is NOT a one-click solution. You'll need to:
- Install Python
- Use a terminal / command prompt
- Understand IP addresses
- Open firewall ports where needed
- Set up a Windows scheduled task (the installer does this)

If these terms are unfamiliar or you don't want to spend the time, consider commercial alternatives like:
- Qustodio
- Net Nanny
- Windows Family Safety

## Quick Setup

This is the most common scenario.  For others, see below.

You need:

* One or more Windows PCs used by your child
* One parent Windows PC (For Mac/Linux see below)
* Both on the same home network


* [Git](https://git-scm.com/install/)

### Before You Start

On every computer you will need:

1. [Python](https://www.python.org/downloads/)


During installation on Windows:

- Check "Add Python to PATH"
- Choose "Install for all users"

Test it:

```powershell
python --version
```

2.  [Git](https://git-scm.com/install/)


Test it:

```powershell
git --version
```

### On the kid’s PC

Log in as the kid and open PowerShell as an Admin user.

Run:
```powershell
git clone https://github.com/cpmurphy/kid-pc-monitor.git
cd kid-pc-monitor
pip install -r requirements.txt
python scripts\install.py
```

The install script walks you through the installation.
For this setup, you want to:

 1. You would like the first option, `Create/Update scheduled task`
 2. You're running as admin, so choose (2) the monitoring agent should run
    under a different user.
 3. Enter the kid's username when asked.
 4. Enter the regular bed time, wake-up time and daily time allowance.
 5. When prompted about public networks, you should allow it unless you
    really are concerned about your home network being insecure.
 

### On the parent PC

 1. Install Python from python.org
 2. Open PowerShell

```powershell
git clone https://github.com/cpmurphy/kid-pc-monitor.git
cd kid-pc-monitor
pip install -r requirements.txt
pip install -e .
kid-pc-web-panel
```

Then

Open this on your phone or laptop:

http://`<IP address of parent's PC>`:5000

#### How to Find Your PC's IP Address

Open Powershell and type:

```powershell
ipconfig
```

You'll want the line that says `IPv4 Address`,

```powershell
IPv4 Address . . . . . . . . . . : 192.168.x.x
```

## To Uninstall

### On the Kid’s PC

```powershell
cd kid-pc-monitor
python scripts\install.py
```

Choose option 2, `Remove scheduled task`

### On the Parent’s PC

No action needed because you didn't install anything. (You will need to
remember to run the web panel again if you reboot.)

## 📸 Screenshots

![Web Interface](screenshots/screenshot_1.png)
![Screenshot 2](screenshots/screenshot_2.png)
![Screenshot 3](screenshots/screenshot_3.png)

## Prerequisites

To use this tool effectively, you'll want to have a separate parent/admin
machine to run the web interface.

- **Kid's PCs:** Windows 10/11 (the monitoring agent uses Windows APIs)
- **Parent / admin machine:** Windows, Linux, or macOS with Python 3.7+ (runs the Flask web panel only) The web panel listens on TCP **5000** for your browser or phone.

## Network Consideratinos

The kids' PCs must accept inbound TCP **9999** from the machine running
the web panel (usually the same LAN; cross-subnet works if routed and
allowed by firewalls).

The parent computer and kid computers usually need to be:

* on the same home Wi-Fi network
* able to reach each other directly

<details>
<summary>Scanning for PCs (Technical Details)</summary>
By default the `/24` subnet containing the parent
machine's primary IPv4 address is scanned. (See `scan_for_servers` in
`src/kid_pc_monitor/web_panel.py`). If discovery misses a PC, you can
still use it once the agent is reachable at its IP.  If you need to
scan an entirely different network (rare), you can enter a different
`/24` to scan.
</details>

## Installation

Installation is in two parts.  You install the agent on the kid's PC (as
many PCs and as many accounts as needed) and you install the admin UI on
a computer you control.

## Option A -- Separate Kid and Parent PCs

### Kid's PC

Only Windows is supported currently.

```powershell
git clone https://github.com/cpmurphy/kid-pc-monitor.git
cd kid-pc-monitor
pip install -r requirements.txt

<# Run installer as administrator #>
python scripts\install.py
```

The installer asks whether to install for **this account** (the simple
path — works when the kid's account is the only one on the PC, even
if it has admin rights) or for **a different user account** (cross-user
install: a parent/admin runs the installer and provides the child's
username; the agent then launches in the child's session at their logon).

For cross-user mode:
- Files install to `C:\ProgramData\KidPCMonitor` and the child account is granted read+execute.
- Python must be installed **for all users** (not the per-user `%LOCALAPPDATA%\Programs\Python\…` install) so the child's task can launch `pythonw.exe`. The installer refuses with a clear message if only a per-user Python is found.
- The scheduled task runs at the child's logon only, with `LeastPrivilege` (no UAC prompt for the kid).
- The agent writes its log and state to `%LOCALAPPDATA%\KidPCMonitor` in the child's profile.

#### Windows agent firewall

When you run `scripts/install.py` as administrator, it creates a
Windows Firewall inbound rule for TCP **9999** scoped to the scheduled
`pythonw.exe`. By default the rule applies only on **Private** and
**Domain** networks—not **Public**—so strangers on open Wi‑Fi
cannot reach the agent.

After the scheduled task is created, the installer asks whether to
allow **Public** networks too. Say **yes** if you use a laptop and a
child might disconnect and reconnect Wi‑Fi; Windows can then treat
your home network as Public and block remote control until you fix the
network profile or re-run the installer. Desktop PCs on a trusted home
LAN usually keep the default (**no**). Only enable Public if you accept
the extra exposure on genuinely untrusted networks.

### Parent's PC

Run the web panel on a separate PC (your own computer). More secure since kids can't access the admin interface.

2. **On your PC (Windows for MacOS/Linux, see the Linux parent steps below):**

```powershell
git clone https://github.com/cpmurphy/kid-pc-monitor.git
cd kid-pc-monitor
pip install -r requirements.txt
pip install -e .

<# Run the web panel (any of these work): #>
kid-pc-web-panel
<# or: python -m kid_pc_monitor.web_panel #>
<# or: python scripts/run_web_panel.py #>

<# Open in browser: http://YOUR-PC-IP:5000 #>
```

After that, use `./venv/bin/kid-pc-web-panel`, `./venv/bin/kid-pc-cli`,
or (the launch scripts switch to `venv/` automatically when it exists).

#### MacOS/Linux

```bash
cd kid-pc-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
kid-pc-web-panel
```
#### Install as a Service (Advanced, Linux Only)

Assuming you have a system that runs systemd, you can run the web
panel as a background service.

After creating the venv and running
`./venv/bin/python3 -m pip install -r requirements.txt`:


```bash
./scripts/install_web_panel_linux.sh install   # writes ~/.config/systemd/user/kid-pc-monitor-web-panel.service
./scripts/install_web_panel_linux.sh status
# ./scripts/install_web_panel_linux.sh uninstall   # when you want it gone
```

## Option B: Single PC Setup

Run everything on the kid's PC and access the admin panel from your
phone. Convenient if you don't have a separate PC always running.

1. **On the kid's PC (as administrator):**
```powershell
git clone https://github.com/cpmurphy/kid-pc-monitor.git
cd kid-pc-monitor
pip install -r requirements.txt

<# Install both services #>
python scripts/install.py           <# Installs pc_control #>
python scripts/install_web_panel.py <# Installs web panel #>
```

2. **On your phone:**
   - Open browser and go to `http://KIDS-PC-IP:5000`
   - Bookmark it for easy access

Both services run invisibly in the background using `pythonw.exe`.

**Note:** With this setup, a tech-savvy child could potentially discover the web panel at `localhost:5000`. Option A is more secure.

---

*Side note: if your kid is "good" with computers, consider copying the scripts somewhere less obvious.*

## 📖 Usage Guide

### Setting Up Daily Limits
1. Open the web interface on your phone
2. Click on a PC
3. View current settings in the "📊 Current Settings" section
4. Use quick buttons: "30 min", "1 hour", "2 hours"
5. Or set a custom time limit
6. Page auto-refreshes to show the new limit

### Setting Bedtime and Wake-up
1. Select a PC
2. Under **Set Bedtime Lock**, choose bedtime (e.g., 9:00 PM)
3. Under **Set Wake-up Time**, choose when locks lift and the daily limit resets (e.g., 7:00 AM)
4. PC will lock automatically at that time and stay locked until the **wake-up time** set during install (default 7:00 AM) — if the child signs back in after bedtime or before wake-up, the agent re-locks immediately. Early-morning use before wake-up is still blocked.

   Wake-up time is stored in `C:\ProgramData\KidPCMonitor\install_config.json` and copied into the child's `%LOCALAPPDATA%\KidPCMonitor\state.json` when possible. For cross-user installs, the child account should **sign in at least once** before install so their profile path exists.
5. See the scheduled lock in "Current Settings"

Note: when a usage limit, bedtime, or manual lock is active, the agent re-issues the lock whenever it detects the screen has been unlocked, so the child can't bypass it by typing their Windows password. The **Lock Computer Now** button enables a manual lock that remains active until you clear all limits.

### Clearing/Removing Limits
1. View the "📊 Current Settings" section
2. Click the **❌ Clear** button next to any limit you want to remove
3. Or click **🗑️ Clear All Limits** to remove everything
4. Changes take effect immediately

### Emergency Unlock
While remote unlock isn't possible for security, you can:
- Clear the usage limit to grant unlimited time
- Clear scheduled locks to prevent automatic locking
- Clear all limits to release a manual **Lock Computer Now** lock
- Send a message to request unlock
- Restart the PC (if no password)

## ⚙️ Configuration

### Custom PC Names
Edit `CUSTOM_PC_NAMES` in `src/kid_pc_monitor/remote_client.py` (used by the web panel and `kid-pc-cli`):
```python
CUSTOM_PC_NAMES = {
    '192.168.1.105': 'Tommy\'s Laptop',
    '192.168.1.112': 'Sarah\'s Desktop',
}
```

### User-Specific Monitoring
Monitor only specific Windows user accounts. Edit `src/kid_pc_monitor/pc_control.py`:

```python
# Option 1: Monitor ONLY these specific users
MONITORED_USERS = ['Tommy', 'Sarah']  # Only these kids are restricted
EXEMPT_USERS = []

# Option 2: Monitor everyone EXCEPT these users
MONITORED_USERS = []
EXEMPT_USERS = ['pavel', 'Mom', 'Dad']  # Parents are exempt

# Option 3: Monitor ALL users (default)
MONITORED_USERS = []
EXEMPT_USERS = []
```

**Use Case:** If multiple family members share one PC, you can restrict
only the children's accounts while leaving parent accounts unrestricted.

### Persistent State

Settings are automatically saved to `state.json` including:
- Daily usage limits
- Scheduled lock times
- Start time for usage tracking

This means restrictions **survive PC restarts** - kids can't bypass by rebooting!

## 🖥️ Command-line client

From the repo root, run the CLI on your parent machine (Linux, macOS,
or Windows). On Linux, create a venv first if you have not already (see
[Python virtual environment (Linux)](#python-virtual-environment-linux)):

```bash
cd kid-pc-monitor
python3 -m venv venv          # only needed on Linux (Debian/Ubuntu)
./venv/bin/python3 -m pip install -e .
./venv/bin/kid-pc-cli scan
./venv/bin/kid-pc-cli inspect 192.168.1.105
./venv/bin/kid-pc-cli set-limit 192.168.1.105 60
./venv/bin/kid-pc-cli add-lock-time 192.168.1.105 21:00
./venv/bin/kid-pc-cli lock 192.168.1.105
```

Use `./venv/bin/kid-pc-cli --help` for all commands (`message`, `shutdown`, `extend-time`, `clear-all`, `raw`, etc.). Add `--json` for scripting. Scan a specific subnet with `./venv/bin/kid-pc-cli scan --subnet 192.168.1.0/24`.


## 🔧 Troubleshooting

See [docs/FAQ.md](docs/FAQ.md) for questions and answers.

### "PC shows as Unknown"
- Add custom names in configuration
- Check Windows Firewall settings
- Ensure PCs are on same network

### Scan finds no PCs (agent may still be running)
- On the kid PC, read `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` — startup logs network profile and firewall rule.
- **Public network profile** is a common cause: the installer allows inbound TCP 9999 on **Private/Domain** only unless you opted into **Public**. Minecraft works; parent scan does not.
- Set home Wi‑Fi to **Private**, or re-run `scripts/install.py` and allow Public for port 9999.
- Ensure parent and kid are on the same subnet (or scan the kid's subnet explicitly).

### "Can't connect from phone"
- Check firewall allows port 5000 (web panel host) and port 9999 (each kid PC running the agent)
- On Linux parents, ensure the host firewall allows inbound **5000/tcp** (e.g. `ufw allow 5000/tcp`)
- Use the web panel machine's IP address, not localhost
- Ensure the web panel is running (`kid-pc-web-panel` or `python -m kid_pc_monitor.web_panel`)

### "Lock status not updating"
- Restart `pc_control.py`
- Check if LogonUI.exe detection works
- See logs in console window

## 🛡️ Security Notes

- Only works on local network (not internet)
- Optional **parent web panel** password: use **Add password protection** on the home page. Only a secure hash is stored in `web_panel_auth.json` next to the app (not the plain password). Until you set one, anyone on the LAN can use the panel—the same as before this feature.
- Can't bypass Windows lock screen
- Kids can close the agent if their account has admin rights. If you install in cross-user mode (admin installs, non-admin child runs), the child cannot stop or delete the scheduled task or its files.

## 🤝 Contributing

Parents and developers welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### Recent Improvements (v2.0)
- ✅ Grace period warnings (15, 5, 1 minute before lock)
- ✅ Persistent state storage (settings survive restarts)
- ✅ User-specific restrictions (monitor only certain accounts)
- ✅ Fixed usage time calculation bug
- ✅ Improved error handling and logging
- ✅ Web UI shows current limits and time remaining
- ✅ Better resource management

### Ideas for Future Contributions
- Linux/macOS **agent** (kid-side monitoring; the web panel already runs on Linux/macOS/Windows)
- Mobile app
- Usage statistics/reports
- Reward system integration
- Application-specific time limits
- Authentication/password protection

## 📄 License

MIT License - feel free to modify for your family's needs!

## ❤️ Acknowledgments

Created by parents, for parents. Special thanks to all contributors who help make screen time management easier!

---

**Need Help?** Open an [issue](https://github.com/cpmurphy/kid-pc-monitor/issues) or check our [FAQ](docs/FAQ.md)
