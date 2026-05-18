# Frequently Asked Questions

## General Questions

### Is this spyware?
No! This tool:
- Only works on your local network
- Doesn't track browsing history
- Doesn't take screenshots
- Doesn't log keystrokes
- Only manages time limits and lock status

### Can my kids bypass it?
If they have administrator access, yes. This tool is based on trust and communication, not enforcement. For younger kids who don't have admin rights, it's quite effective.

### Does it work on Mac/Linux?
- **Kid PC (monitoring agent):** Windows only today (`pc_control.py` uses Windows-specific lock and session APIs).
- **Parent web panel:** Runs on **Windows, Linux, or macOS**. Install Python, `pip install -r requirements.txt` (on non-Windows, `pywin32` is skipped automatically), then run `web_panel.py` from `src/`. The panel talks to each kid PC over TCP port **9999** on your network.

## Setup Issues

### "Python is not recognized as a command"
- Download Python from python.org
- During installation, check "Add Python to PATH"
- Restart your computer

### "Can't connect from my phone"
1. Check both devices are on same WiFi (or that routing exists between subnets if you use VLANs)
2. **Firewall:** On Windows (kid PC or a Windows parent), allow Python / ports **5000** (web panel) and **9999** (agent). On a **Linux** machine running the web panel, allow inbound **5000/tcp** (e.g. `sudo ufw allow 5000/tcp` on Ubuntu)
3. Use the IP address shown when starting `web_panel.py`, not `localhost`, from the other device

### "PC shows as Unknown"
This is normal. You can:
1. Add custom names in config.py
2. The PC will still work, just with generic name

### Scan finds no PCs / pc_cli cannot connect, but the kid PC is online

The agent may be running and listening on port **9999** locally while **Windows Firewall still blocks inbound** connections from your parent PC or phone.

**Most common cause — Public network profile:** When you run `scripts/install.py`, the firewall rule allows inbound TCP 9999 only on **Private** and **Domain** networks by default (not **Public**). If Windows classifies your home Wi‑Fi as Public—common after disconnecting and reconnecting Wi‑Fi—the agent keeps running but remote scans and `pc_cli` time out.

**Fix (pick one):**
1. On the kid PC: **Settings → Network & Internet → Wi‑Fi → (your network) → Network profile → Private**
2. Re-run `scripts/install.py` as administrator and answer **yes** when asked to allow **Public** networks (trade-off: slightly less isolation on real public Wi‑Fi)
3. Manually add or edit the inbound rule **Kid PC Monitor Agent (TCP 9999)** in Windows Defender Firewall

**Check the agent log** on the kid PC: `%LOCALAPPDATA%\KidPCMonitor\pc_control.log`. At startup it logs network profiles, firewall rule profiles, and whether the listener bound. Look for `Network profile: ... category=Public` or a warning about Public networks.

**Other causes:** Agent not running (Task Scheduler), wrong subnet in scan, firewall rule scoped to a different `pythonw.exe` path than the one running the task, or parent and kid PC on different VLANs without routing.

Set `KID_PC_MONITOR_LOG_LEVEL=DEBUG` on the kid PC (Task Scheduler → task → Environment) for per-connection detail without changing code.

## Usage Questions

### Can I unlock a PC remotely?
No, Windows doesn't allow this for security. You can:
- Grant extra time before it locks
- Send a message asking them to save work
- Set up specific "homework time" extensions

### How do I set different limits for different days?
Currently manual, but you can:
- Change limits each day via phone
- Set longer limits on weekends
- Remove limits for special occasions

### What happens if the script crashes?
The PC returns to normal (no restrictions). You can:
- Set it up to restart automatically
- Check logs to see why it crashed
- Kids might notice and restart it (if they're honest!)

## Technical Questions

### How does lock detection work?
We check if LogonUI.exe (Windows lock screen) is running. This is very reliable.

### How can I contribute?
- Report bugs via GitHub issues
- Submit pull requests
- Share your setup tips
- Translate to other languages

### Is this legal to use?
Yes, for your own children on your own computers. Don't use it on computers you don't own or without consent.
