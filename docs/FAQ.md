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

### Safari on iPhone won't autofill my saved password

iOS Safari only auto-offers saved passwords on **HTTPS** pages with a **trusted** certificate. The web panel defaults to plain `http://192.168.x.x:5000`, so Keychain may store your password but Safari will not show the key icon or inline autofill prompt.

**Quick workaround (HTTP, no setup):**
1. **Settings → Passwords** → open the saved entry → tap the website link (Safari may fill when launched from there).
2. Long-press the password field → **Autofill** → **Passwords** → pick the entry.

**Permanent fix (one-tap autofill):**

Caveat: this does involve you managing your own certificate authority (CA). If
someone gets access to the CA's private key, they could use it to create
fake certificates for any site they want.  Only do this if you understand
and accept the risks.

On the machine running the web panel, install
[mkcert](https://github.com/FiloSottile/mkcert#installation), then
generate a root CA and a certificate for the web panel.

```bash
mkcert -install
mkdir -p ~/.config/kid-pc-monitor/tls
KEY_FILE=~/.config/kid-pc-monitor/tls/cert.pem
CERT_FILE=~/.config/kid-pc-monitor/tls/cert.pem
# know what you're using for <parents-pc> before you run this mkcert command
mkcert -key-file "$KEY_FILE" -cert-file "$CERT_FILE" "<parents-pc>"
```

The panel auto-detects certificates at `~/.config/kid-pc-monitor/tls/cert.pem` and `key.pem` (or `%LOCALAPPDATA%\kid-pc-monitor\tls\` on Windows).
You can also set `KID_PC_MONITOR_SSL_CERT` and `KID_PC_MONITOR_SSL_KEY` explicitly.

Then on your iPhone:
1. Install and fully trust the mkcert root CA (see mkcert documentation for steps).
2. Restart the web panel.
3. Open `https://<parent-pc>:5000` (not `http://`).
4. Sign in once and save the password again at the `https://` URL (delete any old `http://` entry).

**Windows parent:** install [mkcert](https://github.com/FiloSottile/mkcert#installation), then run the same commands manually:

```powershell
mkcert -install
mkdir "$env:LOCALAPPDATA\kid-pc-monitor\tls"
<# know what you're using for <parents_pc> before running #>
mkcert -key-file "$env:LOCALAPPDATA\kid-pc-monitor\tls\key.pem" `
       -cert-file "$env:LOCALAPPDATA\kid-pc-monitor\tls\cert.pem" `
       <parents_pc>
```

Trust the mkcert root CA on your iPhone as above.

**Advanced:** run Caddy or nginx in front of the panel with TLS termination; keep Flask on HTTP locally (`http://127.0.0.1:5000` behind the proxy).

**Note:** A self-signed certificate that is not trusted on the phone still will not enable autofill — you need a CA installed on iOS (mkcert is the simplest option for home LAN use).

### "PC shows as Unknown"
This is normal. You can:
1. Add custom names in config.py
2. The PC will still work, just with generic name

### Scan finds no PCs / `pc_cli` cannot connect, but the kid PC is online

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
