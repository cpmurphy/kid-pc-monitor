# Agent Guide — Kid PC Monitor

This is a Go project. The module is the repository root (`module kidpcmonitor`, Go 1.26+). It was ported from a Python implementation that is no longer in the tree; [`testdata/`](testdata/) holds the frozen vectors from that port. See the historical note in [README.md](README.md). Package map, build, and compatibility notes are in [docs/TECH.md](docs/TECH.md).

## Project Layout

- `cmd/kid-pc-agent` is the Windows agent (standard library only; CI checks). `cmd/kid-pc-web-panel` is the parent web panel (Windows, Linux, macOS). `cmd/wincheck` is a manual Windows check of lock detection. The panel's third-party dependencies are `modernc.org/sqlite` (pure Go) and `golang.org/x/crypto` (scrypt); `golang.org/x/term` is the password prompt. See [docs/TECH.md](docs/TECH.md).
- `scripts/` — Installers. `install_agent.ps1` and `install_web_panel.ps1` (Windows), `install_web_panel_linux.sh` (Linux systemd user service).
- `tests/` — PowerShell installer tests (`install_agent_test.ps1`, `install_web_panel_test.ps1`). The Linux installer is tested from `cmd/kid-pc-web-panel/install_linux_test.go`.
- `docs/` — Protocol spec (`agent-protocol.md`), FAQ, cross-user install notes, [TECH.md](docs/TECH.md), and a guide to reading the Go source.
- `testdata/` — Frozen golden vectors. They were generated from the original Python implementation. Change a file in the same commit as the Go behavior it describes. There is no generator.

## Two Components

1. **Agent** (`cmd/kid-pc-agent`) — Kid-side Windows program. Monitors the session, enforces locks, and connects outbound to the panel reverse port (**TCP 9998**).
2. **Web Panel** (`cmd/kid-pc-web-panel`) — Parent admin UI (HTTP on **TCP 5000**) plus the reverse listener (**TCP 9998**). Runs on Windows, Linux, or macOS. Optional TLS via `config_dir()/tls/cert.pem` + `key.pem` or `KID_PC_MONITOR_SSL_CERT` / `KID_PC_MONITOR_SSL_KEY`. iOS Safari password autofill requires trusted HTTPS (see the FAQ).

## Dev Setup

Go 1.26 or later. From the repository root:

```bash
go test ./...
gofmt -l .
go vet ./...
```

On Linux and macOS the web panel builds and tests. The agent and `winplatform` are Windows-only; CI's `go-windows` job builds and tests them.

The Linux firewall check used by the installer lives in `firewall` and is exposed as `kid-pc-web-panel check-firewall`.

## Testing

```bash
go test ./...          # all packages; -race in CI on Linux
go test ./policy/ -v   # one package
```

`vectors_test.go` files replay `testdata/*/vectors.json`. A CSS or JS edit under `panel/web/static/` also updates the SHA-256 recorded in `testdata/panelweb/vectors.json`.

`panel/pyval` is how the panel reads JSON and `panel.db` rows written by the original Python panel (truthiness, `int()`, `repr`, float `repr`, `fromisoformat`). Keep new vector inputs to values those rules treat stably.

Templates live in `panel/web/templates/` (`html/template`). Static files live in `panel/web/static/` and are embedded; they are not a generated copy of anything else.

PowerShell installer tests (no admin rights; CI's `go-windows` job):

```powershell
powershell -ExecutionPolicy Bypass -File tests\install_agent_test.ps1
powershell -ExecutionPolicy Bypass -File tests\install_web_panel_test.ps1 -PanelExe kid-pc-web-panel.exe
```

## Agent Protocol

- KDL-subset over TCP with a **length-prefix** frame (see `docs/agent-protocol.md`).
- **v2** added HMAC-SHA256 mutual auth; the signing key is the UTF-8 bytes of the shared secret.
- **v3** is the only wire version. New capabilities (e.g. `get_logs`) are optional actions at v3; unsupported agents return `unknown_action`.
- Write actions (`set`, `lock`, `unlock`, `extend`, `shutdown`, `message`) require `name` matching the agent's hostname.
- Timestamp window: ±60 s.
- Agents dial out to the panel reverse port (**9998**) and speak native v3; HTTP `/agent/v1/discover` on **5000** is bootstrap only (env/cache, then agent `/24` scan).
- The web panel **Agent log** page (`/logs/<ip>`) uses `get_logs` over the reverse session.

## State file handling

`state` never silently discards a file: an unusable `daily_settings.json` / `state.json` is renamed to `<name>.corrupt-<timestamp>` and the last good `<name>.bak` (refreshed on every save) is restored. `Store` lists what happened. Values are validated strictly (see `state/doc.go`). A load that fails with an I/O error makes the monitor skip saving, so defaults never overwrite real files.

## Monitoring loop

One iteration of the monitor runs its phases (usage tick, warnings, lock enforcement, periodic save) independently, so an error in one is logged once and never stops the others. Platform query errors fail toward enforcement: an unknown lock state counts as unlocked (so the lock is re-issued), an unknown session state as active (so time is counted). The monitor takes a clock and can be driven deterministically; see `testdata/monitor/vectors.json`.

## Windows Install

- **Cross-user install**: an admin runs `scripts/install_agent.ps1`, and the child account runs the agent. Files go to `C:\ProgramData\KidPCMonitor`; the child gets read+execute via an explicit ACL. See [docs/cross-user-install.md](docs/cross-user-install.md).
- The installer builds `cmd/kid-pc-agent` (or takes `-AgentExe`), installs `kid-pc-agent.exe`, removes leftover files from an older Python agent, and keeps the same task name, settings files, and Fernet secret format. Keep the script ASCII-only (Windows PowerShell 5.1 reads BOM-less scripts as ANSI) and write JSON as UTF-8 **without** a BOM (the agent treats a BOM as corrupt). Dot-sourcing loads the functions without running.
- The kid's PC needs no Git: `install_agent.ps1` is a release asset and runs standalone. Installs keep `version.txt`, a copy of the installer, and `update.cmd` in `C:\ProgramData\KidPCMonitor`. `-Update` installs the latest release and is a no-op when `version.txt` already names it. `-Uninstall` also removes the auto-update task.
- Without Go (or with `-Download`), the installer downloads `kid-pc-agent-windows-<amd64|arm64>.exe` from the GitHub release and verifies it against `SHA256SUMS`. Releases are published by `.github/workflows/release.yml` when a `v*` tag is pushed.
- `scripts/install_web_panel.ps1` installs the web panel on Windows: `-PanelExe`, a build from this checkout, or the release binary checked against `SHA256SUMS`. It copies a legacy auth file, runs `set-secret`, and registers the `KidPCMonitorWebPanel` task (`serve -background`).
- `scripts/install_web_panel_linux.sh install` installs the same panel as a systemd `--user` service (build, `--binary`, or a checked release). `--go` is accepted and changes nothing. The script then calls `kid-pc-web-panel check-firewall` and only suggests firewall or linger changes that are needed.
- The parent host needs inbound **5000** and **9998**.

## State & Logging Paths

- Agent: `%LOCALAPPDATA%\KidPCMonitor\pc_control.log` and state files (Windows).
- Agent log rotation: size-based, matching the original rotating log (200 KiB active file, 4 backups → `pc_control.log.1` …).
- Web panel auth: `%LOCALAPPDATA%\kid-pc-monitor\web_panel_auth.json` (Windows) or `~/.config/kid-pc-monitor/web_panel_auth.json` (Linux/macOS).
- Log level: `KID_PC_MONITOR_LOG_LEVEL` env var (default `INFO`).
- `get_logs` returns only the active `pc_control.log` tail; older lines may be in rotated `.N` siblings on disk.

## Daily Settings

- `daily_settings.json` (merged at install, lives in the agent state dir) controls `wake_time`, `bed_time`, `allowance`.
- Daily usage resets at **wake_time**, not midnight.
- `extend` accumulates; it does not zero already-counted time.

## Common Gotchas

- **Parent firewall must allow 5000 and 9998**: reverse control is inbound on the panel host, not the kid PC.
- The agent re-locks whenever it detects an unlock while any limit (bedtime, allowance, manual lock) is active.
- The panel shows the hostname the agent reports. There is no separate custom-name table.
