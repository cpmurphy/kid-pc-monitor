#!/usr/bin/env bash
# Install the Kid PC Monitor web panel as a systemd --user service (Linux only).
# Requires: systemd, bash. Uses the repo layout: this file lives in scripts/.
#
# `install` does everything: it finds or creates a virtualenv with Python 3.11+
# (using uv to download Python when the system has none), installs the package,
# asks for the shared secret, starts the service, and then checks whether
# lingering or firewall changes are actually needed before suggesting them.

set -euo pipefail

UNIT_NAME="kid-pc-monitor-web-panel.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/src"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_PATH="${UNIT_DIR}/${UNIT_NAME}"
PANEL_PORT=5000
REVERSE_PORT=9998
# Keep in sync with requires-python in pyproject.toml.
MIN_PYTHON="3.11"
UV_INSTALL_URL="https://astral.sh/uv/install.sh"

# Set by ensure_venv.
VENV_DIR=""
VENV_PY=""

usage() {
    cat <<'EOF'
Usage: install_web_panel_linux.sh <command>

Commands:
  install     Set up the virtualenv, install the panel, enable and start the service.
              Safe to re-run (e.g. after git pull) to update dependencies and restart.
  uninstall   Stop, disable, and remove the user unit.
  status      Show systemctl --user status.
  cat-unit    Print the unit file that would be used (no writes).

Environment (optional):
  PYTHON      Python 3.11+ used to create the virtualenv when the repo has none
              (default: the newest python3 on PATH, else uv-managed Python)
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

require_linux() {
    case "$(uname -s)" in
        Linux) ;;
        *) die "This script is for Linux only (found: $(uname -s))." ;;
    esac
}

require_systemctl_user() {
    systemctl --user status >/dev/null 2>&1 || die \
        "systemctl --user failed. Is systemd user session available? Try: loginctl enable-linger \"$USER\" (may require sudo) or log in once with a desktop session."
}

# Run a command and exit this script on any non-zero status.
# An explicit exit is required: set -e does not fire when the caller uses
# `if` or `||`, and a failed Python command must not continue the install.
run_python() {
    local status=0
    "$@" || status=$?
    if [[ "$status" -ne 0 ]]; then
        exit "$status"
    fi
}

# Ask a yes/no question on the terminal; $2 is the default (y or n).
# Without a terminal the default is "no" so unattended runs never escalate.
confirm() {
    local prompt="$1" default="$2" answer hint="[y/N]"
    [[ "$default" == "y" ]] && hint="[Y/n]"
    [[ -t 0 ]] || return 1
    read -r -p "$prompt $hint " answer || return 1
    answer="${answer:-$default}"
    [[ "$answer" == [Yy]* ]]
}

python_is_supported() {
    "$1" -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PYTHON/./, }) else 1)" \
        >/dev/null 2>&1
}

# A venv works when its Python runs and still matches pyvenv.cfg; importing
# the package runs that check and exits non-zero after a Python upgrade.
venv_is_healthy() {
    python_is_supported "$1" && env PYTHONPATH="${SRC_DIR}" "$1" -c 'import kid_pc_monitor' >/dev/null 2>&1
}

existing_venv_dir() {
    local dir
    for dir in "${REPO_ROOT}/venv" "${REPO_ROOT}/.venv"; do
        if [[ -e "${dir}/pyvenv.cfg" || -e "${dir}/bin/python3" ]]; then
            echo "$dir"
            return
        fi
    done
}

# Print a system Python new enough to build the venv, or fail.
pick_base_python() {
    if [[ -n "${PYTHON:-}" ]]; then
        echo "$PYTHON"
        return
    fi
    local candidate path
    for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
        path="$(command -v "$candidate" 2>/dev/null)" || continue
        if python_is_supported "$path"; then
            echo "$path"
            return
        fi
    done
    return 1
}

# Print the path to uv, offering to install it into ~/.local/bin if missing.
find_or_install_uv() {
    local candidate
    for candidate in "$(command -v uv 2>/dev/null || true)" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [[ -n "$candidate" && -x "$candidate" ]]; then
            echo "$candidate"
            return
        fi
    done
    {
        echo ""
        echo "No usable Python ${MIN_PYTHON}+ was found on this system."
        echo "uv (https://docs.astral.sh/uv/) can download a private copy of Python for"
        echo "the panel without touching the system Python. It installs to ~/.local/bin."
    } >&2
    if ! confirm "Install uv now?" y; then
        die "Install Python ${MIN_PYTHON}+ (e.g. sudo apt install python3 python3-venv) or uv, then re-run."
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf "$UV_INSTALL_URL" | env UV_NO_MODIFY_PATH=1 sh >&2
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$UV_INSTALL_URL" | env UV_NO_MODIFY_PATH=1 sh >&2
    else
        die "Neither curl nor wget is available to download uv."
    fi
    [[ -x "$HOME/.local/bin/uv" ]] || die "uv install did not produce ~/.local/bin/uv."
    echo "$HOME/.local/bin/uv"
}

create_venv() {
    local dir="$1" base uv
    if [[ -n "${PYTHON:-}" ]] && ! python_is_supported "$PYTHON"; then
        die "PYTHON ($PYTHON) is not a runnable Python ${MIN_PYTHON}+."
    fi
    if base="$(pick_base_python)"; then
        echo "Creating virtualenv ${dir} with ${base}"
        if "$base" -m venv --clear "$dir"; then
            return
        fi
        echo "'${base} -m venv' failed (on Debian/Ubuntu the python3-venv package may be missing)."
    fi
    uv="$(find_or_install_uv)"
    echo "Creating virtualenv ${dir} with uv (downloads Python ${MIN_PYTHON}+ if needed)"
    "$uv" venv --clear --seed --python ">=${MIN_PYTHON}" "$dir"
}

# Reuse a working repo venv, recreate a broken one, or create venv/.
ensure_venv() {
    local dir
    dir="$(existing_venv_dir)"
    if [[ -n "$dir" ]] && venv_is_healthy "${dir}/bin/python3"; then
        echo "Using virtualenv: $dir"
    elif [[ -n "$dir" ]]; then
        echo "The virtualenv at ${dir} no longer works (its Python was upgraded or removed); recreating it."
        create_venv "$dir"
    else
        dir="${REPO_ROOT}/venv"
        create_venv "$dir"
    fi
    VENV_DIR="$dir"
    VENV_PY="${dir}/bin/python3"
}

install_package() {
    echo "Installing kid-pc-monitor and its dependencies into ${VENV_DIR} ..."
    if ! "$VENV_PY" -m pip --version >/dev/null 2>&1; then
        run_python "$VENV_PY" -m ensurepip --upgrade
    fi
    run_python "$VENV_PY" -m pip install --quiet --disable-pip-version-check -e "$REPO_ROOT"
    run_python env PYTHONPATH="${SRC_DIR}" "$VENV_PY" -c 'import kid_pc_monitor.web_panel'
}

# Print a systemd user unit to stdout (paths must not contain shell metacharacters).
render_unit() {
    local venv_dir="$1"
    cat <<EOF
[Unit]
Description=Kid PC Monitor web panel (parent UI on port ${PANEL_PORT})
After=network.target

[Service]
Type=simple
WorkingDirectory=${REPO_ROOT}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${SRC_DIR}
ExecStart=${venv_dir}/bin/kid-pc-web-panel
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
}

write_unit() {
    mkdir -p "$UNIT_DIR"
    render_unit "$VENV_DIR" >"$UNIT_PATH"
    echo "Wrote: $UNIT_PATH"
}

# Prompt for and store the panel <-> agent shared secret via the Python helper,
# so the guidance and storage match the other installers.
prompt_shared_secret() {
    run_python env PYTHONPATH="${SRC_DIR}" "$VENV_PY" -c 'from kid_pc_monitor.shared_secret import prompt_and_store_shared_secret; prompt_and_store_shared_secret()'
}

# Wait briefly for the service to listen so a crash shows up now, not later.
wait_for_panel() {
    local _
    if command -v ss >/dev/null 2>&1; then
        for _ in $(seq 1 15); do
            if ss -Hltn "sport = :${PANEL_PORT}" 2>/dev/null | grep -q . \
                && systemctl --user is-active --quiet "$UNIT_NAME"; then
                return 0
            fi
            sleep 1
        done
    elif systemctl --user is-active --quiet "$UNIT_NAME"; then
        return 0
    fi
    echo "Warning: the panel is not listening on port ${PANEL_PORT}."
    echo "  See why with: journalctl --user -u ${UNIT_NAME} -e"
    return 1
}

panel_url() {
    env PYTHONPATH="${SRC_DIR}" "$VENV_PY" -c '
from kid_pc_monitor.network import get_local_ip
from kid_pc_monitor.paths import resolve_tls_cert_paths
scheme = "https" if resolve_tls_cert_paths() else "http"
print(f"{scheme}://{get_local_ip()}:'"${PANEL_PORT}"'")
' 2>/dev/null || echo "http://<this-host-ip>:${PANEL_PORT}"
}

# User services stop at logout and only start at login unless lingering is on.
check_linger() {
    local user linger
    user="${USER:-$(id -un)}"
    linger="$(loginctl show-user "$user" --property=Linger --value 2>/dev/null || true)"
    if [[ "$linger" == "yes" ]]; then
        echo "Start at boot: enabled (lingering is on for ${user})."
        return
    fi
    echo "Start at boot: not enabled. Without lingering, the panel only runs while"
    echo "  ${user} is logged in. To keep it running after reboots and logouts:"
    echo "    sudo loginctl enable-linger ${user}"
    if confirm "  Run this now with sudo?" n; then
        sudo loginctl enable-linger "$user" || echo "  Could not enable lingering; run the command above later."
    fi
}

check_firewall() {
    env PYTHONPATH="${SRC_DIR}" "$VENV_PY" -m kid_pc_monitor.linux_firewall --interactive \
        "$PANEL_PORT" "$REVERSE_PORT" \
        || echo "  (Firewall changes were not applied; see the commands above.)"
}

cmd_install() {
    require_linux
    require_systemctl_user
    ensure_venv
    install_package
    prompt_shared_secret
    write_unit
    systemctl --user daemon-reload
    systemctl --user enable "$UNIT_NAME"
    systemctl --user restart "$UNIT_NAME"
    echo ""
    if wait_for_panel; then
        echo "Service is enabled and running. Check: systemctl --user status $UNIT_NAME"
        echo "Open: $(panel_url)"
    fi
    echo ""
    check_linger
    echo ""
    check_firewall
    echo ""
    echo "iPhone password autofill: see docs/FAQ.md for instructions to run with trusted HTTPS."
}

cmd_uninstall() {
    require_linux
    systemctl --user disable --now "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_PATH"
    systemctl --user daemon-reload
    echo "Removed $UNIT_NAME (if it was present)."
}

cmd_status() {
    require_linux
    systemctl --user status "$UNIT_NAME" || true
}

cmd_cat_unit() {
    require_linux
    local dir
    dir="$(existing_venv_dir)"
    echo "# Preview (not written to disk):"
    render_unit "${dir:-${REPO_ROOT}/venv}"
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        install) cmd_install ;;
        uninstall) cmd_uninstall ;;
        status) cmd_status ;;
        cat-unit) cmd_cat_unit ;;
        -h|--help|help) usage ;;
        *) usage; exit 1 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
