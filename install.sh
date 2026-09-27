#!/usr/bin/env bash
#
# WireCub installer for Debian-family Linux (Kali, Ubuntu, Mint, Debian).
#
# Installs into a virtual environment so nothing touches the system Python.
# Only Python and pip are required: WireCub parses captures itself and does
# not call tshark, tcpdump, Zeek or any other external tool.

set -euo pipefail

INSTALL_DIR="${WIRECUB_HOME:-$HOME/.local/share/wirecub}"
BIN_LINK="${HOME}/.local/bin/wirecub"
PORT="${WIRECUB_PORT:-8000}"
# WireCub has no login of its own when run locally, so it listens on this
# machine only. Set WIRECUB_HOST=0.0.0.0 to expose it deliberately.
HOST="${WIRECUB_HOST:-127.0.0.1}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CYAN=$'\033[36m'; BLUE=$'\033[34m'; DIM=$'\033[2m'
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'

say()  { printf '%s==>%s %s\n' "$CYAN" "$OFF" "$1"; }
warn() { printf '%s !%s  %s\n' "$YELLOW" "$OFF" "$1"; }
die()  { printf '%s ✗%s  %s\n' "$RED" "$OFF" "$1" >&2; exit 1; }
ok()   { printf '%s ✓%s  %s\n' "$GREEN" "$OFF" "$1"; }

banner() {
  printf '\n%s' "$BLUE"
  cat <<'ART'
 ┌──────────────────────────────────────────┐
 │   W I R E C U B                          │
 │   packet capture analysis                │
 └──────────────────────────────────────────┘
ART
  printf '%s\n' "$OFF"
}

detect_distro() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    DISTRO_ID="unknown"; DISTRO_NAME="unknown Linux"; DISTRO_LIKE=""
  fi

  case "$DISTRO_ID $DISTRO_LIKE" in
    *kali*|*ubuntu*|*debian*|*linuxmint*|*mint*|*pop*|*elementary*|*raspbian*)
      FAMILY="debian" ;;
    *fedora*|*rhel*|*centos*)   FAMILY="fedora" ;;
    *arch*|*manjaro*)           FAMILY="arch" ;;
    *)                          FAMILY="unknown" ;;
  esac
}

need_sudo() {
  if [[ $EUID -eq 0 ]]; then SUDO=""; else
    command -v sudo >/dev/null 2>&1 || die "sudo is required but not installed."
    SUDO="sudo"
  fi
}

install_python() {
  say "Installing Python prerequisites"
  need_sudo
  case "$FAMILY" in
    debian)
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -qq python3 python3-venv python3-pip
      ;;
    fedora) $SUDO dnf install -y python3 python3-pip ;;
    arch)   $SUDO pacman -Sy --noconfirm python python-pip ;;
    *)      die "Unsupported distribution. Install Python 3.11+ manually, then re-run." ;;
  esac
}

check_python() {
  local candidate version major minor
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      version="$("$candidate" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo 0.0)"
      major="${version%%.*}"; minor="${version##*.}"
      if (( major == 3 && minor >= 11 )); then
        PYTHON="$candidate"
        ok "Found Python $version at $(command -v "$candidate")"
        return 0
      fi
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------

banner
detect_distro
say "Detected ${DISTRO_NAME}"

if ! check_python; then
  warn "Python 3.11 or newer was not found."
  install_python
  check_python || die "Still no suitable Python after installing. Install 3.11+ manually."
fi

if ! "$PYTHON" -c 'import venv' >/dev/null 2>&1; then
  warn "The venv module is missing."
  install_python
fi

say "Installing to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/backend" "$INSTALL_DIR/public"
cp -r "$SOURCE_DIR/backend" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/public" "$INSTALL_DIR/"
find "$INSTALL_DIR/backend" -name __pycache__ -type d -prune -exec rm -rf {} +
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/data"

say "Creating the virtual environment"
"$PYTHON" -m venv "$INSTALL_DIR/venv"

say "Installing dependencies"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
ok "Dependencies installed"

say "Creating the launcher"
mkdir -p "$(dirname "$BIN_LINK")"
cat > "$BIN_LINK" <<LAUNCHER
#!/usr/bin/env bash
# Starts the WireCub server and opens the interface.
set -euo pipefail
PORT="\${WIRECUB_PORT:-${PORT}}"
HOST="\${WIRECUB_HOST:-${HOST}}"
export WIRECUB_DATA="\${WIRECUB_DATA:-${INSTALL_DIR}/data}"

cd "${INSTALL_DIR}/backend"

printf '\n  WireCub is starting on http://localhost:%s\n' "\$PORT"
printf '  Press Ctrl-C to stop.\n\n'

if command -v xdg-open >/dev/null 2>&1; then
  ( sleep 2; xdg-open "http://localhost:\$PORT" >/dev/null 2>&1 || true ) &
fi

exec "${INSTALL_DIR}/venv/bin/uvicorn" app:app --host "\$HOST" --port "\$PORT"
LAUNCHER
chmod +x "$BIN_LINK"
ok "Launcher written to $BIN_LINK"

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  warn "$HOME/.local/bin is not on your PATH."
  for profile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$profile" ]] || continue
    grep -q '.local/bin' "$profile" 2>/dev/null && continue
    printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$profile"
    ok "Added it to $(basename "$profile")"
  done
  warn "Open a new terminal, or run: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# Optional: run at boot as the current user.
if [[ "${1:-}" == "--service" ]]; then
  say "Installing the systemd service"
  need_sudo
  $SUDO tee /etc/systemd/system/wirecub.service >/dev/null <<UNIT
[Unit]
Description=WireCub packet capture analysis
After=network.target

[Service]
Type=simple
User=${USER}
Environment=WIRECUB_DATA=${INSTALL_DIR}/data
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app:app --host ${HOST} --port ${PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now wirecub
  ok "Service enabled. Check it with: systemctl status wirecub"
fi

printf '\n'
ok "WireCub is installed"
printf '\n  Start it:      %swirecub%s\n' "$CYAN" "$OFF"
printf '  Then open:     %shttp://localhost:%s%s\n' "$CYAN" "$PORT" "$OFF"
printf '  Run at boot:   %s./install.sh --service%s\n' "$DIM" "$OFF"
printf '  Uninstall:     %srm -rf %s %s%s\n\n' "$DIM" "$INSTALL_DIR" "$BIN_LINK" "$OFF"
