#!/usr/bin/env bash
# MSTFAXWSF installer for Kali / Debian-based systems.
# Installs the five scanners (+ seclists wordlists) via apt and adds a `mstfaxwsf` command.
# Usage: ./install.sh [--yes]
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSUME_YES=0
[[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]] && ASSUME_YES=1

RED=$'\e[38;2;255;38;38m'; DIM=$'\e[38;2;150;150;150m'; RST=$'\e[0m'
say() { printf '%s[*]%s %s\n' "$RED" "$RST" "$*"; }
ask() { [[ $ASSUME_YES -eq 1 ]] && return 0; read -r -p "$1 [y/N] " a || return 1; [[ "$a" =~ ^[Yy] ]]; }

command -v apt-get >/dev/null 2>&1 || { echo "apt-get not found. Install the tools manually (see README)."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required."; exit 1; }

SUDO=""
if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo "Run as root or install sudo."; exit 1; }
  SUDO="sudo"
fi

PKGS=(whatweb nikto ffuf nuclei katana seclists)
say "This will run:  $SUDO apt-get update  and install: ${PKGS[*]}"
if ask "Continue?"; then
  $SUDO apt-get update || say "apt-get update failed (continuing)"
  for pkg in "${PKGS[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      say "$pkg already installed"
    elif $SUDO apt-get install -y "$pkg"; then
      say "$pkg installed"
    else
      say "$pkg could not be installed via apt. MSTFAXWSF can retry with 'go install' (mstfaxwsf tools --install)."
    fi
  done
else
  say "Skipped package installation."
fi

chmod +x "$DIR/mstfaxwsf.py"
if ask "Create the 'mstfaxwsf' command in /usr/local/bin?"; then
  printf '#!/usr/bin/env bash\nexec python3 "%s/mstfaxwsf.py" "$@"\n' "$DIR" | $SUDO tee /usr/local/bin/mstfaxwsf >/dev/null
  $SUDO chmod +x /usr/local/bin/mstfaxwsf
  say "Installed. Try:  mstfaxwsf"
else
  say "Run it directly with:  $DIR/mstfaxwsf.py"
fi

if command -v nuclei >/dev/null 2>&1 && ask "Download Nuclei templates now (needs internet)?"; then
  nuclei -update-templates || say "Template update failed; run 'mstfaxwsf templates' later."
fi
printf '%sDone. Only scan systems you own or are explicitly authorized to test.%s\n' "$DIM" "$RST"
