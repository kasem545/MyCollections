#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ========== Pretty colors & helpers ==========
ESCAPE_SEQ='\033['
RESET="${ESCAPE_SEQ}0m"
BOLD="${ESCAPE_SEQ}1m"
DIM="${ESCAPE_SEQ}2m"

RED="${ESCAPE_SEQ}31m"
GREEN="${ESCAPE_SEQ}32m"
YELLOW="${ESCAPE_SEQ}33m"
BLUE="${ESCAPE_SEQ}34m"
MAGENTA="${ESCAPE_SEQ}35m"
CYAN="${ESCAPE_SEQ}36m"

info()    { printf "%b %b%s%b\n" "🛈" "${BOLD}${BLUE}" "$1" "${RESET}"; }
step()    { printf "%b %b%s%b\n" "▶" "${BOLD}${CYAN}" "$1" "${RESET}"; }
success() { printf "%b %b%s%b\n" "✔" "${BOLD}${GREEN}" "$1" "${RESET}"; }
warn()    { printf "%b %b%s%b\n" "⚠" "${BOLD}${YELLOW}" "$1" "${RESET}"; }
error()   { printf "%b %b%s%b\n" "✖" "${BOLD}${RED}" "$1" "${RESET}" >&2; }

# trap for graceful exit
on_exit() {
  local rc=$?
  if [ $rc -ne 0 ]; then
    error "Script exited with error code $rc"
  fi
}
trap on_exit EXIT

# ========== Configuration ==========
DEST_DIR="/opt"
REPOS=(
  "https://github.com/sham00n/buster.git"
  "https://github.com/xm1k3/cent.git"
  "https://github.com/BishopFox/cloudfox.git"
  "https://github.com/aquasecurity/cloudsploit.git"
  "https://github.com/cve-search/cve-search.git"
  "https://github.com/hahwul/dalfox.git"
  "https://github.com/imthaghost/goclone.git"
  "https://github.com/pemistahl/grex.git"
  "https://github.com/HavocFramework/Havoc.git"
  "https://github.com/fortra/impacket.git"
  "https://github.com/ropnop/kerbrute.git"
  "https://github.com/deathmarine/Luyten.git"
  "https://github.com/samratashok/nishang.git"
  "https://github.com/ayadim/Nuclei-bug-hunter.git"
  "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
  "https://github.com/BishopFox/sliver.git"
  "https://github.com/trufflesecurity/trufflehog.git"
  "https://github.com/0xKayala/ParamSpider.git"
  "https://github.com/cathugger/mkp224o.git"
  "https://github.com/gotr00t0day/spyhunt.git"
  "https://github.com/trickest/cve.git"
  "https://github.com/Flangvik/SharpCollection.git"
  "https://github.com/urbanadventurer/username-anarchy.git"
  "https://github.com/nicocha30/ligolo-ng.git"
  "https://github.com/x90skysn3k/brutespray.git"
  "https://github.com/GerbenJavado/LinkFinder.git"
  "https://github.com/hakluke/hakrawler.git"
  
)

# Commands considered dependencies (package names for apt are attempted install names)
APT_PACKAGES=(curl wget gcc make build-essential golang-go python3 python3-pip python3-venv pipx parallel jq unzip git docker.io docker-compose)
# note: we won't try to install "golang-src" etc as package names are distro-specific

# ========== Utilities ==========
repo_name_from_url() {
  local url="$1"
  local base="${url##*/}"
  base="${base%.git}"
  base="${base%%/*}"
  printf '%s' "$base"
}

is_valid_git_url() {
  local url="$1"
  if [[ "$url" =~ ^https?:// ]] && [[ "$url" == *.git ]]; then
    return 0
  fi
  if [[ "$url" =~ ^git@ ]]; then
    return 0
  fi
  return 1
}

# ========== Dependency checks & install ==========
check_dependencies() {
  info "Checking for system dependencies..."
  local missing=()
  for pkg in "${APT_PACKAGES[@]}"; do
    # try to check for binary presence for common tools, else fallback to apt package name
    case "$pkg" in
      docker-compose)
        if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
          missing+=("$pkg")
        fi
        ;;
      pipx)
        if ! command -v pipx &>/dev/null; then
          missing+=("$pkg")
        fi
        ;;
      *)
        if ! command -v "${pkg%%-*}" &>/dev/null && ! dpkg -s "$pkg" &>/dev/null 2>/dev/null; then
          missing+=("$pkg")
        fi
        ;;
    esac
  done

  if [ ${#missing[@]} -eq 0 ]; then
    success "All system dependencies present."
    return 0
  fi

  warn "Missing packages: ${missing[*]}"
  step "Installing missing packages via apt (requires sudo)..."
  sudo apt update -y
  sudo apt install -y "${missing[@]}" || {
    error "Failed to install some apt packages. Please install them manually and re-run."
    return 1
  }

  # ensure pipx is available and on PATH
  if ! command -v pipx &>/dev/null; then
    step "Installing pipx via pip..."
    python3 -m pip install --user pipx || true
    python3 -m pipx ensurepath || true
    export PATH="$PATH:$HOME/.local/bin"
  fi

  success "Dependencies installed."
  return 0
}

# ========== Git clone / update ==========
install_git_repos() {
  step "Preparing destination: $DEST_DIR"
  sudo mkdir -p "$DEST_DIR"
  sudo chown "$(id -u):$(id -g)" "$DEST_DIR" || true

  for repo in "${REPOS[@]}"; do
    if ! is_valid_git_url "$repo"; then
      warn "Skipping invalid/unsupported git URL: $repo"
      continue
    fi

    name=$(repo_name_from_url "$repo")
    target="$DEST_DIR/$name"

    if [ -d "$target/.git" ]; then
      info "Updating $name..."
      if ! git -C "$target" pull --ff-only --rebase; then
        warn "git pull failed for $name — attempting a safe fetch"
        git -C "$target" fetch --all --prune || warn "fetch failed for $name"
      fi
      success "Updated $name"
    else
      info "Cloning $name → $target"
      if git clone --depth 1 "$repo" "$target"; then
        success "Cloned $name"
      else
        warn "Clone failed for $repo. Skipping."
        continue
      fi
    fi

    # sane permissions
    chmod -R u+rwX,go+rX,go-w "$target" || true
  done
}

# ========== Go tools ==========
install_go_tools() {
  if ! command -v go &>/dev/null; then
    warn "Go not found in PATH. Skipping Go tool installs."
    return 0
  fi

  info "Installing Go tools (go env GOPATH: $(go env GOPATH 2>/dev/null || echo 'unset'))"
  # ensure GOPATH/bin is on PATH for immediate use
  export PATH="$(go env GOPATH 2>/dev/null)/bin:${PATH:-/usr/local/bin}"

  local go_tools=(
    "github.com/takshal/freq@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/takshal/bfxss@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gron@latest"
    "github.com/hakluke/hakcheckurl@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/ffuf/pencode/cmd/pencode@latest"
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    "github.com/glitchedgitz/cook/v2/cmd/cook@latest"
    "github.com/GoToolSharing/htb-cli@latest"
  )

  for tool in "${go_tools[@]}"; do
    step "go install $tool"
    if ! go install "$tool"; then
      warn "go install failed for $tool — continuing"
    else
      success "Installed $(basename "$tool" | cut -d@ -f1)"
    fi
  done
}

# ========== Python tools via pipx ==========
install_python_tools() {
  if ! command -v pipx &>/dev/null; then
    warn "pipx not found; skipping Python tool installs."
    return 0
  fi

  info "Installing Python tools via pipx..."
  local py_tools=(
    "git+https://github.com/dwisiswant0/apkleaks.git"
    "git+https://github.com/s0md3v/Arjun.git"
    "git+https://github.com/s0md3v/uro.git"
    "git+https://github.com/sherlock-project/sherlock.git"
    "git+https://github.com/brightio/penelope.git"
  )

  for pkg in "${py_tools[@]}"; do
    step "pipx install $pkg"
    if ! pipx install --force "$pkg"; then
      warn "pipx install failed for $pkg; attempting pipx install without --force"
      pipx install "$pkg" || warn "pipx still failed for $pkg"
    else
      success "Installed $(basename "$pkg")"
    fi
  done
}

# ========== exploitdb (go-exploitdb) ==========
exploitdb() {
  local repo_path="${GOPATH:-$HOME/go}/src/github.com/vulsio/go-exploitdb"
  step "Installing/updating go-exploitdb in $repo_path"
  mkdir -p "$(dirname "$repo_path")"
  if [ ! -d "$repo_path" ]; then
    if git clone https://github.com/vulsio/go-exploitdb.git "$repo_path"; then
      success "Cloned go-exploitdb"
    else
      warn "Failed to clone go-exploitdb"
      return 1
    fi
  else
    info "Updating go-exploitdb"
    git -C "$repo_path" pull || warn "Failed to update go-exploitdb"
  fi

  cd "$repo_path" || return 1
  if make install; then
    success "go-exploitdb installed"
  else
    warn "make install failed for go-exploitdb"
  fi
}

# ========== BloodHound CLI (optional) ==========
install_bloodhound() {
  if ! command -v wget &>/dev/null; then
    warn "wget missing; cannot install bloodhound-cli automatically."
    return 0
  fi

  info "Installing BloodHound CLI (if available)"
  local tmp="/tmp/bloodhound-cli-linux-amd64.tar.gz"
  if wget -q -O "$tmp" "https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz"; then
    sudo tar -xvzf "$tmp" -C /usr/local/bin/ || warn "tar extraction warning"
    sudo chmod +x /usr/local/bin/bloodhound-cli || true
    success "BloodHound CLI binary installed to /usr/local/bin/"
  else
    warn "Could not download BloodHound CLI release (maybe no internet or release missing)."
  fi
}

install_ronin() {
  info "Attempting Ronin install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -sSL "https://raw.githubusercontent.com/ronin-rb/scripts/main/ronin-install.sh" | bash; then
      success "Ronin installed"
    else
      warn "Ronin install script failed"
    fi
  else
    warn "curl not present; cannot install Ronin automatically."
  fi
}

font_packages_install() {
  local font_dir="${HOME}/.local/share/fonts"
  local tmp="/tmp/hack-nerd-font.zip"
  local url="https://github.com/ryanoasis/nerd-fonts/releases/download/v3.4.0/Hack.zip"

  step "Preparing font directory: $font_dir"
  mkdir -p "$font_dir" || { error "mkdir failed"; return 1; }

  info "Installing Hack Nerd Font (for better terminal experience)"

  if ! command -v unzip &>/dev/null; then
    warn "unzip not found. Installing..."
    sudo apt update -y && sudo apt install -y unzip || {
      error "Failed to install unzip. Aborting font install."
      return 1
    }
  fi

  if command -v wget &>/dev/null; then
    step "Downloading Hack Nerd Font..."
    if wget -q -O "$tmp" "$url"; then
      step "Extracting fonts to $font_dir..."
      unzip -oq "$tmp" -d "$font_dir" || warn "Font extraction warning"
      fc-cache -fv >/dev/null 2>&1
      success "Hack Nerd Font installed successfully."
    else
      error "Failed to download font from $url"
      return 1
    fi
  else
    error "wget not found. Please install wget or curl before running this."
    return 1
  fi

  rm -f "$tmp"
}

# ========== MAIN ==========
main() {
  info "Starting installer (pretty mode enabled)"

  check_dependencies
  font_packages_install
  install_git_repos
  install_go_tools
  install_python_tools
  exploitdb
  install_bloodhound
  install_ronin

  success "All done — repos + tools attempted. Inspect the output for any warnings."
  info "Tips: Run this as a user with sudo privileges. Some installs (docker, go) may need manual follow-up."
}

# run when invoked, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
