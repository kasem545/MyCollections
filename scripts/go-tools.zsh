# ~/.zshrc (or ~/.zsh/functions/go-tools.zsh)

# ---- Go tool helpers (for ~/go/bin style workflows) ----

# Print Go tool install dir (GOBIN if set, else GOPATH/bin)
# Help menu for the Go tool helpers above
gohelp() {
  cat <<'EOF'
Go Tool Helper Functions (zsh)

CORE
  gobin
    Prints the Go install bin directory:
      - go env GOBIN (if set)
      - else: $(go env GOPATH)/bin

  go_pathfix
    Ensures the Go bin directory is on your PATH for the current shell.

INVENTORY / FORENSICS
  go_mods [DIR]
    Lists binaries in DIR (default: gobin) that contain Go module metadata,
    printing: <binary> <module-path>

    Example:
      go_mods
      go_mods ~/go/bin

  go_modof <binary|/full/path>
    Prints the embedded module path for a given binary.
    Works best when the binary was installed/built with module info.

    Examples:
      go_modof anew
      go_modof ~/go/bin/anew

UPDATE / INSTALL
  goup <binary>
    Updates a single tool by binary name using its embedded module path:
      go install <module>@latest

    Example:
      goup anew

  goupall [-p N] [-d DIR]
    Updates all Go module binaries found in DIR (default: gobin).
      -p N   Parallel installs (default: 4)
      -d DIR Directory to scan

    Examples:
      goupall
      goupall -p 8
      goupall -d ~/go/bin -p 6

  goinstall <module-path>[@version]
    Installs/updates directly by module path.
    If @version is omitted, uses @latest.

    Examples:
      goinstall github.com/tomnomnom/anew
      goinstall github.com/tomnomnom/anew@latest
      goinstall github.com/tomnomnom/anew@v0.2.0

NOTES / GOTCHAS
  - If a binary has no module metadata, go_mods/goup/goupall may skip it.
    (That can happen if it was built old-school, stripped, or isn't a Go tool.)
  - You can inspect metadata manually with:
      go version -m /path/to/binary
EOF
}

# Optional: short alias
alias goh='gohelp'


gobin() {
  local gobin
  gobin="$(go env GOBIN 2>/dev/null)"
  if [[ -n "$gobin" ]]; then
    print -r -- "$gobin"
  else
    print -r -- "$(go env GOPATH 2>/dev/null)/bin"
  fi
}

# List module paths embedded in binaries (inventory)
go_mods() {
  local dir="${1:-$(gobin)}"
  [[ -d "$dir" ]] || { print -u2 "No such dir: $dir"; return 1; }

  local b mod
  for b in "$dir"/*(N); do
    mod="$(go version -m "$b" 2>/dev/null | awk '$1=="path"{print $2; exit}')"
    [[ -n "$mod" ]] && print -r -- "$(basename "$b")\t$mod"
  done | column -t
}

# Find the module path for a specific installed binary
go_modof() {
  local bin="$1"
  [[ -n "$bin" ]] || { print -u2 "Usage: go_modof <binary|/full/path>"; return 1; }

  local path="$bin"
  if [[ "$bin" != /* ]]; then
    path="$(command -v -- "$bin" 2>/dev/null)"
  fi
  [[ -n "$path" && -f "$path" ]] || { print -u2 "Binary not found: $bin"; return 1; }

  local mod
  mod="$(go version -m "$path" 2>/dev/null | awk '$1=="path"{print $2; exit}')"
  [[ -n "$mod" ]] || { print -u2 "No module metadata in: $path"; return 2; }

  print -r -- "$mod"
}

# Update ONE tool by binary name (uses embedded module path)
goup() {
  local bin="$1"
  [[ -n "$bin" ]] || { print -u2 "Usage: goup <binary>"; return 1; }

  local mod
  mod="$(go_modof "$bin")" || return $?
  print -r -- "[*] Updating $bin -> $mod@latest"
  go install "$mod"@latest
}

# Update ALL go-installed tools in dir (default: $(gobin))
# Options:
#   -p N   parallelism (default 4)
#   -d DIR directory to scan (default $(gobin))
goupall() {
  local parallel=4
  local dir="$(gobin)"

  while getopts "p:d:" opt; do
    case "$opt" in
      p) parallel="$OPTARG" ;;
      d) dir="$OPTARG" ;;
      *) print -u2 "Usage: goupall [-p parallel] [-d dir]"; return 1 ;;
    esac
  done
  shift $((OPTIND-1))

  [[ -d "$dir" ]] || { print -u2 "No such dir: $dir"; return 1; }

  # Collect unique module paths from binaries (skip non-Go/non-module)
  local mods
  mods="$(
    local b
    for b in "$dir"/*(N); do
      go version -m "$b" 2>/dev/null | awk '$1=="path"{print $2; exit}'
    done | sed '/^$/d' | sort -u
  )"

  [[ -n "$mods" ]] || { print -u2 "No updatable Go module binaries found in: $dir"; return 2; }

  print -r -- "[*] Updating $(print -r -- "$mods" | wc -l | tr -d ' ') tools from: $dir (parallel=$parallel)"
  print -r -- "$mods" | xargs -n1 -P"$parallel" -I{} sh -c 'echo "[*] go install {}@latest"; go install "{}@latest"'
}

# Quick install/update when you only know the module path
goinstall() {
  local mod="$1"
  [[ -n "$mod" ]] || { print -u2 "Usage: goinstall <module-path>[@version]"; return 1; }
  # If no @version provided, default to @latest
  if [[ "$mod" == *@* ]]; then
    go install "$mod"
  else
    go install "$mod"@latest
  fi
}

# Convenience: ensure Go bin dir is on PATH in the current shell
go_pathfix() {
  local dir="$(gobin)"
  if [[ ":$PATH:" != *":$dir:"* ]]; then
    export PATH="$dir:$PATH"
    print -r -- "[*] Added to PATH: $dir"
  else
    print -r -- "[*] PATH already contains: $dir"
  fi
}

