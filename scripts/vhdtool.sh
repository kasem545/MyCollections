#!/usr/bin/env bash
# ==============================================================================
#  vhdx.sh — Professional VHD/VHDX Mount Utility for Linux
#  Author  : vhdx.sh
#  Version : 2.0.0
#  Requires: qemu-utils, nbd-client, dislocker (for BitLocker)
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── constants ──────────────────────────────────────────────────────────────────
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly NBD_DEV="/dev/nbd0"
readonly NBD_PART="${NBD_DEV}p1"
readonly DISLOCKER_DIR="/mnt/dislocker_tmp"
readonly LOG_FILE="/tmp/vhdx_$$.log"

# ── ansi colors ────────────────────────────────────────────────────────────────
if [[ "${NO_COLOR:-}" == "" ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ── logging ────────────────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $*" >&2; }
log_error()   { echo -e "${RED}[-]${RESET} $*" >&2; }
log_section() { echo -e "\n${BOLD}${DIM}── $* ${RESET}"; }

# ── error handling ─────────────────────────────────────────────────────────────
die() { log_error "$*"; exit 1; }

# trap unexpected errors and print the line that failed
trap 'log_error "Unexpected error at line ${LINENO}. Check ${LOG_FILE} for details."' ERR

# redirect stderr to log file while keeping it visible
exec 2> >(tee -a "$LOG_FILE" >&2)

# ── dependency check ───────────────────────────────────────────────────────────
check_deps() {
    local deps=("$@")
    local missing=()
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing dependencies: ${missing[*]}. Run: ${SCRIPT_NAME} install"
    fi
}

# ── require root ──────────────────────────────────────────────────────────────
require_root() {
    [[ $EUID -eq 0 ]] || die "This command must be run as root (use sudo)."
}

# ── usage ──────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}${SCRIPT_NAME}${RESET} v${VERSION} — VHD/VHDX Mount Utility"
    echo
    echo -e "${BOLD}USAGE${RESET}"
    echo    "  ${SCRIPT_NAME} <command> [options]"
    echo
    echo -e "${BOLD}COMMANDS${RESET}"
    echo    "  install                              Install required dependencies"
    echo    "  mount    <image> <mountpoint>        Mount a VHD/VHDX image"
    echo    "  umount   <mountpoint>                Unmount a VHD/VHDX image"
    echo    "  bitlocker <image> <mountpoint>       Mount a BitLocker-encrypted VHD/VHDX"
    echo    "             [-p <password>]             User password"
    echo    "             [-r <recovery_key>]         48-digit recovery key"
    echo    "             [-k <keyfile>]              BEK keyfile path"
    echo    "  bitlocker-umount <mountpoint>        Unmount a BitLocker volume"
    echo    "  status                               Show current NBD device status"
    echo    "  version                              Show version"
    echo
    echo -e "${BOLD}SUPPORTED FORMATS${RESET}"
    echo    "  .vhd   (Microsoft Virtual PC — vpc)"
    echo    "  .vhdx  (Hyper-V — vhdx)"
    echo    "  other  (auto-detected via qemu-img)"
    echo
    exit 0
}

# ── detect image format ────────────────────────────────────────────────────────
# Extension takes priority — qemu-img may misdetect VHD as raw
detect_fmt() {
    local img="$1"
    local ext fmt
    ext="${img##*.}"
    case "${ext^^}" in
        VHD)  echo "vpc";  return ;;
        VHDX) echo "vhdx"; return ;;
    esac
    # fallback: let qemu-img probe it
    fmt=$(qemu-img info "$img" 2>/dev/null \
          | awk -F': ' '/^file format/{print $2}' \
          | tr -d '[:space:]')
    echo "${fmt:-raw}"
}

# ── nbd lifecycle ──────────────────────────────────────────────────────────────
nbd_load() {
    log_info "Loading nbd kernel module (max_part=16)..."
    rmmod nbd 2>/dev/null || true
    modprobe nbd max_part=16
}

nbd_attach() {
    local img="$1"
    local fmt
    fmt=$(detect_fmt "$img")
    log_info "Image format   : ${BOLD}${fmt}${RESET}"

    nbd_load

    # detach stale connection if device is still held
    if [[ -b "$NBD_DEV" ]]; then
        log_info "Releasing stale ${NBD_DEV}..."
        qemu-nbd -d "$NBD_DEV" 2>/dev/null || true
    fi

    log_info "Attaching ${BOLD}${img}${RESET} -> ${NBD_DEV}"
    qemu-nbd -f "$fmt" -c "$NBD_DEV" "$img"

    log_info "Refreshing partition table..."
    partprobe "$NBD_DEV"
    # give the kernel a moment to register partition nodes
    sleep 0.5

    [[ -b "$NBD_PART" ]] || die "Partition ${NBD_PART} not found after attach. Image may have no partition table."
}

nbd_detach() {
    log_info "Detaching ${NBD_DEV}..."
    qemu-nbd -d "$NBD_DEV" 2>/dev/null || true
    log_info "Unloading nbd module..."
    rmmod nbd 2>/dev/null || true
}

# ── ensure directory exists ────────────────────────────────────────────────────
ensure_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        log_info "Creating directory: ${dir}"
        mkdir -p "$dir"
    fi
}

# ── commands ───────────────────────────────────────────────────────────────────

cmd_install() {
    require_root
    log_section "Installing dependencies"
    apt-get install -y qemu-utils nbd-client dislocker
    log_ok "All dependencies installed."
}

cmd_mount() {
    local img="${1:-}" mnt="${2:-}"
    require_root
    check_deps qemu-nbd partprobe

    [[ -n "$img" && -n "$mnt" ]] || die "Usage: ${SCRIPT_NAME} mount <image> <mountpoint>"
    [[ -f "$img" ]]              || die "Image not found: ${img}"

    log_section "Mounting ${img}"
    ensure_dir "$mnt"
    nbd_attach "$img"

    log_info "Mounting ${NBD_PART} -> ${mnt}"
    mount -o rw,nouser "$NBD_PART" "$mnt"

    log_ok "Mounted at ${BOLD}${mnt}${RESET}"
}

cmd_umount() {
    local mnt="${1:-}"
    require_root

    [[ -n "$mnt" ]] || die "Usage: ${SCRIPT_NAME} umount <mountpoint>"
    mountpoint -q "$mnt" || die "Not a mountpoint: ${mnt}"

    log_section "Unmounting ${mnt}"
    umount "$mnt"
    nbd_detach
    log_ok "Done."
}

cmd_bitlocker() {
    local img="${1:-}" mnt="${2:-}"
    shift 2 || true
    require_root
    check_deps qemu-nbd partprobe dislocker

    [[ -n "$img" && -n "$mnt" ]] || die "Usage: ${SCRIPT_NAME} bitlocker <image> <mountpoint> [-p|-r|-k] <value>"
    [[ -f "$img" ]]              || die "Image not found: ${img}"

    # ── parse auth flags ──
    # dislocker requires inline syntax: -u<password>  -r<recovery>
    local dislocker_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p) dislocker_args+=("-u${2}"); shift 2 ;;   # user password  → -u<pass>
            -r) dislocker_args+=("-r${2}"); shift 2 ;;   # recovery key   → -r<key>
            -k) dislocker_args+=(-k "$2"); shift 2  ;;   # BEK keyfile    → -k <path>
            *)  die "Unknown flag: $1. Valid flags: -p -r -k" ;;
        esac
    done

    [[ ${#dislocker_args[@]} -gt 0 ]] \
        || die "No unlock method provided. Use -p <password>, -r <recovery_key>, or -k <keyfile>."

    log_section "Mounting BitLocker volume: ${img}"
    ensure_dir "$mnt"
    ensure_dir "$DISLOCKER_DIR"

    # step 1 — attach image
    nbd_attach "$img"

    # step 2 — decrypt with dislocker
    log_info "Decrypting ${NBD_PART} with dislocker..."
    dislocker -V "$NBD_PART" "${dislocker_args[@]}" -- "$DISLOCKER_DIR" \
        || die "dislocker failed. Check password/key and that the partition is BitLocker-encrypted."

    [[ -f "${DISLOCKER_DIR}/dislocker-file" ]] \
        || die "dislocker-file not found in ${DISLOCKER_DIR}. Decryption may have failed."

    # step 3 — loop-mount the virtual cleartext file
    log_info "Mounting decrypted volume -> ${mnt}"
    mount -o loop "${DISLOCKER_DIR}/dislocker-file" "$mnt"

    log_ok "BitLocker volume mounted at ${BOLD}${mnt}${RESET}"
    log_info "Dislocker tmp  : ${DISLOCKER_DIR}"
}

cmd_bitlocker_umount() {
    local mnt="${1:-}"
    require_root

    [[ -n "$mnt" ]] || die "Usage: ${SCRIPT_NAME} bitlocker-umount <mountpoint>"

    log_section "Unmounting BitLocker volume: ${mnt}"

    mountpoint -q "$mnt" && umount "$mnt" || log_warn "${mnt} was not mounted, skipping."

    if mountpoint -q "$DISLOCKER_DIR" 2>/dev/null; then
        log_info "Unmounting dislocker layer (${DISLOCKER_DIR})..."
        umount "$DISLOCKER_DIR"
    fi

    nbd_detach
    log_ok "Done."
}

cmd_status() {
    log_section "NBD Device Status"
    if [[ -b "$NBD_DEV" ]]; then
        local info
        info=$(cat /sys/block/nbd0/size 2>/dev/null || echo "0")
        if [[ "$info" -gt 0 ]]; then
            log_info "${NBD_DEV} is ${BOLD}active${RESET}"
            lsblk "$NBD_DEV" 2>/dev/null || true
        else
            log_info "${NBD_DEV} exists but is ${DIM}idle${RESET}"
        fi
    else
        log_info "nbd module not loaded."
    fi

    log_section "Active Mounts"
    mount | grep -E "nbd|dislocker" || log_info "No VHD/VHDX mounts detected."
}

cmd_version() {
    echo "${SCRIPT_NAME} v${VERSION}"
}

# ── dispatch ───────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && usage

case "$1" in
    install)           cmd_install ;;
    mount)             cmd_mount              "${2:-}" "${3:-}" ;;
    umount)            cmd_umount             "${2:-}" ;;
    bitlocker)         cmd_bitlocker          "${2:-}" "${3:-}" "${@:4}" ;;
    bitlocker-umount)  cmd_bitlocker_umount   "${2:-}" ;;
    status)            cmd_status ;;
    version|--version) cmd_version ;;
    help|--help|-h)    usage ;;
    *)                 die "Unknown command: $1. Run '${SCRIPT_NAME} help' for usage." ;;
esac
