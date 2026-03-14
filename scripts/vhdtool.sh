#!/usr/bin/env bash
# ==============================================================================
#  vhdtool — Professional VHD/VHDX Mount Utility for Linux
#  
#  Features:
#    - Auto-detection of BitLocker encryption (no separate commands needed)
#    - Multi-NBD device support with automatic allocation
#    - State tracking for clean unmount operations
#    - Interactive password prompt for encrypted volumes
#    - Robust error handling with automatic cleanup
#
#  Author  : VHDTool Team
#  Version : 3.0.0
#  License : MIT
#  Requires: qemu-utils, nbd-client, dislocker (for BitLocker)
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

readonly VERSION="3.0.0"
readonly SCRIPT_NAME="${0##*/}"
readonly STATE_DIR="/var/run/vhdtool"
readonly LOG_DIR="/var/log/vhdtool"
readonly LOG_FILE="${LOG_DIR}/vhdtool.log"
readonly MAX_NBD_DEVICES=16

# BitLocker signature: "-FVE-FS-" at offset 3 in the partition
readonly BITLOCKER_SIG="-FVE-FS-"

# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL COLORS
# ══════════════════════════════════════════════════════════════════════════════

if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    readonly C_RED=$'\033[0;31m'
    readonly C_GREEN=$'\033[0;32m'
    readonly C_YELLOW=$'\033[0;33m'
    readonly C_BLUE=$'\033[0;34m'
    readonly C_CYAN=$'\033[0;36m'
    readonly C_BOLD=$'\033[1m'
    readonly C_DIM=$'\033[2m'
    readonly C_RESET=$'\033[0m'
else
    readonly C_RED='' C_GREEN='' C_YELLOW='' C_BLUE=''
    readonly C_CYAN='' C_BOLD='' C_DIM='' C_RESET=''
fi

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

_log() {
    local level="$1" color="$2" symbol="$3"
    shift 3
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    printf '%b[%s]%b %s\n' "$color" "$symbol" "$C_RESET" "$*"
    
    if [[ -d "$LOG_DIR" ]]; then
        printf '[%s] [%s] %s\n' "$timestamp" "$level" "$*" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_info()    { _log "INFO"  "$C_CYAN"   "•" "$@"; }
log_ok()      { _log "OK"    "$C_GREEN"  "✓" "$@"; }
log_warn()    { _log "WARN"  "$C_YELLOW" "!" "$@" >&2; }
log_error()   { _log "ERROR" "$C_RED"    "✗" "$@" >&2; }
log_debug()   { [[ "${VHDTOOL_DEBUG:-}" == "1" ]] && _log "DEBUG" "$C_DIM" "⋯" "$@" || true; }
log_section() { printf '\n%b━━ %s %b\n' "$C_BOLD$C_BLUE" "$*" "$C_RESET"; }

die() {
    log_error "$@"
    exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

# State files track: mountpoint -> { nbd_device, dislocker_dir, image_path, is_bitlocker }
# Format: /var/run/vhdtool/<mountpoint_hash>.state

state_init() {
    mkdir -p "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true
}

state_hash() {
    echo "$1" | md5sum | cut -c1-16
}

state_save() {
    local mountpoint="$1" nbd_dev="$2" dislocker_dir="$3" image="$4" is_bitlocker="$5"
    local state_file="${STATE_DIR}/$(state_hash "$mountpoint").state"
    
    cat > "$state_file" <<-EOF
	MOUNTPOINT="$mountpoint"
	NBD_DEVICE="$nbd_dev"
	DISLOCKER_DIR="$dislocker_dir"
	IMAGE_PATH="$image"
	IS_BITLOCKER="$is_bitlocker"
	MOUNT_TIME="$(date -Iseconds)"
	EOF
    
    log_debug "State saved: $state_file"
}

state_load() {
    local mountpoint="$1"
    local state_file="${STATE_DIR}/$(state_hash "$mountpoint").state"
    
    if [[ -f "$state_file" ]]; then
        # shellcheck source=/dev/null
        source "$state_file"
        return 0
    fi
    return 1
}

state_remove() {
    local mountpoint="$1"
    local state_file="${STATE_DIR}/$(state_hash "$mountpoint").state"
    rm -f "$state_file" 2>/dev/null || true
}

state_list() {
    local state_file
    if [[ ! -d "$STATE_DIR" ]] || [[ -z "$(ls -A "$STATE_DIR" 2>/dev/null)" ]]; then
        return
    fi
    
    for state_file in "$STATE_DIR"/*.state; do
        [[ -f "$state_file" ]] || continue
        # shellcheck source=/dev/null
        source "$state_file"
        printf '%s|%s|%s|%s\n' "$MOUNTPOINT" "$NBD_DEVICE" "$IS_BITLOCKER" "$IMAGE_PATH"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  NBD DEVICE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

nbd_ensure_module() {
    if ! lsmod | grep -q '^nbd\b'; then
        log_info "Loading nbd kernel module..."
        modprobe nbd max_part=16 || die "Failed to load nbd module"
    fi
}

nbd_find_free() {
    local i
    for ((i = 0; i < MAX_NBD_DEVICES; i++)); do
        local dev="/dev/nbd${i}"
        [[ -b "$dev" ]] || continue
        
        local size
        size=$(cat "/sys/block/nbd${i}/size" 2>/dev/null || echo "0")
        
        if [[ "$size" == "0" ]]; then
            echo "$dev"
            return 0
        fi
    done
    
    return 1
}

nbd_attach() {
    local image="$1" nbd_dev="$2"
    local fmt
    
    fmt=$(detect_image_format "$image")
    log_info "Image format: ${C_BOLD}${fmt}${C_RESET}"
    
    qemu-nbd -d "$nbd_dev" &>/dev/null || true
    sleep 0.2
    
    log_info "Attaching ${C_BOLD}${image##*/}${C_RESET} → ${nbd_dev}"
    qemu-nbd -f "$fmt" -c "$nbd_dev" "$image" || die "Failed to attach image to $nbd_dev"
    
    partprobe "$nbd_dev" 2>/dev/null || true
    sleep 0.5
    
    local retries=10
    while ((retries > 0)); do
        if [[ -b "${nbd_dev}p1" ]]; then
            log_debug "Partition ${nbd_dev}p1 ready"
            return 0
        fi
        sleep 0.2
        ((retries--))
    done
    
    die "Partition ${nbd_dev}p1 not found. Image may lack a partition table."
}

nbd_detach() {
    local nbd_dev="$1"
    
    if [[ -b "$nbd_dev" ]]; then
        log_info "Detaching ${nbd_dev}..."
        qemu-nbd -d "$nbd_dev" &>/dev/null || true
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  IMAGE FORMAT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

detect_image_format() {
    local image="$1"
    local ext="${image##*.}"
    
    case "${ext,,}" in
        vhd)  echo "vpc";  return ;;
        vhdx) echo "vhdx"; return ;;
    esac
    
    local fmt
    fmt=$(qemu-img info --output=json "$image" 2>/dev/null | \
          grep -oP '"format":\s*"\K[^"]+' || echo "raw")
    
    echo "${fmt:-raw}"
}

# ══════════════════════════════════════════════════════════════════════════════
#  BITLOCKER DETECTION
# ══════════════════════════════════════════════════════════════════════════════

is_bitlocker_partition() {
    local partition="$1"
    
    # BitLocker signature "-FVE-FS-" at boot sector offset 3
    local sig
    sig=$(dd if="$partition" bs=1 skip=3 count=8 2>/dev/null | tr -d '\0')
    
    if [[ "$sig" == "$BITLOCKER_SIG" ]]; then
        log_debug "BitLocker signature detected: $sig"
        return 0
    fi
    
    local fstype
    fstype=$(blkid -s TYPE -o value "$partition" 2>/dev/null || echo "")
    
    if [[ "$fstype" == "BitLocker" ]]; then
        log_debug "BitLocker detected via blkid"
        return 0
    fi
    
    local header
    header=$(xxd -l 512 -p "$partition" 2>/dev/null | head -c 200)
    
    # 2d465645 = "-FVE" in hex
    if [[ "$header" == *"2d465645"* ]]; then
        log_debug "BitLocker pattern detected in header"
        return 0
    fi
    
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD HANDLING
# ══════════════════════════════════════════════════════════════════════════════

prompt_password() {
    local password
    
    if [[ -t 0 ]]; then
        printf '%b' "${C_YELLOW}Enter BitLocker password: ${C_RESET}" >&2
        read -rs password
        printf '\n' >&2
    else
        die "BitLocker password required. Use -p <password> or run interactively."
    fi
    
    [[ -n "$password" ]] || die "Password cannot be empty"
    echo "$password"
}

# ══════════════════════════════════════════════════════════════════════════════
#  CLEANUP HANDLING
# ══════════════════════════════════════════════════════════════════════════════

declare -g CLEANUP_MOUNTPOINT=""
declare -g CLEANUP_DISLOCKER_DIR=""
declare -g CLEANUP_NBD_DEV=""

cleanup_on_failure() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log_warn "Operation failed, performing cleanup..."
        
        [[ -n "$CLEANUP_MOUNTPOINT" ]] && mountpoint -q "$CLEANUP_MOUNTPOINT" 2>/dev/null && \
            umount "$CLEANUP_MOUNTPOINT" 2>/dev/null || true
        
        [[ -n "$CLEANUP_DISLOCKER_DIR" ]] && mountpoint -q "$CLEANUP_DISLOCKER_DIR" 2>/dev/null && \
            umount "$CLEANUP_DISLOCKER_DIR" 2>/dev/null || true
        
        [[ -n "$CLEANUP_NBD_DEV" ]] && qemu-nbd -d "$CLEANUP_NBD_DEV" 2>/dev/null || true
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECK
# ══════════════════════════════════════════════════════════════════════════════

check_dependencies() {
    local -a required=("qemu-nbd" "partprobe" "blkid")
    local -a optional=("dislocker")
    local -a missing=()
    
    for cmd in "${required[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    
    if ((${#missing[@]} > 0)); then
        die "Missing required dependencies: ${missing[*]}\nRun: sudo ${SCRIPT_NAME} install"
    fi
    
    for cmd in "${optional[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log_warn "Optional dependency '$cmd' not found (needed for BitLocker)"
        fi
    done
}

require_root() {
    ((EUID == 0)) || die "This command requires root privileges. Use: sudo ${SCRIPT_NAME} $*"
}

# ══════════════════════════════════════════════════════════════════════════════
#  CORE COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

cmd_install() {
    require_root "install"
    
    log_section "Installing Dependencies"
    
    if command -v apt-get &>/dev/null; then
        log_info "Detected: Debian/Ubuntu"
        apt-get update -qq
        apt-get install -y qemu-utils nbd-client dislocker parted
        
    elif command -v dnf &>/dev/null; then
        log_info "Detected: Fedora/RHEL"
        dnf install -y qemu-img nbd dislocker parted
        
    elif command -v yum &>/dev/null; then
        log_info "Detected: CentOS/RHEL (legacy)"
        yum install -y epel-release
        yum install -y qemu-img nbd dislocker parted
        
    elif command -v pacman &>/dev/null; then
        log_info "Detected: Arch Linux"
        pacman -Sy --noconfirm qemu-img nbd dislocker parted
        
    elif command -v zypper &>/dev/null; then
        log_info "Detected: openSUSE/SLES"
        zypper install -y qemu-tools nbd dislocker parted
        
    elif command -v apk &>/dev/null; then
        log_info "Detected: Alpine Linux"
        apk add --no-cache qemu-img nbd dislocker parted
        
    elif command -v emerge &>/dev/null; then
        log_info "Detected: Gentoo"
        emerge --ask=n app-emulation/qemu sys-block/nbd sys-fs/dislocker sys-block/parted
        
    elif command -v xbps-install &>/dev/null; then
        log_info "Detected: Void Linux"
        xbps-install -Sy qemu nbd dislocker parted
        
    else
        log_error "Unsupported package manager"
        echo
        echo "Install these packages manually:"
        echo "  - qemu-utils / qemu-img  (VHD/VHDX support)"
        echo "  - nbd / nbd-client       (Network Block Device)"
        echo "  - dislocker              (BitLocker decryption)"
        echo "  - parted                 (Partition handling)"
        echo
        die "Then re-run: ${SCRIPT_NAME} install"
    fi
    
    log_ok "Dependencies installed successfully"
    
    state_init
    log_ok "State directories initialized"
}

cmd_mount() {
    local image="" mountpoint=""
    local password="" recovery_key="" keyfile=""
    local force_bitlocker=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--password)     password="$2"; shift 2 ;;
            -r|--recovery)     recovery_key="$2"; shift 2 ;;
            -k|--keyfile)      keyfile="$2"; shift 2 ;;
            -b|--bitlocker)    force_bitlocker=true; shift ;;
            -h|--help)         cmd_mount_help; return 0 ;;
            -*)                die "Unknown option: $1" ;;
            *)
                if [[ -z "$image" ]]; then
                    image="$1"
                elif [[ -z "$mountpoint" ]]; then
                    mountpoint="$1"
                else
                    die "Unexpected argument: $1"
                fi
                shift
                ;;
        esac
    done
    
    require_root "mount"
    check_dependencies
    state_init
    
    [[ -n "$image" ]]      || die "Image path required. See: ${SCRIPT_NAME} mount --help"
    [[ -n "$mountpoint" ]] || die "Mountpoint required. See: ${SCRIPT_NAME} mount --help"
    [[ -f "$image" ]]      || die "Image not found: $image"
    
    image=$(realpath "$image")
    mountpoint=$(realpath -m "$mountpoint")
    
    if mountpoint -q "$mountpoint" 2>/dev/null; then
        die "Mountpoint already in use: $mountpoint"
    fi
    
    log_section "Mounting VHD Image"
    log_info "Image: ${C_BOLD}${image##*/}${C_RESET}"
    log_info "Target: ${C_BOLD}${mountpoint}${C_RESET}"
    
    nbd_ensure_module
    
    local nbd_dev
    nbd_dev=$(nbd_find_free) || die "No free NBD devices available"
    log_info "Using device: ${C_BOLD}${nbd_dev}${C_RESET}"
    
    CLEANUP_NBD_DEV="$nbd_dev"
    trap cleanup_on_failure EXIT
    
    mkdir -p "$mountpoint"
    
    nbd_attach "$image" "$nbd_dev"
    
    local partition="${nbd_dev}p1"
    local is_bitlocker=false
    local dislocker_dir=""
    
    log_info "Detecting encryption..."
    
    if is_bitlocker_partition "$partition" || [[ "$force_bitlocker" == true ]]; then
        is_bitlocker=true
        log_info "Encryption: ${C_BOLD}${C_YELLOW}BitLocker detected${C_RESET}"
        
        command -v dislocker &>/dev/null || \
            die "dislocker required for BitLocker volumes. Run: ${SCRIPT_NAME} install"
        
        local -a dislocker_args=()
        
        if [[ -n "$password" ]]; then
            dislocker_args+=("-u${password}")
        elif [[ -n "$recovery_key" ]]; then
            dislocker_args+=("-p${recovery_key}")
        elif [[ -n "$keyfile" ]]; then
            [[ -f "$keyfile" ]] || die "Keyfile not found: $keyfile"
            dislocker_args+=("-k" "$keyfile")
        else
            password=$(prompt_password)
            dislocker_args+=("-u${password}")
        fi
        
        dislocker_dir="/tmp/vhdtool_dislocker_$(state_hash "$mountpoint")"
        mkdir -p "$dislocker_dir"
        CLEANUP_DISLOCKER_DIR="$dislocker_dir"
        
        log_info "Decrypting volume..."
        if ! dislocker -V "$partition" "${dislocker_args[@]}" -- "$dislocker_dir" 2>&1; then
            die "Decryption failed. Check your password/recovery key."
        fi
        
        local dislocker_file="${dislocker_dir}/dislocker-file"
        [[ -f "$dislocker_file" ]] || die "Decryption produced no output. Verify credentials."
        
        CLEANUP_MOUNTPOINT="$mountpoint"
        log_info "Mounting decrypted filesystem..."
        mount -o loop,rw "$dislocker_file" "$mountpoint" || \
            die "Failed to mount decrypted volume"
        
    else
        log_info "Encryption: ${C_BOLD}${C_GREEN}None${C_RESET}"
        
        CLEANUP_MOUNTPOINT="$mountpoint"
        log_info "Mounting filesystem..."
        mount -o rw "$partition" "$mountpoint" || \
            die "Failed to mount partition. Check filesystem type."
    fi
    
    state_save "$mountpoint" "$nbd_dev" "$dislocker_dir" "$image" "$is_bitlocker"
    
    trap - EXIT
    CLEANUP_MOUNTPOINT="" CLEANUP_DISLOCKER_DIR="" CLEANUP_NBD_DEV=""
    
    log_ok "Successfully mounted at ${C_BOLD}${mountpoint}${C_RESET}"
    
    echo
    df -h "$mountpoint" 2>/dev/null | tail -1 || true
}

cmd_mount_help() {
    cat <<-EOF
	${C_BOLD}USAGE${C_RESET}
	  ${SCRIPT_NAME} mount <image> <mountpoint> [options]
	
	${C_BOLD}DESCRIPTION${C_RESET}
	  Mount a VHD/VHDX image. Automatically detects and handles BitLocker
	  encrypted volumes.
	
	${C_BOLD}OPTIONS${C_RESET}
	  -p, --password <pass>     BitLocker user password
	  -r, --recovery <key>      BitLocker 48-digit recovery key
	  -k, --keyfile <path>      BitLocker BEK keyfile
	  -b, --bitlocker           Force BitLocker mode (skip auto-detection)
	  -h, --help                Show this help
	
	${C_BOLD}EXAMPLES${C_RESET}
	  # Auto-detect encryption (prompts for password if needed)
	  ${SCRIPT_NAME} mount disk.vhd /mnt/disk
	
	  # Provide password directly
	  ${SCRIPT_NAME} mount encrypted.vhd /mnt/encrypted -p "mypassword"
	
	  # Use recovery key
	  ${SCRIPT_NAME} mount encrypted.vhd /mnt/encrypted -r "123456-789012-..."
	
	EOF
}

cmd_umount() {
    local mountpoint="${1:-}"
    
    require_root "umount"
    
    [[ -n "$mountpoint" ]] || die "Usage: ${SCRIPT_NAME} umount <mountpoint>"
    
    mountpoint=$(realpath -m "$mountpoint")
    
    log_section "Unmounting Volume"
    
    local NBD_DEVICE="" DISLOCKER_DIR="" IS_BITLOCKER="" IMAGE_PATH=""
    
    if state_load "$mountpoint"; then
        log_info "State loaded for: ${mountpoint}"
    else
        log_warn "No state found. Attempting basic unmount..."
        
        if mountpoint -q "$mountpoint" 2>/dev/null; then
            umount "$mountpoint"
            log_ok "Unmounted: $mountpoint"
        else
            die "Not a mountpoint: $mountpoint"
        fi
        return 0
    fi
    
    if mountpoint -q "$mountpoint" 2>/dev/null; then
        log_info "Unmounting ${mountpoint}..."
        umount "$mountpoint" || die "Failed to unmount $mountpoint (device busy?)"
    else
        log_warn "Mountpoint was not mounted: $mountpoint"
    fi
    
    if [[ -n "$DISLOCKER_DIR" ]] && [[ -d "$DISLOCKER_DIR" ]]; then
        if mountpoint -q "$DISLOCKER_DIR" 2>/dev/null; then
            log_info "Unmounting dislocker layer..."
            umount "$DISLOCKER_DIR" || log_warn "Failed to unmount dislocker layer"
        fi
        rmdir "$DISLOCKER_DIR" 2>/dev/null || true
    fi
    
    if [[ -n "$NBD_DEVICE" ]]; then
        nbd_detach "$NBD_DEVICE"
    fi
    
    state_remove "$mountpoint"
    
    log_ok "Successfully unmounted"
}

cmd_status() {
    require_root "status"
    state_init
    
    log_section "VHDTool Status"
    
    printf '\n%b%s%b\n' "$C_BOLD" "Mounted Volumes:" "$C_RESET"
    
    local has_mounts=false
    local line
    while IFS='|' read -r mnt nbd bitlocker img; do
        [[ -n "$mnt" ]] || continue
        has_mounts=true
        
        local enc_status
        if [[ "$bitlocker" == "true" ]]; then
            enc_status="${C_YELLOW}BitLocker${C_RESET}"
        else
            enc_status="${C_GREEN}None${C_RESET}"
        fi
        
        printf '  %b%-30s%b  %s  [%s]  %s\n' \
            "$C_CYAN" "$mnt" "$C_RESET" "$nbd" "$enc_status" "${img##*/}"
    done < <(state_list)
    
    if [[ "$has_mounts" == false ]]; then
        printf '  %b(no volumes mounted)%b\n' "$C_DIM" "$C_RESET"
    fi
    
    printf '\n%b%s%b\n' "$C_BOLD" "NBD Devices:" "$C_RESET"
    
    local i active=0
    for ((i = 0; i < 8; i++)); do
        local dev="/dev/nbd${i}"
        [[ -b "$dev" ]] || continue
        
        local size
        size=$(cat "/sys/block/nbd${i}/size" 2>/dev/null || echo "0")
        
        if [[ "$size" -gt 0 ]]; then
            local size_human
            size_human=$(numfmt --to=iec $((size * 512)) 2>/dev/null || echo "${size} blocks")
            printf '  %s: %bactive%b (%s)\n' "$dev" "$C_GREEN" "$C_RESET" "$size_human"
            ((active++))
        fi
    done
    
    if ((active == 0)); then
        printf '  %b(no active NBD devices)%b\n' "$C_DIM" "$C_RESET"
    fi
    
    echo
}

cmd_list() {
    require_root "list"
    state_init
    
    local has_mounts=false
    
    printf '%b%-35s  %-12s  %-10s  %s%b\n' \
        "$C_BOLD" "MOUNTPOINT" "DEVICE" "ENCRYPTION" "IMAGE" "$C_RESET"
    printf '%s\n' "$(printf '─%.0s' {1..80})"
    
    while IFS='|' read -r mnt nbd bitlocker img; do
        [[ -n "$mnt" ]] || continue
        has_mounts=true
        
        local enc_label
        [[ "$bitlocker" == "true" ]] && enc_label="BitLocker" || enc_label="None"
        
        printf '%-35s  %-12s  %-10s  %s\n' "$mnt" "$nbd" "$enc_label" "${img##*/}"
    done < <(state_list)
    
    if [[ "$has_mounts" == false ]]; then
        echo "(no mounted volumes)"
    fi
}

cmd_info() {
    local image="${1:-}"
    
    [[ -n "$image" ]] || die "Usage: ${SCRIPT_NAME} info <image>"
    [[ -f "$image" ]] || die "Image not found: $image"
    
    log_section "Image Information"
    
    local size
    size=$(stat -c%s "$image" 2>/dev/null || echo "0")
    local size_human
    size_human=$(numfmt --to=iec "$size" 2>/dev/null || echo "$size bytes")
    
    printf '%b%-15s%b %s\n' "$C_BOLD" "File:" "$C_RESET" "${image##*/}"
    printf '%b%-15s%b %s\n' "$C_BOLD" "Path:" "$C_RESET" "$(realpath "$image")"
    printf '%b%-15s%b %s\n' "$C_BOLD" "Size:" "$C_RESET" "$size_human"
    
    local fmt
    fmt=$(detect_image_format "$image")
    printf '%b%-15s%b %s\n' "$C_BOLD" "Format:" "$C_RESET" "$fmt"
    
    echo
    qemu-img info "$image" 2>/dev/null || true
}

cmd_version() {
    echo "${SCRIPT_NAME} v${VERSION}"
    echo "Professional VHD/VHDX Mount Utility"
}

# ══════════════════════════════════════════════════════════════════════════════
#  USAGE / HELP
# ══════════════════════════════════════════════════════════════════════════════

usage() {
    cat <<-EOF
	${C_BOLD}${SCRIPT_NAME}${C_RESET} v${VERSION} — Professional VHD/VHDX Mount Utility
	
	${C_BOLD}USAGE${C_RESET}
	  ${SCRIPT_NAME} <command> [arguments] [options]
	
	${C_BOLD}COMMANDS${C_RESET}
	  ${C_CYAN}mount${C_RESET} <image> <mountpoint>    Mount VHD/VHDX (auto-detects BitLocker)
	       -p, --password <pass>       Provide BitLocker password
	       -r, --recovery <key>        Provide recovery key
	       -k, --keyfile <path>        Provide BEK keyfile
	
	  ${C_CYAN}umount${C_RESET} <mountpoint>           Unmount a mounted volume
	  ${C_CYAN}list${C_RESET}                          List all mounted volumes
	  ${C_CYAN}status${C_RESET}                        Show detailed status
	  ${C_CYAN}info${C_RESET} <image>                  Show image information
	  ${C_CYAN}install${C_RESET}                       Install required dependencies
	  ${C_CYAN}version${C_RESET}                       Show version information
	  ${C_CYAN}help${C_RESET}                          Show this help message
	
	${C_BOLD}SUPPORTED FORMATS${C_RESET}
	  • .vhd   (Microsoft Virtual PC / vpc format)
	  • .vhdx  (Hyper-V format)
	  • Other formats auto-detected via qemu-img
	
	${C_BOLD}EXAMPLES${C_RESET}
	  # Mount a regular VHD
	  sudo ${SCRIPT_NAME} mount disk.vhd /mnt/disk
	
	  # Mount BitLocker encrypted VHD (auto-detected, prompts for password)
	  sudo ${SCRIPT_NAME} mount encrypted.vhd /mnt/secure
	
	  # Mount with password provided
	  sudo ${SCRIPT_NAME} mount encrypted.vhd /mnt/secure -p "mypassword"
	
	  # Unmount
	  sudo ${SCRIPT_NAME} umount /mnt/secure
	
	EOF
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN DISPATCH
# ══════════════════════════════════════════════════════════════════════════════

main() {
    local cmd="${1:-help}"
    shift || true
    
    case "$cmd" in
        mount)                     cmd_mount "$@" ;;
        umount|unmount)            cmd_umount "$@" ;;
        list|ls)                   cmd_list ;;
        status)                    cmd_status ;;
        info)                      cmd_info "$@" ;;
        install)                   cmd_install ;;
        version|--version|-v)     cmd_version ;;
        help|--help|-h)           usage ;;
        *)
            log_error "Unknown command: $cmd"
            echo "Run '${SCRIPT_NAME} help' for usage information."
            exit 1
            ;;
    esac
}

main "$@"
