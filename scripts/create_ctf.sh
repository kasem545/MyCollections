#!/usr/bin/env bash

BASE_DIR="${HOME}/CTF_Machines"

DIRS=(
    "nmap"
    "exploits"
    "scripts"
    "loot"
    "screenshots"
    "writeup"
    "notes"
)

ESCAPE_SEQ='\033['
RESET="${ESCAPE_SEQ}0m"
BOLD="${ESCAPE_SEQ}1m"
GREEN="${ESCAPE_SEQ}32m"
YELLOW="${ESCAPE_SEQ}33m"
BLUE="${ESCAPE_SEQ}34m"
RED="${ESCAPE_SEQ}31m"

info()    { printf "%b %b%s%b\n" "🛈" "${BOLD}${BLUE}" "$1" "${RESET}"; }
success() { printf "%b %b%s%b\n" "✔" "${BOLD}${GREEN}" "$1" "${RESET}"; }
warn()    { printf "%b %b%s%b\n" "⚠" "${BOLD}${YELLOW}" "$1" "${RESET}"; }
error()   { printf "%b %b%s%b\n" "✖" "${BOLD}${RED}" "$1" "${RESET}" >&2; }

# ========== Functions ==========
create_ctf_directories() {
    local machine_name=$1
    local base_machine_dir="$BASE_DIR/$machine_name"
    
    if [ -d "$base_machine_dir" ]; then
        warn "Directory already exists: $machine_name (skipping)"
        return 0
    fi
    
    info "Creating directories for: $machine_name"
    
    if ! mkdir -p "$base_machine_dir"; then
        error "Failed to create base directory for $machine_name"
        return 1
    fi
    
    for dir in "${DIRS[@]}"; do
        if ! mkdir -p "$base_machine_dir/$dir"; then
            error "Failed to create $dir for $machine_name"
            return 1
        fi
    done
    
    local notes_file="$base_machine_dir/notes/README.md"
    cat > "$notes_file" <<EOF
# $machine_name

**Date Started:** $(date +"%Y-%m-%d")  
**Platform:** HTB/THM/Other  
**Difficulty:**  
**IP Address:**  

---

## Enumeration

### Nmap Scan


### Services


---

## Exploitation


---

## Privilege Escalation


---

## Flags

- **User Flag:** 
- **Root Flag:** 

---

## Notes

EOF
    
    chmod 644 "$notes_file" 2>/dev/null || true
    
    success "Created structure for: $machine_name"
    echo "   └─ Location: $base_machine_dir"
}

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] <machine_name_1> [machine_name_2] ... [machine_name_N]

Create organized directory structures for CTF machines.

Options:
    -h, --help     Show this help message
    -l, --list     List all existing machines

Examples:
    $0 Bashed
    $0 Lame Legacy Blue
    $0 "Machine Name With Spaces"
EOF
}

list_machines() {
    if [ ! -d "$BASE_DIR" ]; then
        warn "No CTF directory found at: $BASE_DIR"
        return 0
    fi
    
    info "Existing CTF machines in: $BASE_DIR"
    echo ""
    
    local count=0
    
    for machine in "$BASE_DIR"/*/ ; do
        if [ -d "$machine" ]; then
            local machine_name=$(basename "$machine")
            echo "   • $machine_name"
            ((count++))
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo "   (no machines found)"
    fi
    
    echo ""
    success "Total: $count machine(s)"
}

# ========== Main ==========
main() {

    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_usage
        exit 0
    fi
        if [ "$1" = "-l" ] || [ "$1" = "--list" ]; then
        list_machines
        exit 0
    fi

    info "Base directory: $BASE_DIR"
    mkdir -p "$BASE_DIR" || {
        error "Failed to create base directory: $BASE_DIR"
        exit 1
    }
    
    echo ""
        local success_count=0
    local total=$#
    
    for machine in "$@"; do
        if [ -z "$machine" ]; then
            warn "Skipping empty machine name"
            continue
        fi
        
        if [ "$machine" = "-h" ] || [ "$machine" = "--help" ] || [ "$machine" = "-l" ] || [ "$machine" = "--list" ]; then
            continue
        fi
        
        if create_ctf_directories "$machine"; then
            ((success_count++))
        fi
    done
    
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
