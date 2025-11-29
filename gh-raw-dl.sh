#!/usr/bin/env bash

set -euo pipefail

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEBUG=0
USE_CURL=0
GH_API="https://api.github.com"

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
debug() { ((DEBUG)) && echo -e "${YELLOW}[DEBUG]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }

# Respect GH_TOKEN if set
GH_TOKEN="${GH_TOKEN:-}"

# Detect wget/curl
check_deps() {
    if command -v wget >/dev/null; then
        USE_CURL=0
    elif command -v curl >/dev/null; then
        USE_CURL=1
    else
        error "Install wget or curl."
    fi
}

# Parse GitHub URL into owner, repo, ref, path
parse_github_url() {
    local url="$1"
    debug "Parsing URL: $url"

    if [[ ! "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/(blob|tree)/([^/]+)/(.+)$ ]]; then
        error "URL must be a GitHub blob or tree URL (e.g., https://github.com/user/repo/blob/main/file or .../tree/main/dir)"
    fi

    local owner="${BASH_REMATCH[1]}"
    local repo="${BASH_REMATCH[2]}"
    local type="${BASH_REMATCH[3]}"   # blob or tree
    local ref="${BASH_REMATCH[4]}"    # branch/tag/commit
    local path="${BASH_REMATCH[5]}"

    echo "$owner|$repo|$type|$ref|$path"
}

# Make authenticated or unauthenticated API request
gh_api_get() {
    local endpoint="$1"
    debug "GitHub API call: $endpoint"
    local headers=()
    if [[ -n "$GH_TOKEN" ]]; then
        headers+=("-H" "Authorization: token $GH_TOKEN")
        debug "Using GH_TOKEN for auth"
    fi

    if (( USE_CURL )); then
        curl --silent --fail --show-error "${headers[@]}" "$endpoint"
    else
        wget --quiet --header="Accept: application/vnd.github.v3+json" "${headers[@]/#/--header=}" -O - "$endpoint"
    fi
}

# Download single raw file
download_raw_file() {
    local raw_url="$1"
    local output="$2"

    if (( USE_CURL )); then
        curl --fail --location --show-error --progress-bar -o "$output" "$raw_url" \
            || error "curl failed to download $raw_url"
    else
        wget --continue --progress=bar --show-progress -O "$output" "$raw_url" \
            || error "wget failed to download $raw_url"
    fi
}

# Ensure local directory exists
ensure_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        debug "Creating directory: $dir"
        mkdir -p "$dir"
    fi
}

# Download a folder recursively
download_folder() {
    local owner="$1"
    local repo="$2"
    local ref="$3"
    local remote_path="$4"   # e.g., "NetFramework_4.7_x64"
    local local_base="$5"    # e.g., "./NetFramework_4.7_x64"

    local api_url="$GH_API/repos/$owner/$repo/contents/${remote_path}?ref=$ref"
    debug "Fetching dir contents from: $api_url"

    local response
    response=$(gh_api_get "$api_url") || error "Failed to fetch directory listing (rate limited or invalid path?)"

    # Parse JSON using a robust but POSIX-compatible method
    # We'll use a small jq-like parser with grep/sed (if jq not available)
    if command -v jq >/dev/null; then
        echo "$response" | jq -e 'type == "array"' >/dev/null || error "API returned non-array (file? 404?)"
        local files
        files=$(echo "$response" | jq -r '.[] | select(.type == "file") | "\(.path)|\(.download_url)"')
        local dirs
        dirs=$(echo "$response" | jq -r '.[] | select(.type == "dir") | .path')
    else
        # Fallback: crude but works for simple cases
        if [[ "$response" != *'"type":"file"'* && "$response" != *'"type":"dir"'* ]]; then
            error "Unable to parse API response without 'jq'. Install jq for folder support."
        fi
        warn "jq not found. Using basic parser (may fail on complex paths)."
        files=$(echo "$response" | grep -o '"path":"[^"]*","type":"file"' | sed 's/"path":"\([^"]*\)","type":"file"/\1/' | while read -r p; do
            # Reconstruct raw URL
            echo "$p|https://raw.githubusercontent.com/$owner/$repo/$ref/$p"
        done)
        dirs=$(echo "$response" | grep -o '"path":"[^"]*","type":"dir"' | sed 's/"path":"\([^"]*\)","type":"dir"/\1/')
    fi

    # Download files
    while IFS='|' read -r fpath raw_url; do
        [[ -z "$fpath" ]] && continue
        local rel_path="${fpath#${remote_path}/}"
        local local_file="$local_base/$rel_path"
        ensure_dir "$(dirname "$local_file")"
        log "Downloading file: $fpath"
        download_raw_file "$raw_url" "$local_file"
    done <<< "$(echo -e "$files")"

    # Recurse into subdirs
    while IFS= read -r dpath; do
        [[ -z "$dpath" ]] && continue
        local subdir_name="${dpath##*/}"
        local new_local_base="$local_base/$subdir_name"
        log "Entering subdirectory: $dpath"
        download_folder "$owner" "$repo" "$ref" "$dpath" "$new_local_base"
    done <<< "$(echo -e "$dirs")"
}

# Download a single file (original logic)
download_single_file() {
    local blob_url="$1"
    local output="$2"
    local checksum="$3"

    # Convert to raw URL
    local raw_url="${blob_url/\/blob\//\/raw\/}"
    if [[ "$raw_url" != "https://raw.githubusercontent.com/"* ]]; then
        error "Failed to convert to raw URL."
    fi

    download_raw_file "$raw_url" "$output"
    verify_hash "$output" "$checksum"
}

verify_hash() {
    local file="$1"
    local expected_hash="$2"
    [[ -z "$expected_hash" ]] && return 0
    log "Verifying SHA256 checksum..."
    local actual_hash
    if command -v sha256sum >/dev/null; then
        actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null; then
        actual_hash=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
        warn "No checksum tool. Skipping."
        return 0
    fi
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        success "Checksum verified."
    else
        error "Checksum mismatch! Expected: $expected_hash, Got: $actual_hash"
    fi
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS] <GITHUB_URL>

Download a file or entire subdirectory from GitHub.

URL must be:
  - File: https://github.com/user/repo/blob/branch/path/file
  - Folder: https://github.com/user/repo/tree/branch/path/dir

OPTIONS:
  -o, --output PATH       Output file (for single file) or base dir (for folder)
  -c, --checksum HASH     SHA256 hash (single file only)
  --debug                 Enable debug output *Necessary for Downloading Subfolders*
  -h, --help              Show help

ENV:
  GH_TOKEN               Optional GitHub token (increases rate limit)

EXAMPLES:
  $0 https://github.com/user/repo/blob/main/tool.exe
  $0 https://github.com/user/repo/tree/blob/scripts
  GH_TOKEN=xxx ./gh-raw-dl.sh -o ./tools/ --debug <folder-url>

EOF
}

main() {
    local output_path=""
    local checksum=""
    local input_url=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output) output_path="$2"; shift 2 ;;
            -c|--checksum) checksum="$2"; shift 2 ;;
            --debug) DEBUG=1; log "Debug mode enabled"; shift ;;
            -h|--help) show_help; exit 0 ;;
            --) shift; break ;;
            -*)
                error "Unknown option: $1"
                ;;
            *)
                if [[ -n "$input_url" ]]; then error "Only one URL allowed."; fi
                input_url="$1"
                shift
                ;;
        esac
    done

    [[ -z "$input_url" ]] && error "Missing GitHub URL."

    check_deps
    local parsed
    parsed=$(parse_github_url "$input_url") || error "Invalid GitHub URL format."
    IFS='|' read -r owner repo type ref path <<< "$parsed"

    if [[ "$type" == "blob" ]]; then
        # Single file
        local filename="${path##*/}"
        output_path="${output_arch:-$filename}"
        log "Mode: Single file"
        log "File: $path"
        download_single_file "$input_url" "$output_path" "$checksum"
        success "Saved as: $output_path"
    elif [[ "$type" == "tree" ]]; then
        # Folder
        if [[ -n "$checksum" ]]; then
            warn "Checksum ignored (folder mode)."
        fi
        local default_dir="${path##*/}"
        output_path="${output_path:-$default_dir}"
        log "Mode: Directory"
        log "Remote path: $path"
        log "Local output dir: ./$output_path"
        ensure_dir "$output_path"
        download_folder "$owner" "$repo" "$ref" "$path" "$output_path"
        success "Folder downloaded to: ./$output_path"
    else
        error "Unknown content type: $type"
    fi
}

main "$@"
