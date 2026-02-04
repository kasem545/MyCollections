#!/usr/bin/env bash

""" 
Advanced GitHub downloader that fetches files or entire directories by URL, 
supports branches/tags/commits, handles private repos via token, recursively mirrors folders

Usage: 

    # Download a single file from a repository:
        gh-raw-dl.sh https://github.com/USER/REPO/blob/master/path/to/file.exe
    
    # Save a file with a custom output name:
        gh-raw-dl.sh -o myfile.bin https://github.com/USER/REPO/blob/dev/build/output.bin
    
    # Download an entire folder recursively:
        gh-raw-dl.sh  https://github.com/USER/REPO/tree/main/tools
"""

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEBUG=0
USE_CURL=0
GH_API="https://api.github.com"
GH_TOKEN="${GH_TOKEN:-}"

log() { echo -e "${BLUE}[INFO]${NC} $*"; }
debug() { [[ $DEBUG -eq 1 ]] && echo -e "${YELLOW}[DEBUG]${NC} $*" >&2 || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }

check_deps() {
    if command -v wget >/dev/null; then USE_CURL=0; else USE_CURL=1; fi
}

parse_github_url() {
    local url="$1"
    debug "Parsing URL: $url"

    if [[ ! "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/(blob|tree)/([^/]+)/(.+)$ ]]; then
        error "Invalid GitHub URL. Must be: https://github.com/user/repo/blob|tree/REF/path"
    fi

    local owner="${BASH_REMATCH[1]}"
    local repo="${BASH_REMATCH[2]}"
    local type="${BASH_REMATCH[3]}"
    local ref="${BASH_REMATCH[4]}"
    local path="${BASH_REMATCH[5]}"

    if [[ "$type" == "tree" ]]; then
        local basename="${path##*/}"

        case "$basename" in
            *.exe|*.dll|*.bin|*.ps1|*.bat|*.sh|*.txt|*.xml|*.config|*.json|*.yml|*.yaml|*.zip|*.msi|*.js)
                debug "Heuristic: '$basename' matches known file extension. Forcing 'blob' mode."
                type="blob"
                ;;
            *)
                debug "Heuristic: '$basename' does not look like a file. Keeping 'tree' mode."
                ;;
        esac
    fi

    debug "Parsed → owner='$owner', repo='$repo', type='$type', ref='$ref', path='$path'"
    echo "$owner|$repo|$type|$ref|$path"
}

gh_api_get() {
    local url="$1"
    local hdr=()
    [[ -n "$GH_TOKEN" ]] && hdr+=("-H" "Authorization: token $GH_TOKEN")
    if (( USE_CURL )); then
        curl -s --fail "${hdr[@]}" "$url"
    else
        wget -q "${hdr[@]/#/--header=}" -O - "$url"
    fi
}

download_raw_file() {
    local url="$1" out="$2"
    if (( USE_CURL )); then
        curl -fL# -o "$out" "$url" || error "Download failed: $url"
    else
        wget -q -c --progress=bar -O "$out" "$url" || error "Download failed: $url"
    fi
}

verify_hash() {
    local f="$1" h="$2"
    [[ -z "$h" ]] && return 0
    local actual
    if command -v sha256sum >/dev/null; then
        actual=$(sha256sum "$f" | cut -d' ' -f1)
    elif command -v shasum >/dev/null; then
        actual=$(shasum -a 256 "$f" | cut -d' ' -f1)
    else
        warn "No hash tool. Skipping."
        return 0
    fi
    [[ "$actual" == "$h" ]] && success "Checksum OK." || error "Hash mismatch!"
}

download_folder() {
    local owner="$1" repo="$2" ref="$3" path="$4" outdir="$5"
    local api="$GH_API/repos/$owner/$repo/contents/$path?ref=$ref"
    debug "API: $api"
    log "Fetching contents from: $path"

    local res
    res=$(gh_api_get "$api") || error "API call failed (404? rate limit?)"

    if ! command -v jq >/dev/null; then
        error "Install 'jq' to download folders."
    fi

    # Check if response is an error message
    if echo "$res" | jq -e '.message' >/dev/null 2>&1; then
        local msg=$(echo "$res" | jq -r '.message')
        error "GitHub API error: $msg"
    fi

    local files dirs
    files=$(echo "$res" | jq -r '.[] | select(.type=="file") | "\(.path)|\(.name)|\(.download_url)"' 2>/dev/null || true)
    dirs=$(echo "$res" | jq -r '.[] | select(.type=="dir") | .path' 2>/dev/null || true)

    debug "Files found: $(echo "$files" | wc -l)"
    debug "Dirs found: $(echo "$dirs" | wc -l)"

    if [[ -n "$files" ]]; then
        while IFS='|' read -r fpath fname download_url; do
            [[ -z "$fpath" ]] && continue
            local local_rel="${fpath#${path}/}"
            [[ "$local_rel" == "$fpath" ]] && local_rel="$fname"
            local local_file="$outdir/$local_rel"
            mkdir -p "$(dirname "$local_file")"
            
            local raw_url="$download_url"
            if [[ -z "$raw_url" || "$raw_url" == "null" ]]; then
                raw_url="https://raw.githubusercontent.com/$owner/$repo/$ref/$fpath"
            fi
            
            log "→ Downloading: $fname"
            debug "  Path: $fpath"
            debug "  URL: $raw_url"
            debug "  Local: $local_file"
            download_raw_file "$raw_url" "$local_file"
        done <<< "$files"
    else
        debug "No files to download in this directory"
    fi

    if [[ -n "$dirs" ]]; then
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            local subdir="${d##*/}"
            log "→ Entering directory: $subdir/"
            mkdir -p "$outdir/$subdir"
            download_folder "$owner" "$repo" "$ref" "$d" "$outdir/$subdir"
        done <<< "$dirs"
    else
        debug "No subdirectories to process"
    fi
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS] <GITHUB_URL>

Supports:
  File:  https://github.com/user/repo/blob/master/path/file
  Folder:https://github.com/user/repo/tree/master/path/dir

Uses raw URLs in format:
  https://raw.githubusercontent.com/user/repo/master/...

OPTIONS:
  -o, --output PATH       Output file or directory
  -c, --checksum HASH     Verify SHA256 (files only)
  --debug                 Enable debug mode
  -h, --help              Show help

ENV:
  GH_TOKEN                Optional GitHub token

EXAMPLE:
  $0 https://github.com/USER/REPO/blob/master/FOLDER/file.exe
  $0 https://github.com/USER/REPO/tree/master/FOLDER

EOF
}

main() {
    local out="" hash="" url=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output) out="$2"; shift 2 ;;
            -c|--checksum) hash="$2"; shift 2 ;;
            --debug) DEBUG=1; shift ;;
            -h|--help) show_help; exit 0 ;;
            -*) error "Unknown flag: $1" ;;
            *) [[ -n "$url" ]] && error "Only one URL allowed"; url="$1"; shift ;;
        esac
    done

    [[ -z "$url" ]] && error "Missing URL"

    check_deps
    IFS='|' read -r user repo type ref path <<< "$(parse_github_url "$url")"

    if [[ "$type" == "blob" ]]; then
        out="${out:-${path##*/}}"
        local raw="https://raw.githubusercontent.com/$user/$repo/$ref/$path"
        log "Downloading file (ref: $ref)"
        debug "Raw URL: $raw"
        download_raw_file "$raw" "$out"
        verify_hash "$out" "$hash"
        success "Saved: ./$out"

    elif [[ "$type" == "tree" ]]; then
        [[ -n "$hash" ]] && warn "Checksum ignored for folders"
        out="${out:-${path##*/}}"
        log "Downloading folder (ref: $ref)"
        mkdir -p "$out"
        download_folder "$user" "$repo" "$ref" "$path" "$out"
        success "Folder saved to: $(pwd)/$out"

    else
        error "Unknown type: $type"
    fi
}

main "$@"
