#!/usr/bin/bash
#
# git-raw-dl.sh
# Universal Git Downloader
# Version: 2.1.0
#
# Usage:
#   ./git-raw-dl.sh URL
#   ./git-raw-dl.sh --file URL
#   ./git-raw-dl.sh --folder URL
#   ./git-raw-dl.sh --repo URL
#
# SUPPORTED PLATFORMS:
#    GitHub
#    GitLab
#    Bitbucket
#    Gitea
#    Forgejo
#    Codeberg
#    SourceHut
#    GitHub Enterprise
#    GitLab Self-Managed
#    Custom Git servers



set -Eeuo pipefail
IFS=$'\n\t'

VERSION="2.1.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

MODE="auto"
OUTPUT=""
REF_OVERRIDE=""
TOKEN="${GIT_TOKEN:-}"
CHECKSUM=""
DEBUG=0
KEEP_TEMP=0
FORCE=0

HOST=""
REPO_PATH=""
REPO_NAME=""
CLONE_URL=""
URL_TYPE="repo"
REF=""
TARGET_PATH=""
PROVIDER="generic"

TMPDIR_GIT=""
GIT_AUTH_ARGS=()

# --------------------------------------------------
# LOGGING
# --------------------------------------------------

log() {
    printf "${BLUE}[INFO]${NC} %s\n" "$*"
}

success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$*"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$*" >&2
    exit 1
}

debug() {
    if (( DEBUG )); then
        printf "${CYAN}[DEBUG]${NC} %s\n" "$*" >&2
    fi
}

# --------------------------------------------------
# HELP
# --------------------------------------------------

usage() {
    cat <<EOF
Universal Git Downloader v$VERSION

USAGE:
    $0 [OPTIONS] URL

DOWNLOAD MODES:
    --auto              Automatically detect URL type (default)
    --file              Download a single file
    --folder            Download a directory recursively
    --repo              Download entire repository

OPTIONS:
    -o, --output PATH   Output file or directory
    -r, --ref REF       Branch, tag or commit hash
    -t, --token TOKEN   Git access token
    -c, --checksum HASH Verify SHA256
        --force         Overwrite existing output
        --keep-temp     Keep temporary clone
        --debug         Enable debug output
    -h, --help          Show help

ENVIRONMENT:
    GIT_TOKEN           Default access token

EXAMPLES:

    # Repository
    $0 https://github.com/user/repo

    # Directory
    $0 https://github.com/user/repo/tree/main/tools

    # File
    $0 https://github.com/user/repo/blob/main/tools/install.sh

    # GitLab nested groups
    $0 https://gitlab.com/group/subgroup/project/-/tree/main/src

    # Bitbucket
    $0 https://bitbucket.org/workspace/repo/src/main/tools

    # Gitea / Forgejo / Codeberg
    $0 https://codeberg.org/user/repo/src/branch/main/tools

    # Private repository
    $0 --token TOKEN https://github.com/user/private-repo

    # Custom branch
    $0 --ref develop --repo https://github.com/user/repo

    # Custom output
    $0 -o ./downloads/tools URL

    # SHA256 verification
    $0 -c SHA256 URL

EOF
}

# --------------------------------------------------
# DEPENDENCIES
# --------------------------------------------------

check_dependencies() {
    command -v git >/dev/null 2>&1 ||
        error "Git is required."

    command -v curl >/dev/null 2>&1 ||
        error "curl is required."

    if ! command -v sha256sum >/dev/null 2>&1 &&
       ! command -v shasum >/dev/null 2>&1; then
        error "sha256sum or shasum is required."
    fi

    export GIT_TERMINAL_PROMPT=0
    export GIT_LFS_SKIP_SMUDGE=1
}

# --------------------------------------------------
# CLEANUP
# --------------------------------------------------

cleanup() {
    if [[ -n "$TMPDIR_GIT" &&
          -d "$TMPDIR_GIT" &&
          "$KEEP_TEMP" -eq 0 ]]; then

        rm -rf -- "$TMPDIR_GIT"
    fi
}

trap cleanup EXIT

# --------------------------------------------------
# URL PARSER
# --------------------------------------------------


decode_url_path() {
    python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$1"
}

parse_url() {
    local input="$1"
    local rest

    [[ "$input" =~ ^https?://([^/]+)/(.+)$ ]] ||
        error "Invalid repository URL"

    HOST="${BASH_REMATCH[1]}"
    rest="${BASH_REMATCH[2]}"

    rest="${rest%%\?*}"
    rest="${rest%%\#*}"
    rest="${rest%/}"

    PROVIDER="generic"
    URL_TYPE="repo"
    REF=""
    TARGET_PATH=""

    # GitLab
    if [[ "$rest" =~ ^(.+)/-/((blob|tree))/([^/]+)/(.*)$ ]]; then
        REPO_PATH="${BASH_REMATCH[1]}"
        URL_TYPE="${BASH_REMATCH[2]}"
        REF="${BASH_REMATCH[4]}"
        TARGET_PATH="${BASH_REMATCH[5]}"
        PROVIDER="gitlab"

    # Gitea / Forgejo: branch URLs
    elif [[ "$rest" =~ ^(.+)/src/branch/([^/]+)/(.*)$ ]]; then
        REPO_PATH="${BASH_REMATCH[1]}"
        REF="${BASH_REMATCH[2]}"
        TARGET_PATH="${BASH_REMATCH[3]}"
        URL_TYPE="tree"
        PROVIDER="gitea"

    # Gitea / Forgejo: commit URLs
    elif [[ "$rest" =~ ^(.+)/src/commit/([^/]+)/(.*)$ ]]; then
        REPO_PATH="${BASH_REMATCH[1]}"
        REF="${BASH_REMATCH[2]}"
        TARGET_PATH="${BASH_REMATCH[3]}"
        URL_TYPE="tree"
        PROVIDER="gitea"

    # Bitbucket
    elif [[ "$rest" =~ ^([^/]+)/([^/]+)/src/([^/]+)/(.*)$ ]]; then
        REPO_PATH="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
        REF="${BASH_REMATCH[3]}"
        TARGET_PATH="${BASH_REMATCH[4]}"
        URL_TYPE="tree"
        PROVIDER="bitbucket"

    # GitHub
    elif [[ "$rest" =~ ^([^/]+)/([^/]+)/(blob|tree)/([^/]+)/(.*)$ ]]; then
        REPO_PATH="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
        URL_TYPE="${BASH_REMATCH[3]}"
        REF="${BASH_REMATCH[4]}"
        TARGET_PATH="${BASH_REMATCH[5]}"
        PROVIDER="github"

    # Generic repository
    else
        REPO_PATH="${rest%.git}"
        URL_TYPE="repo"
    fi

    REPO_NAME="${REPO_PATH##*/}"
    REPO_NAME="${REPO_NAME%.git}"

    case "$HOST" in
        github.com) PROVIDER="github" ;;
        gitlab.com) PROVIDER="gitlab" ;;
        bitbucket.org) PROVIDER="bitbucket" ;;
        codeberg.org) PROVIDER="forgejo" ;;
        git.sr.ht) PROVIDER="sourcehut" ;;
    esac

    # Decode URL-encoded file and directory names.
    TARGET_PATH="$(decode_url_path "$TARGET_PATH")"

    # Detect individual files.
    if [[ "$URL_TYPE" == "tree" ]]; then
        local basename="${TARGET_PATH##*/}"

        case "$basename" in
            *.*)
                URL_TYPE="blob"
                ;;
        esac
    fi

    CLONE_URL="https://${HOST}/${REPO_PATH}.git"

    [[ "$PROVIDER" == "sourcehut" ]] &&
        CLONE_URL="https://${HOST}/${REPO_PATH}"

    [[ -n "$REF_OVERRIDE" ]] && REF="$REF_OVERRIDE"

    debug "Host: $HOST"
    debug "Provider: $PROVIDER"
    debug "Repository: $REPO_PATH"
    debug "Clone URL: $CLONE_URL"
    debug "Type: $URL_TYPE"
    debug "Ref: $REF"
    debug "Path: $TARGET_PATH"
}


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

git_auth() {
    [[ -z "$TOKEN" ]] && return 0

    local username="git"
    local encoded

    case "$PROVIDER" in
        github)
            username="x-access-token"
            ;;
        gitlab)
            username="oauth2"
            ;;
        bitbucket)
            username="x-token-auth"
            ;;
        *)
            username="git"
            ;;
    esac

    encoded="$(
        printf '%s:%s' "$username" "$TOKEN" |
        base64 |
        tr -d '\n'
    )"

    GIT_AUTH_ARGS=(
        -c "http.extraheader=AUTHORIZATION: basic $encoded"
    )
}

run_git() {
    git "${GIT_AUTH_ARGS[@]}" "$@"
}

# --------------------------------------------------
# OUTPUT HANDLING
# --------------------------------------------------

check_output() {
    local path="$1"

    if [[ -e "$path" && "$FORCE" -eq 0 ]]; then
        error "Output already exists: $path (use --force)"
    fi

    if [[ -e "$path" && "$FORCE" -eq 1 ]]; then

        if [[ -d "$path" && ! -L "$path" ]]; then
            rm -rf -- "$path"
        else
            rm -f -- "$path"
        fi

    fi
}

# --------------------------------------------------
# REPOSITORY CLONING
# --------------------------------------------------

clone_repository() {
    local destination="$1"
    local ref="${2:-}"
    local sparse_path="${3:-}"

    local args=(
        clone
        --no-tags
        --filter=blob:none
        --no-checkout
    )

    if [[ -n "$ref" &&
          ! "$ref" =~ ^[0-9a-fA-F]{7,64}$ ]]; then

        args+=(--branch "$ref" --depth 1)

    fi

    log "Connecting to $HOST..."
    log "Fetching repository metadata..."

    run_git "${args[@]}" -- "$CLONE_URL" "$destination" ||
        error "Unable to clone repository. Check URL and credentials."

    if [[ -n "$sparse_path" ]]; then

        log "Enabling sparse checkout..."

        git -C "$destination" sparse-checkout init --cone ||
            error "Sparse checkout initialization failed."

        git -C "$destination" sparse-checkout set -- "$sparse_path" ||
            error "Unable to configure sparse checkout."

    fi

    if [[ -n "$ref" ]]; then

        log "Checking out ref: $ref"

        run_git -C "$destination" checkout --detach "$ref" ||
            error "Unable to checkout ref: $ref"

    else

        run_git -C "$destination" checkout ||
            error "Unable to checkout default branch."

    fi
}

# --------------------------------------------------
# CHECKSUM
# --------------------------------------------------

verify_checksum() {
    local file="$1"

    [[ -z "$CHECKSUM" ]] && return 0

    local actual

    if command -v sha256sum >/dev/null 2>&1; then

        actual="$(sha256sum "$file" | awk '{print $1}')"

    else

        actual="$(shasum -a 256 "$file" | awk '{print $1}')"

    fi

    if [[ "${actual,,}" != "${CHECKSUM,,}" ]]; then
        error "SHA256 verification failed."
    fi

    success "SHA256 verified."
}

# --------------------------------------------------
# DOWNLOAD FILE
# --------------------------------------------------

download_file() {
    [[ -n "$TARGET_PATH" ]] ||
        error "No file path found."

    local destination="${OUTPUT:-${TARGET_PATH##*/}}"
    local sparse_dir

    sparse_dir="$(dirname "$TARGET_PATH")"

    [[ "$sparse_dir" == "." ]] && sparse_dir=""

    check_output "$destination"

    mkdir -p "$(dirname "$destination")"

    TMPDIR_GIT="$(mktemp -d)"

    local repo="$TMPDIR_GIT/repo"

    clone_repository "$repo" "$REF" "$sparse_dir"

    local source="$repo/$TARGET_PATH"

    [[ -f "$source" ]] ||
        error "File not found: $TARGET_PATH"

    cp -- "$source" "$destination"

    verify_checksum "$destination"

    success "Downloaded: $destination"
}

# --------------------------------------------------
# DOWNLOAD FOLDER
# --------------------------------------------------

download_folder() {
    [[ -n "$TARGET_PATH" ]] ||
        error "No directory path found."

    local destination="${OUTPUT:-${TARGET_PATH##*/}}"

    check_output "$destination"

    TMPDIR_GIT="$(mktemp -d)"

    local repo="$TMPDIR_GIT/repo"

    clone_repository "$repo" "$REF" "$TARGET_PATH"

    local source="$repo/$TARGET_PATH"

    [[ -d "$source" ]] ||
        error "Directory not found: $TARGET_PATH"

    mkdir -p "$destination"

    log "Copying directory recursively..."

    cp -a "$source/." "$destination/"

    success "Directory downloaded: $destination"
}

# --------------------------------------------------
# DOWNLOAD REPOSITORY
# --------------------------------------------------

download_repo() {
    local destination="${OUTPUT:-$REPO_NAME}"

    check_output "$destination"

    local args=(
        clone
        --filter=blob:none
    )

    if [[ -n "$REF" ]]; then
        args+=(--branch "$REF")
    fi

    log "Downloading repository: $REPO_NAME"

    run_git "${args[@]}" -- "$CLONE_URL" "$destination" ||
        error "Repository download failed."

    success "Repository saved: $destination"
}

# --------------------------------------------------
# MAIN
# --------------------------------------------------

main() {
    local url=""

    while (($#)); do

        case "$1" in

            -o|--output)
                (($# >= 2)) || error "Missing output path."
                OUTPUT="$2"
                shift 2
                ;;

            -r|--ref|--branch)
                (($# >= 2)) || error "Missing ref."
                REF_OVERRIDE="$2"
                shift 2
                ;;

            -t|--token)
                (($# >= 2)) || error "Missing token."
                TOKEN="$2"
                shift 2
                ;;

            -c|--checksum)
                (($# >= 2)) || error "Missing checksum."
                CHECKSUM="$2"
                shift 2
                ;;

            --file)
                MODE="file"
                shift
                ;;

            --folder)
                MODE="folder"
                shift
                ;;

            --repo)
                MODE="repo"
                shift
                ;;

            --auto)
                MODE="auto"
                shift
                ;;

            --force)
                FORCE=1
                shift
                ;;

            --keep-temp)
                KEEP_TEMP=1
                shift
                ;;

            --debug)
                DEBUG=1
                shift
                ;;

            -h|--help)
                usage
                exit 0
                ;;

            --)
                shift
                break
                ;;

            -*)
                error "Unknown option: $1"
                ;;

            *)
                [[ -z "$url" ]] ||
                    error "Only one URL allowed."

                url="$1"
                shift
                ;;

        esac

    done

    [[ -n "$url" ]] || {
        usage
        exit 1
    }

    check_dependencies
    parse_url "$url"
    git_auth

    if [[ "$MODE" == "auto" ]]; then

        case "$URL_TYPE" in
            blob) MODE="file" ;;
            tree) MODE="folder" ;;
            *) MODE="repo" ;;
        esac

    fi

    log "Git provider: $PROVIDER"
    log "Download mode: $MODE"

    case "$MODE" in

        file)
            download_file
            ;;

        folder)
            download_folder
            ;;

        repo)
            download_repo
            ;;

        *)
            error "Unknown download mode: $MODE"
            ;;

    esac
}

main "$@"
