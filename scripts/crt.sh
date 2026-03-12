#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat << EOF
Usage: $0 -d DOMAIN [OPTIONS]

Subdomain enumeration using crt.sh certificate transparency logs

Required:
  -d DOMAIN        The domain to query (e.g., example.com)

Optional:
  -o OUTPUT_FILE   Save output to a file
  -f FORMAT        Output format: text (default) or json
  -t TIMEOUT       Request timeout in seconds (default: 300)
  -r RETRIES       Number of retry attempts (default: 5)
  -w               Include wildcard entries (*.domain.com)
  -v               Verbose output with progress
  -h               Display this help message

Examples:
  $0 -d example.com
  $0 -d example.com -o subs.txt
  $0 -d example.com -f json -o results.json -v
  $0 -d example.com -t 600 -r 10
  $0 -d example.com -w -v

EOF
}

OUTPUT_FILE=""
FORMAT="text"
DOMAIN=""
TIMEOUT=300
RETRIES=5
VERBOSE=false
INCLUDE_WILDCARDS=false
TEMP_FILE="/tmp/crtsh_$$_response.json"

while getopts "d:o:f:t:r:wvh" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        f) FORMAT="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        r) RETRIES="$OPTARG" ;;
        w) INCLUDE_WILDCARDS=true ;;
        v) VERBOSE=true ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}[✖]${NC} Error: Domain is required"
    usage
    exit 1
fi

check_dependencies() {
    local missing=()
    
    for cmd in curl jq; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[✖]${NC} Missing required tools: ${missing[*]}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

show_progress() {
    local pid=$1
    local delay=0.5
    local elapsed=0
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        if [ "$VERBOSE" = true ]; then
            printf "\r${CYAN}[${spinstr:0:1}]${NC} Waiting for response... ${elapsed}s elapsed"
        else
            printf "\r${CYAN}[${spinstr:0:1}]${NC} Fetching data..."
        fi
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        elapsed=$((elapsed + 1))
    done
    printf "\r"
}

fix_json_response() {
    local input_file=$1
    local output_file="${input_file}.fixed"
    
    local raw_content=$(cat "$input_file")
    
    raw_content=$(echo "$raw_content" | sed 's/^,//')
    
    if echo "$raw_content" | jq empty 2>/dev/null; then
        cat "$input_file" > "$output_file"
        return 0
    fi
    
    if echo "$raw_content" | grep -q '^{'; then
        echo "[$raw_content]" > "$output_file"
    else
        echo "$raw_content" > "$output_file"
    fi
    
    if jq empty "$output_file" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

fetch_subdomains() {
    local domain=$1
    local attempt=1
    
    local encoded_domain=$(echo "%.${domain}" | sed 's/ /%20/g')
    local url="https://crt.sh/json?q=${encoded_domain}"
    
    while [ $attempt -le $RETRIES ]; do
        echo -e "${BLUE}[*]${NC} Attempt $attempt/$RETRIES - Querying crt.sh for: ${YELLOW}$domain${NC}"
        
        if [ "$VERBOSE" = true ]; then
            echo -e "${BLUE}[*]${NC} URL: $url"
            echo -e "${BLUE}[*]${NC} Timeout: ${TIMEOUT}s | Connect timeout: 60s"
            echo -e "${BLUE}[*]${NC} Note: crt.sh can be very slow, please be patient..."
        fi
        
        if [ $attempt -gt 1 ]; then
            local wait_time=$((attempt * 5))
            echo -e "${YELLOW}[!]${NC} Waiting ${wait_time}s before retry..."
            sleep $wait_time
        fi
        
        (
            curl -s -w "\nHTTP_CODE:%{http_code}\n" \
                --connect-timeout 60 \
                --max-time "$TIMEOUT" \
                --retry 3 \
                --retry-delay 5 \
                --retry-max-time $((TIMEOUT + 60)) \
                --compressed \
                -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
                -H "Accept: application/json, text/javascript, */*; q=0.01" \
                -H "Accept-Encoding: gzip, deflate, br" \
                -H "Accept-Language: en-US,en;q=0.9" \
                -H "Referer: https://crt.sh/" \
                "$url" > "$TEMP_FILE" 2>&1
        ) &
        
        local curl_pid=$!
        
        show_progress $curl_pid
        wait $curl_pid
        local curl_exit=$?
        
        if [ "$VERBOSE" = true ]; then
            echo -e "${BLUE}[*]${NC} Curl exit code: $curl_exit"
        fi
        
        if [ ! -f "$TEMP_FILE" ] || [ ! -s "$TEMP_FILE" ]; then
            echo -e "${RED}[✖]${NC} No response received"
            ((attempt++))
            continue
        fi
        
        local http_code=$(grep "HTTP_CODE:" "$TEMP_FILE" | cut -d: -f2)
        
        sed -i.bak '/HTTP_CODE:/d' "$TEMP_FILE" && rm -f "${TEMP_FILE}.bak"
        
        if [ "$VERBOSE" = true ] && [ -n "$http_code" ]; then
            echo -e "${BLUE}[*]${NC} HTTP Status Code: $http_code"
        fi
        
        if [ -n "$http_code" ]; then
            case $http_code in
                200)
                    if [ "$VERBOSE" = true ]; then
                        echo -e "${GREEN}[+]${NC} HTTP 200 OK"
                    fi
                    ;;
                429)
                    echo -e "${RED}[✖]${NC} HTTP 429: Rate limit exceeded"
                    echo -e "${YELLOW}[!]${NC} Waiting 30s before retry..."
                    sleep 30
                    ((attempt++))
                    continue
                    ;;
                500|502|503|504)
                    echo -e "${RED}[✖]${NC} HTTP $http_code: Server error"
                    ((attempt++))
                    continue
                    ;;
            esac
        fi
        
        local file_size=$(stat -f%z "$TEMP_FILE" 2>/dev/null || stat -c%s "$TEMP_FILE" 2>/dev/null)
        
        if [ "$VERBOSE" = true ]; then
            echo -e "${BLUE}[*]${NC} Response size: $file_size bytes"
            echo -e "${BLUE}[*]${NC} First 200 chars: $(head -c 200 "$TEMP_FILE")"
        fi
        
        if [ $curl_exit -eq 28 ]; then
            echo -e "${RED}[✖]${NC} Request timed out after ${TIMEOUT}s"
            echo -e "${YELLOW}[!]${NC} Try increasing timeout with: -t $((TIMEOUT * 2))"
            ((attempt++))
            continue
        fi
        
        if [ $curl_exit -eq 7 ]; then
            echo -e "${RED}[✖]${NC} Failed to connect to crt.sh"
            echo -e "${YELLOW}[!]${NC} Check your internet connection or try again later"
            ((attempt++))
            continue
        fi
        
        if head -n 1 "$TEMP_FILE" | grep -qi "<!doctype\|<html"; then
            echo -e "${RED}[✖]${NC} Received HTML error page instead of JSON"
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[*]${NC} First line: $(head -n 1 "$TEMP_FILE")"
            fi
            ((attempt++))
            continue
        fi
        
        if grep -qi "error\|rate.limit\|too.many" "$TEMP_FILE"; then
            echo -e "${RED}[✖]${NC} API returned an error"
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[*]${NC} Response: $(head -c 500 "$TEMP_FILE")"
            fi
            ((attempt++))
            continue
        fi
        
        echo -e "${BLUE}[*]${NC} Fixing JSON response format..."
        if ! fix_json_response "$TEMP_FILE"; then
            echo -e "${RED}[✖]${NC} Failed to fix JSON response"
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[*]${NC} First 500 chars:"
                head -c 500 "$TEMP_FILE"
                echo ""
            fi
            ((attempt++))
            continue
        fi
        
        mv "${TEMP_FILE}.fixed" "$TEMP_FILE"
        
        if ! jq empty "$TEMP_FILE" 2>/dev/null; then
            echo -e "${RED}[✖]${NC} Invalid JSON response after fixing"
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[*]${NC} First 500 chars:"
                head -c 500 "$TEMP_FILE"
                echo ""
            fi
            ((attempt++))
            continue
        fi
        
        local json_check=$(jq -r 'if . == [] or . == null then "empty" else "ok" end' "$TEMP_FILE" 2>/dev/null)
        if [ "$json_check" = "empty" ]; then
            echo -e "${YELLOW}[!]${NC} No certificate records found for $domain"
            rm -f "$TEMP_FILE"
            return 1
        fi
        
        local entry_count=$(jq '. | length' "$TEMP_FILE" 2>/dev/null)
        
        if [ -z "$entry_count" ] || [ "$entry_count" -eq 0 ]; then
            echo -e "${RED}[✖]${NC} Response contains no certificate entries"
            ((attempt++))
            continue
        fi
        
        local has_name_value=$(jq -r 'if type == "array" then .[0] | has("name_value") else has("name_value") end' "$TEMP_FILE" 2>/dev/null)
        if [ "$has_name_value" != "true" ]; then
            echo -e "${RED}[✖]${NC} Response missing expected 'name_value' field"
            if [ "$VERBOSE" = true ]; then
                echo -e "${BLUE}[*]${NC} First entry structure:"
                jq -r 'if type == "array" then .[0] else . end' "$TEMP_FILE" 2>/dev/null | head -c 300
                echo ""
            fi
            ((attempt++))
            continue
        fi
        
        echo -e "${GREEN}[+]${NC} Successfully fetched $entry_count certificate record(s)"
        return 0
        
        ((attempt++))
    done
    
    echo -e "${RED}[✖]${NC} Failed after $RETRIES attempts"
    rm -f "$TEMP_FILE"
    return 1
}

process_subdomains() {
    echo -e "${BLUE}[*]${NC} Extracting subdomains from certificate data..."
    
    local raw_result=$(jq -r '.[] | .name_value // .common_name // empty' "$TEMP_FILE" 2>/dev/null)
    
    if [ -z "$raw_result" ]; then
        echo -e "${RED}[✖]${NC} No subdomains could be extracted"
        return 1
    fi
    
    local result=$(echo "$raw_result" | \
        tr '\n' '\n' | \
        tr '[:upper:]' '[:lower:]' | \
        sort -u)
    
    if [ "$INCLUDE_WILDCARDS" = false ]; then
        result=$(echo "$result" | grep -v '^\*\.')
    fi
    
    result=$(echo "$result" | sed '/^$/d')
    
    if [ -z "$result" ]; then
        echo -e "${RED}[✖]${NC} No subdomains remaining after filtering"
        return 1
    fi
    
    echo "$result"
    return 0
}

show_stats() {
    local data=$1
    local count=$(echo "$data" | wc -l | tr -d ' ')
    
    echo ""
    echo -e "${GREEN}[+]${NC} Found ${YELLOW}$count${NC} unique subdomain(s)"
    
    if [ "$VERBOSE" = true ]; then
        echo ""
        echo -e "${BLUE}[*]${NC} Statistics:"
        
        local wildcards=$(echo "$data" | grep -c '^\*\.' || echo 0)
        if [ "$INCLUDE_WILDCARDS" = true ]; then
            echo "  - Wildcard entries: $wildcards"
        fi
        
        local level2=$(echo "$data" | awk -F. 'NF==2' | wc -l | tr -d ' ')
        local level3=$(echo "$data" | awk -F. 'NF==3' | wc -l | tr -d ' ')
        local level4=$(echo "$data" | awk -F. 'NF>=4' | wc -l | tr -d ' ')
        
        echo "  - Depth distribution:"
        echo "    • Level 2 (domain.tld): $level2"
        echo "    • Level 3 (sub.domain.tld): $level3"
        echo "    • Level 4+ (deep nesting): $level4"
        
        local tld_count=$(echo "$data" | awk -F. '{print $NF}' | sort -u | wc -l | tr -d ' ')
        echo "  - Unique TLDs: $tld_count"
        
        echo ""
        echo -e "${BLUE}[*]${NC} Sample subdomains (first 10):"
        echo "$data" | head -10 | while read -r line; do
            echo "  - $line"
        done
        
        if [ -f "$TEMP_FILE" ]; then
            echo ""
            echo -e "${BLUE}[*]${NC} Certificate info:"
            local earliest=$(jq -r '[.[] | .not_before] | min' "$TEMP_FILE" 2>/dev/null)
            local latest=$(jq -r '[.[] | .not_after] | max' "$TEMP_FILE" 2>/dev/null)
            if [ -n "$earliest" ] && [ "$earliest" != "null" ]; then
                echo "  - Earliest certificate: $earliest"
            fi
            if [ -n "$latest" ] && [ "$latest" != "null" ]; then
                echo "  - Latest expiry: $latest"
            fi
        fi
    fi
}

save_output() {
    local data=$1
    
    if [ "$FORMAT" == "json" ]; then
        local json_output=$(echo "$data" | jq -R -s -c 'split("\n") | map(select(length > 0))')
        
        if [ -n "$OUTPUT_FILE" ]; then
            if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
                echo -e "${BLUE}[*]${NC} Merging with existing JSON file..."
                local existing=$(cat "$OUTPUT_FILE")
                local merged=$(jq -s '.[0] + .[1] | unique | sort' \
                    <(echo "$existing") <(echo "$json_output") 2>/dev/null)
                
                if [ $? -eq 0 ] && [ -n "$merged" ]; then
                    echo "$merged" | jq '.' > "$OUTPUT_FILE"
                else
                    echo -e "${YELLOW}[!]${NC} Merge failed, overwriting file"
                    echo "$json_output" | jq '.' > "$OUTPUT_FILE"
                fi
            else
                echo "$json_output" | jq '.' > "$OUTPUT_FILE"
            fi
            echo -e "${GREEN}[+]${NC} Saved to: ${YELLOW}$OUTPUT_FILE${NC}"
        else
            echo ""
            echo -e "${BLUE}[*]${NC} JSON Output:"
            echo "$json_output" | jq '.'
        fi
    else

        if [ -n "$OUTPUT_FILE" ]; then
            if [ -f "$OUTPUT_FILE" ]; then

                cat "$OUTPUT_FILE" <(echo "$data") | sort -u > "${OUTPUT_FILE}.tmp"
                mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            else
                echo "$data" > "$OUTPUT_FILE"
            fi
            echo -e "${GREEN}[+]${NC} Saved to: ${YELLOW}$OUTPUT_FILE${NC}"
        else
            echo ""
            echo -e "${BLUE}[*]${NC} Results:"
            echo ""
            echo "$data"
        fi
    fi
}

cleanup() {
    rm -f "$TEMP_FILE" "${TEMP_FILE}.fixed" "${TEMP_FILE}.bak"
}

trap cleanup EXIT INT TERM

main() {
    local start_time=$(date +%s)
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    CRT.SH Subdomain Enumeration Tool      ║${NC}"
    echo -e "${CYAN}║         Using /json API Endpoint          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_dependencies
    
    echo -e "${BLUE}[*]${NC} Target Domain: ${YELLOW}$DOMAIN${NC}"
    echo -e "${BLUE}[*]${NC} Timeout: ${TIMEOUT}s | Retries: $RETRIES"
    if [ "$INCLUDE_WILDCARDS" = true ]; then
        echo -e "${BLUE}[*]${NC} Including wildcard entries"
    fi
    echo ""
    
    if ! fetch_subdomains "$DOMAIN"; then
        echo ""
        echo -e "${RED}[✖]${NC} Failed to fetch certificate data"
        echo ""
        echo -e "${YELLOW}Suggestions:${NC}"
        echo "  1. Increase timeout: $0 -d $DOMAIN -t 600"
        echo "  2. Increase retries: $0 -d $DOMAIN -r 10"
        echo "  3. Try again later (crt.sh may be overloaded)"
        echo "  4. Check if domain exists in CT logs"
        echo "  5. Try with verbose mode: $0 -d $DOMAIN -v"
        echo ""
        exit 1
    fi
    
    local subdomains
    if ! subdomains=$(process_subdomains); then
        echo -e "${RED}[✖]${NC} Failed to process certificate data"
        exit 1
    fi
    
    show_stats "$subdomains"
    
    echo ""
    save_output "$subdomains"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${GREEN}[+]${NC} Completed in ${CYAN}${duration}s${NC}"
    echo ""
}

main