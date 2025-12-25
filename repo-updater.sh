#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SUCCESS_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

cd /opt || { echo -e "${RED}Error: Cannot access /opt${NC}"; exit 1; }

echo -e "${BLUE}Starting git repository updates in /opt...${NC}\n"

for dir in */; do
    dir="${dir%/}"
    
    if [ -d "$dir/.git" ]; then
        cd "$dir" || { 
            echo -e "${RED}✗ $dir - Cannot access directory${NC}"
            ((FAILED_COUNT++))
            continue
        }
        
        echo -ne "${BLUE}→ Updating $dir...${NC} "
        
        if ! git diff-index --quiet HEAD -- 2>/dev/null; then
            echo -e "${YELLOW}SKIPPED (uncommitted changes)${NC}"
            ((SKIPPED_COUNT++))
            cd /opt
            continue
        fi
        
        if git pull --quiet 2>/dev/null; then
            echo -e "${GREEN}✓ Success${NC}"
            ((SUCCESS_COUNT++))
        else
            echo -e "${RED}✗ Failed${NC}"
            ((FAILED_COUNT++))
        fi
        
        cd /opt
    fi
done

echo -e "\n${BLUE}═══════════════════════════════════${NC}"
echo -e "${GREEN}Successful: $SUCCESS_COUNT${NC}"
echo -e "${RED}Failed: $FAILED_COUNT${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED_COUNT${NC}"
echo -e "${BLUE}═══════════════════════════════════${NC}"