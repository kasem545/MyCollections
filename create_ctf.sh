#!/bin/bash

BASE_DIR="$HOME/CTF_Machines"

create_ctf_directories() {
    local machine_name=$1
    local base_machine_dir="$BASE_DIR/$machine_name"

    dirs=("nmap" "exploits" "scripts" "loot" "screenshots" "writesup")

    mkdir -p "$base_machine_dir"

    for dir in "${dirs[@]}"; do
        mkdir -p "$base_machine_dir/$dir"
    done

    echo "Directories created for $machine_name"
}

if [ $# -lt 1 ]; then
    echo "Usage: $0 <machine_name_1> <machine_name_2> ... <machine_name_N>"
    exit 1
fi

mkdir -p "$BASE_DIR"

for machine in "$@"; do
    create_ctf_directories "$machine"
done

echo "All CTF directories have been created."
