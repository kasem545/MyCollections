#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <ip> <domain1> [domain2 ... domainN] <platform>"
    echo "Example: sudo $0 10.10.x.x example.htb dc01.example.htb ftp.example.htb htb"
    exit 1
fi

ip="$1"
platform="${!#}"
num_args=$#
domains=("${@:2:$((num_args-2))}")
hosts_file="/etc/hosts"

# Remove any existing lines containing any of the domains
tmpfile=$(mktemp)
grepargs=()
for d in "${domains[@]}"; do
    grepargs+=(-e "$d")
done
sudo grep -vF "${grepargs[@]}" "$hosts_file" > "$tmpfile" || true

# Create one single line with all domains for this IP
entry="$ip"
for d in "${domains[@]}"; do
    entry+=" $d"
done

header="# ====== $platform ======"

if grep -Fxq "$header" "$tmpfile"; then
    awk -v hdr="$header" -v ent="$entry" '{
        print $0
        if ($0==hdr) print ent
    }' "$tmpfile" | sudo tee "$hosts_file" > /dev/null
else
    sudo bash -c "cat >> '$hosts_file' <<-EOF

$header
$entry
EOF"
fi

rm -f "$tmpfile"
