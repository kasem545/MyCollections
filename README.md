# Security & Penetration Testing Toolkit

A comprehensive collection of scripts and tools designed for penetration testing, CTF competitions, security research, and bug bounty hunting.

## Table of Contents

- [Installation](#installation)
- [Tools Overview](#tools-overview)
  - [CTF & Challenge Tools](#ctf--challenge-tools)
  - [Reconnaissance & OSINT](#reconnaissance--osint)
  - [Web Security](#web-security)
  - [Network Analysis](#network-analysis)
  - [Payload Generation](#payload-generation)
  - [Utilities](#utilities)
- [Detailed Usage](#detailed-usage)
- [License](#license)

---

## Installation

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/MyScripts.git
cd MyScripts

# Make scripts executable
chmod +x *.sh

# Install security tools (requires sudo)
sudo ./tools-install-v2.sh
```

### Dependencies

Most scripts require minimal dependencies. Check individual tool sections for specific requirements.

---

## Tools Overview


### create_ctf.sh
**Automated CTF machine directory structure generator**

Creates organized workspace for CTF challenges with pre-configured directories and README template.

**Usage:**
```bash
./create_ctf.sh <machine_name> [machine_name2] ...

# Examples
./create_ctf.sh Bashed
./create_ctf.sh Lame Legacy Blue
./create_ctf.sh "Machine Name With Spaces"
```

**Options:**
- `-l, --list` - List all existing machines
- `-h, --help` - Show help

**Directory Structure Created:**
```
~/CTF_Machines/<machine_name>/
├── nmap/              # Scan results
├── exploits/          # Exploit code
├── scripts/           # Custom scripts
├── loot/              # Extracted data
├── screenshots/       # Visual documentation
├── writeup/           # Final writeup
└── notes/             # README with template
```

---

### addhost.sh
**Manage /etc/hosts entries for CTF platforms**

Easily add and organize IP-to-domain mappings for HTB, THM, and other platforms.

**Usage:**
```bash
sudo ./addhost.sh <ip> <domain1> [domain2...] <platform>

# Examples
sudo ./addhost.sh 10.10.10.10 example.htb dc01.example.htb htb
sudo ./addhost.sh 10.10.11.20 target.thm thm
```

**Features:**
- Automatic deduplication
- Platform-based organization with headers
- Single-line entries for multiple domains
- Safe removal of old entries

---

### Reconnaissance & OSINT

### crt.sh
**Subdomain enumeration using Certificate Transparency logs**

Query crt.sh for SSL/TLS certificates to discover subdomains.

**Usage:**
```bash
./crt.sh -d DOMAIN [OPTIONS]

# Examples
./crt.sh -d example.com
./crt.sh -d example.com -o subs.txt
./crt.sh -d example.com -f json -o results.json -v
./crt.sh -d example.com -w -v  # Include wildcards
```

**Options:**
- `-d DOMAIN` - Target domain (required)
- `-o FILE` - Save output to file
- `-f FORMAT` - Output format: text (default) or json
- `-t TIMEOUT` - Request timeout in seconds (default: 300)
- `-r RETRIES` - Number of retry attempts (default: 5)
- `-w` - Include wildcard entries (*.domain.com)
- `-v` - Verbose output with progress

**Features:**
- Robust error handling and retry logic
- JSON response validation
- Statistics and depth analysis
- Automatic deduplication
- Progress spinner

---

### Web Security

### jsendpoints.js
**Browser bookmarklet to extract JavaScript endpoints**

Extract API endpoints, URLs, and paths from JavaScript files on any webpage.

**Installation:**
1. Copy the contents of `jsendpoints.js`
2. Create a new bookmark in your browser
3. Paste the code as the URL/location

**Usage:**
1. Navigate to target website
2. Click the bookmarklet
3. Endpoints are automatically extracted and displayed

**Features:**
- Internal vs External URL categorization
- Status code checking (2xx, 3xx, 4xx, 5xx)
- Custom regex support
- Export to TXT, CSV, or JSON
- File extension color coding
- Stealth mode (disable automatic requests)

---

#### Bookmark-CVE-Search.js
**Multi-source CVE search bookmarklet**

Instantly search for CVEs across multiple vulnerability databases.

**Installation:**
Same as jsendpoints.js - add as browser bookmark

**Supported Sources:**
- Search-Vulns
- Sploitify
- Sploitus
- Vulners

**Features:**
- Auto-generate search links for all sources
- Real-time result counting
- Clean, dark-themed UI
- Copy individual URLs to clipboard

---

### Network Analysis

### Pcap-shark.py
**PCAP file analyzer for credential and file extraction**

Extract cleartext credentials and files from network captures.

**Installation:**
```bash
pip install scapy
```

**Usage:**
```bash
python3 Pcap-shark.py <pcap_file>
```

**Features:**
- Credential extraction from insecure protocols:
  - HTTP Basic Auth
  - FTP (USER/PASS)
  - Telnet
  - POP3/IMAP
  - SMTP
  - DNS queries
- File extraction from:
  - HTTP transfers
  - FTP transfers
  - TFTP transfers
  - SMB file shares
- Automatic file hashing (MD5/SHA256)
- Metadata preservation
- Color-coded output

**Output Structure:**
```
extracted_files/
├── http/
├── ftp/
├── tftp/
└── smb/
```

---

### Payload Generation

### revshell.sh
**Multi-language reverse shell payload generator**

Generate reverse shell payloads for various programming languages and tools.

**Usage:**
```bash
source revshell.sh
revshell <ip> <port>

# Example
revshell 10.10.14.5 4444
```

**Generated Payloads:**
- Bash (standard & base64 encoded)
- Netcat (busybox)
- Python
- PHP
- PowerShell (base64 encoded)
- Netcat FIFO
- Java Runtime.exec()

**Use Cases:**
- Quick payload generation during pentests
- CTF challenges
- Security testing

---

### Utilities

### gh-raw-dl.sh
**Download files and folders from GitHub without cloning**

Download specific files or directories from GitHub repositories using raw URLs.

**Usage:**
```bash
./gh-raw-dl.sh [OPTIONS] <GITHUB_URL>

# Download single file
./gh-raw-dl.sh https://github.com/user/repo/blob/master/file.exe

# Download entire folder
./gh-raw-dl.sh https://github.com/user/repo/tree/master/folder

# With checksum verification
./gh-raw-dl.sh -c <sha256_hash> -o output.bin <url>
```

**Options:**
- `-o, --output PATH` - Custom output path
- `-c, --checksum HASH` - Verify SHA256 (files only)
- `--debug` - Enable debug mode
- `-h, --help` - Show help

**Environment:**
- `GH_TOKEN` - Optional GitHub token for private repos or higher rate limits

**Features:**
- Recursive folder download
- Automatic file/folder detection
- SHA256 checksum verification
- GitHub API integration
- Progress indicators

---

### repo-updater.sh
**Bulk update Git repositories**

Update all Git repositories in /opt directory.

**Usage:**
```bash
sudo ./repo-updater.sh
```

**Features:**
- Automatic detection of Git repositories
- Skips repos with uncommitted changes
- Color-coded status reporting
- Summary statistics (successful/failed/skipped)

---

### tools-install-v2.sh
**Automated security tools installer**

Install and configure essential penetration testing tools.

**Usage:**
```bash
sudo ./tools-install-v2.sh
```

**Installed Tools & Repositories:**
- **Web Security:** dalfox, ParamSpider, LinkFinder, hakrawler
- **Cloud Security:** cloudfox, cloudsploit
- **Exploitation:** impacket, Havoc, Sliver, nishang
- **Recon:** cent, buster, nuclei-bug-hunter, spyhunt
- **Wordlists:** SecLists, PayloadsAllTheThings
- **Password Cracking:** brutespray
- **Privilege Escalation:** PrivescCheck, linux-smart-enumeration
- **Active Directory:** kerbrute, targetedKerberoast, ntlm_theft
- **Secret Scanning:** trufflehog
- **Reverse Engineering:** Luyten
- **C2 Frameworks:** AdaptixC2
- **Network Pivoting:** ligolo-ng
- **CVE Research:** cve-search, cve (trickest)
- **Utilities:** goclone, grex, username-anarchy

**System Packages:**
- Development: gcc, make, build-essential, cargo
- Languages: golang, python3, pipx
- Tools: fzf, jq, parallel, docker, tmux, zsh

---

## Detailed Usage

### Example Workflow: HTB Machine

```bash
# 1. Create workspace
./create_ctf.sh DevOops

# 2. Add host entry
sudo ./addhost.sh 10.10.10.91 devoops.htb htb

# 3. Start enumeration
cd ~/CTF_Machines/DevOops/nmap
nmap -sC -sV -oA initial 10.10.10.91

# 4. Take notes
cd ../notes
../../HackPad README.md

# 5. Generate reverse shell when needed
source ../../revshell.sh
revshell 10.10.14.5 4444

# 6. Subdomain enumeration
../../crt.sh -d devoops.htb -o subdomains.txt -v
```

### Example Workflow: Bug Bounty

```bash
# 1. Subdomain discovery
./crt.sh -d target.com -o subs.txt -v

# 2. Use browser bookmarklets
# - Navigate to target site
# - Click jsendpoints.js bookmarklet to extract API endpoints
# - Export results to JSON

# 3. Download specific tool from GitHub
./gh-raw-dl.sh https://github.com/user/tool/blob/master/exploit.py

# 4. Analyze network traffic if provided
python3 Pcap-shark.py capture.pcap

# 5. Search for CVEs found
# Click Bookmark-CVE-Search.js bookmarklet and search for CVE-XXXX-XXXXX
```



---



## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Include relevant error messages and system information
- Provide steps to reproduce any problems

---


## License

This project is licensed under the terms specified in individual files.

Copyright (C) 2025 Kasem Shibli <kasem545@proton.me>

**Use responsibly and ethically.**

