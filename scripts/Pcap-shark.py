#!/usr/bin/env python3
"""
Pcap-shark Credential Analyzer v4.0
- Extract cleartext credentials from insecure protocols
- Comprehensive sensitive data extraction (emails, phones, credit cards, SSN, etc.)
- File extraction (HTTP, FTP, TFTP, SMB)
- Protocol support: HTTP, FTP, SNMP, POP3, IMAP, SMTP, LDAP, RDP, DNS, SMB, VNC, Telnet, TFTP
"""

import sys
import re
import base64
import hashlib
import json
import os
import struct
import binascii
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlparse
from pathlib import Path
from typing import Any

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.l2 import Ether
    from scapy.utils import rdpcap, PcapReader
except ImportError:
    print("[!] Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


@dataclass
class SensitiveMatch:
    """Container for sensitive data match results."""

    pattern_type: str
    value: str
    confidence: str  # HIGH, MEDIUM, LOW
    context: str = ""


class SensitiveDataExtractor:
    """
    Unified sensitive data pattern matching across all protocols.

    Extracts: emails, phone numbers, credit cards, SSN, IBANs,
    credentials, API keys, private keys, database connection strings.
    """

    def __init__(self) -> None:
        self.patterns: dict[str, re.Pattern[str]] = self._compile_patterns()
        self._seen_matches: set[tuple[str, str]] = set()

    def _compile_patterns(self) -> dict[str, re.Pattern[str]]:
        """Compile all regex patterns for sensitive data detection."""
        # Valid TLDs for email validation (common ones)
        tld_pattern = (
            r"(?:com|org|net|edu|gov|mil|int|co|io|ai|dev|app|"
            r"uk|us|ca|au|de|fr|it|es|nl|ru|cn|jp|kr|br|in|mx|"
            r"info|biz|name|pro|aero|museum|coop)"
        )

        return {
            # Email: stricter pattern requiring valid TLD and reasonable local part
            "email": re.compile(
                rf"\b[A-Za-z][A-Za-z0-9._%+-]{{2,63}}@[A-Za-z0-9][-A-Za-z0-9]{{0,62}}"
                rf"(?:\.[A-Za-z0-9][-A-Za-z0-9]{{0,62}})*\.{tld_pattern}\b",
                re.IGNORECASE,
            ),
            # Phone numbers (require clear formatting)
            "phone_us": re.compile(
                r"(?<![0-9])(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]\d{3}[-.\s]\d{4}(?![0-9])"
            ),
            "phone_intl": re.compile(
                r"(?<![0-9])\+[1-9]\d{1,2}[-.\s]\d{2,4}[-.\s]\d{3,4}[-.\s]\d{3,4}(?![0-9])"
            ),
            # Credit card numbers (+ for URL-encoded spaces)
            "cc_visa": re.compile(
                r"(?<![0-9])4[0-9]{3}[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}(?![0-9])"
            ),
            "cc_mastercard": re.compile(
                r"(?<![0-9])5[1-5][0-9]{2}[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}(?![0-9])"
            ),
            "cc_amex": re.compile(
                r"(?<![0-9])3[47][0-9]{2}[-\s+]?[0-9]{6}[-\s+]?[0-9]{5}(?![0-9])"
            ),
            "cc_discover": re.compile(
                r"(?<![0-9])6(?:011|5[0-9]{2})[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}[-\s+]?[0-9]{4}(?![0-9])"
            ),
            # Credit card CVV/CVC (3-4 digits)
            "cc_cvv": re.compile(
                r"(?i)(?:^|[&?])(?:cvv|cvc|cvv2|cvc2|security_code|card_code)"
                r"=([0-9]{3,4})(?:[&\s]|$)"
            ),
            # Credit card expiration (handles URL-encoded / as %2F)
            "cc_expiry": re.compile(
                r"(?i)(?:^|[&?])(?:exp(?:ir[ey])?(?:_?date)?|expiration|exp_date|expdate)"
                r"=([0-9]{1,2}(?:%2F|/|-)[0-9]{2,4})(?:[&\s]|$)"
            ),
            # Cardholder name
            "cc_holder": re.compile(
                r"(?i)(?:^|[&?])(?:card_?(?:holder)?_?name|cc_?name|name_?on_?card|cardholder)"
                r"=([A-Za-z+%][A-Za-z+%0-9\s]{2,50})(?:[&\s]|$)"
            ),
            # SSN: require dashes or spaces for clarity
            "ssn": re.compile(
                r"(?<![0-9])(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}(?![0-9])"
            ),
            # IBAN (require proper format)
            "iban": re.compile(
                r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){2,6}\b"
            ),
            # Credentials: URL-encoded values allowed (% for encoding)
            "password_field": re.compile(
                r"(?i)(?:^|[&?])(?:pass(?:word|wd|phrase)?|pwd|secret|credential)"
                r"=([A-Za-z0-9@#$%^&*!._+%-]{4,64})(?:[&\s]|$)",
            ),
            "user_field": re.compile(
                r"(?i)(?:^|[&?])(?:user(?:name)?|login|account|usr|uname)"
                r"=([A-Za-z][A-Za-z0-9._@+-]{2,63})(?:[&\s]|$)",
            ),
            # Authentication headers
            "auth_basic": re.compile(
                r"Authorization:\s*Basic\s+([A-Za-z0-9+/]{10,}={0,2})", re.IGNORECASE
            ),
            "auth_bearer": re.compile(
                r"Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]{20,})", re.IGNORECASE
            ),
            "auth_digest": re.compile(
                r'Authorization:\s*Digest\s+.*?username="([^"]+)"', re.IGNORECASE
            ),
            "auth_ntlm": re.compile(
                r"Authorization:\s*NTLM\s+([A-Za-z0-9+/]{20,}={0,2})", re.IGNORECASE
            ),
            # Cookies: only capture session-related cookies
            "session_cookie": re.compile(
                r"(?i)(?:session|sess|auth|token|jwt|sid)[_-]?(?:id)?=([A-Za-z0-9_\-]{16,})",
            ),
            # Tokens
            "jwt_token": re.compile(
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ),
            "oauth_token": re.compile(
                r'(?i)(?:access_token|refresh_token|oauth_token)[=:\s"\']+([A-Za-z0-9_\-.]{20,})',
            ),
            # API Keys (require minimum length and specific prefixes)
            "api_key": re.compile(
                r"(?i)(?:api[_-]?key|apikey|api_secret|api_token|x-api-key)"
                r'[=:\s"\']+([A-Za-z0-9_\-]{20,})',
            ),
            "aws_access_key": re.compile(
                r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
            ),
            "aws_secret_key": re.compile(
                r"(?i)(?:aws_secret|secret_access_key)[=:\s]+([A-Za-z0-9/+=]{40})"
            ),
            "github_token": re.compile(
                r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}"
            ),
            "slack_token": re.compile(
                r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"
            ),
            "stripe_key": re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
            "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            # Private keys
            "private_key": re.compile(
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
            ),
            "pgp_private": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            # Database connection strings
            "db_connection": re.compile(
                r"(?i)(?:mongodb|mysql|postgres|postgresql|mssql|sqlserver|redis|oracle)"
                r"://[A-Za-z0-9_]+:[^@\s]+@[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_]+",
            ),
            "jdbc_connection": re.compile(
                r"jdbc:[a-z]+://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_]+", re.IGNORECASE
            ),
            # bcrypt hash (very specific format)
            "bcrypt_hash": re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}"),
            # NTLM hash (specific format with colon separator)
            "ntlm_hash": re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b"),
            # Domain credentials (Windows) - require clear context
            "domain_creds": re.compile(
                r"(?i)(?:domain|ntdomain)[=:\s\\]+([A-Za-z][A-Za-z0-9_\-.]{1,15})"
            ),
        }

    def _is_valid_match(self, pattern_name: str, value: str) -> bool:
        """Filter out false positive matches from binary/encrypted data."""
        if not value or len(value) < 3:
            return False

        # Must be printable ASCII (filter out binary garbage)
        if not all(32 <= ord(c) <= 126 for c in value):
            return False

        # High entropy check (exclude passwords - they're supposed to be random)
        unique_chars = len(set(value))
        if len(value) > 10 and unique_chars / len(value) > 0.95:
            if pattern_name in ("email", "user_field", "phone_us", "phone_intl"):
                return False

        # Email-specific validation
        if pattern_name == "email":
            if ".." in value or value.startswith(".") or "@." in value:
                return False
            local, _, domain = value.partition("@")
            if len(local) < 2 or len(domain) < 4:
                return False

        # Username should look like a real username
        if pattern_name == "user_field":
            # Should start with letter, be mostly alphanumeric
            if not value[0].isalpha():
                return False
            alnum_ratio = sum(c.isalnum() or c in "._@-" for c in value) / len(value)
            if alnum_ratio < 0.8:
                return False

        # Password field: reject if too much special character noise
        if pattern_name == "password_field":
            alnum_ratio = sum(c.isalnum() for c in value) / len(value)
            if alnum_ratio < 0.5:
                return False

        return True

    def extract_all(
        self, data: str, context: str = "", dedupe: bool = True
    ) -> list[SensitiveMatch]:
        """
        Extract all sensitive data from provided text.

        Args:
            data: Text to analyze
            context: Additional context (protocol, source, etc.)
            dedupe: Whether to deduplicate matches within this call

        Returns:
            List of SensitiveMatch objects
        """
        matches: list[SensitiveMatch] = []

        for pattern_name, pattern in self.patterns.items():
            found = pattern.findall(data)
            for match in found:
                if isinstance(match, tuple):
                    value = match[-1] if match[-1] else match[0]
                    match_context = (
                        match[0] if len(match) > 1 and match[0] != value else ""
                    )
                else:
                    value = match
                    match_context = ""

                value = str(value).strip()

                # Validate match quality
                if not self._is_valid_match(pattern_name, value):
                    continue

                dedup_key = (pattern_name, value)
                if dedupe and dedup_key in self._seen_matches:
                    continue
                self._seen_matches.add(dedup_key)

                confidence = self._assess_confidence(pattern_name, value)

                matches.append(
                    SensitiveMatch(
                        pattern_type=pattern_name,
                        value=value,
                        confidence=confidence,
                        context=f"{context} {match_context}".strip(),
                    )
                )

        return matches

    def _assess_confidence(self, pattern_type: str, value: str) -> str:
        """Assess confidence level of a match."""
        high_confidence_patterns = {
            "cc_visa",
            "cc_mastercard",
            "cc_amex",
            "cc_discover",
            "ssn",
            "jwt_token",
            "aws_access_key",
            "github_token",
            "slack_token",
            "stripe_key",
            "private_key",
            "auth_basic",
            "bcrypt_hash",
            "ntlm_hash",
        }

        medium_confidence_patterns = {
            "email",
            "phone_us",
            "phone_intl",
            "password_field",
            "user_field",
            "api_key",
            "db_connection",
            "oauth_token",
            "iban",
        }

        if pattern_type in high_confidence_patterns:
            return "HIGH"
        if pattern_type in medium_confidence_patterns:
            return "MEDIUM"
        return "LOW"

    def validate_credit_card(self, number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = re.sub(r"[\s-]", "", number)
        if not digits.isdigit():
            return False

        total = 0
        for i, digit in enumerate(reversed(digits)):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def reset_dedup(self) -> None:
        """Reset deduplication cache."""
        self._seen_matches.clear()


class FileExtractor:
    """Handle file extraction from network protocols."""

    def __init__(self, output_dir: str = "extracted_files") -> None:
        self.output_dir = output_dir
        self.extracted_files: list[dict[str, Any]] = []
        self.http_streams: dict[str, dict[str, Any]] = defaultdict(dict)
        self.ftp_streams: dict[str, dict[str, Any]] = defaultdict(dict)
        self.tftp_blocks: dict[str, dict[str, Any]] = defaultdict(dict)
        self.smb_files: dict[str, dict[str, Any]] = defaultdict(dict)

        # Create output directory structure
        Path(output_dir).mkdir(exist_ok=True)
        for proto in ["http", "ftp", "tftp", "smb"]:
            Path(f"{output_dir}/{proto}").mkdir(exist_ok=True)

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal."""
        filename = os.path.basename(filename)
        filename = re.sub(r"[^\w\s\-\.]", "_", filename)
        return filename[:255]

    def save_file(
        self,
        protocol: str,
        filename: str,
        data: bytes,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Save extracted file to disk."""
        if not data or len(data) == 0:
            return None

        safe_filename = self.sanitize_filename(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        name, ext = os.path.splitext(safe_filename)
        if not ext:
            ext = ".bin"
        final_filename = f"{name}_{timestamp}{ext}"

        filepath = os.path.join(self.output_dir, protocol, final_filename)

        try:
            with open(filepath, "wb") as f:
                f.write(data)

            meta_file = filepath + ".meta.json"
            meta_info = {
                "original_filename": filename,
                "saved_as": final_filename,
                "protocol": protocol,
                "size": len(data),
                "timestamp": timestamp,
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            }

            if metadata:
                meta_info.update(metadata)

            with open(meta_file, "w") as f:
                json.dump(meta_info, f, indent=2)

            self.extracted_files.append(
                {
                    "protocol": protocol,
                    "filename": final_filename,
                    "path": filepath,
                    "size": len(data),
                    "metadata": meta_info,
                }
            )

            return filepath
        except OSError:
            return None

    def extract_http_file(self, packet: Packet) -> str | None:
        """Extract files from HTTP traffic."""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None

            payload = packet[Raw].load

            # HTTP Response with file
            if b"HTTP/" in payload[:20]:
                if b"\r\n\r\n" in payload:
                    headers, body = payload.split(b"\r\n\r\n", 1)
                    headers_str = headers.decode("utf-8", errors="ignore")

                    # Extract filename
                    filename_match = re.search(
                        r'[Ff]ilename[*]?=(?:"([^"]+)"|([^\s;]+))', headers_str
                    )
                    content_type = re.search(
                        r"Content-Type:\s*([^\r\n;]+)", headers_str, re.IGNORECASE
                    )

                    filename = None
                    if filename_match:
                        filename = filename_match.group(1) or filename_match.group(2)
                    elif content_type and body:
                        ct = content_type.group(1).strip()
                        ext = self.get_extension_from_content_type(ct)
                        filename = f"http_response_{packet[TCP].sport}{ext}"

                    if filename and body and len(body) > 100:
                        metadata = {
                            "src": packet[IP].src,
                            "dst": packet[IP].dst,
                            "sport": packet[TCP].sport,
                            "dport": packet[TCP].dport,
                            "content_type": (
                                content_type.group(1) if content_type else "unknown"
                            ),
                        }
                        return self.save_file("http", filename, body, metadata)

            # HTTP POST file upload
            elif (
                b"POST " in payload[:50]
                and b"Content-Type: multipart/form-data" in payload
            ):
                boundary_match = re.search(b"boundary=([^\r\n;]+)", payload)
                if boundary_match:
                    boundary = boundary_match.group(1).strip()
                    parts = payload.split(b"--" + boundary)
                    for part in parts:
                        if b"filename=" in part and b"\r\n\r\n" in part:
                            fn_match = re.search(b'filename="([^"]+)"', part)
                            if fn_match:
                                filename = fn_match.group(1).decode(
                                    "utf-8", errors="ignore"
                                )
                                _, file_data = part.split(b"\r\n\r\n", 1)
                                file_data = file_data.split(b"\r\n--")[0]

                                if len(file_data) > 0:
                                    metadata = {
                                        "src": packet[IP].src,
                                        "dst": packet[IP].dst,
                                        "direction": "upload",
                                    }
                                    return self.save_file(
                                        "http", filename, file_data, metadata
                                    )
        except (KeyError, AttributeError, ValueError):
            pass
        return None

    def extract_ftp_file(self, packet: Packet) -> str | None:
        """Extract files from FTP data channel."""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None

            payload = packet[Raw].load

            # FTP Control (port 21)
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                payload_str = payload.decode("utf-8", errors="ignore")

                if "RETR " in payload_str:
                    filename = payload_str.split("RETR ")[1].split("\r\n")[0].strip()
                    data_key = f"{packet[IP].src}:{packet[IP].dst}"
                    self.ftp_streams[data_key] = {
                        "filename": filename,
                        "data": b"",
                        "command": "RETR",
                    }
                elif "STOR " in payload_str:
                    filename = payload_str.split("STOR ")[1].split("\r\n")[0].strip()
                    data_key = f"{packet[IP].src}:{packet[IP].dst}"
                    self.ftp_streams[data_key] = {
                        "filename": filename,
                        "data": b"",
                        "command": "STOR",
                    }
            else:
                # FTP data channel
                for key in list(self.ftp_streams.keys()):
                    if packet[IP].src in key or packet[IP].dst in key:
                        self.ftp_streams[key]["data"] += payload

                        if packet[TCP].flags & 0x01:
                            if len(self.ftp_streams[key]["data"]) > 0:
                                filename = self.ftp_streams[key]["filename"]
                                data = self.ftp_streams[key]["data"]

                                metadata = {
                                    "src": packet[IP].src,
                                    "dst": packet[IP].dst,
                                    "command": self.ftp_streams[key].get(
                                        "command", "unknown"
                                    ),
                                }

                                result = self.save_file("ftp", filename, data, metadata)
                                del self.ftp_streams[key]
                                return result
        except (KeyError, AttributeError, ValueError):
            pass
        return None

    def extract_tftp_file(self, packet: Packet) -> str | None:
        """Extract files from TFTP traffic."""
        try:
            if not packet.haslayer(UDP) or not packet.haslayer(Raw):
                return None

            payload = packet[Raw].load
            if len(payload) < 4:
                return None

            opcode = struct.unpack("!H", payload[:2])[0]

            if opcode in [1, 2, 3]:
                stream_key = (
                    f"{packet[IP].src}:{packet[UDP].sport}-"
                    f"{packet[IP].dst}:{packet[UDP].dport}"
                )

                if opcode in (1, 2):
                    null_pos = payload.find(b"\x00", 2)
                    if null_pos > 2:
                        filename = payload[2:null_pos].decode("utf-8", errors="ignore")
                        self.tftp_blocks[stream_key] = {
                            "filename": filename,
                            "blocks": {},
                            "opcode": opcode,
                        }

                elif opcode == 3:
                    block_num = struct.unpack("!H", payload[2:4])[0]
                    data = payload[4:]

                    reverse_key = (
                        f"{packet[IP].dst}:{packet[UDP].dport}-"
                        f"{packet[IP].src}:{packet[UDP].sport}"
                    )
                    for key in [stream_key, reverse_key]:
                        if key in self.tftp_blocks:
                            self.tftp_blocks[key]["blocks"][block_num] = data

                            if len(data) < 512:
                                tftp_data = self.tftp_blocks[key]
                                filename = tftp_data["filename"]

                                sorted_blocks = sorted(tftp_data["blocks"].items())
                                file_data = b"".join([d for _, d in sorted_blocks])

                                if len(file_data) > 0:
                                    metadata = {
                                        "src": packet[IP].src,
                                        "dst": packet[IP].dst,
                                        "blocks": len(tftp_data["blocks"]),
                                    }

                                    result = self.save_file(
                                        "tftp", filename, file_data, metadata
                                    )
                                    del self.tftp_blocks[key]
                                    return result
                            break
        except (KeyError, AttributeError, ValueError, struct.error):
            pass
        return None

    def extract_smb_file(self, packet: Packet) -> str | None:
        """Extract files from SMB traffic."""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None

            if packet[TCP].dport != 445 and packet[TCP].sport != 445:
                return None

            payload = packet[Raw].load

            if b"\xfeSMB" in payload[:10]:
                unicode_matches = re.findall(b"(?:[\x20-\x7e][\x00]){5,}", payload)
                for match in unicode_matches:
                    try:
                        text = match.decode("utf-16-le").strip()
                        if "\\" in text and "." in text:
                            filename = text.split("\\")[-1]
                            if 3 < len(filename) < 100:
                                stream_key = f"{packet[IP].src}:{packet[TCP].sport}"
                                if stream_key not in self.smb_files:
                                    self.smb_files[stream_key] = {
                                        "filename": filename,
                                        "data": b"",
                                    }
                    except (UnicodeDecodeError, AttributeError):
                        pass
        except (KeyError, AttributeError, ValueError):
            pass
        return None

    def get_extension_from_content_type(self, content_type: str) -> str:
        """Get file extension from Content-Type."""
        ct_map = {
            "text/html": ".html",
            "text/plain": ".txt",
            "application/json": ".json",
            "application/pdf": ".pdf",
            "application/zip": ".zip",
            "application/msword": ".doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "image/gif": ".gif",
        }
        return ct_map.get(content_type.lower(), ".bin")

    def get_summary(self) -> dict[str, Any]:
        """Get summary of extracted files."""
        summary: dict[str, Any] = {
            "total_files": len(self.extracted_files),
            "by_protocol": defaultdict(int),
            "total_size": 0,
        }

        for file_info in self.extracted_files:
            summary["by_protocol"][file_info["protocol"]] += 1
            summary["total_size"] += file_info["size"]

        return dict(summary)


class PCAPAnalyzer:
    """Main PCAP analysis engine with comprehensive protocol support."""

    def __init__(self, pcap_file: str, extract_files: bool = False) -> None:
        self.pcap_file = pcap_file
        self.extract_files = extract_files
        self.findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.stats: dict[str, int] = defaultdict(int)

        # Initialize sensitive data extractor
        self.sensitive_extractor = SensitiveDataExtractor()

        # Initialize file extractor if needed
        self.file_extractor: FileExtractor | None = (
            FileExtractor() if extract_files else None
        )

        # Track sessions for protocols
        self.ftp_sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.smtp_sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.pop3_sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.imap_sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.rdp_sessions: dict[str, dict[str, Any]] = defaultdict(dict)
        self.smb_sessions: dict[str, dict[str, Any]] = defaultdict(dict)

        # Dedup tracking
        self._reported_findings: set[str] = set()

    def detect_file_type(self) -> str:
        """Detect if file is PCAP or PCAPNG."""
        try:
            with open(self.pcap_file, "rb") as f:
                magic = f.read(4)

                if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
                    return "pcap"
                if magic == b"\x0a\x0d\x0d\x0a":
                    return "pcapng"
                return "unknown"
        except OSError:
            return "unknown"

    def load_packets(self) -> list[Packet]:
        """Load packets from PCAP or PCAPNG file."""
        file_type = self.detect_file_type()
        print(f"{Colors.YELLOW}[*] Detected file type: {file_type.upper()}{Colors.END}")

        try:
            packets = rdpcap(self.pcap_file)
            return list(packets)
        except Exception:
            print(
                f"{Colors.YELLOW}[*] Trying alternative loading method...{Colors.END}"
            )
            try:
                packets = []
                with PcapReader(self.pcap_file) as pcap_reader:
                    for pkt in pcap_reader:
                        packets.append(pkt)
                return packets
            except Exception as e2:
                print(f"{Colors.RED}[!] Failed to load packets: {e2}{Colors.END}")
                return []

    def add_finding(
        self,
        protocol: str,
        severity: str,
        description: str,
        details: dict[str, Any],
    ) -> None:
        """Add a finding with deduplication."""
        # Create dedup key
        dedup_key = f"{protocol}:{description}:{json.dumps(details, sort_keys=True)}"
        if dedup_key in self._reported_findings:
            return
        self._reported_findings.add(dedup_key)

        self.findings[protocol].append(
            {
                "severity": severity,
                "description": description,
                "details": details,
            }
        )
        self.stats[protocol] += 1

    def extract_payload(self, packet: Packet) -> str:
        """Extract payload from packet."""
        if packet.haslayer(Raw):
            try:
                return packet[Raw].load.decode("utf-8", errors="ignore")
            except (UnicodeDecodeError, AttributeError):
                try:
                    return packet[Raw].load.decode("latin-1", errors="ignore")
                except (UnicodeDecodeError, AttributeError):
                    return ""
        return ""

    def extract_raw_payload(self, packet: Packet) -> bytes:
        """Extract raw binary payload from packet."""
        if packet.haslayer(Raw):
            return bytes(packet[Raw].load)
        return b""

    def get_session_key(self, packet: Packet) -> str:
        """Generate a session key from packet."""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            return f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
        if packet.haslayer(IP) and packet.haslayer(UDP):
            return f"{packet[IP].src}:{packet[UDP].sport}-{packet[IP].dst}:{packet[UDP].dport}"
        return ""

    def extract_sensitive_data(
        self, payload: str, protocol: str, packet: Packet, skip_cc: bool = False
    ) -> None:
        """Extract all sensitive data from payload using SensitiveDataExtractor."""
        if not payload or len(payload) < 5:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        matches = self.sensitive_extractor.extract_all(
            payload, context=f"{protocol} {src_ip}->{dst_ip}"
        )

        cc_patterns = {
            "cc_visa",
            "cc_mastercard",
            "cc_amex",
            "cc_discover",
            "cc_cvv",
            "cc_expiry",
            "cc_holder",
        }

        for match in matches:
            if skip_cc and match.pattern_type in cc_patterns:
                continue

            severity_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
            severity = severity_map.get(match.confidence, "LOW")

            critical_types = {
                "cc_visa",
                "cc_mastercard",
                "cc_amex",
                "cc_discover",
                "ssn",
                "aws_access_key",
                "private_key",
                "password_field",
                "auth_basic",
            }
            if match.pattern_type in critical_types:
                severity = "CRITICAL"

            if match.pattern_type.startswith("cc_") and match.pattern_type in {
                "cc_visa",
                "cc_mastercard",
                "cc_amex",
                "cc_discover",
            }:
                if not self.sensitive_extractor.validate_credit_card(match.value):
                    severity = "LOW"

            self.add_finding(
                protocol,
                severity,
                f"Sensitive Data: {match.pattern_type}",
                {
                    "type": match.pattern_type,
                    "value": match.value[:100]
                    if len(match.value) > 100
                    else match.value,
                    "confidence": match.confidence,
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

    # ==========================================================================
    # HTTP Protocol Handler
    # ==========================================================================
    def analyze_http(self, packet: Packet) -> None:
        """Analyze HTTP traffic with comprehensive credential and data extraction."""
        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_http_file(packet)
            if extracted:
                self.add_finding(
                    "HTTP",
                    "INFO",
                    "File Extracted",
                    {
                        "filename": os.path.basename(extracted),
                        "path": extracted,
                        "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                    },
                )

        payload = self.extract_payload(packet)
        if not payload:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # HTTP Basic Authentication
        if "Authorization: Basic" in payload:
            match = self.sensitive_extractor.patterns["auth_basic"].search(payload)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode(
                        "utf-8", errors="ignore"
                    )
                    if ":" in decoded:
                        user, pwd = decoded.split(":", 1)
                        self.add_finding(
                            "HTTP",
                            "CRITICAL",
                            "Basic Auth Credentials",
                            {
                                "username": user,
                                "password": pwd,
                                "src": src_ip,
                                "dst": dst_ip,
                            },
                        )
                except (ValueError, binascii.Error):
                    pass

        # Digest Authentication
        digest_match = self.sensitive_extractor.patterns["auth_digest"].search(payload)
        if digest_match:
            digest_data = digest_match.group(1)
            username_match = re.search(r'username="([^"]+)"', digest_data)
            realm_match = re.search(r'realm="([^"]+)"', digest_data)
            nonce_match = re.search(r'nonce="([^"]+)"', digest_data)
            response_match = re.search(r'response="([^"]+)"', digest_data)

            self.add_finding(
                "HTTP",
                "HIGH",
                "Digest Authentication",
                {
                    "username": username_match.group(1) if username_match else "N/A",
                    "realm": realm_match.group(1) if realm_match else "N/A",
                    "nonce": nonce_match.group(1)[:32] if nonce_match else "N/A",
                    "response_hash": response_match.group(1)
                    if response_match
                    else "N/A",
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # NTLM Authentication
        ntlm_match = self.sensitive_extractor.patterns["auth_ntlm"].search(payload)
        if ntlm_match:
            ntlm_data = ntlm_match.group(1)
            self.add_finding(
                "HTTP",
                "HIGH",
                "NTLM Authentication",
                {
                    "ntlm_blob": ntlm_data[:64] + "..."
                    if len(ntlm_data) > 64
                    else ntlm_data,
                    "src": src_ip,
                    "dst": dst_ip,
                    "note": "NTLM authentication detected - credentials may be extractable",
                },
            )

        # Bearer Token
        bearer = self.sensitive_extractor.patterns["auth_bearer"].search(payload)
        if bearer:
            self.add_finding(
                "HTTP",
                "HIGH",
                "Bearer Token",
                {
                    "token": (
                        bearer.group(1)[:50] + "..."
                        if len(bearer.group(1)) > 50
                        else bearer.group(1)
                    ),
                    "src": src_ip,
                },
            )

        # JWT
        jwt = self.sensitive_extractor.patterns["jwt_token"].search(payload)
        if jwt:
            jwt_token = jwt.group(0)
            # Decode JWT header and payload
            try:
                parts = jwt_token.split(".")
                if len(parts) >= 2:
                    # Decode header
                    header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = base64.urlsafe_b64decode(header_padded).decode(
                        "utf-8", errors="ignore"
                    )
                    # Decode payload
                    payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    jwt_payload = base64.urlsafe_b64decode(payload_padded).decode(
                        "utf-8", errors="ignore"
                    )

                    self.add_finding(
                        "HTTP",
                        "HIGH",
                        "JWT Token",
                        {
                            "token": jwt_token[:50] + "...",
                            "header": header[:100],
                            "payload": jwt_payload[:200],
                            "src": src_ip,
                        },
                    )
            except (ValueError, binascii.Error):
                self.add_finding(
                    "HTTP",
                    "HIGH",
                    "JWT Token",
                    {"token": jwt_token[:50] + "...", "src": src_ip},
                )

        # POST/GET data with credentials
        if any(method in payload[:50] for method in ["POST ", "GET ", "PUT "]):
            user_match = self.sensitive_extractor.patterns["user_field"].search(payload)
            pass_match = self.sensitive_extractor.patterns["password_field"].search(
                payload
            )

            if user_match or pass_match:
                self.add_finding(
                    "HTTP",
                    "CRITICAL" if pass_match else "HIGH",
                    "Form Credentials",
                    {
                        "username": user_match.group(2) if user_match else "N/A",
                        "password": pass_match.group(2) if pass_match else "N/A",
                        "src": src_ip,
                        "dst": dst_ip,
                        "url": self.extract_url(payload),
                    },
                )

        # Cookies with session data
        cookie_match = re.search(r"Cookie:\s*(.+?)(?:\r?\n|$)", payload, re.IGNORECASE)
        if cookie_match:
            cookie = cookie_match.group(1)
            sensitive_cookies = [
                "session",
                "auth",
                "token",
                "login",
                "jwt",
                "bearer",
                "sid",
            ]
            if any(s in cookie.lower() for s in sensitive_cookies):
                self.add_finding(
                    "HTTP",
                    "MEDIUM",
                    "Session Cookie",
                    {"cookie": cookie[:150], "src": src_ip},
                )

        # Set-Cookie (server response)
        set_cookie_match = re.search(
            r"Set-Cookie:\s*(.+?)(?:\r?\n|$)", payload, re.IGNORECASE
        )
        if set_cookie_match:
            cookie = set_cookie_match.group(1)
            if any(
                s in cookie.lower() for s in ["session", "auth", "token", "jwt", "sid"]
            ):
                self.add_finding(
                    "HTTP",
                    "MEDIUM",
                    "Set-Cookie Header",
                    {"cookie": cookie[:150], "src": src_ip, "dst": dst_ip},
                )

        # Credit card data extraction (group all CC fields together)
        has_cc_data = self._extract_credit_card_data(payload, src_ip, dst_ip)

        # Extract all sensitive data patterns (skip CC if already extracted)
        self.extract_sensitive_data(payload, "HTTP", packet, skip_cc=has_cc_data)

    def _extract_credit_card_data(self, payload: str, src_ip: str, dst_ip: str) -> bool:
        """Extract and group credit card information from payment forms."""
        cc_data: dict[str, str] = {}

        for cc_type in ["cc_visa", "cc_mastercard", "cc_amex", "cc_discover"]:
            match = self.sensitive_extractor.patterns[cc_type].search(payload)
            if match:
                cc_data["card_number"] = match.group(0).replace("+", " ")
                cc_data["card_type"] = cc_type.replace("cc_", "").upper()
                break

        cvv_match = self.sensitive_extractor.patterns["cc_cvv"].search(payload)
        if cvv_match:
            cc_data["cvv"] = cvv_match.group(1)

        exp_match = self.sensitive_extractor.patterns["cc_expiry"].search(payload)
        if exp_match:
            exp_raw = exp_match.group(1)
            cc_data["expiry"] = unquote(exp_raw.replace("%2F", "/"))

        holder_match = self.sensitive_extractor.patterns["cc_holder"].search(payload)
        if holder_match:
            holder_raw = holder_match.group(1)
            cc_data["cardholder"] = unquote(holder_raw.replace("+", " ")).strip()

        if "card_number" in cc_data:
            self.add_finding(
                "HTTP",
                "CRITICAL",
                "Credit Card Data",
                {
                    "card_type": cc_data.get("card_type", "UNKNOWN"),
                    "card_number": cc_data.get("card_number", "N/A"),
                    "cardholder": cc_data.get("cardholder", "N/A"),
                    "expiry": cc_data.get("expiry", "N/A"),
                    "cvv": cc_data.get("cvv", "N/A"),
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )
            return True
        return False

    def extract_url(self, payload: str) -> str:
        """Extract URL from HTTP request."""
        lines = payload.split("\r\n")
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                return parts[1]
        return "N/A"

    # ==========================================================================
    # FTP Protocol Handler
    # ==========================================================================
    def analyze_ftp(self, packet: Packet) -> None:
        """Analyze FTP traffic with full session tracking and credential extraction."""
        if not packet.haslayer(TCP):
            return

        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_ftp_file(packet)
            if extracted:
                self.add_finding(
                    "FTP",
                    "INFO",
                    "File Extracted",
                    {
                        "filename": os.path.basename(extracted),
                        "path": extracted,
                        "src": packet[IP].src,
                    },
                )

        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            payload = self.extract_payload(packet)
            session_key = self.get_session_key(packet)

            src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

            # Initialize session
            if session_key not in self.ftp_sessions:
                self.ftp_sessions[session_key] = {
                    "username": None,
                    "password": None,
                    "commands": [],
                    "files": [],
                    "current_dir": "/",
                }

            session = self.ftp_sessions[session_key]

            # USER command
            if "USER " in payload:
                username = payload.split("USER ")[1].split("\r\n")[0].strip()
                session["username"] = username
                self.add_finding(
                    "FTP",
                    "HIGH",
                    "Username",
                    {"username": username, "src": src_ip, "dst": dst_ip},
                )

            # PASS command
            if "PASS " in payload:
                password = payload.split("PASS ")[1].split("\r\n")[0].strip()
                session["password"] = password
                self.add_finding(
                    "FTP",
                    "CRITICAL",
                    "Password",
                    {
                        "username": session.get("username", "N/A"),
                        "password": password,
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

            # Track commands
            ftp_commands = [
                "RETR",
                "STOR",
                "LIST",
                "NLST",
                "CWD",
                "PWD",
                "MKD",
                "RMD",
                "DELE",
                "RNFR",
                "RNTO",
            ]
            for cmd in ftp_commands:
                if f"{cmd} " in payload:
                    arg = payload.split(f"{cmd} ")[1].split("\r\n")[0].strip()
                    session["commands"].append(f"{cmd} {arg}")

                    if cmd == "CWD":
                        session["current_dir"] = arg

                    if cmd in ("RETR", "STOR"):
                        session["files"].append(arg)
                        self.add_finding(
                            "FTP",
                            "MEDIUM",
                            f"File {'Download' if cmd == 'RETR' else 'Upload'}",
                            {
                                "filename": arg,
                                "directory": session["current_dir"],
                                "src": src_ip,
                                "dst": dst_ip,
                            },
                        )

            # Server responses with sensitive info
            if payload.startswith("230 "):  # Successful login
                self.add_finding(
                    "FTP",
                    "INFO",
                    "Successful Login",
                    {
                        "username": session.get("username", "N/A"),
                        "response": payload[:100],
                        "src": src_ip,
                    },
                )

            # Directory listings may contain sensitive info
            if "LIST" in payload or "-rw" in payload or "drw" in payload:
                self.extract_sensitive_data(payload, "FTP", packet)

    # ==========================================================================
    # SNMP Protocol Handler
    # ==========================================================================
    def analyze_snmp(self, packet: Packet) -> None:
        """Analyze SNMP traffic with full community string and data extraction."""
        if not packet.haslayer(UDP):
            return

        snmp_ports = [161, 162]
        if packet[UDP].dport not in snmp_ports and packet[UDP].sport not in snmp_ports:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Use scapy's SNMP layer if available (best method)
        try:
            from scapy.layers.snmp import SNMP

            if packet.haslayer(SNMP):
                snmp_layer = packet[SNMP]
                community = snmp_layer.community
                if community:
                    if isinstance(community, bytes):
                        community = community.decode("utf-8", errors="ignore")
                    community = str(community)

                    # Determine severity based on community string
                    weak_strings = ["public", "private"]
                    severity = (
                        "MEDIUM" if community.lower() in weak_strings else "CRITICAL"
                    )

                    self.add_finding(
                        "SNMP",
                        severity,
                        "Community String",
                        {
                            "community": community,
                            "src": src_ip,
                            "dst": dst_ip,
                            "port": packet[UDP].dport,
                        },
                    )
                return
        except ImportError:
            pass

        # Fallback: manual extraction from raw payload
        raw_payload = self.extract_raw_payload(packet)
        payload = self.extract_payload(packet)

        # Common community strings to check
        common_strings = [
            "public",
            "private",
            "community",
            "admin",
            "manager",
            "cisco",
            "router",
            "switch",
            "monitor",
            "secret",
            "default",
            "password",
            "SNMP",
            "test",
            "write",
            "read",
        ]

        for cs in common_strings:
            if cs.encode() in raw_payload or cs in payload.lower():
                self.add_finding(
                    "SNMP",
                    "HIGH" if cs not in ["public", "private"] else "MEDIUM",
                    f"Community String: {cs}",
                    {
                        "string": cs,
                        "src": src_ip,
                        "dst": dst_ip,
                        "port": packet[UDP].dport,
                    },
                )
                break

        # ASN.1 manual extraction for custom community strings
        try:
            if len(raw_payload) > 10:
                # Look for printable strings that could be community strings
                printable_matches = re.findall(
                    b"[\x04]([\x01-\x40])([\x20-\x7e]{3,32})", raw_payload
                )
                for length_byte, potential_cs in printable_matches:
                    cs_str = potential_cs.decode("ascii", errors="ignore")
                    if len(cs_str) >= 3 and cs_str.isprintable():
                        self.add_finding(
                            "SNMP",
                            "HIGH",
                            "Extracted Community String",
                            {
                                "string": cs_str,
                                "src": src_ip,
                                "dst": dst_ip,
                            },
                        )
        except (ValueError, AttributeError):
            pass

        # SNMP Trap detection (port 162)
        if packet[UDP].dport == 162 or packet[UDP].sport == 162:
            self.add_finding(
                "SNMP",
                "MEDIUM",
                "SNMP Trap Detected",
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "data_length": len(raw_payload),
                },
            )

        # Extract any sensitive data from SNMP payload
        self.extract_sensitive_data(payload, "SNMP", packet)

    # ==========================================================================
    # POP3 Protocol Handler
    # ==========================================================================
    def analyze_pop3(self, packet: Packet) -> None:
        """Analyze POP3 traffic with full email content extraction."""
        if not packet.haslayer(TCP):
            return

        pop3_ports = [110, 995]
        if packet[TCP].dport not in pop3_ports and packet[TCP].sport not in pop3_ports:
            return

        payload = self.extract_payload(packet)
        session_key = self.get_session_key(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Initialize session
        if session_key not in self.pop3_sessions:
            self.pop3_sessions[session_key] = {
                "username": None,
                "password": None,
                "emails": [],
                "state": "init",
            }

        session = self.pop3_sessions[session_key]

        # USER command
        if "USER " in payload:
            username = payload.split("USER ")[1].split("\r\n")[0].strip()
            session["username"] = username
            self.add_finding(
                "POP3",
                "HIGH",
                "Username",
                {"username": username, "src": src_ip, "dst": dst_ip},
            )

        # PASS command
        if "PASS " in payload:
            password = payload.split("PASS ")[1].split("\r\n")[0].strip()
            session["password"] = password
            self.add_finding(
                "POP3",
                "CRITICAL",
                "Password",
                {
                    "username": session.get("username", "N/A"),
                    "password": password,
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # APOP (MD5 hash authentication)
        if "APOP " in payload:
            parts = payload.split("APOP ")[1].split()
            if len(parts) >= 2:
                self.add_finding(
                    "POP3",
                    "HIGH",
                    "APOP Authentication",
                    {
                        "username": parts[0],
                        "md5_digest": parts[1].split("\r\n")[0],
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

        # Email content extraction
        if "+OK" in payload and ("From:" in payload or "Subject:" in payload):
            # Extract email headers
            headers = {}
            header_patterns = [
                ("From", r"From:\s*(.+?)(?:\r\n|\n)"),
                ("To", r"To:\s*(.+?)(?:\r\n|\n)"),
                ("Subject", r"Subject:\s*(.+?)(?:\r\n|\n)"),
                ("Date", r"Date:\s*(.+?)(?:\r\n|\n)"),
            ]

            for name, pattern in header_patterns:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    headers[name] = match.group(1).strip()

            if headers:
                self.add_finding(
                    "POP3",
                    "MEDIUM",
                    "Email Headers",
                    {
                        "from": headers.get("From", "N/A"),
                        "to": headers.get("To", "N/A"),
                        "subject": headers.get("Subject", "N/A"),
                        "date": headers.get("Date", "N/A"),
                        "src": src_ip,
                    },
                )

        # Extract sensitive data from email content
        self.extract_sensitive_data(payload, "POP3", packet)

    # ==========================================================================
    # IMAP Protocol Handler
    # ==========================================================================
    def analyze_imap(self, packet: Packet) -> None:
        """Analyze IMAP traffic with full command parsing and email extraction."""
        if not packet.haslayer(TCP):
            return

        imap_ports = [143, 993]
        if packet[TCP].dport not in imap_ports and packet[TCP].sport not in imap_ports:
            return

        payload = self.extract_payload(packet)
        session_key = self.get_session_key(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Initialize session
        if session_key not in self.imap_sessions:
            self.imap_sessions[session_key] = {
                "username": None,
                "password": None,
                "mailboxes": [],
                "authenticated": False,
            }

        session = self.imap_sessions[session_key]

        # LOGIN command
        login_match = re.search(
            r"[A-Za-z0-9]+\s+LOGIN\s+(\S+)\s+(\S+)", payload, re.IGNORECASE
        )
        if login_match:
            username = login_match.group(1).strip('"')
            password = login_match.group(2).strip('"').rstrip("\r\n")
            session["username"] = username
            session["password"] = password
            self.add_finding(
                "IMAP",
                "CRITICAL",
                "Login Credentials",
                {
                    "username": username,
                    "password": password,
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # AUTHENTICATE command (various methods)
        if "AUTHENTICATE" in payload.upper():
            auth_match = re.search(r"AUTHENTICATE\s+(\S+)", payload, re.IGNORECASE)
            if auth_match:
                auth_method = auth_match.group(1)
                self.add_finding(
                    "IMAP",
                    "HIGH",
                    "Authentication Method",
                    {
                        "method": auth_method,
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

        # SELECT command (mailbox names)
        select_match = re.search(r'SELECT\s+"?([^"\r\n]+)"?', payload, re.IGNORECASE)
        if select_match:
            mailbox = select_match.group(1).strip()
            session["mailboxes"].append(mailbox)
            self.add_finding(
                "IMAP",
                "LOW",
                "Mailbox Access",
                {
                    "mailbox": mailbox,
                    "src": src_ip,
                },
            )

        # FETCH responses (email content)
        if "FETCH" in payload.upper() and ("From:" in payload or "Subject:" in payload):
            # Extract email headers
            headers = {}
            header_patterns = [
                ("From", r"From:\s*(.+?)(?:\r\n|\n)"),
                ("To", r"To:\s*(.+?)(?:\r\n|\n)"),
                ("Subject", r"Subject:\s*(.+?)(?:\r\n|\n)"),
                ("Date", r"Date:\s*(.+?)(?:\r\n|\n)"),
            ]

            for name, pattern in header_patterns:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    headers[name] = match.group(1).strip()

            if headers:
                self.add_finding(
                    "IMAP",
                    "MEDIUM",
                    "Email Headers",
                    {
                        "from": headers.get("From", "N/A"),
                        "to": headers.get("To", "N/A"),
                        "subject": headers.get("Subject", "N/A"),
                        "date": headers.get("Date", "N/A"),
                        "src": src_ip,
                    },
                )

        # Extract sensitive data from email content
        self.extract_sensitive_data(payload, "IMAP", packet)

    # ==========================================================================
    # SMTP Protocol Handler
    # ==========================================================================
    def analyze_smtp(self, packet: Packet) -> None:
        """Analyze SMTP traffic with full email content and credential extraction."""
        if not packet.haslayer(TCP):
            return

        smtp_ports = [25, 465, 587, 2525]
        if packet[TCP].dport not in smtp_ports and packet[TCP].sport not in smtp_ports:
            return

        payload = self.extract_payload(packet)
        session_key = self.get_session_key(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Initialize session
        if session_key not in self.smtp_sessions:
            self.smtp_sessions[session_key] = {
                "auth_method": None,
                "credentials": [],
                "mail_from": None,
                "rcpt_to": [],
                "data_mode": False,
            }

        session = self.smtp_sessions[session_key]

        # AUTH LOGIN/PLAIN
        if "AUTH LOGIN" in payload or "AUTH PLAIN" in payload:
            method = "LOGIN" if "LOGIN" in payload else "PLAIN"
            session["auth_method"] = method
            self.add_finding(
                "SMTP",
                "HIGH",
                f"AUTH {method} Detected",
                {"method": method, "src": src_ip, "dst": dst_ip},
            )

        # AUTH PLAIN with credentials inline
        if "AUTH PLAIN " in payload:
            parts = payload.split("AUTH PLAIN ")[1].split("\r\n")[0]
            try:
                decoded = base64.b64decode(parts).decode("utf-8", errors="ignore")
                # AUTH PLAIN format: \0username\0password
                creds = decoded.split("\x00")
                if len(creds) >= 3:
                    self.add_finding(
                        "SMTP",
                        "CRITICAL",
                        "AUTH PLAIN Credentials",
                        {
                            "username": creds[1],
                            "password": creds[2],
                            "src": src_ip,
                            "dst": dst_ip,
                        },
                    )
            except (ValueError, binascii.Error):
                pass

        # Base64 credentials (standalone lines during AUTH LOGIN)
        if (
            session["auth_method"] == "LOGIN"
            and payload
            and len(payload.strip()) < 100
            and len(payload.strip()) > 4
        ):
            try:
                decoded = base64.b64decode(payload.strip()).decode(
                    "utf-8", errors="ignore"
                )
                if decoded and len(decoded) > 2 and decoded.isprintable():
                    session["credentials"].append(decoded)
                    self.add_finding(
                        "SMTP",
                        "HIGH",
                        "AUTH Credential",
                        {
                            "decoded": decoded,
                            "src": src_ip,
                            "dst": dst_ip,
                            "note": "Part of AUTH LOGIN sequence",
                        },
                    )
            except (ValueError, binascii.Error):
                pass

        # MAIL FROM
        mail_from_match = re.search(r"MAIL FROM:\s*<([^>]+)>", payload, re.IGNORECASE)
        if mail_from_match:
            sender = mail_from_match.group(1)
            session["mail_from"] = sender
            self.add_finding(
                "SMTP",
                "LOW",
                "Sender Address",
                {"email": sender, "src": src_ip},
            )

        # RCPT TO
        rcpt_to_match = re.search(r"RCPT TO:\s*<([^>]+)>", payload, re.IGNORECASE)
        if rcpt_to_match:
            recipient = rcpt_to_match.group(1)
            session["rcpt_to"].append(recipient)
            self.add_finding(
                "SMTP",
                "LOW",
                "Recipient Address",
                {"email": recipient, "src": src_ip},
            )

        # Email headers in DATA section
        if "From:" in payload or "Subject:" in payload:
            headers = {}
            header_patterns = [
                ("From", r"From:\s*(.+?)(?:\r\n|\n)"),
                ("To", r"To:\s*(.+?)(?:\r\n|\n)"),
                ("Subject", r"Subject:\s*(.+?)(?:\r\n|\n)"),
                ("Date", r"Date:\s*(.+?)(?:\r\n|\n)"),
            ]

            for name, pattern in header_patterns:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    headers[name] = match.group(1).strip()

            if headers:
                self.add_finding(
                    "SMTP",
                    "MEDIUM",
                    "Email Headers",
                    {
                        "from": headers.get("From", "N/A"),
                        "to": headers.get("To", "N/A"),
                        "subject": headers.get("Subject", "N/A"),
                        "src": src_ip,
                    },
                )

        # Extract sensitive data from email content
        self.extract_sensitive_data(payload, "SMTP", packet)

    # ==========================================================================
    # LDAP Protocol Handler
    # ==========================================================================
    def analyze_ldap(self, packet: Packet) -> None:
        """Analyze LDAP traffic with DN parsing and credential extraction."""
        if not packet.haslayer(TCP):
            return

        ldap_ports = [389, 636, 3268, 3269]
        if packet[TCP].dport not in ldap_ports and packet[TCP].sport not in ldap_ports:
            return

        payload = self.extract_payload(packet)
        raw_payload = self.extract_raw_payload(packet)

        if not payload and not raw_payload:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Simple bind detection
        if "simple" in payload.lower() or b"\x80" in raw_payload:
            self.add_finding(
                "LDAP",
                "HIGH",
                "Simple Bind Request",
                {
                    "note": "Simple authentication (cleartext password)",
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # Extract DN patterns
        dn_patterns = [
            r"cn=([^,\r\n]+)",
            r"uid=([^,\r\n]+)",
            r"ou=([^,\r\n]+)",
            r"dc=([^,\r\n]+)",
            r"mail=([^,\r\n]+)",
            r"sAMAccountName=([^,\r\n]+)",
            r"userPrincipalName=([^,\r\n@]+)",
        ]

        for pattern in dn_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            for match in matches[:3]:  # Limit per pattern
                attr_name = pattern.split("=")[0]
                self.add_finding(
                    "LDAP",
                    "MEDIUM",
                    f"LDAP Attribute: {attr_name}",
                    {
                        "attribute": attr_name,
                        "value": match,
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

        # Full DN extraction
        dn_match = re.search(
            r"((?:CN|OU|DC|UID)=[^,]+(?:,(?:CN|OU|DC|UID)=[^,]+)+)",
            payload,
            re.IGNORECASE,
        )
        if dn_match:
            self.add_finding(
                "LDAP",
                "HIGH",
                "Distinguished Name",
                {
                    "dn": dn_match.group(1)[:150],
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # Search filter extraction
        filter_match = re.search(r"\(([a-zA-Z]+=[^)]+)\)", payload)
        if filter_match:
            self.add_finding(
                "LDAP",
                "LOW",
                "Search Filter",
                {
                    "filter": filter_match.group(1),
                    "src": src_ip,
                },
            )

        # Credential extraction
        user_match = self.sensitive_extractor.patterns["user_field"].search(payload)
        pass_match = self.sensitive_extractor.patterns["password_field"].search(payload)

        if user_match and pass_match:
            self.add_finding(
                "LDAP",
                "CRITICAL",
                "Cleartext Credentials",
                {
                    "username": user_match.group(2),
                    "password": pass_match.group(2),
                    "src": src_ip,
                    "dst": dst_ip,
                },
            )

        # Domain info
        domain_match = re.search(r"(?i)domain[=:\s\\]+([A-Za-z0-9_\-.]+)", payload)
        if domain_match:
            self.add_finding(
                "LDAP",
                "MEDIUM",
                "Domain Name",
                {
                    "domain": domain_match.group(1),
                    "src": src_ip,
                },
            )

        # Extract other sensitive data
        self.extract_sensitive_data(payload, "LDAP", packet)

    # ==========================================================================
    # RDP Protocol Handler
    # ==========================================================================
    def analyze_rdp(self, packet: Packet) -> None:
        """Analyze RDP traffic for credential and session information."""
        if not packet.haslayer(TCP):
            return

        rdp_ports = [3389, 3388]
        if packet[TCP].dport not in rdp_ports and packet[TCP].sport not in rdp_ports:
            return

        raw_payload = self.extract_raw_payload(packet)
        payload = self.extract_payload(packet)
        session_key = self.get_session_key(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Initialize session
        if session_key not in self.rdp_sessions:
            self.rdp_sessions[session_key] = {
                "username": None,
                "domain": None,
                "client_name": None,
                "encryption": None,
                "handshake_complete": False,
            }

        session = self.rdp_sessions[session_key]

        # RDP Connection Request (CR) - starts with 0x03 (TPKT)
        if len(raw_payload) > 10 and raw_payload[0:1] == b"\x03":
            # TPKT header detected
            self.add_finding(
                "RDP",
                "INFO",
                "RDP Connection Initiated",
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "direction": (
                        "client->server"
                        if packet[TCP].dport in rdp_ports
                        else "server->client"
                    ),
                },
            )

        # Look for CredSSP/NLA authentication
        if b"NTLMSSP" in raw_payload:
            self.add_finding(
                "RDP",
                "HIGH",
                "NTLM Authentication Detected",
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "note": "NTLM authentication in RDP - credentials may be capturable",
                },
            )

            # Extract NTLM domain and username
            # NTLMSSP_AUTH message contains domain and username
            ntlm_start = raw_payload.find(b"NTLMSSP\x00")
            if ntlm_start != -1:
                ntlm_data = raw_payload[ntlm_start:]
                # Message type at offset 8 (4 bytes little endian)
                if len(ntlm_data) > 12:
                    msg_type = struct.unpack("<I", ntlm_data[8:12])[0]

                    # Type 3 is AUTH message with credentials
                    if msg_type == 3 and len(ntlm_data) > 72:
                        try:
                            # Domain offset at 28, length at 24
                            domain_len = struct.unpack("<H", ntlm_data[28:30])[0]
                            domain_offset = struct.unpack("<I", ntlm_data[32:36])[0]

                            # Username offset at 36, length at 32
                            user_len = struct.unpack("<H", ntlm_data[36:38])[0]
                            user_offset = struct.unpack("<I", ntlm_data[40:44])[0]

                            if domain_offset < len(ntlm_data) and user_offset < len(
                                ntlm_data
                            ):
                                domain = ntlm_data[
                                    domain_offset : domain_offset + domain_len
                                ]
                                username = ntlm_data[
                                    user_offset : user_offset + user_len
                                ]

                                # Try to decode (could be UTF-16LE)
                                try:
                                    domain_str = domain.decode(
                                        "utf-16-le", errors="ignore"
                                    )
                                    username_str = username.decode(
                                        "utf-16-le", errors="ignore"
                                    )
                                except (UnicodeDecodeError, AttributeError):
                                    domain_str = domain.decode("utf-8", errors="ignore")
                                    username_str = username.decode(
                                        "utf-8", errors="ignore"
                                    )

                                if username_str:
                                    session["username"] = username_str
                                    session["domain"] = domain_str

                                    self.add_finding(
                                        "RDP",
                                        "CRITICAL",
                                        "NTLM Credentials",
                                        {
                                            "username": username_str,
                                            "domain": domain_str,
                                            "src": src_ip,
                                            "dst": dst_ip,
                                        },
                                    )
                        except (struct.error, IndexError):
                            pass

        # CredSSP (TLS wrapped)
        if b"\x30" in raw_payload[:5] and b"credssp" in payload.lower():
            self.add_finding(
                "RDP",
                "MEDIUM",
                "CredSSP/NLA Authentication",
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "note": "CredSSP detected - encrypted credentials",
                },
            )

        # Look for client info in cleartext (older RDP or misconfig)
        # Client cluster data may contain hostname
        unicode_strings = re.findall(b"(?:[\x20-\x7e][\x00]){4,}", raw_payload)
        for ustring in unicode_strings:
            try:
                decoded = ustring.decode("utf-16-le", errors="ignore").strip()
                if len(decoded) >= 3 and decoded.isprintable():
                    # Likely computer name or domain
                    if not session["client_name"]:
                        session["client_name"] = decoded
                        self.add_finding(
                            "RDP",
                            "LOW",
                            "Client Information",
                            {
                                "client_info": decoded[:50],
                                "src": src_ip,
                                "dst": dst_ip,
                            },
                        )
            except (UnicodeDecodeError, AttributeError):
                pass

        # Check for keyboard layout (indicates active session)
        if b"keyboardLayout" in raw_payload or b"\x04\x01" in raw_payload[:20]:
            self.add_finding(
                "RDP",
                "INFO",
                "RDP Session Data",
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "note": "Active RDP session detected",
                },
            )

        # Extract any sensitive data patterns
        self.extract_sensitive_data(payload, "RDP", packet)

    # ==========================================================================
    # DNS Protocol Handler
    # ==========================================================================
    def analyze_dns(self, packet: Packet) -> None:
        """Analyze DNS traffic with data exfiltration and suspicious pattern detection."""
        if not packet.haslayer(DNS):
            return

        dns_layer = packet[DNS]
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # DNS Queries
        if dns_layer.qd:
            for i in range(dns_layer.qdcount):
                try:
                    qname = (
                        dns_layer.qd[i]
                        .qname.decode("utf-8", errors="ignore")
                        .rstrip(".")
                    )
                    qtype = dns_layer.qd[i].qtype
                except (AttributeError, IndexError):
                    continue

                # Query type mapping
                qtype_map = {
                    1: "A",
                    2: "NS",
                    5: "CNAME",
                    6: "SOA",
                    12: "PTR",
                    15: "MX",
                    16: "TXT",
                    28: "AAAA",
                    33: "SRV",
                    255: "ANY",
                }
                qtype_str = qtype_map.get(qtype, str(qtype))

                # Suspicious TLDs
                suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click"]
                is_suspicious_tld = any(qname.endswith(tld) for tld in suspicious_tlds)

                # Known legitimate cloud/CDN providers (skip exfil detection)
                legitimate_suffixes = (
                    "amazonaws.com",
                    "cloudfront.net",
                    "azure.com",
                    "azure-api.net",
                    "googleapis.com",
                    "gstatic.com",
                    "google.com",
                    "googlevideo.com",
                    "cloudflare.com",
                    "cloudflare-dns.com",
                    "akamai.net",
                    "akamaiedge.net",
                    "fastly.net",
                    "edgekey.net",
                    "edgecastcdn.net",
                    "cdn77.org",
                    "mozilla.org",
                    "mozilla.com",
                    "mozilla.net",
                    "mozgcp.net",
                    "facebook.com",
                    "fbcdn.net",
                    "instagram.com",
                    "whatsapp.net",
                    "apple.com",
                    "icloud.com",
                    "microsoft.com",
                    "msedge.net",
                    "windows.net",
                    "office365.com",
                    "office.com",
                    "outlook.com",
                    "github.com",
                    "githubusercontent.com",
                    "gitlab.com",
                    "docker.com",
                    "docker.io",
                    "npmjs.org",
                    "pypi.org",
                )
                is_legitimate = any(
                    qname.endswith(suffix) for suffix in legitimate_suffixes
                )

                if is_legitimate:
                    continue

                subdomain_parts = qname.split(".")
                is_exfil = False
                exfil_reason = ""

                # Check for hex/base64 encoded subdomains (stronger indicator)
                for part in subdomain_parts[:-2]:
                    if len(part) > 40:
                        is_exfil = True
                        exfil_reason = f"Long subdomain: {len(part)} chars"
                        break
                    if re.match(r"^[A-Fa-f0-9]{20,}$", part):
                        is_exfil = True
                        exfil_reason = "Hex-encoded subdomain"
                        break
                    if re.match(r"^[A-Za-z0-9+/]{24,}={0,2}$", part):
                        is_exfil = True
                        exfil_reason = "Base64-encoded subdomain"
                        break

                if is_exfil:
                    self.add_finding(
                        "DNS",
                        "HIGH",
                        "Potential Data Exfiltration",
                        {
                            "query": qname[:100],
                            "type": qtype_str,
                            "reason": exfil_reason,
                            "src": src_ip,
                        },
                    )
                elif is_suspicious_tld:
                    self.add_finding(
                        "DNS",
                        "MEDIUM",
                        "Suspicious Domain Query",
                        {
                            "query": qname,
                            "type": qtype_str,
                            "src": src_ip,
                        },
                    )

                # TXT queries (often used for exfil/C2)
                if qtype == 16:
                    self.add_finding(
                        "DNS",
                        "LOW",
                        "TXT Record Query",
                        {
                            "query": qname,
                            "src": src_ip,
                            "note": "TXT records can contain encoded data",
                        },
                    )

        # DNS Responses
        if dns_layer.an:
            for i in range(dns_layer.ancount):
                try:
                    answer = dns_layer.an[i]
                    rname = answer.rrname.decode("utf-8", errors="ignore").rstrip(".")
                    rtype = answer.type

                    # TXT record responses (may contain sensitive data)
                    if rtype == 16:
                        txt_data = ""
                        if hasattr(answer, "rdata"):
                            if isinstance(answer.rdata, bytes):
                                txt_data = answer.rdata.decode("utf-8", errors="ignore")
                            elif isinstance(answer.rdata, list):
                                txt_data = b"".join(answer.rdata).decode(
                                    "utf-8", errors="ignore"
                                )

                        if txt_data:
                            self.add_finding(
                                "DNS",
                                "MEDIUM",
                                "TXT Record Response",
                                {
                                    "name": rname,
                                    "data": txt_data[:200],
                                    "src": src_ip,
                                },
                            )

                            # Check TXT for sensitive patterns
                            self.extract_sensitive_data(txt_data, "DNS", packet)

                except (AttributeError, IndexError):
                    continue

    # ==========================================================================
    # SMB Protocol Handler
    # ==========================================================================
    def analyze_smb(self, packet: Packet) -> None:
        """Analyze SMB traffic with NTLM hash extraction and share enumeration."""
        if not packet.haslayer(TCP):
            return

        smb_ports = [445, 139]
        if packet[TCP].dport not in smb_ports and packet[TCP].sport not in smb_ports:
            return

        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_smb_file(packet)
            if extracted:
                self.add_finding(
                    "SMB",
                    "INFO",
                    "File Extracted",
                    {
                        "filename": os.path.basename(extracted),
                        "path": extracted,
                        "src": packet[IP].src,
                    },
                )

        raw_payload = self.extract_raw_payload(packet)
        payload = self.extract_payload(packet)
        session_key = self.get_session_key(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Initialize session
        if session_key not in self.smb_sessions:
            self.smb_sessions[session_key] = {
                "username": None,
                "domain": None,
                "shares": [],
                "files": [],
                "ntlm_captured": False,
            }

        session = self.smb_sessions[session_key]

        # SMB1 header
        if b"\xffSMB" in raw_payload[:10] or b"\xfeSMB" in raw_payload[:10]:
            smb_version = "SMB1" if b"\xffSMB" in raw_payload else "SMB2/3"

            # NTLM authentication
            if b"NTLMSSP" in raw_payload:
                ntlm_start = raw_payload.find(b"NTLMSSP\x00")
                if ntlm_start != -1:
                    ntlm_data = raw_payload[ntlm_start:]

                    if len(ntlm_data) > 12:
                        msg_type = struct.unpack("<I", ntlm_data[8:12])[0]

                        # Type 2: Challenge
                        if msg_type == 2 and len(ntlm_data) > 32:
                            try:
                                challenge = ntlm_data[24:32]
                                challenge_hex = binascii.hexlify(challenge).decode()
                                self.add_finding(
                                    "SMB",
                                    "HIGH",
                                    "NTLM Challenge",
                                    {
                                        "challenge": challenge_hex,
                                        "src": src_ip,
                                        "dst": dst_ip,
                                        "smb_version": smb_version,
                                    },
                                )
                            except (struct.error, IndexError):
                                pass

                        # Type 3: Authentication Response (contains hash)
                        if msg_type == 3 and len(ntlm_data) > 88:
                            try:
                                # Extract fields
                                lm_len = struct.unpack("<H", ntlm_data[12:14])[0]
                                lm_offset = struct.unpack("<I", ntlm_data[16:20])[0]
                                nt_len = struct.unpack("<H", ntlm_data[20:22])[0]
                                nt_offset = struct.unpack("<I", ntlm_data[24:28])[0]
                                domain_len = struct.unpack("<H", ntlm_data[28:30])[0]
                                domain_offset = struct.unpack("<I", ntlm_data[32:36])[0]
                                user_len = struct.unpack("<H", ntlm_data[36:38])[0]
                                user_offset = struct.unpack("<I", ntlm_data[40:44])[0]

                                # Extract values
                                if nt_offset < len(ntlm_data) and nt_len > 0:
                                    nt_hash = ntlm_data[nt_offset : nt_offset + nt_len]
                                    nt_hash_hex = binascii.hexlify(nt_hash).decode()

                                    domain = ""
                                    username = ""

                                    if (
                                        domain_offset < len(ntlm_data)
                                        and domain_len > 0
                                    ):
                                        domain_bytes = ntlm_data[
                                            domain_offset : domain_offset + domain_len
                                        ]
                                        domain = domain_bytes.decode(
                                            "utf-16-le", errors="ignore"
                                        )

                                    if user_offset < len(ntlm_data) and user_len > 0:
                                        user_bytes = ntlm_data[
                                            user_offset : user_offset + user_len
                                        ]
                                        username = user_bytes.decode(
                                            "utf-16-le", errors="ignore"
                                        )

                                    session["username"] = username
                                    session["domain"] = domain
                                    session["ntlm_captured"] = True

                                    # NTLMv2 hash format for cracking
                                    if nt_len > 24:  # NTLMv2
                                        self.add_finding(
                                            "SMB",
                                            "CRITICAL",
                                            "NTLMv2 Hash Captured",
                                            {
                                                "username": username,
                                                "domain": domain,
                                                "nt_hash": nt_hash_hex[:64] + "...",
                                                "hash_length": nt_len,
                                                "src": src_ip,
                                                "dst": dst_ip,
                                                "note": "Hash can be cracked with hashcat/john",
                                            },
                                        )
                                    else:  # NTLMv1
                                        self.add_finding(
                                            "SMB",
                                            "CRITICAL",
                                            "NTLMv1 Hash Captured",
                                            {
                                                "username": username,
                                                "domain": domain,
                                                "nt_hash": nt_hash_hex,
                                                "src": src_ip,
                                                "dst": dst_ip,
                                                "note": "NTLMv1 is weak and easily cracked",
                                            },
                                        )
                            except (struct.error, IndexError):
                                pass

            # Extract share names
            share_patterns = [
                rb"\\\\[^\\]+\\([A-Za-z0-9_$]+)",
                rb"IPC\$",
                rb"ADMIN\$",
                rb"C\$",
                rb"D\$",
            ]
            for pattern in share_patterns:
                shares = re.findall(pattern, raw_payload)
                for share in shares:
                    if isinstance(share, bytes):
                        share = share.decode("utf-8", errors="ignore")
                    if share and share not in session["shares"]:
                        session["shares"].append(share)
                        self.add_finding(
                            "SMB",
                            "MEDIUM",
                            "Share Access",
                            {
                                "share": share,
                                "src": src_ip,
                                "dst": dst_ip,
                            },
                        )

            # Extract file paths (Unicode strings)
            unicode_matches = re.findall(b"(?:[\x20-\x7e][\x00]){5,}", raw_payload)
            for match in unicode_matches:
                try:
                    text = match.decode("utf-16-le", errors="ignore").strip()
                    if "\\" in text and ("." in text or "$" in text):
                        if text not in session["files"]:
                            session["files"].append(text)
                            # Only report actual file paths (not just share names)
                            if text.count("\\") > 1:
                                self.add_finding(
                                    "SMB",
                                    "LOW",
                                    "File Path",
                                    {
                                        "path": text[:100],
                                        "src": src_ip,
                                        "dst": dst_ip,
                                    },
                                )
                except (UnicodeDecodeError, AttributeError):
                    pass

        # Extract sensitive data patterns
        self.extract_sensitive_data(payload, "SMB", packet)

    # ==========================================================================
    # VNC Protocol Handler
    # ==========================================================================
    def analyze_vnc(self, packet: Packet) -> None:
        """Analyze VNC traffic with authentication detection and password extraction."""
        if not packet.haslayer(TCP):
            return

        vnc_ports = list(range(5900, 5910)) + [5800]
        if packet[TCP].dport not in vnc_ports and packet[TCP].sport not in vnc_ports:
            return

        raw_payload = self.extract_raw_payload(packet)
        payload = self.extract_payload(packet)

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # VNC Protocol Version (handshake start)
        if payload.startswith("RFB "):
            version_match = re.match(r"RFB (\d+\.\d+)", payload)
            if version_match:
                self.add_finding(
                    "VNC",
                    "INFO",
                    "VNC Handshake",
                    {
                        "version": version_match.group(1),
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

        # Security type negotiation
        # Common security types: 1=None, 2=VNC Auth, 16=Tight, 18=TLS
        if len(raw_payload) > 0 and not payload.startswith("RFB"):
            # After version exchange, server sends supported security types
            if len(raw_payload) >= 2:
                num_types = raw_payload[0]
                if 0 < num_types < 20:
                    security_types = list(raw_payload[1 : 1 + num_types])
                    sec_type_names = {
                        0: "Invalid",
                        1: "None (No Auth)",
                        2: "VNC Authentication",
                        5: "RA2",
                        6: "RA2ne",
                        16: "Tight",
                        17: "Ultra",
                        18: "TLS",
                        19: "VeNCrypt",
                    }

                    for st in security_types:
                        if st in sec_type_names:
                            severity = "CRITICAL" if st == 1 else "MEDIUM"
                            self.add_finding(
                                "VNC",
                                severity,
                                f"Security Type: {sec_type_names.get(st, 'Unknown')}",
                                {
                                    "type_id": st,
                                    "type_name": sec_type_names.get(st, "Unknown"),
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "note": (
                                        "No authentication required!" if st == 1 else ""
                                    ),
                                },
                            )

            # VNC Authentication challenge/response (DES encrypted)
            # Challenge is 16 bytes, response is 16 bytes
            if len(raw_payload) == 16:
                # Could be challenge or response
                challenge_hex = binascii.hexlify(raw_payload).decode()
                self.add_finding(
                    "VNC",
                    "HIGH",
                    "VNC Auth Challenge/Response",
                    {
                        "data": challenge_hex,
                        "data_length": 16,
                        "src": src_ip,
                        "dst": dst_ip,
                        "note": "VNC uses DES encryption - password can be brute-forced",
                    },
                )

        # VNC authentication result
        if len(raw_payload) == 4:
            result = struct.unpack(">I", raw_payload)[0]
            if result == 0:
                self.add_finding(
                    "VNC",
                    "INFO",
                    "VNC Authentication Successful",
                    {"src": src_ip, "dst": dst_ip},
                )
            elif result == 1:
                self.add_finding(
                    "VNC",
                    "LOW",
                    "VNC Authentication Failed",
                    {"src": src_ip, "dst": dst_ip},
                )

        # Extract sensitive data
        self.extract_sensitive_data(payload, "VNC", packet)

    # ==========================================================================
    # Telnet Protocol Handler
    # ==========================================================================
    def analyze_telnet(self, packet: Packet) -> None:
        """Analyze Telnet traffic."""
        if not packet.haslayer(TCP):
            return

        if packet[TCP].dport != 23 and packet[TCP].sport != 23:
            return

        payload = self.extract_payload(packet)

        if not payload or len(payload.strip()) == 0:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        # Login prompts
        login_keywords = ["login:", "username:", "user:", "password:", "passwd:"]
        for keyword in login_keywords:
            if keyword in payload.lower():
                self.add_finding(
                    "Telnet",
                    "HIGH",
                    "Login Prompt Detected",
                    {
                        "data": payload[:100],
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )
                break

        # Cleartext data (potential credentials)
        if len(payload.strip()) > 3 and payload.isprintable():
            # Check if it looks like a command or credential
            if not any(ctrl in payload for ctrl in ["\xff", "\xfb", "\xfd", "\xfe"]):
                self.add_finding(
                    "Telnet",
                    "MEDIUM",
                    "Cleartext Data",
                    {
                        "data": payload[:100],
                        "src": src_ip,
                        "dst": dst_ip,
                    },
                )

        # Extract sensitive data
        self.extract_sensitive_data(payload, "Telnet", packet)

    # ==========================================================================
    # TFTP Protocol Handler
    # ==========================================================================
    def analyze_tftp(self, packet: Packet) -> None:
        """Analyze TFTP traffic."""
        if not packet.haslayer(UDP):
            return

        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_tftp_file(packet)
            if extracted:
                self.add_finding(
                    "TFTP",
                    "INFO",
                    "File Extracted",
                    {
                        "filename": os.path.basename(extracted),
                        "path": extracted,
                        "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                    },
                )

        # TFTP uses port 69 for initial connection
        if packet[UDP].dport == 69 or packet[UDP].sport == 69:
            raw_payload = self.extract_raw_payload(packet)
            if len(raw_payload) >= 4:
                opcode = struct.unpack("!H", raw_payload[:2])[0]

                if opcode == 1:  # RRQ (Read Request)
                    null_pos = raw_payload.find(b"\x00", 2)
                    if null_pos > 2:
                        filename = raw_payload[2:null_pos].decode(
                            "utf-8", errors="ignore"
                        )
                        self.add_finding(
                            "TFTP",
                            "MEDIUM",
                            "Read Request",
                            {
                                "filename": filename,
                                "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                                "dst": packet[IP].dst if packet.haslayer(IP) else "N/A",
                            },
                        )

                elif opcode == 2:  # WRQ (Write Request)
                    null_pos = raw_payload.find(b"\x00", 2)
                    if null_pos > 2:
                        filename = raw_payload[2:null_pos].decode(
                            "utf-8", errors="ignore"
                        )
                        self.add_finding(
                            "TFTP",
                            "MEDIUM",
                            "Write Request",
                            {
                                "filename": filename,
                                "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                                "dst": packet[IP].dst if packet.haslayer(IP) else "N/A",
                            },
                        )

    # ==========================================================================
    # Additional Protocols
    # ==========================================================================
    def analyze_netbios(self, packet: Packet) -> None:
        """Analyze NetBIOS traffic."""
        if not packet.haslayer(UDP):
            return

        if packet[UDP].dport != 137 and packet[UDP].sport != 137:
            return

        payload = self.extract_payload(packet)
        if payload:
            self.add_finding(
                "NetBIOS",
                "LOW",
                "NetBIOS Name Service",
                {
                    "data": payload[:50],
                    "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                },
            )

    def analyze_syslog(self, packet: Packet) -> None:
        """Analyze Syslog traffic."""
        if not packet.haslayer(UDP):
            return

        if packet[UDP].dport != 514:
            return

        payload = self.extract_payload(packet)
        if not payload or len(payload) <= 20:
            return

        # Only report if contains sensitive keywords
        sensitive_keywords = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "auth",
            "login",
            "failed",
        ]
        if any(kw in payload.lower() for kw in sensitive_keywords):
            self.add_finding(
                "Syslog",
                "MEDIUM",
                "Syslog Message with Sensitive Data",
                {
                    "message": payload[:150],
                    "src": packet[IP].src if packet.haslayer(IP) else "N/A",
                },
            )

        # Extract sensitive data
        self.extract_sensitive_data(payload, "Syslog", packet)

    # ==========================================================================
    # Main Analysis
    # ==========================================================================
    def analyze_packet(self, packet: Packet) -> None:
        """Analyze a single packet across all protocols."""
        try:
            if not packet.haslayer(IP):
                return

            # Analyze different protocols
            self.analyze_http(packet)
            self.analyze_ftp(packet)
            self.analyze_telnet(packet)
            self.analyze_smtp(packet)
            self.analyze_pop3(packet)
            self.analyze_imap(packet)
            self.analyze_snmp(packet)
            self.analyze_ldap(packet)
            self.analyze_rdp(packet)
            self.analyze_dns(packet)
            self.analyze_smb(packet)
            self.analyze_vnc(packet)
            self.analyze_tftp(packet)
            self.analyze_netbios(packet)
            self.analyze_syslog(packet)

        except Exception:
            pass  # Silently skip problematic packets

    def print_findings(self) -> None:
        """Print all findings in a formatted way."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * 70}{Colors.END}")
        print(
            f"{Colors.BOLD}{Colors.HEADER}{'PCAP-SHARK ANALYSIS RESULTS':^70}{Colors.END}"
        )
        print(f"{Colors.BOLD}{Colors.HEADER}{'=' * 70}{Colors.END}\n")

        severity_colors = {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.YELLOW,
            "MEDIUM": Colors.CYAN,
            "LOW": Colors.GREEN,
            "INFO": Colors.BLUE,
        }

        severity_icons = {
            "CRITICAL": "[!!!]",
            "HIGH": "[!!]",
            "MEDIUM": "[!]",
            "LOW": "[*]",
            "INFO": "[i]",
        }

        # File extraction summary
        if self.file_extractor:
            file_stats = self.file_extractor.get_summary()
            if file_stats["total_files"] > 0:
                print(f"{Colors.BOLD}{Colors.GREEN}Extracted Files:{Colors.END}")
                print(
                    f"  Files: {file_stats['total_files']} | Size: {file_stats['total_size']:,} bytes"
                )
                for proto, count in file_stats["by_protocol"].items():
                    print(f"  - {proto.upper()}: {count} files")
                print()

        if not self.findings:
            print(f"{Colors.GREEN}[+] No sensitive data found in cleartext{Colors.END}")
            if self.file_extractor and self.file_extractor.extracted_files:
                print(
                    f"{Colors.GREEN}[+] Files saved to: {self.file_extractor.output_dir}/{Colors.END}"
                )
            return

        total_findings = sum(self.stats.values())
        critical_count = sum(
            1 for p in self.findings.values() for f in p if f["severity"] == "CRITICAL"
        )
        print(f"{Colors.BOLD}Summary:{Colors.END} {total_findings} findings", end="")
        if critical_count > 0:
            print(f" ({Colors.RED}{critical_count} CRITICAL{Colors.END})")
        else:
            print()
        print()

        for protocol in sorted(self.findings.keys()):
            findings = self.findings[protocol]
            print(f"{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.END}")
            print(
                f"{Colors.BOLD}{Colors.CYAN} {protocol} {Colors.END}({len(findings)} findings)"
            )
            print(f"{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.END}")

            for finding in findings:
                severity = finding["severity"]
                color = severity_colors.get(severity, Colors.END)
                icon = severity_icons.get(severity, "[?]")
                desc = finding["description"]

                print(f"\n{color}{icon} {desc}{Colors.END}")

                details = finding["details"]
                for key, value in details.items():
                    if isinstance(value, str) and len(value) > 80:
                        value = value[:77] + "..."

                    if key in ("password", "cvv"):
                        print(f"    {Colors.RED}{key}: {value}{Colors.END}")
                    elif key in ("username", "cardholder", "card_number"):
                        print(f"    {Colors.YELLOW}{key}: {value}{Colors.END}")
                    elif key in ("src", "dst"):
                        print(f"    {Colors.BLUE}{key}: {value}{Colors.END}")
                    else:
                        print(f"    {key}: {value}")

            print()

        if self.file_extractor:
            print(
                f"{Colors.GREEN}[+] Files saved to: {self.file_extractor.output_dir}/{Colors.END}"
            )

    def save_report(self, output_file: str) -> None:
        """Save findings to a file."""
        with open(output_file, "w") as f:
            f.write("Pcap-shark ANALYZER REPORT v4.0\n")
            f.write("=" * 70 + "\n")
            f.write(f"PCAP File: {self.pcap_file}\n")
            f.write(f"File Type: {self.detect_file_type().upper()}\n")
            f.write(
                f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            # File extraction summary
            if self.file_extractor:
                file_stats = self.file_extractor.get_summary()
                if file_stats["total_files"] > 0:
                    f.write("EXTRACTED FILES SUMMARY\n")
                    f.write("-" * 70 + "\n")
                    f.write(f"Total Files: {file_stats['total_files']}\n")
                    f.write(f"Total Size: {file_stats['total_size']:,} bytes\n")
                    for proto, count in file_stats["by_protocol"].items():
                        f.write(f"  {proto.upper()}: {count} files\n")
                    f.write(f"\nFiles saved to: {self.file_extractor.output_dir}/\n\n")

            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            for protocol, count in sorted(
                self.stats.items(), key=lambda x: x[1], reverse=True
            ):
                f.write(f"{protocol}: {count} findings\n")
            f.write("\n")

            f.write("DETAILED FINDINGS\n")
            f.write("=" * 70 + "\n\n")

            for protocol in sorted(self.findings.keys()):
                findings = self.findings[protocol]
                f.write(f"[{protocol}] - {len(findings)} findings\n")
                f.write("-" * 70 + "\n")

                for idx, finding in enumerate(findings, 1):
                    f.write(f"  [{finding['severity']}] {finding['description']}\n")

                    for key, value in finding["details"].items():
                        if isinstance(value, str) and len(value) > 200:
                            value = value[:200] + "..."
                        f.write(f"    {key}: {value}\n")

                    f.write("\n")

                f.write("\n")

    def analyze(self) -> None:
        """Run the main analysis."""
        print(f"{Colors.YELLOW}[*] Loading PCAP file...{Colors.END}")

        try:
            packets = self.load_packets()
            total_packets = len(packets)
            print(f"{Colors.GREEN}[+] Loaded {total_packets} packets{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading PCAP: {e}{Colors.END}")
            return

        if self.extract_files:
            print(f"{Colors.GREEN}[+] File extraction enabled{Colors.END}")

        print(f"{Colors.YELLOW}[*] Analyzing packets...{Colors.END}")

        for idx, packet in enumerate(packets, 1):
            if idx % 1000 == 0:
                print(
                    f"{Colors.YELLOW}[*] Processed {idx}/{total_packets} packets..."
                    f"{Colors.END}",
                    end="\r",
                )
            self.analyze_packet(packet)

        print(f"{Colors.GREEN}[+] Analysis complete!{Colors.END}" + " " * 30)

        self.print_findings()


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Pcap-shark Credential Analyzer v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcapng --extract-files
  %(prog)s capture.pcap --extract-files -o report.txt

Supported Protocols:
  HTTP, FTP, Telnet, SMTP, POP3, IMAP, SNMP, LDAP, RDP, SMB, VNC,
  DNS, TFTP, NetBIOS, Syslog

Sensitive Data Detection:
  - Credentials (usernames, passwords, API keys)
  - Credit card numbers (Visa, MC, Amex, Discover)
  - Social Security Numbers (SSN)
  - Email addresses and phone numbers
  - JWT tokens, OAuth tokens, Bearer tokens
  - AWS keys, GitHub tokens, Stripe keys
  - Private keys (RSA, DSA, EC, PGP)
  - Database connection strings
  - NTLM hashes, MD5, SHA hashes
  - IBAN numbers, routing numbers
        """,
    )

    parser.add_argument("pcap_file", help="PCAP or PCAPNG file to analyze")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument(
        "--extract-files",
        action="store_true",
        help="Extract files from protocols (HTTP, FTP, TFTP, SMB)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"{Colors.RED}[!] Error: File '{args.pcap_file}' not found{Colors.END}")
        sys.exit(1)

    analyzer = PCAPAnalyzer(args.pcap_file, extract_files=args.extract_files)
    analyzer.analyze()

    if args.output:
        print(f"\n{Colors.YELLOW}[*] Saving report to {args.output}...{Colors.END}")
        analyzer.save_report(args.output)
        print(f"{Colors.GREEN}[+] Report saved successfully{Colors.END}")


if __name__ == "__main__":
    main()
