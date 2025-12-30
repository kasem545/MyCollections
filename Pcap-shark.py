#!/usr/bin/env python3
"""
Pcap-shark Credential Analyzer
- Extract cleartext credentials from insecure protocols
- File extraction (HTTP, FTP, TFTP, SMB)
"""

import sys
import re
import base64
import hashlib
import json
import os
import struct
from collections import defaultdict
from datetime import datetime
from urllib.parse import parse_qs, unquote
from pathlib import Path

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
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class FileExtractor:
    """Handle file extraction from network protocols"""
    
    def __init__(self, output_dir='extracted_files'):
        self.output_dir = output_dir
        self.extracted_files = []
        self.http_streams = defaultdict(dict)
        self.ftp_streams = defaultdict(dict)
        self.tftp_blocks = defaultdict(dict)
        self.smb_files = defaultdict(dict)
        
        # Create output directory structure
        Path(output_dir).mkdir(exist_ok=True)
        for proto in ['http', 'ftp', 'tftp', 'smb']:
            Path(f"{output_dir}/{proto}").mkdir(exist_ok=True)
    
    def sanitize_filename(self, filename):
        """Sanitize filename to prevent path traversal"""
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\s\-\.]', '_', filename)
        return filename[:255]
    
    def save_file(self, protocol, filename, data, metadata=None):
        """Save extracted file to disk"""
        if not data or len(data) == 0:
            return None
            
        safe_filename = self.sanitize_filename(filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        
        name, ext = os.path.splitext(safe_filename)
        if not ext:
            ext = '.bin'
        final_filename = f"{name}_{timestamp}{ext}"
        
        filepath = os.path.join(self.output_dir, protocol, final_filename)
        
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
            
            meta_file = filepath + '.meta.json'
            meta_info = {
                'original_filename': filename,
                'saved_as': final_filename,
                'protocol': protocol,
                'size': len(data),
                'timestamp': timestamp,
                'md5': hashlib.md5(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
            
            if metadata:
                meta_info.update(metadata)
            
            with open(meta_file, 'w') as f:
                json.dump(meta_info, f, indent=2)
            
            self.extracted_files.append({
                'protocol': protocol,
                'filename': final_filename,
                'path': filepath,
                'size': len(data),
                'metadata': meta_info
            })
            
            return filepath
        except Exception as e:
            return None
    
    def extract_http_file(self, packet):
        """Extract files from HTTP traffic"""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None
            
            payload = packet[Raw].load
            
            # HTTP Response with file
            if b'HTTP/' in payload[:20]:
                if b'\r\n\r\n' in payload:
                    headers, body = payload.split(b'\r\n\r\n', 1)
                    headers_str = headers.decode('utf-8', errors='ignore')
                    
                    # Extract filename
                    filename_match = re.search(r'[Ff]ilename[*]?=(?:"([^"]+)"|([^\s;]+))', headers_str)
                    content_type = re.search(r'Content-Type:\s*([^\r\n;]+)', headers_str, re.IGNORECASE)
                    
                    filename = None
                    if filename_match:
                        filename = filename_match.group(1) or filename_match.group(2)
                    elif content_type and body:
                        ct = content_type.group(1).strip()
                        ext = self.get_extension_from_content_type(ct)
                        filename = f"http_response_{packet[TCP].sport}{ext}"
                    
                    if filename and body and len(body) > 100:
                        metadata = {
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'sport': packet[TCP].sport,
                            'dport': packet[TCP].dport,
                            'content_type': content_type.group(1) if content_type else 'unknown'
                        }
                        return self.save_file('http', filename, body, metadata)
            
            # HTTP POST file upload
            elif b'POST ' in payload[:50] and b'Content-Type: multipart/form-data' in payload:
                boundary_match = re.search(b'boundary=([^\r\n;]+)', payload)
                if boundary_match:
                    boundary = boundary_match.group(1).strip()
                    parts = payload.split(b'--' + boundary)
                    for part in parts:
                        if b'filename=' in part and b'\r\n\r\n' in part:
                            fn_match = re.search(b'filename="([^"]+)"', part)
                            if fn_match:
                                filename = fn_match.group(1).decode('utf-8', errors='ignore')
                                _, file_data = part.split(b'\r\n\r\n', 1)
                                file_data = file_data.split(b'\r\n--')[0]
                                
                                if len(file_data) > 0:
                                    metadata = {
                                        'src': packet[IP].src,
                                        'dst': packet[IP].dst,
                                        'direction': 'upload'
                                    }
                                    return self.save_file('http', filename, file_data, metadata)
        except Exception:
            pass
        return None
    
    def extract_ftp_file(self, packet):
        """Extract files from FTP data channel"""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None
            
            stream_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            payload = packet[Raw].load
            
            # FTP Control (port 21)
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                if 'RETR ' in payload_str:
                    filename = payload_str.split('RETR ')[1].split('\r\n')[0].strip()
                    data_key = f"{packet[IP].src}:{packet[IP].dst}"
                    self.ftp_streams[data_key] = {'filename': filename, 'data': b'', 'command': 'RETR'}
                elif 'STOR ' in payload_str:
                    filename = payload_str.split('STOR ')[1].split('\r\n')[0].strip()
                    data_key = f"{packet[IP].src}:{packet[IP].dst}"
                    self.ftp_streams[data_key] = {'filename': filename, 'data': b'', 'command': 'STOR'}
            else:
                # FTP data channel
                for key in list(self.ftp_streams.keys()):
                    if packet[IP].src in key or packet[IP].dst in key:
                        self.ftp_streams[key]['data'] += payload
                        
                        if packet[TCP].flags & 0x01:
                            if len(self.ftp_streams[key]['data']) > 0:
                                filename = self.ftp_streams[key]['filename']
                                data = self.ftp_streams[key]['data']
                                
                                metadata = {
                                    'src': packet[IP].src,
                                    'dst': packet[IP].dst,
                                    'command': self.ftp_streams[key].get('command', 'unknown')
                                }
                                
                                result = self.save_file('ftp', filename, data, metadata)
                                del self.ftp_streams[key]
                                return result
        except Exception:
            pass
        return None
    
    def extract_tftp_file(self, packet):
        """Extract files from TFTP traffic"""
        try:
            if not packet.haslayer(UDP) or not packet.haslayer(Raw):
                return None
            
            payload = packet[Raw].load
            if len(payload) < 4:
                return None
            
            opcode = struct.unpack('!H', payload[:2])[0]
            
            if opcode in [1, 2, 3]:
                stream_key = f"{packet[IP].src}:{packet[UDP].sport}-{packet[IP].dst}:{packet[UDP].dport}"
                
                if opcode == 1 or opcode == 2:
                    null_pos = payload.find(b'\x00', 2)
                    if null_pos > 2:
                        filename = payload[2:null_pos].decode('utf-8', errors='ignore')
                        self.tftp_blocks[stream_key] = {
                            'filename': filename,
                            'blocks': {},
                            'opcode': opcode
                        }
                
                elif opcode == 3:
                    block_num = struct.unpack('!H', payload[2:4])[0]
                    data = payload[4:]
                    
                    for key in [stream_key] + [f"{packet[IP].dst}:{packet[UDP].dport}-{packet[IP].src}:{packet[UDP].sport}"]:
                        if key in self.tftp_blocks:
                            self.tftp_blocks[key]['blocks'][block_num] = data
                            
                            if len(data) < 512:
                                tftp_data = self.tftp_blocks[key]
                                filename = tftp_data['filename']
                                
                                sorted_blocks = sorted(tftp_data['blocks'].items())
                                file_data = b''.join([d for _, d in sorted_blocks])
                                
                                if len(file_data) > 0:
                                    metadata = {
                                        'src': packet[IP].src,
                                        'dst': packet[IP].dst,
                                        'blocks': len(tftp_data['blocks'])
                                    }
                                    
                                    result = self.save_file('tftp', filename, file_data, metadata)
                                    del self.tftp_blocks[key]
                                    return result
                            break
        except Exception:
            pass
        return None
    
    def extract_smb_file(self, packet):
        """Extract files from SMB traffic"""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None
            
            if packet[TCP].dport != 445 and packet[TCP].sport != 445:
                return None
            
            payload = packet[Raw].load
            
            if b'\xfeSMB' in payload[:10]:
                unicode_matches = re.findall(b'(?:[\x20-\x7e][\x00]){5,}', payload)
                for match in unicode_matches:
                    try:
                        text = match.decode('utf-16-le').strip()
                        if '\\' in text and '.' in text:
                            filename = text.split('\\')[-1]
                            if len(filename) > 3 and len(filename) < 100:
                                stream_key = f"{packet[IP].src}:{packet[TCP].sport}"
                                if stream_key not in self.smb_files:
                                    self.smb_files[stream_key] = {
                                        'filename': filename,
                                        'data': b''
                                    }
                    except:
                        pass
        except Exception:
            pass
        return None
    
    def get_extension_from_content_type(self, content_type):
        """Get file extension from Content-Type"""
        ct_map = {
            'text/html': '.html',
            'text/plain': '.txt',
            'application/json': '.json',
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
        }
        return ct_map.get(content_type.lower(), '.bin')
    
    def get_summary(self):
        """Get summary of extracted files"""
        summary = {
            'total_files': len(self.extracted_files),
            'by_protocol': defaultdict(int),
            'total_size': 0
        }
        
        for file_info in self.extracted_files:
            summary['by_protocol'][file_info['protocol']] += 1
            summary['total_size'] += file_info['size']
        
        return dict(summary)

class PCAPAnalyzer:
    def __init__(self, pcap_file, extract_files=False):
        self.pcap_file = pcap_file
        self.extract_files = extract_files
        self.findings = defaultdict(list)
        self.stats = defaultdict(int)
        
        # Initialize file extractor if needed
        if extract_files:
            self.file_extractor = FileExtractor()
        else:
            self.file_extractor = None
        
        # Regex patterns for sensitive data
        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'password_field': re.compile(r'(?i)(pass(?:word|wd|phrase)?|pwd|secret|auth)[=:\s"\'>]+([^\s&\r\n<"\']{3,})', re.IGNORECASE),
            'user_field': re.compile(r'(?i)(user(?:name)?|login|account|uid|email|usr)[=:\s"\'>]+([^\s&\r\n<"\']{3,})', re.IGNORECASE),
            'auth_basic': re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE),
            'auth_bearer': re.compile(r'Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+)', re.IGNORECASE),
            'cookie': re.compile(r'(?i)Cookie:\s*(.+)', re.IGNORECASE),
            'session': re.compile(r'(?i)(session|sess|token|apikey)[=:\s]+([^\s&\r\n;]+)', re.IGNORECASE),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey|api_secret|api_token)[=:\s"\'>]+([A-Za-z0-9_\-]{20,})'),
            'aws_key': re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
            'github_token': re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
            'private_key': re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        }


    def detect_file_type(self):
        """Detect if file is PCAP or PCAPNG"""
        try:
            with open(self.pcap_file, 'rb') as f:
                magic = f.read(4)
                
                if magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xd4\xc3\xb2\xa1':
                    return 'pcap'
                elif magic == b'\x0a\x0d\x0d\x0a':
                    return 'pcapng'
                else:
                    return 'unknown'
        except Exception:
            return 'unknown'

    def load_packets(self):
        """Load packets from PCAP or PCAPNG file"""
        file_type = self.detect_file_type()
        
        print(f"{Colors.YELLOW}[*] Detected file type: {file_type.upper()}{Colors.END}")
        
        try:
            packets = rdpcap(self.pcap_file)
            return packets
        except Exception as e:
            print(f"{Colors.YELLOW}[*] Trying alternative loading method...{Colors.END}")
            try:
                packets = []
                with PcapReader(self.pcap_file) as pcap_reader:
                    for pkt in pcap_reader:
                        packets.append(pkt)
                return packets
            except Exception as e2:
                print(f"{Colors.RED}[!] Failed to load packets: {e2}{Colors.END}")
                return []

    def add_finding(self, protocol, severity, description, details):
        self.findings[protocol].append({
            'severity': severity,
            'description': description,
            'details': details
        })
        self.stats[protocol] += 1

    def extract_payload(self, packet):
        """Extract payload from packet"""
        if packet.haslayer(Raw):
            try:
                return packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                try:
                    return packet[Raw].load.decode('latin-1', errors='ignore')
                except:
                    return ""
        return ""

    def analyze_http(self, packet):
        """Analyze HTTP traffic"""
        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_http_file(packet)
            if extracted:
                self.add_finding('HTTP', 'INFO', 'File Extracted', {
                    'filename': os.path.basename(extracted),
                    'path': extracted,
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })
        
        payload = self.extract_payload(packet)
        
        if not payload:
            return
            
        # HTTP Basic Authentication
        if 'Authorization: Basic' in payload:
            match = self.patterns['auth_basic'].search(payload)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')
                    if ':' in decoded:
                        user, pwd = decoded.split(':', 1)
                        self.add_finding('HTTP', 'CRITICAL', 'Basic Auth Credentials', {
                            'username': user,
                            'password': pwd,
                            'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                            'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                        })
                except:
                    pass
        
        # Bearer Token
        bearer = self.patterns['auth_bearer'].search(payload)
        if bearer:
            self.add_finding('HTTP', 'HIGH', 'Bearer Token', {
                'token': bearer.group(1)[:50] + '...' if len(bearer.group(1)) > 50 else bearer.group(1),
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # JWT
        jwt = self.patterns['jwt_token'].search(payload)
        if jwt:
            self.add_finding('HTTP', 'HIGH', 'JWT Token', {
                'token': jwt.group(0)[:50] + '...',
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # POST data with credentials
        if 'POST' in payload[:50] or 'GET' in payload[:50]:
            user_match = self.patterns['user_field'].search(payload)
            pass_match = self.patterns['password_field'].search(payload)
            
            if user_match or pass_match:
                self.add_finding('HTTP', 'HIGH', 'POST Credentials', {
                    'username': user_match.group(2) if user_match else 'N/A',
                    'password': pass_match.group(2) if pass_match else 'N/A',
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A',
                    'url': self.extract_url(payload)
                })
        
        # Cookies
        cookie_match = self.patterns['cookie'].search(payload)
        if cookie_match:
            cookie = cookie_match.group(1)
            if any(s in cookie.lower() for s in ['session', 'auth', 'token', 'login']):
                self.add_finding('HTTP', 'MEDIUM', 'Cookie', {
                    'cookie': cookie[:100],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })
        
        # Session tokens
        session_match = self.patterns['session'].search(payload)
        if session_match:
            self.add_finding('HTTP', 'MEDIUM', 'Session Token', {
                'type': session_match.group(1),
                'token': session_match.group(2)[:50],
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # API Keys
        api_match = self.patterns['api_key'].search(payload)
        if api_match:
            self.add_finding('HTTP', 'CRITICAL', 'API Key', {
                'key_name': api_match.group(1),
                'key_value': api_match.group(2)[:20] + '...',
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # AWS Keys
        aws = self.patterns['aws_key'].search(payload)
        if aws:
            self.add_finding('HTTP', 'CRITICAL', 'AWS Access Key', {
                'key': aws.group(0),
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # GitHub Tokens
        github = self.patterns['github_token'].search(payload)
        if github:
            self.add_finding('HTTP', 'CRITICAL', 'GitHub Token', {
                'token': github.group(0)[:30] + '...',
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # Email addresses
        emails = self.patterns['email'].findall(payload)
        if emails:
            for email in set(emails)[:3]:  # Limit to first 3
                self.add_finding('HTTP', 'LOW', 'Email Address', {
                    'email': email,
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def extract_url(self, payload):
        """Extract URL from HTTP request"""
        lines = payload.split('\r\n')
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                return parts[1]
        return 'N/A'

    def analyze_ftp(self, packet):
        """Analyze FTP traffic"""
        if not packet.haslayer(TCP):
            return
        
        # File extraction
        if self.extract_files and self.file_extractor:
            extracted = self.file_extractor.extract_ftp_file(packet)
            if extracted:
                self.add_finding('FTP', 'INFO', 'File Extracted', {
                    'filename': os.path.basename(extracted),
                    'path': extracted,
                    'src': packet[IP].src
                })
        
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            payload = self.extract_payload(packet)
            
            if 'USER ' in payload:
                username = payload.split('USER ')[1].split('\r\n')[0].strip()
                self.add_finding('FTP', 'HIGH', 'Username', {
                    'username': username,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            if 'PASS ' in payload:
                password = payload.split('PASS ')[1].split('\r\n')[0].strip()
                self.add_finding('FTP', 'CRITICAL', 'Password', {
                    'password': password,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_telnet(self, packet):
        """Analyze Telnet traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 23 or packet[TCP].sport == 23):
            payload = self.extract_payload(packet)
            
            if payload and len(payload.strip()) > 0:
                if any(keyword in payload.lower() for keyword in ['login:', 'username:', 'password:']):
                    self.add_finding('Telnet', 'HIGH', 'Login Prompt Detected', {
                        'data': payload[:100],
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })
                elif len(payload.strip()) > 3 and payload.isprintable():
                    self.add_finding('Telnet', 'MEDIUM', 'Cleartext Data', {
                        'data': payload[:100],
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })

    def analyze_smtp(self, packet):
        """Analyze SMTP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport in [25, 587] or packet[TCP].sport in [25, 587]):
            payload = self.extract_payload(packet)
            
            if 'AUTH LOGIN' in payload or 'AUTH PLAIN' in payload:
                self.add_finding('SMTP', 'HIGH', 'AUTH LOGIN Detected', {
                    'method': 'LOGIN' if 'LOGIN' in payload else 'PLAIN',
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            # Base64 credentials
            if payload and len(payload.strip()) < 100 and len(payload.strip()) > 10:
                try:
                    decoded = base64.b64decode(payload.strip()).decode('utf-8', errors='ignore')
                    if decoded and len(decoded) > 3 and decoded.isprintable():
                        self.add_finding('SMTP', 'HIGH', 'Potential Credential', {
                            'decoded': decoded,
                            'src': packet[IP].src,
                            'dst': packet[IP].dst
                        })
                except:
                    pass
            
            # Email addresses
            if 'MAIL FROM:' in payload or 'RCPT TO:' in payload:
                emails = self.patterns['email'].findall(payload)
                for email in set(emails)[:3]:
                    self.add_finding('SMTP', 'LOW', 'Email Address', {
                        'email': email,
                        'src': packet[IP].src
                    })

    def analyze_pop3(self, packet):
        """Analyze POP3 traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 110 or packet[TCP].sport == 110):
            payload = self.extract_payload(packet)
            
            if 'USER ' in payload:
                username = payload.split('USER ')[1].split('\r\n')[0].strip()
                self.add_finding('POP3', 'HIGH', 'Username', {
                    'username': username,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            if 'PASS ' in payload:
                password = payload.split('PASS ')[1].split('\r\n')[0].strip()
                self.add_finding('POP3', 'CRITICAL', 'Password', {
                    'password': password,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_imap(self, packet):
        """Analyze IMAP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 143 or packet[TCP].sport == 143):
            payload = self.extract_payload(packet)
            
            if 'LOGIN' in payload:
                parts = payload.split()
                if len(parts) >= 4 and 'LOGIN' in parts:
                    idx = parts.index('LOGIN')
                    if idx + 2 < len(parts):
                        self.add_finding('IMAP', 'CRITICAL', 'Login Credentials', {
                            'username': parts[idx + 1],
                            'password': parts[idx + 2] if idx + 2 < len(parts) else 'N/A',
                            'src': packet[IP].src,
                            'dst': packet[IP].dst
                        })

    def analyze_snmp(self, packet):
        """Analyze SNMP traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 161 or packet[UDP].sport == 161):
            payload = self.extract_payload(packet)
            
            common_strings = ['public', 'private', 'community']
            for cs in common_strings:
                if cs in payload.lower():
                    self.add_finding('SNMP', 'MEDIUM', f'Community String: {cs}', {
                        'string': cs,
                        'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                        'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                    })
                    break

    def analyze_ldap(self, packet):
        """Analyze LDAP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 389 or packet[TCP].sport == 389):
            payload = self.extract_payload(packet)
            
            if payload and ('simple' in payload.lower() or 'bindrequest' in payload.lower()):
                self.add_finding('LDAP', 'HIGH', 'Bind Request', {
                    'data': payload[:100],
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_dns(self, packet):
        """Analyze DNS traffic"""
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            if dns_layer.qd:
                query = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                
                # Only report suspicious domains
                suspicious = any(tld in query for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
                if suspicious:
                    self.add_finding('DNS', 'MEDIUM', 'Suspicious Domain Query', {
                        'query': query,
                        'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                    })

    def analyze_tftp(self, packet):
        """Analyze TFTP traffic"""
        if packet.haslayer(UDP):
            # File extraction
            if self.extract_files and self.file_extractor:
                extracted = self.file_extractor.extract_tftp_file(packet)
                if extracted:
                    self.add_finding('TFTP', 'INFO', 'File Extracted', {
                        'filename': os.path.basename(extracted),
                        'path': extracted,
                        'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                    })

    def analyze_vnc(self, packet):
        """Analyze VNC traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 5900 or packet[TCP].sport == 5900 or 
                                     5901 <= packet[TCP].dport <= 5909):
            payload = self.extract_payload(packet)
            
            if 'RFB' in payload[:10]:
                self.add_finding('VNC', 'MEDIUM', 'VNC Handshake', {
                    'version': payload[:12],
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_smb(self, packet):
        """Analyze SMB traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 445 or packet[TCP].sport == 445 or
                                     packet[TCP].dport == 139 or packet[TCP].sport == 139):
            # File extraction
            if self.extract_files and self.file_extractor:
                extracted = self.file_extractor.extract_smb_file(packet)
                if extracted:
                    self.add_finding('SMB', 'INFO', 'File Extracted', {
                        'filename': os.path.basename(extracted),
                        'path': extracted,
                        'src': packet[IP].src
                    })
            
            payload = self.extract_payload(packet)
            
            if payload and ('SMB' in payload[:10] or 'NTLMSSP' in payload):
                # Only report once per connection
                if 'NTLMSSP' in payload:
                    self.add_finding('SMB', 'HIGH', 'NTLM Authentication', {
                        'src': packet[IP].src,
                        'dst': packet[IP].dst,
                        'note': 'NTLM hashes may be captured'
                    })

    def analyze_netbios(self, packet):
        """Analyze NetBIOS traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 137 or packet[UDP].sport == 137):
            payload = self.extract_payload(packet)
            
            if payload:
                self.add_finding('NetBIOS', 'LOW', 'NetBIOS Name Service', {
                    'data': payload[:50],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def analyze_ntp(self, packet):
        """Analyze NTP traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 123 or packet[UDP].sport == 123):
            # NTP is usually not interesting for credentials, skip
            pass

    def analyze_syslog(self, packet):
        """Analyze Syslog traffic"""
        if packet.haslayer(UDP) and packet[UDP].dport == 514:
            payload = self.extract_payload(packet)
            
            if payload and len(payload) > 20:
                # Only report if contains sensitive keywords
                if any(kw in payload.lower() for kw in ['password', 'secret', 'key', 'token']):
                    self.add_finding('Syslog', 'MEDIUM', 'Syslog Message with Sensitive Data', {
                        'message': payload[:100],
                        'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                    })

    def analyze_packet(self, packet):
        """Analyze a single packet"""
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
            self.analyze_dns(packet)
            self.analyze_tftp(packet)
            self.analyze_vnc(packet)
            self.analyze_smb(packet)
            self.analyze_netbios(packet)
            self.analyze_ntp(packet)
            self.analyze_syslog(packet)
            
        except Exception as e:
            pass  # Silently skip problematic packets

    def print_findings(self):
        """Print all findings in a formatted way"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== ANALYSIS RESULTS ==={Colors.END}\n")
        
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MEDIUM': Colors.CYAN,
            'LOW': Colors.GREEN,
            'INFO': Colors.BLUE
        }
        
        # File extraction summary
        if self.file_extractor:
            file_stats = self.file_extractor.get_summary()
            if file_stats['total_files'] > 0:
                print(f"{Colors.BOLD}{Colors.GREEN}Extracted Files Summary:{Colors.END}")
                print(f"  Total Files: {file_stats['total_files']}")
                print(f"  Total Size: {file_stats['total_size']:,} bytes")
                for proto, count in file_stats['by_protocol'].items():
                    print(f"  {proto.upper()}: {count} files")
                print()
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No sensitive data found in cleartext{Colors.END}")
            if self.file_extractor and self.file_extractor.extracted_files:
                print(f"{Colors.GREEN}[+] Files saved to: {self.file_extractor.output_dir}/{Colors.END}")
            return
        
        # Print statistics
        print(f"{Colors.BOLD}Statistics:{Colors.END}")
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {protocol}: {count} findings")
        print()
        
        # Print findings by protocol
        for protocol in sorted(self.findings.keys()):
            findings = self.findings[protocol]
            print(f"{Colors.BOLD}{Colors.CYAN}[{protocol}] - {len(findings)} findings{Colors.END}")
            print("-" * 70)
            
            for idx, finding in enumerate(findings, 1):
                severity = finding['severity']
                color = severity_colors.get(severity, Colors.END)
                
                print(f"{color}  [{severity}] {finding['description']}{Colors.END}")
                
                for key, value in finding['details'].items():
                    if isinstance(value, str) and len(value) > 100:
                        value = value[:100] + "..."
                    print(f"    {key}: {value}")
                
                if idx < len(findings):
                    print()
            
            print()
        
        if self.file_extractor:
            print(f"{Colors.GREEN}[+] Files saved to: {self.file_extractor.output_dir}/{Colors.END}")

    def save_report(self, output_file):
        """Save findings to a file"""
        with open(output_file, 'w') as f:
            f.write("Pcap-shark ANALYZER REPORT v3.1\n")
            f.write("=" * 70 + "\n")
            f.write(f"PCAP File: {self.pcap_file}\n")
            f.write(f"File Type: {self.detect_file_type().upper()}\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # File extraction summary
            if self.file_extractor:
                file_stats = self.file_extractor.get_summary()
                if file_stats['total_files'] > 0:
                    f.write("EXTRACTED FILES SUMMARY\n")
                    f.write("-" * 70 + "\n")
                    f.write(f"Total Files: {file_stats['total_files']}\n")
                    f.write(f"Total Size: {file_stats['total_size']:,} bytes\n")
                    for proto, count in file_stats['by_protocol'].items():
                        f.write(f"  {proto.upper()}: {count} files\n")
                    f.write(f"\nFiles saved to: {self.file_extractor.output_dir}/\n\n")
            
            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
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
                    
                    for key, value in finding['details'].items():
                        if isinstance(value, str) and len(value) > 200:
                            value = value[:200] + "..."
                        f.write(f"    {key}: {value}\n")
                    
                    f.write("\n")
                
                f.write("\n")

    def analyze(self):

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
                print(f"{Colors.YELLOW}[*] Processed {idx}/{total_packets} packets...{Colors.END}", end='\r')
            self.analyze_packet(packet)
        
        print(f"{Colors.GREEN}[+] Analysis complete!{Colors.END}" + " " * 30)
        
        self.print_findings()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Pcap-shark Credential Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcapng --extract-files
  %(prog)s capture.pcap --extract-files -o report.txt

Supported Protocols:
  HTTP, FTP, Telnet, SMTP, POP3, IMAP, SNMP, LDAP, SMB, NetBIOS,
  TFTP, VNC, DNS, Syslog, NTP, and more

        '''
    )
    
    parser.add_argument('pcap_file', help='PCAP or PCAPNG file to analyze')
    parser.add_argument('-o', '--output', help='Save report to file')
    parser.add_argument('--extract-files', action='store_true', 
                       help='Extract files from protocols (HTTP, FTP, TFTP, SMB)')
    
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
