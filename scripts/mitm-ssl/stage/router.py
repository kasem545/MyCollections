"""
OS settings that needed for making attacker machine act as a router
"""
import subprocess
import sys
from termcolor import cprint

SETUP_COMMANDS = [
    'iptables -F',
    'iptables --policy FORWARD ACCEPT',
    'sysctl -w net.ipv4.ip_forward=1',
]

CLEANUP_COMMANDS = [
    'iptables -F',
    'iptables --policy FORWARD DROP',
    'sysctl -w net.ipv4.ip_forward=0',
]

def _run_commands(commands):
    for c in commands:
        cprint(f'Executing: {c}', 'light_grey', attrs=['dark'])
        result = subprocess.run(c.split(), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            print(f'Error in executing: {c}')
            sys.exit(1)

def run():
    print('Configuring attacker machine as a router ...')
    _run_commands(SETUP_COMMANDS)

def cleanup():
    print('Restoring network configuration ...')
    _run_commands(CLEANUP_COMMANDS)
