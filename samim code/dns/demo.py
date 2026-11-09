"""
demo.py
The whole DNS story in one command: the server starts on a free UDP port and a
fixed list of queries shows every case. For a live run use dns_server.py and
dns_client.py (or Windows nslookup) in two terminals instead.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: DNS)

    python demo.py              all steps (step 6 needs internet)
    python demo.py --offline    skip the internet steps
    python demo.py --step       wait for Enter between steps
"""

import argparse
import time

from dns_client import show
from dns_server import DnsServer


def heading(n, text, step):
    if step:
        input("\n(press Enter for the next step)")
    print(f"\n{'=' * 78}\nSTEP {n}: {text}\n{'=' * 78}", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Scripted DNS demonstration")
    ap.add_argument("--offline", action="store_true", help="skip the steps that need the internet")
    ap.add_argument("--step", action="store_true", help="pause between steps")
    args = ap.parse_args()

    server = DnsServer(port=0, forward=not args.offline).start()     # port 0 = any free port
    addr = server.addr
    ask = lambda name, qtype="A", hexdump=False: (show(name, qtype, addr, hexdump, 2.0, 3, True), time.sleep(0.2))

    heading(1, "The server loads its zone file", args.step)
    print(server.zone_text())
    print(f"\nListening on UDP {addr[0]}:{addr[1]}")

    heading(2, "A normal lookup (A record), with the bytes on the wire", args.step)
    ask("www.cse.myuniv.edu", "A", True)
    print("\nQuery: 12-byte header (id, flags 01 00 = RD), then the name as labels 03 www 03 cse ...,")
    print("then type 00 01 (A) and class 00 01 (IN). The reply repeats the question and adds")
    print("one answer: TTL 00 00 01 2c = 300 s, length 4, address c0 a8 97 04 = 192.168.151.4.")

    heading(3, "An alias: the server follows the CNAME chain", args.step)
    ask("portal.cse.myuniv.edu")

    heading(4, "Other record types: MX (mail server), NS (name server), PTR (reverse)", args.step)
    ask("cse.myuniv.edu", "MX")
    ask("cse.myuniv.edu", "NS")
    ask("5.151.168.192.in-addr.arpa", "PTR")

    heading(5, "A name that does not exist in our zone", args.step)
    ask("nothere.cse.myuniv.edu")

    if args.offline:
        print("\n(--offline: skipping the forwarding and caching steps)")
    else:
        heading(6, "A name outside our zone: forwarded to 8.8.8.8, then cached", args.step)
        ask("www.wikipedia.org")
        print("\nAsk again: answered from the cache, no upstream query, TTL counting down")
        time.sleep(1.2)
        ask("www.wikipedia.org")

    heading(7, "No server listening: the client retries, then gives up", args.step)
    server.stop()
    time.sleep(0.5)
    show("www.cse.myuniv.edu", "A", addr, False, 0.5, 3, True)
    print("\nDemo finished.")


if __name__ == "__main__":
    main()
