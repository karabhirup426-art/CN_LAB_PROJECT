"""
demo.py
The whole ARP story in one command: a switch and three hosts start, and a fixed
script walks through every case. Good for showing the professor quickly; for a
live multi-terminal run use switch.py and host.py instead.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: ARP)

    python demo.py            run all steps
    python demo.py --hex      also print the first ARP frames byte by byte
    python demo.py --step     wait for Enter between steps
"""

import argparse
import time

from host import Host
from switch import Switch

HOSTS = [("A", "192.168.1.10"), ("B", "192.168.1.20"), ("C", "192.168.1.30")]
NOBODY = "192.168.1.99"


def heading(n, text, step):
    if step:
        input("\n(press Enter for the next step)")
    print(f"\n{'=' * 78}\nSTEP {n}: {text}\n{'=' * 78}", flush=True)


def settle():
    time.sleep(0.4)                          # let the other threads finish printing


def main():
    ap = argparse.ArgumentParser(description="Scripted ARP demonstration")
    ap.add_argument("--hex", action="store_true", help="show ARP frames byte by byte in step 2")
    ap.add_argument("--step", action="store_true", help="pause between steps")
    ap.add_argument("--ttl", type=float, default=5.0, help="ARP cache lifetime in seconds (short for the demo)")
    args = ap.parse_args()

    t0 = time.time()
    switch = Switch(("127.0.0.1", 0))
    switch.t0 = t0
    switch.start()
    hosts = {name: Host(name, ip, switch.addr, cache_ttl=args.ttl, timeout=0.8, t0=t0) for name, ip in HOSTS}
    a, b, c = hosts["A"], hosts["B"], hosts["C"]

    heading(1, "Hosts join the LAN and send a gratuitous ARP", args.step)
    for h in hosts.values():
        h.start()
        settle()
    print("\nNobody stores these announcements, because nobody knew these hosts before.")

    heading(2, f"A wants to talk to B ({b.ip}) but only knows its IP", args.step)
    a.show_hex = b.show_hex = args.hex
    mac = a.resolve(b.ip)
    settle()
    a.show_hex = b.show_hex = False
    print(f"\nResult: {b.ip} -> {mac}")
    print("C received the broadcast too, saw it was not its IP, and ignored it.")
    print("The reply went unicast, so the switch sent it to A's port only.")

    heading(3, "A asks again: the answer comes from the cache", args.step)
    a.resolve(b.ip)
    settle()

    heading(4, "B learned A from the request, so B can reply without asking", args.step)
    b.send_message(a.ip, "hello A, I already know your MAC")
    settle()
    print()
    print(a.table_text())
    print(b.table_text())
    print(c.table_text())

    heading(5, "Sending data needs ARP first: C sends to A", args.step)
    c.send_message(a.ip, "hi A, this is C")
    settle()

    heading(6, f"A asks for {NOBODY}, an IP that no host has", args.step)
    a.resolve(NOBODY)
    settle()

    heading(7, f"Cache entries expire after {args.ttl:g} s", args.step)
    print("waiting until A's entry for B has expired ...", flush=True)
    time.sleep(args.ttl + 0.5)
    a.resolve(b.ip)
    settle()

    heading(8, "The switch learned every MAC address while forwarding", args.step)
    print(switch.table_text())

    for h in hosts.values():
        h.stop()
    switch.stop()
    print("\nDemo finished.")


if __name__ == "__main__":
    main()
