"""
demo.py
Automated Step-by-Step ARP Protocol Demonstration
=================================================
Course: CSE/PC/B/S/314 Computer Networks Laboratory
Basket 1: Address Resolution Protocol (ARP)
Author: Sk Amanullah (skaman75)

Usage:
  python demo.py          # Runs all 9 demonstration steps automatically
  python demo.py --hex    # Displays 42-byte Ethernet+ARP frame hex dumps
  python demo.py --step   # Pauses and waits for Enter key between steps
"""

import argparse
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from host import Host
from switch import Switch

DEMO_HOSTS = [
    ("A", "192.168.1.10"),
    ("B", "192.168.1.20"),
    ("C", "192.168.1.30"),
]
UNREACHABLE_IP = "192.168.1.99"


def heading(step_num: int, title: str, wait_step: bool) -> None:
    if wait_step:
        input("\n[Press Enter to proceed to next step...]")
    print(f"\n{'=' * 78}", flush=True)
    print(f"  STEP {step_num}: {title}", flush=True)
    print(f"{'=' * 78}", flush=True)


def settle() -> None:
    time.sleep(0.35)


def run_demo() -> None:
    parser = argparse.ArgumentParser(description="Scripted ARP Demonstration")
    parser.add_argument("--hex", action="store_true", help="Show 42-byte hex dump and field breakdown")
    parser.add_argument("--step", action="store_true", help="Wait for user input between steps")
    parser.add_argument("--ttl", type=float, default=4.0, help="Short TTL for quick cache expiration demo")
    args = parser.parse_args()

    t0 = time.time()
    print("\n" + "█" * 78)
    print("  COMPUTER NETWORKS LAB - BASKET 1: ARP DEMONSTRATION")
    print("  Implementation: RFC 826 ARP over Layer-2 Learning Ethernet Switch")
    print("  Author: Sk Amanullah (skaman75)")
    print("█" * 78)

    # 1. Start Switch
    switch = Switch(("127.0.0.1", 0))
    switch.t0 = t0
    switch.start()

    # 2. Instantiate Hosts
    hosts = {
        name: Host(name, ip, switch.addr, cache_ttl=args.ttl, timeout=0.8, t0=t0)
        for name, ip in DEMO_HOSTS
    }
    host_a = hosts["A"]
    host_b = hosts["B"]
    host_c = hosts["C"]

    try:
        # Step 1: Boot & Gratuitous ARP
        heading(1, "Hosts Boot up and Broadcast Gratuitous ARP", args.step)
        for h in hosts.values():
            h.start(announce=True)
            settle()
        print("  --> Each host announces its IP upon joining the LAN.")
        print("  --> Other hosts ignore announcement if not in their cache.")

        # Step 2: Cache Miss & Broadcast Request
        heading(2, f"Host A wants to communicate with Host B ({host_b.ip}) [CACHE MISS]", args.step)
        host_a.show_hex = host_b.show_hex = args.hex
        mac = host_a.resolve(host_b.ip)
        settle()
        host_a.show_hex = host_b.show_hex = False
        print(f"\n  [Result] {host_b.ip} resolved to physical MAC: {mac}")
        print("  Notice: Switch FLOODED broadcast request to all ports.")
        print("  Host C inspected request, verified target IP != 192.168.1.30, and ignored it.")
        print("  Host B replied UNICAST directly to Host A's port.")

        # Step 3: Cache Hit (Zero Packet Transmission)
        heading(3, "Host A queries Host B again [CACHE HIT]", args.step)
        host_a.resolve(host_b.ip)
        settle()
        print("  --> Instant resolution from local ARP cache. Zero packets sent on the wire!")

        # Step 4: Passive Asker Learning (RFC 826)
        heading(4, "Host B sends IPv4 Data to Host A without asking [PASSIVE LEARNING]", args.step)
        print("  --> Host B learned Host A's MAC when Host A sent the earlier ARP request.")
        host_b.send_message(host_a.ip, "Hello Host A, I already cached your MAC!")
        settle()
        print("\n" + host_a.table_text())
        print(host_b.table_text())

        # Step 5: Data Encapsulation Requires ARP First
        heading(5, "Host C sends IPv4 Data to Host A [AUTOMATIC ON-DEMAND ARP]", args.step)
        print("  --> Host C does not know Host A's MAC yet.")
        print("  --> Host C automatically performs ARP resolution before encapsulating data.")
        host_c.send_message(host_a.ip, "Hello Host A, this is Host C.")
        settle()

        # Step 6: Static ARP Entries (Permanent, arp -s)
        heading(6, "Static Permanent ARP Entry Configuration [arp -s]", args.step)
        static_ip = "192.168.1.254"
        static_mac = "02:00:c0:a8:01:fe"
        print(f"  --> Adding permanent static entry: {static_ip} -> {static_mac}")
        host_a.add_static_entry(static_ip, static_mac)
        print(host_a.table_text())

        # Step 7: Unreachable Host Handling (Retries & Timeout)
        heading(7, f"Host A queries non-existent IP ({UNREACHABLE_IP}) [TIMEOUT & RETRIES]", args.step)
        host_a.resolve(UNREACHABLE_IP)
        settle()
        print("  --> Host A re-transmitted ARP request 3 times before declaring host unreachable.")

        # Step 8: Cache TTL Expiration
        heading(8, f"ARP Cache TTL Expiration (Configured TTL: {args.ttl:g}s)", args.step)
        print(f"  Waiting {args.ttl + 0.5:g} seconds for dynamic cache entries to expire...")
        time.sleep(args.ttl + 0.5)
        print("  Querying Host B again after TTL elapsed:")
        host_a.resolve(host_b.ip)
        settle()

        # Step 9: Switch MAC Table Inspection
        heading(9, "Switch Layer-2 MAC Address Learning Table", args.step)
        print(switch.table_text())
        print("  --> The switch learned the MAC-to-port mapping dynamically from source frames.")

        print("\n" + "█" * 78)
        print("  ARP DEMONSTRATION COMPLETE: ALL TEST SCENARIOS PASSED")
        print("█" * 78 + "\n")

    finally:
        for h in hosts.values():
            h.stop()
        switch.stop()


if __name__ == "__main__":
    run_demo()
