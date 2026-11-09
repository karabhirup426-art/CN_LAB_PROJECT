"""
switch.py
A learning Ethernet switch built on one UDP socket. It is the "LAN" that the
ARP hosts are plugged into.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: ARP)

WHY A SWITCH PROGRAM
  Real ARP frames go straight onto the wire (a raw socket, needing admin rights
  and a capture driver). Here every host is a normal program with a UDP socket,
  and it sends its raw 42-byte Ethernet frame to this switch instead. Each host's
  UDP address plays the part of one switch port.

WHAT IT DOES WITH EACH FRAME (same rules as the 2950 switch in Assignment 6)
  1. Learn:   source MAC -> the port it came from, into the MAC table.
  2. Forward: destination MAC
                ff:ff:ff:ff:ff:ff (broadcast) -> every port except the one it came in on
                known MAC                     -> only that port
                unknown MAC                   -> every other port (flooding)

Run it first, then start hosts in other terminals:

    python switch.py
    python host.py --name A --ip 192.168.1.10
"""

import argparse
import socket
import threading
import time

from arp_packet import BROADCAST_MAC, ETHERTYPE_ARP, ArpPacket, EthernetFrame

DEFAULT_SWITCH = ("127.0.0.1", 9000)


class Switch:
    def __init__(self, addr=DEFAULT_SWITCH, quiet=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(addr)
        self.sock.settimeout(0.3)
        self.addr = self.sock.getsockname()
        self.quiet = quiet
        self.mac_table = {}        # MAC -> UDP address (its "port")
        self.port_numbers = {}     # UDP address -> port number 1, 2, 3 ...
        self.stop_event = threading.Event()
        self.t0 = time.time()

    def log(self, msg):
        if not self.quiet:
            print(f"[{time.time() - self.t0:6.2f}s] [Switch] {msg}", flush=True)

    def port(self, addr):
        if addr not in self.port_numbers:
            self.port_numbers[addr] = len(self.port_numbers) + 1
        return f"port {self.port_numbers[addr]}"

    def handle(self, data, addr):
        try:
            frame = EthernetFrame.from_bytes(data)
        except ValueError:
            return                                    # not an Ethernet frame: drop it

        if self.mac_table.get(frame.src_mac) != addr:
            self.mac_table[frame.src_mac] = addr
            self.log(f"learned {frame.src_mac} on {self.port(addr)}")

        what = "data"
        if frame.ethertype == ETHERTYPE_ARP:
            what = ArpPacket.from_bytes(frame.payload).describe()

        if frame.dst_mac == BROADCAST_MAC:
            out = [a for a in set(self.mac_table.values()) if a != addr]
            self.log(f"broadcast from {self.port(addr)} -> flooding to {len(out)} port(s)   [{what}]")
        elif frame.dst_mac in self.mac_table:
            out = [self.mac_table[frame.dst_mac]]
            self.log(f"unicast {self.port(addr)} -> {self.port(out[0])} only   [{what}]")
        else:
            out = [a for a in set(self.mac_table.values()) if a != addr]
            self.log(f"unknown MAC {frame.dst_mac} -> flooding to {len(out)} port(s)")

        for a in out:
            self.sock.sendto(data, a)

    def table_text(self):
        rows = [f"    {mac}   {self.port(a)}" for mac, a in self.mac_table.items()]
        return "  MAC address          Port\n" + ("\n".join(rows) if rows else "    (empty)")

    def run(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue                              # Windows: a host closed its socket
            self.handle(data, addr)
        self.sock.close()

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
        return self

    def stop(self):
        self.stop_event.set()


def main():
    ap = argparse.ArgumentParser(description="Learning switch for the ARP hosts")
    ap.add_argument("--port", type=int, default=DEFAULT_SWITCH[1])
    args = ap.parse_args()
    sw = Switch(("127.0.0.1", args.port))
    print(f"Switch running on UDP {sw.addr[0]}:{sw.addr[1]}. Press Ctrl+C to stop.\n", flush=True)
    try:
        sw.run()
    except KeyboardInterrupt:
        print("\nMAC table at exit:\n" + sw.table_text())


if __name__ == "__main__":
    main()
