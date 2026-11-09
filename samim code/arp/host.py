"""
host.py
One computer on the LAN. It owns an IP address and a MAC address, keeps an ARP
cache, and answers ARP requests for its own IP.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: ARP)

THE PROBLEM ARP SOLVES
  To send anything on a LAN, a frame needs the destination MAC address, but
  programs only know the IP address. ARP finds the MAC for an IP:
    1. Look in the ARP cache. Found and not expired -> done, nothing is sent.
    2. Otherwise broadcast an ARP REQUEST: "Who has 192.168.1.20? Tell 192.168.1.10".
       Every host receives it (switch floods broadcasts).
    3. Only the owner of that IP sends an ARP REPLY, unicast, straight back:
       "192.168.1.20 is at 02:00:c0:a8:01:14".
    4. The asker stores the answer in its cache with a time-to-live.
  The owner also stores the asker's IP/MAC from the request, so it will not need
  to ask when it replies to later traffic (RFC 826 does exactly this).

OTHER RULES SHOWN HERE
  - No reply after a timeout -> try again; after 3 tries: host unreachable.
  - Cache entries expire (default 60 s), so a changed MAC is noticed later.
  - Gratuitous ARP: on start-up a host announces its own IP. Others only refresh
    an entry they already had; a host that sees its own IP coming from another
    MAC reports an IP address conflict.

Run (with switch.py already running):

    python host.py --name A --ip 192.168.1.10
    commands:  arp <ip> | send <ip> <message> | table | clear | help | quit
"""

import argparse
import socket
import threading
import time

from arp_packet import (BROADCAST_MAC, ETHERTYPE_ARP, REPLY, REQUEST, ZERO_MAC, ArpPacket,
                        EthernetFrame, arp_frame, explain_frame, hex_dump, mac_for_ip)
from switch import DEFAULT_SWITCH

ETHERTYPE_IPV4 = 0x0800


class Host:
    def __init__(self, name, ip, switch_addr=DEFAULT_SWITCH, cache_ttl=60.0, timeout=1.0,
                 retries=3, show_hex=False, t0=None, mac=None):
        self.name = name
        self.ip = ip
        self.mac = mac or mac_for_ip(ip)
        self.switch_addr = switch_addr
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.retries = retries
        self.show_hex = show_hex
        self.t0 = t0 if t0 is not None else time.time()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.3)
        self.cache = {}            # IP -> [MAC, expiry time]
        self.waiting = {}          # IP -> threading.Event set when its reply arrives
        self.inbox = []            # data messages received
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    # ---------- output ----------
    def log(self, msg):
        print(f"[{time.time() - self.t0:6.2f}s] [Host {self.name}] {msg}", flush=True)

    # ---------- sending ----------
    def send_arp(self, packet, dst_mac):
        data = arp_frame(packet, dst_mac)
        self.sock.sendto(data, self.switch_addr)
        kind = "broadcast" if dst_mac == BROADCAST_MAC else "unicast"
        self.log(f"-> ARP {'REQUEST' if packet.opcode == REQUEST else 'REPLY'} ({kind}, {len(data)} bytes): "
                 f"{packet.describe()}")
        if self.show_hex:
            print(hex_dump(data) + "\n" + explain_frame(data), flush=True)

    def announce(self):
        """Gratuitous ARP: a request for our own IP, sent to everyone."""
        self.send_arp(ArpPacket(REQUEST, self.mac, self.ip, ZERO_MAC, self.ip), BROADCAST_MAC)

    # ---------- the ARP cache ----------
    def lookup(self, ip):
        with self.lock:
            entry = self.cache.get(ip)
            if entry and entry[1] <= time.time():
                del self.cache[ip]
                self.log(f"ARP cache: entry for {ip} expired and was removed")
                return None
            return entry[0] if entry else None

    def learn(self, ip, mac):
        with self.lock:
            old = self.cache.get(ip)
            self.cache[ip] = [mac, time.time() + self.cache_ttl]
        if old is None:
            self.log(f"ARP cache: added   {ip} -> {mac}")
        elif old[0] != mac:
            self.log(f"ARP cache: changed {ip} -> {mac} (was {old[0]})")
        else:
            self.log(f"ARP cache: refreshed {ip} -> {mac}")

    def table_text(self):
        now = time.time()
        with self.lock:
            rows = [f"    {ip:<15}  {mac}   {max(0, exp - now):5.1f} s"
                    for ip, (mac, exp) in sorted(self.cache.items()) if exp > now]
        head = f"  ARP table of Host {self.name} ({self.ip}, {self.mac})\n    IP address       MAC address         expires in"
        return head + "\n" + ("\n".join(rows) if rows else "    (empty)")

    def clear(self):
        with self.lock:
            self.cache.clear()
        self.log("ARP cache cleared")

    # ---------- resolving ----------
    def resolve(self, ip):
        """Return the MAC address for ip, or None if nobody answers."""
        if ip == self.ip:
            return self.mac
        mac = self.lookup(ip)
        if mac:
            self.log(f"ARP cache HIT: {ip} -> {mac} (no packet sent)")
            return mac
        self.log(f"ARP cache MISS for {ip}: asking the LAN")
        for attempt in range(1, self.retries + 1):
            event = threading.Event()
            self.waiting[ip] = event
            self.send_arp(ArpPacket(REQUEST, self.mac, self.ip, ZERO_MAC, ip), BROADCAST_MAC)
            if event.wait(self.timeout):
                self.waiting.pop(ip, None)
                return self.lookup(ip)
            self.log(f"no reply for {ip} within {self.timeout:g} s (attempt {attempt}/{self.retries})")
        self.waiting.pop(ip, None)
        self.log(f"{ip} is unreachable: nobody answered the ARP request")
        return None

    def send_message(self, ip, text):
        """Why ARP matters: a data frame cannot be built until we know the MAC."""
        mac = self.resolve(ip)
        if mac is None:
            self.log(f"message NOT sent: no MAC address for {ip}")
            return False
        payload = f"{self.ip}|{ip}|{text}".encode()
        self.sock.sendto(EthernetFrame(mac, self.mac, ETHERTYPE_IPV4, payload).to_bytes(), self.switch_addr)
        self.log(f"-> data to {ip} at {mac}: \"{text}\"")
        return True

    # ---------- receiving ----------
    def handle(self, data):
        frame = EthernetFrame.from_bytes(data)
        if frame.dst_mac not in (self.mac, BROADCAST_MAC):
            return                                    # a NIC drops frames that are not for it
        if frame.ethertype == ETHERTYPE_IPV4:
            src_ip, _, text = frame.payload.decode(errors="replace").split("|", 2)
            self.inbox.append((src_ip, text))
            self.log(f"<- data from {src_ip}: \"{text}\"")
            return
        if frame.ethertype != ETHERTYPE_ARP:
            return

        arp = ArpPacket.from_bytes(frame.payload)
        self.log(f"<- received: {arp.describe()}")

        if arp.sender_ip == self.ip and arp.sender_mac != self.mac:
            self.log(f"!! IP ADDRESS CONFLICT: {arp.sender_mac} also claims {self.ip}")
            return
        with self.lock:
            already_known = arp.sender_ip in self.cache

        if arp.opcode == REQUEST and arp.target_ip == self.ip and not arp.is_gratuitous:
            self.learn(arp.sender_ip, arp.sender_mac)             # learn the asker too
            self.send_arp(ArpPacket(REPLY, self.mac, self.ip, arp.sender_mac, arp.sender_ip), arp.sender_mac)
        elif arp.opcode == REPLY and arp.target_ip == self.ip:
            self.learn(arp.sender_ip, arp.sender_mac)
            event = self.waiting.get(arp.sender_ip)
            if event:
                event.set()
        elif already_known:
            self.learn(arp.sender_ip, arp.sender_mac)             # RFC 826: refresh what we know
        else:
            self.log("   not for me -> ignored")

    def receive_loop(self):
        while not self.stop_event.is_set():
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                if self.stop_event.is_set():
                    break
                continue
            try:
                self.handle(data)
            except ValueError as err:
                self.log(f"dropped a bad frame: {err}")

    def start(self, announce=True):
        threading.Thread(target=self.receive_loop, daemon=True).start()
        self.log(f"up with IP {self.ip}, MAC {self.mac}")
        if announce:
            self.announce()
        return self

    def stop(self):
        self.stop_event.set()
        self.sock.close()


HELP = """commands:
  arp <ip>             find the MAC address of <ip>
  send <ip> <message>  send a message (does ARP first if needed)
  table                show the ARP cache
  clear                empty the ARP cache
  quit                 stop this host"""


def main():
    ap = argparse.ArgumentParser(description="A host on the simulated LAN")
    ap.add_argument("--name", required=True, help="short name shown in the output, e.g. A")
    ap.add_argument("--ip", required=True, help="this host's IPv4 address, e.g. 192.168.1.10")
    ap.add_argument("--mac", help="this host's MAC address (default: made from the IP)")
    ap.add_argument("--switch-port", type=int, default=DEFAULT_SWITCH[1])
    ap.add_argument("--ttl", type=float, default=60.0, help="ARP cache lifetime in seconds")
    ap.add_argument("--hex", action="store_true", help="print every ARP frame byte by byte")
    args = ap.parse_args()

    host = Host(args.name, args.ip, ("127.0.0.1", args.switch_port), cache_ttl=args.ttl, show_hex=args.hex,
                mac=args.mac)
    host.start()
    print(HELP, flush=True)
    try:
        while True:
            parts = input().strip().split(maxsplit=2)
            if not parts:
                continue
            cmd = parts[0].lower()
            if cmd == "arp" and len(parts) == 2:
                mac = host.resolve(parts[1])
                print(f"  {parts[1]} -> {mac or 'no answer'}", flush=True)
            elif cmd == "send" and len(parts) == 3:
                host.send_message(parts[1], parts[2])
            elif cmd == "table":
                print(host.table_text(), flush=True)
            elif cmd == "clear":
                host.clear()
            elif cmd in ("quit", "exit"):
                break
            else:
                print(HELP, flush=True)
    except (KeyboardInterrupt, EOFError):
        pass
    host.stop()


if __name__ == "__main__":
    main()
