"""
dns_client.py
A small nslookup: builds a DNS query, sends it over UDP, waits for the reply
and prints every section.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: DNS)

  python dns_client.py www.cse.myuniv.edu              A record from our server
  python dns_client.py cse.myuniv.edu -t MX            other record types: A NS CNAME PTR MX AAAA
  python dns_client.py portal.cse.myuniv.edu --hex     also show the raw bytes
  python dns_client.py www.google.com -s 8.8.8.8       ask a real public server
  python dns_client.py                                 interactive: type names one by one

UDP gives no delivery guarantee, so the client waits up to --timeout seconds
and sends the same query again, up to --retries times.
"""

import argparse
import socket
import time

from dns_message import RCODES, DnsMessage, build_query, hex_dump, type_name


def lookup(name, qtype="A", server=("127.0.0.1", 53), timeout=2.0, retries=3, recursion=True):
    """Send one query. Returns (reply DnsMessage or None, query bytes, reply bytes, ms taken)."""
    query = build_query(name, qtype, recursion)
    raw_query = query.to_bytes()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for attempt in range(1, retries + 1):
            start = time.perf_counter()
            sock.sendto(raw_query, server)
            try:
                while True:
                    raw_reply, _ = sock.recvfrom(4096)
                    reply = DnsMessage.from_bytes(raw_reply)
                    if reply.id == query.id:              # ignore stray replies to old queries
                        return reply, raw_query, raw_reply, (time.perf_counter() - start) * 1000
            except socket.timeout:
                print(f";; no reply within {timeout:g} s (attempt {attempt}/{retries})")
            except ConnectionResetError:
                print(f";; nothing is listening on {server[0]}:{server[1]} (attempt {attempt}/{retries})")
                time.sleep(timeout)
    finally:
        sock.close()
    return None, raw_query, b"", 0.0


def show(name, qtype, server, show_hex, timeout, retries, recursion):
    reply, raw_query, raw_reply, ms = lookup(name, qtype, server, timeout, retries, recursion)
    print(f"\n;; Query: {name}  type {qtype.upper()}  ->  server {server[0]}:{server[1]}")
    if show_hex:
        print(f";; query bytes ({len(raw_query)}):\n{hex_dump(raw_query)}")
    if reply is None:
        print(";; connection timed out, no server could be reached")
        return None
    if show_hex:
        print(f";; reply bytes ({len(raw_reply)}):\n{hex_dump(raw_reply)}")
    print(f";; id=0x{reply.id:04x}  status: {RCODES.get(reply.rcode, reply.rcode)}  flags: {reply.flag_text()}"
          f"  time: {ms:.1f} ms  size: {len(raw_reply)} bytes")
    print(";; QUESTION:")
    for q in reply.questions:
        print(f"   {q.name:<26}         {type_name(q.qtype)}")
    for title, records in (("ANSWER", reply.answers), ("AUTHORITY", reply.authority),
                           ("ADDITIONAL", reply.additional)):
        if records:
            print(f";; {title}:")
            for rr in records:
                print(f"   {rr}")
    if not reply.answers:
        print(";; no answer records")
    print("   (authoritative answer)" if reply.flags & 0x0400 else "   (non-authoritative answer)")
    return reply


def main():
    ap = argparse.ArgumentParser(description="Tiny nslookup")
    ap.add_argument("name", nargs="?", help="name to look up (leave out for interactive mode)")
    ap.add_argument("-t", "--type", default="A", type=str.upper,
                    choices=["A", "NS", "CNAME", "PTR", "MX", "AAAA"])
    ap.add_argument("-s", "--server", default="127.0.0.1")
    ap.add_argument("-p", "--port", type=int, default=53)
    ap.add_argument("--hex", action="store_true", help="print query and reply bytes")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-recurse", action="store_true", help="clear the RD (recursion desired) bit")
    args = ap.parse_args()
    server = (args.server, args.port)

    if args.name:
        show(args.name, args.type, server, args.hex, args.timeout, args.retries, not args.no_recurse)
        return
    print("Interactive mode. Type a name, optionally followed by a type (e.g.  cse.myuniv.edu MX). Ctrl+C to quit.")
    try:
        while True:
            parts = input("> ").split()
            if parts:
                show(parts[0], parts[1] if len(parts) > 1 else "A", server, args.hex,
                     args.timeout, args.retries, not args.no_recurse)
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == "__main__":
    main()
