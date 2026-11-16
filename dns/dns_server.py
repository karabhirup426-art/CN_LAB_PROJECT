"""
dns_server.py
A DNS server over UDP. It is the authoritative server for cse.myuniv.edu
(records in zone.txt) and, with --forward, a caching resolver for every other
name: it asks a real DNS server such as 8.8.8.8 and remembers the answer for
its TTL.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: DNS)

WHY UDP
  A lookup is one small question and one small answer, so there is no
  connection to set up. DNS uses UDP port 53. If no reply comes, the client
  simply asks again (see dns_client.py).

WHAT THE SERVER DOES WITH A QUERY
  1. Read the question (name + type) from the bytes.
  2. Name inside cse.myuniv.edu?
       record found         -> answer it, AA flag set (we own this zone)
       CNAME found instead  -> add the CNAME, then look up its target, and so on
       name exists, no data -> NOERROR with no answers
       name does not exist  -> NXDOMAIN (rcode 3)
  3. Any other name:
       --forward on  -> cached and not expired? answer from the cache.
                        Otherwise ask the upstream server, cache the answer for
                        its TTL, and reply with the RA flag (recursion available).
       --forward off -> REFUSED (rcode 5)

Run:
    python dns_server.py                    UDP port 53 on 127.0.0.1
    python dns_server.py --forward          also resolve internet names via 8.8.8.8
    python dns_server.py --port 5300        if port 53 is busy

Then query it with dns_client.py, or with Windows itself:
    nslookup www.cse.myuniv.edu 127.0.0.1
"""

import argparse
import socket
import threading
import time
from pathlib import Path

from dns_message import (RCODES, TYPE_NUMBERS, DnsMessage, ResourceRecord, build_query,
                         response_flags, type_name)

HERE = Path(__file__).resolve().parent
DEFAULT_PORT = 53
MAX_CNAME_CHAIN = 8


def load_zone(path):
    """Read zone.txt into {(name, type number): [ResourceRecord, ...]} and return (origin, records)."""
    origin, ttl, records = "", 300, {}

    def full(name):
        if name == "@":
            return origin
        return name.rstrip(".") if name.endswith(".") else f"{name}.{origin}"

    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "$ORIGIN":
            origin = parts[1].rstrip(".").lower()
            continue
        if parts[0] == "$TTL":
            ttl = int(parts[1])
            continue
        name, rtype, values = full(parts[0]).lower(), parts[1].upper(), parts[2:]
        if rtype in ("CNAME", "NS", "PTR"):
            data = full(values[0]).lower()
        elif rtype == "MX":
            data = (int(values[0]), full(values[1]).lower())
        else:
            data = values[0]
        records.setdefault((name, TYPE_NUMBERS[rtype]), []).append(ResourceRecord(name, TYPE_NUMBERS[rtype], ttl, data))

    # Reverse lookups (IP -> name): 192.168.151.4 is stored as 4.151.168.192.in-addr.arpa
    for (name, rtype), recs in list(records.items()):
        if rtype == TYPE_NUMBERS["A"]:
            for r in recs:
                rev = ".".join(reversed(r.data.split("."))) + ".in-addr.arpa"
                records.setdefault((rev, TYPE_NUMBERS["PTR"]), []).append(
                    ResourceRecord(rev, TYPE_NUMBERS["PTR"], ttl, name))
    return origin, records


class DnsServer:
    def __init__(self, zone_path=HERE / "zone.txt", host="127.0.0.1", port=DEFAULT_PORT,
                 forward=False, upstream=("8.8.8.8", 53), quiet=False):
        self.origin, self.records = load_zone(zone_path)
        self.forward = forward
        self.upstream = upstream
        self.quiet = quiet
        self.cache = {}                    # (name, type) -> (expiry time, rcode, [records])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.3)
        self.addr = self.sock.getsockname()
        self.stop_event = threading.Event()
        self.t0 = time.time()

    def log(self, msg):
        if not self.quiet:
            print(f"[{time.time() - self.t0:7.2f}s] [DNS server] {msg}", flush=True)

    # ---------- our own zone ----------
    def in_zone(self, name):
        """True for names we are in charge of: our zone, plus any name we hold records for (PTRs)."""
        return (name == self.origin or name.endswith("." + self.origin)
                or any(n == name for n, _ in self.records))

    def answer_from_zone(self, name, qtype):
        answers = []
        for _ in range(MAX_CNAME_CHAIN):
            if (name, qtype) in self.records:
                return 0, answers + self.records[(name, qtype)]
            cname = self.records.get((name, TYPE_NUMBERS["CNAME"]))
            if cname and qtype != TYPE_NUMBERS["CNAME"]:
                answers += cname
                self.log(f"   {name} is an alias (CNAME) of {cname[0].data}, following it")
                name = cname[0].data
                if not self.in_zone(name):
                    break
                continue
            break
        if answers:
            return 0, answers
        name_exists = any(n == name for n, _ in self.records)
        return (0 if name_exists else 3), []

    # ---------- other names: forward and cache ----------
    def answer_by_forwarding(self, name, qtype):
        key = (name, qtype)
        hit = self.cache.get(key)
        if hit and hit[0] > time.time():
            left = int(hit[0] - time.time())
            self.log(f"   cache HIT for {name} {type_name(qtype)} ({left} s of TTL left), no upstream query")
            return hit[1], [ResourceRecord(r.name, r.rtype, left, r.data) for r in hit[2]]
        self.log(f"   not in our zone, cache MISS -> asking upstream {self.upstream[0]}")
        query = build_query(name, qtype)
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(2.0)
        try:
            up.sendto(query.to_bytes(), self.upstream)
            reply = DnsMessage.from_bytes(up.recvfrom(4096)[0])
        except (socket.timeout, OSError) as err:
            self.log(f"   upstream did not answer ({err.__class__.__name__}) -> SERVFAIL")
            return 2, []
        finally:
            up.close()
        ttl = min((r.ttl for r in reply.answers), default=60)
        self.cache[key] = (time.time() + ttl, reply.rcode, reply.answers)
        self.log(f"   upstream answered {RCODES.get(reply.rcode)}, cached for {ttl} s")
        return reply.rcode, reply.answers

    # ---------- one query ----------
    def handle(self, data, client):
        try:
            query = DnsMessage.from_bytes(data)
        except (ValueError, IndexError, UnicodeDecodeError):
            self.log(f"malformed message from {client[0]}:{client[1]}, ignored")
            return
        if query.is_response or not query.questions:
            return
        q = query.questions[0]
        name = q.name.lower().rstrip(".")
        self.log(f"query  id=0x{query.id:04x} from {client[0]}:{client[1]}  {name} {type_name(q.qtype)}")

        authoritative = self.in_zone(name)
        if authoritative:
            rcode, answers = self.answer_from_zone(name, q.qtype)
        elif self.forward:
            rcode, answers = self.answer_by_forwarding(name, q.qtype)
        else:
            rcode, answers = 5, []

        reply = DnsMessage(query.id, response_flags(query, rcode, authoritative, self.forward),
                           [q], answers)
        raw = reply.to_bytes()
        self.sock.sendto(raw, client)
        summary = ", ".join(f"{type_name(r.rtype)} {r.value_text()}" for r in answers) or "no records"
        self.log(f"reply  id=0x{query.id:04x} {RCODES.get(rcode)} [{reply.flag_text()}] {summary} ({len(raw)} bytes)")

    def run(self):
        while not self.stop_event.is_set():
            try:
                data, client = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue                    # Windows: a client went away
            try:
                self.handle(data, client)
            except Exception as err:            # one bad query must never stop the server
                self.log(f"error while answering: {err!r} -> SERVFAIL")
                try:
                    query = DnsMessage.from_bytes(data)
                    self.sock.sendto(DnsMessage(query.id, response_flags(query, 2), query.questions).to_bytes(), client)
                except Exception:
                    pass
        self.sock.close()

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
        return self

    def stop(self):
        self.stop_event.set()

    def zone_text(self):
        rows = [f"    {r}" for recs in self.records.values() for r in recs]
        return f"  Zone {self.origin} ({len(rows)} records)\n" + "\n".join(rows)


def main():
    ap = argparse.ArgumentParser(description="DNS server for cse.myuniv.edu")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--zone", default=str(HERE / "zone.txt"))
    ap.add_argument("--forward", action="store_true", help="resolve other names through --upstream and cache them")
    ap.add_argument("--upstream", default="8.8.8.8")
    args = ap.parse_args()
    try:
        server = DnsServer(args.zone, port=args.port, forward=args.forward, upstream=(args.upstream, 53))
    except OSError as err:
        print(f"Could not open UDP port {args.port}: {err}\nTry another port, e.g.  python dns_server.py --port 5300")
        return
    print(server.zone_text())
    print(f"\nDNS server listening on UDP {server.addr[0]}:{server.addr[1]}"
          f"{'  (forwarding to ' + args.upstream + ')' if args.forward else ''}. Press Ctrl+C to stop.\n", flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
