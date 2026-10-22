# DNS and Network Infrastructure Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

### Dan Kaminsky

**Career arc**: Born February 7, 1979, San Francisco. Self-taught from early teens. Timeline:
- Cisco
- Avaya
- Director of Penetration Testing, IOActive. Spent three years advising on Microsoft Vista/Server 2008/Windows 7 releases
- 2012–2021: Co-founder and Chief Scientist, White Ops (renamed HUMAN Security). Co-founded with Michael Tiffany, Ash Kalb, Tamer Hassan. Scale by 2020: 10+ trillion digital interactions verified per week
- Died: April 23, 2021, diabetic ketoacidosis, San Francisco. Age 42

**Recognition**: Internet Hall of Fame, December 14, 2021 (posthumous). Called "a digital Paul Revere" by The New York Times. DNSSEC Trusted Community Representative / Recovery Key Share Holder 7 (2010–2021). Dan Kaminsky Fellowship established posthumously.

**DEF CON "Black Ops" series** — held a recurring DEF CON slot 2001–2015:
| Year | Title / Key Content |
|------|---------------------|
| DC10 (2002) | First Black Ops. Paketto Keiretsu tools: **Scanrand** (stateless TCP scanner predating ZMap by a decade), **Paratrace** (parasitic traceroute attaching to existing TCP flows to bypass stateful firewalls), minewt (NAT), linkcat, phentropy |
| DC11 (2003) | "Stack Black Ops" |
| DC13 (2005) | Temporal attacks against IP; application-layer MD5 collisions; 3D visualization of large network scans; high-speed tunneling stack extending live audio streaming over DNS |
| DC14 (2006) | Internet-wide SSL analysis |
| DC15 (2007) | Design review of Web 2.0; Slirpie (VPN via lured browser) |
| DC16 (2008) | DNS cache poisoning disclosure (see Section II below) |
| DC17 (2009) | X.509 PKI null byte injection (`victim.com\0.attacker.com` in CN field, discovered independently of Moxie Marlinspike); ASN.1 parsing confusion |
| DC18 (2010) | "Black Ops Of Fundamental Defense: Web Edition"; **Domain Key Infrastructure** proposal (PKI anchored in DNSSEC) |
| DC19 (2011) | IPv4/IPv6 fragmentation attacks; Bitcoin DNS seed manipulation; DNS rebinding against enterprise; Net Neutrality transparency engine |
| DC20 (2012) | Generic timing attack defense via network jitter; PRNG critique via clock drift |
| DC22 (2014) | "Secure Random By Default" — argued languages and libc `rand()` should return strong entropy by default |
| DC23 (2015) | Clickjacking elimination by design; **IronFrame** browser isolation; **Autoclave** firewall isolation |

**Black Hat USA appearances**: Keynote 2016: "The Hidden Architecture of our Time — Why This Internet Worked, How We Could Lose It, and the Role Hackers Play."

**Other notable work**:
- **Sony BMG rootkit scope measurement (2005)**: Used DNS cache snooping (send query to public resolvers with RD bit unset; if cached answer for `update.xcp-aurora.com` is present, that resolver served an infected machine) → at least 568,000 networks with infected machines; contributed to regulatory pressure on Sony
- **Interpolique (2010)**: Framework establishing clear data/code boundaries at the language level for injection prevention
- **Conficker detection (2009)**: Found that infected hosts have a detectable remote network signature, later used in Nmap and Nessus

---

### Paul Vixie

**Career arc**: Began maintaining BIND 4 in 1988 at Digital Equipment Corporation (DEC); authored BIND 8 (1997); hired the team that wrote BIND 9. Left DEC 1994. Co-founded Internet Systems Consortium (ISC) with Rick Adams and Carl Malamud (1994/1996). ISC president for ~20 years. Founded Farsight Security (2013) — operates DNSDB (one of the world's largest passive DNS databases, billions of records since 2010). Acquired by DomainTools (2021). Internet Hall of Fame Innovator, 2014.

**Technical contributions**:
- **BIND**: Dominant DNS server implementation globally for decades
- **Cron**: Paul Vixie's cron is the most widely deployed Unix scheduling daemon
- **MAPS (1996)**: First DNS-based Block List (DNSBL / "Realtime Blackhole List") — founded first anti-spam company
- **PAIX (1996)**: First neutral commercial internet exchange point
- **DNS Response Rate Limiting (RRL)**: Co-designed with Vernon Schryver; in BIND 9.10+. Limits response rate per source IP to mitigate amplification attacks. `rate-limit { responses-per-second 5; window 5; }`
- **Response Policy Zones (RPZ)**: DNS "firewall" — override DNS responses based on policy zones. Enables DNS-based malware blocking, phishing prevention, threat intelligence integration. Native BIND support; Infoblox deploys it.
- **DNSSEC**: Early and persistent advocate; co-authored key DNS protocol RFCs (Dynamic Update, EDNS, TSIG); pivotal coordinator in 2008 Kaminsky patch coordination

**On CVE-2008-1447**: "Everything in the digital universe was going to have to get patched" — his assessment upon hearing Kaminsky's description.

---

### Gordon "Fyodor" Lyon

**Career arc**: Created Nmap in 1997. First public release September 1997 in a Phrack Magazine article. Founding member of the Honeynet Project. Author of *Nmap Network Scanning* (2008, the official guide). Co-author of *Stealing the Network: How to Own a Continent* and *Know Your Enemy* (2nd ed.).

**Key talks**: DEF CON 13 (2005) — "Hacking Nmap"; Black Hat/DEF CON 16 (2008) — "Nmap: Scanning the Internet" (results from internet-wide scans of millions of hosts); DEF CON 18 (2010, with David Fifield) — "Mastering the Nmap Scripting Engine" (NSE scripts for SQL injection detection, brute-force auth, webcam exploitation).

---

### Dan Bernstein (djb)

Creator of djbdns (DNS implementation with security as primary objective), qmail. Proposed DNSCurve in 2008 (simultaneous with Kaminsky disclosure). Proposed Curve25519 in 2005 — now used in TLS 1.3 (X25519), Signal protocol, WireGuard, SSH.

**djbdns**: Source port randomization implemented *before* the Kaminsky disclosure — immune to CVE-2008-1447. Strict bailiwick checking; minimal attack surface; privilege separation; runs as non-root. Offers financial security rewards for identified flaws.

**DNSCurve**: Uses Curve25519 ECDH for ephemeral shared secrets between resolvers and authoritative servers. Provides encryption (unlike DNSSEC, which only authenticates) and authentication (server's long-term public key encoded directly in NS record — no separate PKI).

---

### Geoff Huston (APNIC)

Chief Scientist at APNIC. Primary researcher for APNIC Labs. Measures DNSSEC validation adoption using online advertisement systems (Google Ads) to insert a measurement script globally — test fetches of a validly-signed and a bogus-signed name — measured across 15–20 million ad impressions per day. Results: global DNSSEC validation rate ~30–35% (2023–2025); EU average ~49%. DNSSEC World Map: `stats.labs.apnic.net/dnssec`.

---

## II. CVE-2008-1447 — The Kaminsky DNS Cache Poisoning Vulnerability

### Pre-2008 State and the Flaw

The DNS protocol uses two fields to match responses to queries: a 16-bit transaction ID (TXID) and the UDP source port of the query. In vulnerable implementations (BIND 8, BIND 9 pre-fix, most resolvers of the era), the source port was essentially fixed or drawn from a pool of ~1,024 ports:
- TXID: 16 bits (65,536 values)
- Source port: ~10 bits (~1,024 ports)
- **Total randomness: ~26 bits** = ~67 million combinations

Prior reasoning: attacker must guess before legitimate response arrives (~50–100ms window). Considered adequate because each attack attempt was one query.

**Kaminsky's insight**: The attacker controls the *query*. By querying for random non-existent subdomains (`AAAAA.victim.com`, `AAAAB.victim.com`, ...) — each guaranteed not in cache — the attacker creates an unlimited supply of fresh attack windows, each generating a new query with a new TXID. The birthday attack applies across multiple queries: probability of at least one hit exceeds 50% far faster than the naive per-query analysis suggests.

### Attack Mechanics Step-by-Step

1. Attacker queries target recursive resolver for a non-existent subdomain of victim zone: e.g., `AAAAA.victim.com` — not in cache, so resolver issues a new query to `victim.com`'s authoritative nameserver with a new TXID
2. **Simultaneously**, attacker floods resolver with spoofed UDP responses from `victim.com`'s IP address, each trying a different TXID. Each forged response claims:
   ```
   ANSWER:    AAAAA.victim.com A <any IP>
   AUTHORITY: victim.com NS ns.evil.attacker.com
   ADDITIONAL: ns.evil.attacker.com A <attacker's IP>
   ```
3. The NS record is **in-bailiwick** (within authority of `victim.com`) → resolver accepts and caches it
4. Repeat with new random subdomains until one forged response wins the race
5. **Once the forged NS record for `victim.com` is cached**: ALL queries to that resolver for anything in `victim.com` (www, mail, etc.) go to attacker's server for the TTL duration

### Three Defeated Defenses

1. **Bailiwick checking** (only accept records within the queried zone): defeated because the forged response is for a subdomain OF `victim.com`, making the `victim.com` NS record in-bailiwick
2. **TTL-based protection**: defeated by using non-existent subdomains (no cached entry, no TTL to wait out)
3. **16-bit TXID entropy**: defeated by birthday attack across sufficient iterations

### The Fix (RFC 5452, January 2009)

Source port randomization — draw from full ephemeral range (1024–65535 = ~64,511 ports = ~16 bits):
- Combined with 16 bits of TXID = **~32 bits total**
- 2^32 = ~4.3 billion combinations → birthday attack requires millions of packets, taking hours instead of seconds
- **Backward-compatible**: no changes to DNS protocol on the wire

RFC 5452 mandates: unpredictable source port from largest available range; multiple simultaneous source ports for multiple outstanding queries; full 0–65535 TXID range.

**Kaminsky's own assessment**: Source port randomization reduces the attack surface but doesn't eliminate it. DNS over UDP provides no authentication of response origin. The fundamental problem is not fixable without DNSSEC. The fix buys time; DNSSEC is the permanent solution.

**djbdns was immune**: Bernstein had implemented source port randomization and strict bailiwick checking by design years earlier.

### Coordinated Patch Release

Coordinated vendors (simultaneous patch release, July 8, 2008): ISC BIND (9.5.0-P1, 9.4.2-P1, 9.3.5-P1), Microsoft (MS08-037: Windows 2000 SP4, XP SP2/SP3, Server 2003), Cisco, Juniper, Sun, Red Hat, Debian, Ubuntu, FreeBSD, many others.

**Premature disclosure**: July 21, 2008 (13 days after patch release), Halvar Flake independently reverse-engineered the bug and posted to his blog. Thomas Ptacek at Matasano Security confirmed Flake's analysis in a blog post that was quickly removed. US-CERT issued an emergency advisory.

---

## III. DNS Protocol Technical Reference

### Wire Format

**Header (12 bytes)**:
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID (16 bits)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  OPCODE  |AA|TC|RD|RA| Z|AD|CD|   RCODE      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           QDCOUNT    |           ANCOUNT          |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           NSCOUNT    |           ARCOUNT          |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- **ID**: The transaction ID — one of only two authentication fields (the other being source port). The Kaminsky attack target.
- **QR**: 0 = query, 1 = response
- **RD (Recursion Desired)**: Client sets for recursive resolution
- **AD (Authentic Data)**: DNSSEC — resolver has verified response is authentic
- **CD (Checking Disabled)**: DNSSEC — client requests no validation
- **RCODE**: 0=NOERROR, 3=NXDOMAIN (name does not exist), 5=REFUSED

**QNAME encoding**: Domain name as sequence of length-prefixed labels (max label = 63 bytes, max name = 253 characters). `www.example.com` = `\x03www\x07example\x03com\x00`.

**Resource Record format**:
```
NAME (variable, supports message compression via 14-bit offset pointer)
TYPE (16 bits) | CLASS (16 bits, usually 1=IN) | TTL (32 bits) | RDLENGTH | RDATA
```

**Transport**: UDP/53 (default; EDNS0 via RFC 6891 allows advertising up to 4096 bytes); TCP/53 (when TC bit set; required for zone transfers; DNS over HTTPS uses TCP 443, DNS over TLS uses TCP 853).

### Record Types — Security Relevance

| Type | Security Significance |
|------|-----------------------|
| A / AAAA | Primary cache poisoning targets |
| NS | Poisoning the NS record for a zone compromises ALL names within it — the Kaminsky attack goal |
| MX | Poisoning redirects email to attacker-controlled servers |
| CNAME | CNAME chain attacks; zone apex cannot have CNAME (RFC 1034) |
| TXT | SPF, DKIM, DMARC, domain verification tokens; SPF misconfiguration enables email spoofing |
| SRV | Service location (LDAP, SIP, Kerberos); poisoning can redirect authentication services |
| CAA | Restricts which CAs may issue certificates; enforced at CA not browser; no protection against compromised CAs |
| DNAME | Redirects entire subtree of namespace; poisoned DNAME redirects all subdomains simultaneously |
| SOA | MINIMUM field = negative caching TTL (RFC 2308); SERIAL used by zone transfer attackers |

**DNSSEC types**:
| Type | Description |
|------|-------------|
| DNSKEY | Public key record. KSK (flags=257, signs DNSKEY RRset) + ZSK (flags=256, signs all other RRsets). Algorithms: 8=RSA/SHA-256, 13=ECDSA/P-256, 15=Ed25519 |
| RRSIG | Signature covering entire RRset (all records of same TYPE at same NAME). Contains: Type Covered, Algorithm, Labels, Original TTL, Expiration, Inception, Key Tag, Signature |
| DS | Delegation Signer — published by parent zone; contains hash of child KSK. Digest types: 1=SHA-1 (deprecated), 2=SHA-256 |
| NSEC | Proves non-existence by pointing to next name in canonical zone order. **Critical vulnerability**: enables zone enumeration ("NSEC walking") in O(n) queries |
| NSEC3 | Replaces cleartext names with SHA-1 hashes. Opt-out flag for large TLD zones. RFC 9276 (BCP 236) recommends 0 iterations (additional iterations add CPU cost without security benefit). Still vulnerable to offline dictionary attacks |

---

## IV. DNSSEC Architecture

### Chain of Trust

```
Root zone KSK (trust anchor in validator)
    ↓ signs DNSKEY RRset via ZSK
Root zone ZSK signs root RRsets (including DS records for .com)
    ↓ DS record = hash of .com KSK
.com zone KSK signs DNSKEY RRset
    ↓ ZSK signs .com RRsets (including DS records for example.com)
    ↓ DS record = hash of example.com KSK
example.com ZSK signs example.com RRsets (A, MX, TXT, etc.)
```

**Trust anchor**: Root KSK is the ultimate trust anchor. Validators configured with root KSK fingerprint (key tag + hash). Exactly one root KSK in use at a time (brief overlap during rollovers). Root KSK first generated June 16, 2010; rolled in 2018 (first-ever root KSK rollover); next planned 2024–2026.

**KSK/ZSK two-key design rationale**: KSK stored offline/in HSM; changes rarely (annual or less). ZSK rotated more frequently (monthly). If ZSK compromised, only that zone's records at risk for ZSK validity period. KSK can re-sign new ZSK without requiring parent DS update.

**Clock skew vulnerability**: RRSIG inception/expiration timestamps; if validator clock falls outside that window, signatures fail validation. Real operational problem for embedded devices and misconfigured VMs.

### Root KSK Ceremony Architecture

- **East facility**: Culpeper, Virginia (IANA Primary)
- **West facility**: El Segundo, California (IANA Secondary)
- **HSMs**: Thales Luna HSMs (replaced AEP Keyper after EOL). Air-gapped (no network); data enters only via pre-formatted USB key signing request
- **Crypto Officers (7 per facility)**: Hold smartcards required to unlock HSM; quorum required for each ceremony
- **Recovery Key Share Holders (7)**: Each holds one Shamir Secret Share of root KSK backup; quorum (5 of 7) can reconstruct in disaster recovery
- **Ceremony Administrator (IANA staff)**: Executes exhaustively scripted procedure; no improvisation permitted
- **External Auditor**: Independent third party audits against script

Dan Kaminsky held Recovery Key Share Holder 7 from 2010 until his death (2021); listed as "Retired" on `iana.org/dnssec/tcrs`.

### DNSSEC Deployment Reality

- Global validation rate: ~30–35% (APNIC Labs, 2023–2025); EU average ~49%; EU ccTLDs (.nl, .se, .no, .cz) exceed 50%
- .com zone signing rate: ~4% (Verisign, 2023) — the dominant TLD remains largely unsigned
- .gov domains: DNSSEC mandated since 2008 (OMB M-08-23)
- Common validation failures: clock skew; incorrect zone signatures (.se 2009); botched key rollovers (various government zones); incomplete parent DS updates

---

## V. DNS Attacks

### DNS Rebinding

**Mechanism**: Exploits browser same-origin policy enforcement based on domain name, not IP address.

1. Attacker registers `evil.com` with TTL = 1 second; victim visits `http://evil.com` → browser loads attacker's JavaScript
2. Attacker's JS waits for TTL to expire; makes request to `evil.com`
3. Attacker's DNS now returns a private IP (e.g., `192.168.1.1` — victim's router, or `169.254.169.254` — AWS IMDS)
4. Browser sees request as same-origin (`evil.com`) and does NOT block it
5. Browser sends request to internal service with victim's cookies/session; JS receives response

**Attack scenarios**:
- **Router admin panel**: Steal admin credentials, modify DNS settings, change Wi-Fi passwords
- **Internal web services**: Reach any HTTP service on victim's LAN
- **AWS IMDSv1** (`169.254.169.254`): Steal EC2 instance credentials, IAM role tokens. IMDSv2 requires PUT with token header before GET — mitigates simple rebinding, but JS can issue the PUT through the rebind
- **GCP metadata**: Same attack applies

**Historical research**: Tavis Ormandy (Google Project Zero) most prominent modern practitioner; created `rbndr.us` — public rebinding service that alternates between two IPs. Found rebinding vulnerabilities in Blizzard games launcher, Transmission BitTorrent client, routers.

**Mitigations**:
- **Resolver-level**: RFC 5735 private address filtering — refuse to return private/reserved IPs (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16) in responses to public domain queries
- **Service binding**: Bind services to `127.0.0.1` instead of `0.0.0.0` — prevents external access even after rebind
- **Host header validation**: Reject requests with unexpected `Host:` headers
- **DNSSEC**: Does NOT prevent rebinding (attacker controls their own authoritative server and signs responses legitimately)

### DNS Amplification / Reflection DDoS

**Mechanism**: Attacker spoofs UDP packets with victim's IP as source → sends to open recursive resolvers → large responses sent to victim.

**Amplification factors**:
- ANY queries (responses minimized by RFC 8482): US-CERT lists DNS bandwidth amplification at 28–54×
- DNSKEY queries to signed zones: 10–20× typical
- EDNS0 OPT RR with `UDP payload size = 4096`: 40-byte query → 4,096-byte response = 100×

**RFC 8482 (2019)**: Optional guidance to minimize ANY responses; authoritative servers may return a minimal response (e.g., a synthesized HINFO record). Major operators (Cloudflare, Google, AWS Route 53) now return minimal ANY responses.

**Mitigations**:
- **BCP38 (RFC 2827)**: ISPs filter outbound packets whose source IP is not from their allocated space — prevents spoofed UDP source addresses. Adoption remains incomplete globally
- **DNS Response Rate Limiting (RRL)**: BIND 9.10+ (co-designed by Paul Vixie and Vernon Schryver). Limits responses per source IP per second; reduces amplification volume with acceptable legitimate resolution failure rate
- **MANRS**: Internet Society initiative; four actions: filtering, anti-spoofing (BCP38), coordination, global validation (RPKI + IRR)
- **Closed recursive resolvers**: `allow-recursion { your_networks_only; }` in BIND

### KeyTrap (CVE-2023-50387, CVE-2023-50868)

Disclosed February 13, 2024 by ATHENE (Elias Heftrig, Haya Schulmann, Niklas Vogel, Michael Waidner — Fraunhofer SIT / Goethe University Frankfurt / TU Darmstadt). The flaw is in the DNSSEC validation requirement itself — RFC 4035 §5.3.1 directs a validator to try **every** available DNSKEY against **every** available RRSIG when key tags collide. A single malicious response carrying many colliding-tag DNSKEYs and many RRSIGs forces an O(N×M) signature-verification storm; one packet stalls real validators for up to ~16 hours depending on implementation. Affected resolvers included BIND 9, Unbound, PowerDNS Recursor, Knot Resolver, plus public services from Google, Cloudflare, OpenDNS, Quad9. Companion CVE-2023-50868 ("NSEC3 closest encloser proof") forces excessive hash computations during denial-of-existence proofs. ATHENE called it "the worst attack on DNS ever discovered." Final paper at ACM CCS 2024 ("The Harder You Try, The Harder You Fail"). **Doctrinal point**: this is not a bug; it is an algorithmic-complexity attack on the validator state machine the spec mandates. Mitigations (cap key/signature tries, e.g. BIND `max-validation-failures-per-fetch`) are pragmatic ceilings, not protocol fixes. See [ATHENE disclosure](https://www.athene-center.de/en/keytrap), [ISC advisory](https://kb.isc.org/docs/cve-2023-50387), [Akamai analysis](https://www.akamai.com/blog/security/dns-exploit-keytrap-posed-major-internet-threat). Cross-link: `cryptography_expertise.md` for the algorithmic-complexity-attack pattern in signature verification generally.

### DNSBomb (IEEE S&P 2024)

Xiang Li, Daishuai Wu, Haixin Duan, Qi Li (Tsinghua University et al.), *DNSBomb: A New Practical-and-Powerful Pulsing DoS Attack Exploiting DNS Queries-and-Responses*, IEEE S&P 2024, San Francisco, May 20–23 2024. Rediscovers DNS amplification as a **pulsing** attack: attacker sends low-rate DNS queries (each one alone unremarkable), forces resolvers to accumulate queued queries via slow upstream responses, then collapses the buffered work into a synchronized pulse against a victim. Measured peak pulse magnitude ~8.7 Gb/s and bandwidth amplification factor exceeding **20,000×** — orders of magnitude higher than ANY-query amplification because each component primitive (query accumulation, response amplification, pulse concentration) composes multiplicatively. Companion work at USENIX Security 2024 — Duan et al., *CAMP: Compositional Amplification Attacks against DNS* — formalizes the composability framework: enumerate intrinsic DNS amplification primitives, demonstrate they multiply rather than add. **Practical implication**: legacy mitigation (RRL, BCP38, closed recursive resolvers) addresses single-step amplification; DNSBomb/CAMP show that operators must reason about the **product** of every amplification primitive a request chain touches. Paper: [lixiang521.com/publication/oakland24-2](https://lixiang521.com/publication/oakland24-2/) ; site: [dnsbomb.net](https://dnsbomb.net/) ; CAMP paper: [usenix.org/system/files/usenixsecurity24-duan.pdf](https://www.usenix.org/system/files/usenixsecurity24-duan.pdf).

### Sitting Ducks (Eclypsium / Infoblox, July 31 2024)

Disclosed by Infoblox Threat Intel and Eclypsium July 31 2024 ([Infoblox writeup](https://blogs.infoblox.com/threat-intelligence/who-knew-domain-hijacking-is-so-easy/), [Eclypsium](https://eclypsium.com/blog/ducks-now-sitting-dns-internet-infrastructure-insecurity/), [Krebs](https://krebsonsecurity.com/2024/07/dont-let-your-domain-name-become-a-sitting-duck/)). The attack exploits **lame delegations**: the authoritative nameserver for a domain has no record of the zone, but the domain is still pointed (via NS records at the registrar) at that nameserver. If the DNS provider lets a new tenant claim that empty zone without proving registrar control, an attacker registers the orphan zone and silently hijacks the domain without ever touching the legitimate registrar account.

Three required conditions: (1) domain uses different providers for DNS and registrar; (2) the authoritative nameserver lacks the zone data; (3) DNS provider permits zone claim without registrar-side verification. Scale: **~1 million exploitable domains** identified; **30,000+** confirmed hijacked since 2019; threat actors observed using the technique for phishing, malware C2, brand impersonation, traffic redirection. Many hijacked domains belonged to Fortune 100 companies — registrar lock is not protection because the takeover bypasses the registrar entirely.

Predecessor research: Matthew Bryant, [*The Orphaned Internet*](https://thehackerblog.com/the-orphaned-internet-taking-over-120k-domains-via-a-dns-vulnerability-in-aws-google-cloud-and-rackspace/) (2016) — 120,000+ domains takeable via the same primitive at AWS, Google Cloud, Rackspace, DigitalOcean. The 2024 disclosure showed the class is structural and unfixed eight years later; Infoblox subsequently confirmed 70,000+ hijacked domains by November 2024. **Defense**: registrar-side audit of NS records against actual zone existence; periodic re-validation of delegations.

### DNS Tunneling

**Mechanism**: Encode arbitrary data in DNS query/response fields to create bidirectional covert channel traversing firewalls that allow UDP/53 outbound.

**Query channel** (client → server): `<base32-encoded-data>.<attacker-controlled-domain>.com` → propagates through resolver hierarchy to attacker's authoritative server.

**Response channel** (server → client): Data encoded in A, AAAA, TXT (255 bytes/record — highest bandwidth), CNAME, NULL records. High latency.

**Common tools**: `iodine` (IPv4 over DNS; supports A, CNAME, MX, TXT, NULL); `dnscat2` (C2-focused; TXT/CNAME records; ECDH P-256 + Salsa20 encrypted mode); `dns2tcp` (TCP connections over DNS).

**Detection heuristics**:
- **Label entropy**: Human-readable domain names ~2–3 bits/char; base32/base64 tunnel labels approach theoretical maximum (~5 bits/char). Threshold: subdomain entropy > 3.5 bits/char is suspicious
- **Query length**: Tunnel queries routinely use 200–250 character FQDNs (near 253-byte max); legitimate FQDNs typically <100 characters
- **Query rate**: Thousands of DNS queries/hour to a single external domain is anomalous (normal: O(10–100)/host/hour)
- **Record type distribution**: High volume of TXT and NULL queries is rare in legitimate traffic
- **NXDOMAIN rate**: Tunnel clients generate high NXDOMAIN rates probing valid labels
- **Response volume**: High bytes-per-query ratio in TXT responses
- **Known tool signatures**: iodine begins sessions with specific negotiation sequences; dnscat2 has recognizable packet structure

---

## V.5. Modern DDoS Landscape (2023–2026)

### HTTP/2 Rapid Reset (CVE-2023-44487)

Joint disclosure October 10, 2023 by Cloudflare, Google, AWS. Attacker opens an HTTP/2 stream via HEADERS frame, then immediately cancels with RST_STREAM before the server processes the request. The cancellation **does not count against `SETTINGS_MAX_CONCURRENT_STREAMS`** because the stream is closed; the attacker can churn an unbounded request rate per TCP connection. Recorded peaks: Cloudflare 201M rps, AWS 155M rps, **Google 398M rps** — 7.5× the previous record. Exploited in the wild August → October 2023 before coordinated disclosure. Active mitigations now standard: monitor client RST_STREAM rate, close abusive connections, jail abusive IPs across HTTP/2 endpoints, redesign queueing to make cancellation cheap. Specification follow-on: RFC 9113 errata + IETF discussion of stream-cancellation accounting. References: [Cloudflare technical breakdown](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/), [CISA alert](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487), [NVD CVE-2023-44487](https://nvd.nist.gov/vuln/detail/cve-2023-44487). Cross-link: `http_web_security.md` for HTTP/2 stream multiplexing and HPACK detail.

### HTTP/2 CONTINUATION Flood (VU#421644, April 3 2024)

Discovered by Bartek Nowotarski, disclosed via CERT/CC [VU#421644](https://kb.cert.org/vuls/id/421644) April 3, 2024. HTTP/2 splits oversized header blocks across multiple CONTINUATION frames terminated by an `END_HEADERS` flag; vulnerable implementations buffer incoming frames until the flag arrives. Sending unbounded CONTINUATION frames with no terminating `END_HEADERS` exhausts memory (OOM crash) or CPU (HPACK Huffman decode loop). Cluster of 10 CVEs across the major HTTP/2 implementations:

| Project | CVE |
|---|---|
| Apache HTTP Server | CVE-2024-27316 |
| Apache Tomcat | CVE-2024-24549 |
| Apache Traffic Server | CVE-2024-31309 |
| Envoy proxy | CVE-2024-27919, CVE-2024-30255 |
| Golang `net/http` | CVE-2023-45288 |
| nghttp2 | CVE-2024-28182 |
| Node.js | CVE-2024-27983 |
| amphp/http | CVE-2024-2653 |
| Tempesta FW | CVE-2024-2758 |

**Doctrinal point**: RFC 9113 warned implementations against "large numbers of small or empty frames" as a DoS vector but did not require enforcement; every major implementation left enforcement to vendor discretion and ten of them got it wrong simultaneously. Distinct from Rapid Reset: Rapid Reset abuses stream **cancellation**; CONTINUATION Flood abuses stream **header buffering** before the request even completes — which makes it harder to detect, since no HTTP request log line is ever written. Mitigation: vendor patches enforce per-stream CONTINUATION frame and header-byte caps; WAF rules can throttle CONTINUATION-heavy connections. Cross-link: `http_web_security.md` HTTP/2 + HTTP/3 protocol coverage.

### Terabit-Scale Botnets (Cloudflare 2024–2026)

Cloudflare 2024 statistics ([Q4 2024 report](https://blog.cloudflare.com/ddos-threat-report-for-2024-q4/)): 21.3M attacks mitigated full year (+53% YoY); 6.9M in Q4 alone (+83% YoY). Hyper-volumetric attacks (>1 Tbps) grew **1,885%** Q3→Q4. Record peak October 29, 2024: **5.6 Tbps UDP attack** from a Mirai-variant botnet of ~13,000 IoT devices targeting an East Asian ISP, lasting only 80 seconds. By 2025 Q3 Cloudflare reported the [Aisuru botnet](https://blog.cloudflare.com/ddos-threat-report-2025-q3/) launching **29.7 Tbps** attacks. Layer 3/4 vs L7 split is roughly even (49/51 in Q4 2024); SYN floods dominate L3/4 (38%), followed by DNS floods (16%), UDP floods (14%); Memcached and BitTorrent amplification grew 314% and 304% in Q4 2024 alone. Most attacks are short — 72% of HTTP and 91% of network attacks complete in under 10 minutes. Operational consequence: **defenders cannot reactively scale** — autonomous detect-and-mitigate at scrubbing tier is the only viable shape.

### Mirai-Class Botnets 2024–2026 (Aisuru, TurboMirai)

Mirai's source release (Anna-senpai, Hackforums, September 2016) seeded an ongoing line of IoT-router botnets. The 2024–2026 generation is qualitatively different in scale: consumer broadband routers, CCTV/DVR appliances, and CPE devices running same-OEM firmware have created uniform-vulnerability fleets at million-device scale.

| Botnet | First seen | Peak | Notes |
|---|---|---|---|
| Aisuru | XLab, August 2024 | 31.4 Tbps (Dec 2025, Cloudflare) | DDoS-for-hire; restricted clientele; per [NETSCOUT ASERT](https://www.netscout.com/blog/asert/asert-threat-summary-aisuru-and-related-turbomirai-botnet-ddos) and [Cloudflare 2025 Q3](https://blog.cloudflare.com/ddos-threat-report-2025-q3/) tracks between 1M and 4M infected devices |
| TurboMirai (family) | 2025 | >4 Gpps | Mirai-fork lineage with optimized packet generators; tracked by NETSCOUT |
| Four-Faith router botnet | November 2024 | n/a | Exploited Four-Faith industrial router CVE for ingress; documented in [The Hacker News](https://thehackernews.com/2025/01/mirai-botnet-variant-exploits-four.html) |

**Defender implication**: traditional anti-amplification controls (BCP38, RRL, RPKI) are necessary but no longer sufficient — the attack source is now **legitimate compromised endpoints**, not spoofed reflectors. The defense burden shifts to (a) IoT supply-chain hardening, (b) ISP egress filtering of obviously malicious flows, and (c) anycast scrubbing-tier autonomous detection. The 5.6 Tbps attack lasted 80 seconds, was autonomously detected and dropped, and the targeted ISP did not need to be in the loop — that is the new operational baseline.

Cross-link: `firmware_embedded_security.md` for the CPE-firmware substrate problem; `cicd_supply_chain_expertise.md` for the OEM-firmware supply-chain analog.

---

## VI. Post-Kaminsky DNS Enhancements

### 0x20 Bit Encoding (Case Randomization)

Proposed by David Dagon and Paul Vixie; formalized in IETF draft `draft-vixie-dnsext-dns0x20-00` (2008); not advanced to RFC status. DNS is case-insensitive for QNAME matching. Resolvers randomize case of each character: `www.example.com` → `wWw.ExAmPlE.cOm`. Legitimate authoritative servers copy QNAME case from query to response. Spoofed responses are highly unlikely to match exact case pattern.

**Entropy added**: Each alphabetic character adds 1 bit. 10 alphabetic characters → 2^(32+10) = ~4 trillion combinations. Google Public DNS enabled globally (July 2023). Not universally deployed — some authoritative servers do not preserve case, causing spurious failures.

### QNAME Minimization (RFC 9156, 2021)

Sends only the minimum QNAME needed for the next delegation step:
- Query to root: `.` (asking for .com NS)
- Query to .com: `example.com` (asking for example.com NS)
- Query to example.com: `www.example.com` (full name only at authoritative)

Privacy benefit: root servers and TLD servers no longer see the full query name. Deployed by default in BIND 9.14+, Unbound 1.7.2+, Knot Resolver.

### DNS over HTTPS (DoH, RFC 8484) and DNS over TLS (DoT, RFC 7858)

**DoT** (port 853): DNS wrapped in TLS. Detectable/blockable by firewalls. Android Pie (9.0+) enables by default when network indicates support.

**DoH** (port 443): DNS queries in HTTPS POST/GET. Indistinguishable from regular HTTPS traffic. Firefox default for US users February 2020; Chrome default May 2020.

**Enterprise problem**: DoH bypasses enterprise DNS controls (content filtering, malware blocking, split-horizon internal naming). Enterprises must explicitly override browser DoH defaults and deploy their own DoH resolver (Cisco Umbrella, NextDNS, Cloudflare Gateway). RFC 9463 (2023) enables network operators to advertise their DoH/DoT resolver via DHCP/RA.

**Application-level resolution bypass**: Modern browsers resolve DNS internally via DoH rather than the OS resolver. Firefox / Chrome / Edge / Safari each ship their own DoH client; the system DNS-based DLP, OS hosts file, and corporate split-horizon configuration are all bypassed unless the enterprise pushes an explicit "use system DNS only" policy via MDM/group policy (Firefox `network.trr.mode=5`; Chrome `DnsOverHttpsMode=off`). The "where DNS resolution happens" boundary has moved from kernel to userland to application — each layer is a separate enforcement surface.

### DNS over QUIC (DoQ, RFC 9250) and Adaptive Resolvers

**DoQ**: Defined in [RFC 9250](https://datatracker.ietf.org/doc/rfc9250/) (May 2022). DNS over a dedicated QUIC connection (UDP/853, separate from DoT's TCP/853). Privacy on par with DoT; latency closer to classic UDP DNS because QUIC handshake is 0-RTT or 1-RTT and resilient to packet loss. Quad9 enabled DoQ + DNS-over-HTTP/3 in March 2026; AdGuard supports DoQ. Deployment shape often inverts the resolver — a QUIC-capable proxy (`dnsdist`, `doh-proxy`) fronts a classical resolver (BIND, Unbound), letting transport security evolve independently of resolution.

**Adaptive resolvers**: The Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9, AdGuard, OpenDNS ecosystem is now the de facto resolver tier for a large share of end-user devices. Resolver choice is a security decision: Quad9 enforces malware blocklists; AdGuard adds ad/tracker blocking; NextDNS exposes per-profile telemetry. **Operational concern**: most networks have lost visibility into which resolver each endpoint actually uses because DoH/DoQ is application-layer; CISA's 2024 guidance treats this as a default-loss-of-visibility problem to be solved structurally.

### CISA + NSA Encrypted DNS Guidance (2024)

CISA, [*Encrypted DNS Implementation Guidance*](https://www.cisa.gov/sites/default/files/2024-05/Encrypted%20DNS%20Implementation%20Guidance_508c.pdf) (TLP:CLEAR v1.0, April 2024), and NSA, [*Adopting Encrypted DNS in Enterprise Environments*](https://media.defense.gov/2021/Jan/14/2002564889/-1/-1/0/CSI_ADOPTING_ENCRYPTED_DNS_U_OO_102904_21.PDF) (2021, still current), codify federal-civilian DNS architecture under OMB M-22-09 / EO 14028. Its required outcomes include: (1) agency DNS infrastructure uses CISA's Protective DNS service as upstream; (2) endpoints are configured to prevent direct queries to third-party DoH/DoQ resolvers; (3) agency DNS supports encrypted DNS toward endpoints; (4) roaming endpoints use either agency DNS or Protective DNS. The doctrine is "consolidate then encrypt" — every endpoint queries an agency-controlled resolver that itself emits encrypted DNS upstream, preserving telemetry and policy enforcement on the resolver while still meeting the "all DNS encrypted" mandate. NSA's selecting-a-Protective-DNS-service companion guidance (CSI, [March 2025 v1.3](https://media.defense.gov/2025/Mar/24/2003675043/-1/-1/0/CSI-SELECTING-A-PROTECTIVE-DNS-SERVICE-V1.3.PDF)) covers resolver selection criteria. Cross-link: `detection_engineering_expertise.md` for DNS-based detection patterns this guidance preserves; `cloud_iam_expertise.md` for the enterprise device-posture analog.

---

## VII. Network Scanning (Fyodor / Nmap)

### Nmap Scan Types

**SYN Scan (-sS)** — "Half-Open" (default with root): Sends SYN, never completes handshake. Interprets: SYN/ACK = OPEN; RST = CLOSED; no response/ICMP unreachable = FILTERED. Faster; avoids application-layer logging (which requires completed connections). Does not avoid stateful firewall logging.

**Connect Scan (-sT)**: Full TCP connect via OS `connect()` syscall. Fully logged. No raw socket privileges required. Used when raw socket access unavailable.

**UDP Scan (-sU)**: Slow (OS rate-limits ICMP error generation ~1/sec). Non-response = OPEN|FILTERED. Uses protocol-specific payloads from `nmap-payloads` (DNS query to port 53, SNMP query to port 161, etc.).

**ACK Scan (-sA)** — Firewall mapping: Not finding open ports — characterizing firewall ruleset. Stateless firewall passes all ACK packets (look like established connections); stateful firewall drops. RST response = UNFILTERED (firewall passes ACK); no response = FILTERED.

**Idle Scan (-sI `<zombie>`)** — Anonymous scanning: Exploits a third-party "zombie" host with globally incrementing IP ID counter. Each port: (1) probe zombie to note IPID; (2) send SYN to target spoofed as zombie; (3) if OPEN: target sends SYN/ACK to zombie → zombie sends RST → IPID increments by 2; if CLOSED: target sends RST to zombie (ignored) → IPID increments by 1. Scan results attributed to zombie; attacker's IP never appears in target logs. Also reveals firewall rules that allow zombie→target connections specifically.

**FIN/NULL/Xmas (-sF/-sN/-sX)**: RFC 793: no-flag, FIN-only, or FIN+PSH+URG packet should generate RST for CLOSED ports and be silently dropped for OPEN ports. Works against BSD/macOS; useless against Windows (RST for all ports regardless of state).

### OS Detection (-O)

Nmap sends up to 16 probe packets and analyzes responses against `nmap-os-db` (2,600+ fingerprints).

**Measured parameters**:
- **TCP ISN**: Rate of increment, greatest common divisor of consecutive values, sequence predictability index
- **TCP Window Size**: Initial window in SYN/SYN-ACK. Linux: 5840/14600/65535; Windows: 8192/65535
- **TCP Options**: Order and values in SYN packets (MSS, SACK, Timestamps, Window Scale, NOP) — different OSes include different subsets in different orders
- **TTL**: Linux = 64, Windows = 128, Cisco IOS = 255
- **DF bit**: Default set in Windows and most Linux; absent in some older systems
- **IP ID generation**: Globally incremental (old Linux/Windows), per-connection (modern Linux), random (OpenBSD), all-zeros (some firewalls)
- **ICMP response characteristics**: Echo reply DF bit, error message payload size, response TTL and IP ID

### Version Detection (-sV)

Uses `nmap-service-probes` database (about 6,500 pattern matches for more than 650 protocols). Process: connect → wait for banner → NULL probe → protocol-specific probes → match against regex patterns. Reports: service name, application, version, hostname, device type, OS family, CPE identifier.

### Nmap Scripting Engine (NSE)

Lua-based; runs during scans and interacts with target services.

**Script categories**:
| Category | Examples |
|----------|---------|
| `auth` | Bypass auth or test default credentials |
| `brute` | Brute-force credential testing (ssh-brute, http-brute, smb-brute) |
| `default` | Run with `-sC` or `-A`; conservative, non-destructive |
| `discovery` | SNMP, LDAP, DNS zone transfers, broadcast queries |
| `exploit` | Exploit known vulnerabilities |
| `vuln` | Test for specific known vulnerabilities without exploiting (e.g., EternalBlue/MS17-010 via `smb-vuln-ms17-010`) |
| `malware` | Detect known malware backdoors |
| `safe` | Non-intrusive, low-impact scripts |

### Timing Templates

| Template | Name | Use Case |
|----------|------|----------|
| -T0 | Paranoid | Maximum IDS evasion; 5-minute inter-probe; serialized |
| -T1 | Sneaky | Slow IDS evasion; 15-second delay; serialized |
| -T2 | Polite | Avoid congesting network; 0.4-second delay |
| -T3 | Normal | Default; no special constraints |
| -T4 | Aggressive | max-rtt: 1250ms; recommended for LANs |
| -T5 | Insane | max-rtt: 300ms; sacrifices accuracy for speed |

Fyodor recommends `-T4` for modern LANs.

### Internet-Wide Scanning Tools

**Masscan** (Robert Graham, 2013): Stateless TCP SYN scanner; raw packet injection via libpcap/PF_RING; asynchronous send/receive; stateless tracking via SYN sequence number cookie. 10M packets/second. Scanning entire IPv4 in <5 minutes theoretically.

**ZMap** (Durumeric, Wustrow, Halderman — USENIX Security 2013): PF_PACKET raw sockets on Linux (bypasses kernel TCP/IP stack). Single-port TCP SYN scan; address permutation via multiplicative group of integers modulo prime (random order prevents /24 rate-limiting); probes entire IPv4 in ~45 minutes on gigabit Ethernet.

**Project Sonar (Rapid7, HD Moore)**: Continuous automated internet measurement service. Datasets available at `opendata.rapid7.com`: FDNS (billions of A/AAAA/CNAME/TXT records, JSONL format), RDNS (PTR records), endpoint studies (HTTP/HTTPS banner + TLS certificates). Free for security research. Moore created Metasploit; Project Sonar embodies his philosophy of continuous internet measurement.

---

## VIII. BGP Routing Security

### BGP Route Hijacking

BGP's fundamental weakness: no built-in authentication of route announcements. Any AS can announce any IP prefix; neighbors propagate unless they have explicit filters.

**More-specific hijacking**: A /24 route always beats a /23 in BGP selection. Attacker announcing a more-specific sub-prefix attracts traffic for those IPs.

**Notable incidents**:

| Incident | Date | Impact |
|----------|------|--------|
| **Pakistan Telecom → YouTube** | Feb 24, 2008 | AS 17557 injected YouTube's 208.65.153.0/24 prefix; upstream PCCW (AS 3491) propagated globally; YouTube unreachable worldwide ~2 hours; traffic blackholed at Pakistan Telecom |
| **Rostelecom → Google/AWS/Akamai** | Apr 1, 2020 | 8,800+ prefixes hijacked |

### RPKI (Resource Public Key Infrastructure)

Hierarchical PKI where RIRs (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) issue cryptographic certificates validating that a given AS is authorized to originate a given prefix.

**Route Origin Authorization (ROA)**: Signed object stating "AS X is authorized to announce prefix P/len up to maximum prefix length M."

**Route Origin Validation (ROV)**: BGP routers validate received announcements against RPKI ROA database. Invalid routes (origin AS doesn't match any ROA) can be dropped or deprioritized.

**Deployment status (2024–2025)**:
- ~54% of IPv4/IPv6 global routing table prefixes covered by ROAs (NIST RPKI Monitor, MANRS [2024 growth update](https://manrs.org/2025/01/rpki-growth-2024/))
- ~74% of IP traffic destined towards ROA-covered destinations (Kentik measurements)
- MANRS confirmed [a majority of IPv4 routes became ROA-covered](https://manrs.org/2024/05/rpki-rov-deployment-reaches-major-milestone/) May 2024
- RPKI validator software: Routinator (~70% market share), Fort, Cloudflare OctoRPKI
- US Federal: NIST RPKI Monitor ([rpki-monitor.antd.nist.gov](https://rpki-monitor.antd.nist.gov/)) provides public measurement
- Live monitoring of relying-party sync delays (Sediqi et al., [MANRS 2025](https://manrs.org/wp-content/uploads/2025/06/RPKI-Syncing-Delay-in-Relying-Party-Synchronization.pdf)) — relying parties can lag publication by minutes-to-hours, creating brief windows during which a fresh ROA may not yet protect a freshly-announced prefix

**Limitations**: RPKI validates origin, not path. A compromised AS in the middle can still manipulate traffic. BGPsec (signs entire AS path cryptographically) is largely experimental and unlikely to achieve widespread deployment due to operational complexity.

**ASPA (Autonomous System Provider Authorization)** — IETF SIDROPS WG, draft-ietf-sidrops-aspa-profile (Internet-Draft): publishes the set of "upstream providers" each AS legitimately uses, enabling path validation against route-leak attacks (downstream AS announcing transit it should not). Adoption is nascent — ~0.001% of ASes have published an ASPA record as of mid-2025 per MANRS — but ASPA is the most plausible deployment path toward BGP path validation, given BGPsec's stalled state. Cross-link: `cloud_iam_expertise.md` for the analogous "explicit authorization graph" pattern.

---

## IX. PKI and Certificate Infrastructure Attacks

### The Broken CA Trust Model

The web PKI: any of ~150+ root CAs (and 1,000+ intermediate CAs they've delegated to) can issue a certificate for any domain name. Attacker who compromises any single CA can generate valid certs for any HTTPS site — MitM attacks appearing legitimate to browsers.

### Major Compromises

**Comodo (March 2011)**: Attacker (Iranian IP) compromised a Comodo partner account; obtained 9 fraudulent SSL certificates for mail.google.com, www.google.com, login.yahoo.com, login.skype.com, addons.mozilla.org, login.live.com, etc. Revoked within days.

**DigiNotar (June–July 2011)**: Dutch CA trusted by all major browsers and Dutch government.
- First breach: June 17, 2011; attacker pivoted to CA internal network by July 1
- **531 fraudulent certificates** issued before discovery: Google, Microsoft, Skype, Tor, Facebook, Twitter, Yahoo, CIA, Mossad, MI6, *.com, *.org
- ~**300,000 Iranian Gmail users** targeted for MitM using these certificates (Iranian government proxy servers)
- DigiNotar declared bankruptcy September 2011 after browser vendors removed trust
- Lesson: A single compromised CA gives MitM capability against the entire internet for those cert holders

**MD5 Collision Against CA Signing (25C3, December 2008)**: Sotirov, Stevens, Appelbaum, Lenstra et al. demonstrated creating a rogue CA certificate using an MD5 collision. Several CAs were still signing intermediate certs with MD5. Researchers could create a cert browsers would trust as a legitimate CA. Affected CAs moved off MD5 within hours (announced switch to SHA-1).

### Certificate Transparency (RFC 6962 / RFC 9162)

CAs must submit every issued certificate to publicly accessible CT logs before it can be trusted by Chrome/Safari (as of ~2018). Logs are append-only Merkle trees; once submitted, certificates cannot be removed.

**Mechanism**:
1. CA generates certificate; submits to CT log
2. CT log returns **Signed Certificate Timestamp (SCT)** — log's promise to include the cert within the Maximum Merge Delay (MMD, typically 24 hours)
3. SCT embedded in certificate, delivered via TLS extension, or OCSP stapling
4. Browsers verify SCT before displaying HTTPS padlock

**Merkle tree audit proofs**: Verify certificate inclusion in O(log n) steps; verify append-only property (older versions are prefixes of newer).

**Security monitoring uses**:
- `crt.sh`: Search all certificates in CT logs for a domain — critical for subdomain enumeration (SANs reveal subdomains) and unauthorized cert issuance monitoring
- Domain owners can subscribe to CT log streams to detect misissuance
- Tools: Facebook CT Monitoring, Cert Spotter, crt.sh API

### CAA Records (RFC 8659, 2019)

Restrict which CAs may issue certificates for a domain:
```
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issuewild "comodoca.com"    # Wildcard cert issuance separately
example.com. CAA 0 iodef "mailto:security@example.com"
```

**Security caveat**: CAA enforcement occurs at the CA, not the browser. If an attacker has DNS control or the CA is compromised, CAA is bypassed. Provides protection against CAs that follow the rules — no protection against fully malicious or compromised CAs.

### Let's Encrypt and Short-Lived Certificates

Launched 2016; free, automated, open CA. Issues 90-day certificates — short validity acts as practical revocation alternative. **ACME protocol (RFC 8555)**: Programmatic certificate issuance and renewal; standard for automated certificate lifecycle management. ACME **Renewal Information (ARI)** ([RFC 9773](https://datatracker.ietf.org/doc/rfc9773/), 2025) lets the CA signal *when* a client should renew — necessary as lifetimes shorten and CAs need to coordinate emergency mass-rotations (e.g., a CA-key compromise event).

### The 47-Day Certificate Trajectory (CA/Browser Forum Ballot SC-081v3, April 2025)

Apple introduced a draft at the October 2024 CA/B Forum meeting and Sectigo endorsed a [CA/B Forum ballot](https://securityboulevard.com/2025/04/its-official-ca-b-forum-votes-yes-to-47-day-tls-certificates/) reducing maximum TLS-certificate lifetime from 398 days to 47 days. **Ballot SC-081v3 passed April 11, 2025** — 25 CAs and 4 root programs (Apple, Google, Microsoft, Mozilla) in favor; 5 CAs abstained. Phased rollout:

| Date | Max TLS cert lifetime | Max DCV (Domain Control Validation) reuse |
|---|---|---|
| Today | 398 days | 398 days |
| March 15, 2026 | 200 days | 200 days |
| March 15, 2027 | 100 days | 100 days |
| **March 15, 2029** | **47 days** | **10 days** |

**Operational consequence**: any manual renewal workflow is fatal by 2029. ACME automation becomes table-stakes; long-lived certs in IoT, embedded devices, internal CAs, and air-gapped systems become a critical-debt class. Browsers and root programs have not yet committed publicly to the 47-day endpoint for private/internal CAs, but enterprise PKI roadmaps assume parallel pressure ([DigiCert analysis](https://www.digicert.com/blog/tls-certificate-lifetimes-will-officially-reduce-to-47-days)).

Pre-2025 trajectory: the maximum lifetime had already been ratcheted down 39 months → 825 days (2018) → 398 days (2020); Apple's 47-day proposal accelerated what was already a clear direction. Cross-link: `cryptography_expertise.md` for the rotating-key threat model that motivates short-lived certs; `cicd_supply_chain_expertise.md` for the CD-pipeline cert-renewal automation pattern.

### Certificate Transparency Log Operations (2024–2026)

CT log operation has matured into a coordinated tier of infrastructure. The temporally-sharded model (Google "Argon" and "Xenon" series; Cloudflare "Nimbus"; Let's Encrypt "Oak"; DigiCert "Yeti") shards by certificate `Not After` year — each shard accepts certs expiring in one calendar year, then becomes read-only. **Log retirement is now routine**: Argon 2024 stopped accepting submissions December 31, 2024.

Chrome's CT policy (post-2018) requires **two SCTs from distinct log operators** in every publicly trusted cert. Log operator failure modes (extended downtime, MMD violations) result in the log being removed from the "qualified" set — e.g., Certly.IO (2016). The community-run [certificate.transparency.dev/logs](https://certificate.transparency.dev/logs/) page is the canonical operator list; Chromium's [log_list.json](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/certificate_transparency/data/log_list.json) is the source of truth for browser enforcement.

**Operational implication for security teams**: CT log mining (via crt.sh, Facebook CT Monitoring, Cert Spotter) remains the single most reliable subdomain enumeration primitive. Shorter cert lifetimes (post-2029, 47-day) mean every subdomain emits a fresh CT entry every ~5 weeks — CT logs become a near-real-time inventory of internet-facing assets. Detection coverage that misses CT-log monitoring will systematically miss new exposed services.

---

## X. Network Reconnaissance

### Passive Reconnaissance

| Tool | Type | Key Capability |
|------|------|----------------|
| **Shodan** | Search engine | Banner scanning by content, certificate, port; IoT discovery. Founded 2009 John Matherly. |
| **Censys** | Search engine | ZMap-based; 8x more visibility than Shodan across all 65,535 ports; detects new services <24h |
| **crt.sh** | CT log search | All certificates for a domain; SANs = subdomain enumeration |
| **SecurityTrails** | Passive DNS history | Historical DNS record changes; subdomain enumeration |
| **Subfinder** | Subdomain enum | CT logs, passive DNS, API aggregation |
| **Amass** | Asset discovery | OWASP tool; ASN/IP/subdomain mapping via CT, passive DNS, brute force |
| **Farsight DNSDB** | Passive DNS | Billions of DNS records since 2010; Paul Vixie's Farsight Security |

### JARM / JA3 TLS Fingerprinting

- **JA3** (Salesforce): MD5 hash of TLS ClientHello parameters (version, ciphers, extensions, elliptic curves, curve formats). Consistent per client implementation.
- **JA3S**: Server TLS fingerprint
- **JARM**: Active fingerprint of TLS server configuration via 10 specially crafted ClientHello messages. Consistent per server implementation/version — identifies specific versions of BurpSuite proxy, Cobalt Strike C2, Go HTTP server, etc. from their server-side TLS behavior

### DNS Zone Enumeration

- **NSEC walking** (NSEC-signed zones): Follow NSEC chain from first to last name in O(n) queries — reveals entire zone. Tool: `nsec3map`
- **NSEC3 cracking**: Despite SHA-1 hashing, offline dictionary attacks with pre-computed hash tables can reveal zone contents. Hashcat NSEC3 mode; `nsec3map`
- **Certificate Transparency mining**: `crt.sh` for all certificates' SANs — reveals subdomains even if DNS queries are blocked
- **Passive DNS**: SecurityTrails, VirusTotal, Farsight DNSDB — historical resolutions reveal previously active subdomains

---

## XI. Key RFC Reference

| RFC | Title | Year | Security Relevance |
|-----|-------|------|---------------------|
| 1035 | DNS Implementation and Specification | 1987 | DNS wire format, resource records |
| 2308 | Negative Caching (NCACHE) | 1998 | SOA MINIMUM field = negative TTL |
| 2827 | Network Ingress Filtering (BCP38) | 2000 | Anti-spoofing; prevents UDP source spoofing for amplification |
| 4034/4035 | DNSSEC Resource Records / Protocol | 2005 | RRSIG, DS, NSEC mechanics |
| 5011 | Automated DNSSEC Trust Anchor Updates | 2007 | Automatic KSK rollover for validators |
| 5155 | DNSSEC NSEC3 | 2008 | Hashed authenticated denial of existence |
| 5452 | DNS Resilience Against Forged Answers | 2009 | Source port randomization — the Kaminsky fix |
| 6891 | Extension Mechanisms for DNS (EDNS0) | 2013 | OPT RR; 4096-byte UDP; amplification enabler |
| 6962 | Certificate Transparency | 2013 | CT logs (superseded by 9162) |
| 7766 | DNS Transport over TCP | 2016 | TCP DNS mandate |
| 7858 | DNS over TLS (DoT) | 2016 | Port 853 |
| 8484 | DNS over HTTPS (DoH) | 2018 | Port 443; visually indistinguishable from HTTPS |
| 8482 | Minimal Responses to QTYPE=ANY | 2019 | ANY query deprecation — mitigates amplification |
| 8555 | ACME | 2019 | Let's Encrypt certificate lifecycle automation |
| 8659 | DNS CAA Records | 2019 | Certificate Authority Authorization |
| 9156 | DNS QNAME Minimization | 2021 | Privacy: minimum QNAME per delegation step |
| 9162 | Certificate Transparency v2.0 | 2021 | CT v2 (supersedes 6962) |
| 9250 | DNS over Dedicated QUIC Connections | 2022 | DoQ (UDP/853); production deployment 2024-2026 |
| 9276 | NSEC3 Parameter Settings (BCP 236) | 2022 | Recommends 0 iterations |
| 9463 | DHCP/RA Options for Encrypted DNS | 2023 | Enterprise DoH/DoT resolver advertising |
| 9773 | ACME Renewal Information (ARI) | 2025 | CA-driven renewal scheduling for short-lived certs |

---

## XII. Staff-Level Distinguishing Expertise

1. **The Kaminsky attack's true insight was protocol structure, not protocol vulnerability**: The birthday paradox application to DNS cache poisoning wasn't new math — it was recognizing that an attacker can force the resolver to issue thousands of new unique queries, turning a per-query race into a sustained attack. Kaminsky's genius was the non-existent subdomain technique: `random-string.victim.com` is never in cache, so the attack window is unlimited. This is why source port randomization was the correct fix: it increases the number of combinations to brute-force, not the query/response timing.

2. **DNSSEC and the 2018 root KSK rollover was the highest-risk internet-wide operation since Y2K**: The trust anchor for every DNSSEC-validating resolver on Earth was being changed simultaneously. Any resolver that hadn't been updated would fail to validate ALL signed domains. The coordination effort (BIND, Unbound, Windows, resolver operators all upgrading to RFC 5011 automated trust anchor management) was the most carefully managed DNS operational change in history. The delay from October 2017 to October 2018 was specifically due to concerns about validator readiness.

3. **CT logs are now the de facto subdomain enumeration primitive**: Every certificate issued by a CA trusted by Chrome or Safari is logged to a CT log. `crt.sh` returns the SANs of all certs for a domain. This means the security boundary for subdomain discovery shifted from DNS (where zone transfers can be blocked) to certificate issuance. Security teams that don't monitor CT logs for their domains are flying blind on subdomain takeover risk.

4. **DNS rebinding versus SOP**: The same-origin policy in browsers uses *domain name* as the boundary, not IP address. DNS rebinding subverts this by changing what IP address the domain name resolves to after the page loads. The browser doesn't know. The correct architectural defense is not at the DNS level (DNSSEC doesn't help — the attacker controls their own authoritative server and signs correctly) but at the service level: bind internal services to 127.0.0.1, validate Host headers, require CORS preflight for sensitive endpoints.

5. **BGP hijacking is underrated as an attack vector against certificate infrastructure**: The DigiNotar incident was DNS/CA compromise. But BGP hijacking can achieve the same outcome — redirect traffic for `accounts.google.com` at the network layer, intercept ACME HTTP-01 domain validation, obtain a certificate from a co-opted CA. This is why CT monitoring (independent of the TLS handshake path) is the only defense that survives network-layer attacks: you'll see the unauthorized certificate in the CT log within 24 hours.

6. **The Kaminsky Fellowship and the community norm**: Kaminsky spent the 30 days after the July 8, 2008 patch release *actively encouraging ISPs to patch*, rather than staying quiet. His approach — coordinate secretly, patch everyone simultaneously, then give ISPs 30 days to deploy before full disclosure — became the model for large-scale coordinated vulnerability disclosure. This standard is still the framework security vendors reference for coordinated disclosure today.

7. **KeyTrap (2024) is an algorithmic-complexity attack the spec *required*, not a bug**: RFC 4035 §5.3.1 mandates that validators try every key-tag-matching DNSKEY against every available RRSIG. ATHENE's contribution was recognizing this is exploitable: one well-crafted packet creates an O(N×M) signature-verification storm that stalls the validator for minutes-to-hours. The mitigation is not a spec fix — it is a pragmatic cap (e.g., BIND's `max-validation-failures-per-fetch`) every implementation has had to add. **The lesson**: when a security spec demands "validators must try X" without bounding X, the spec itself is a DoS primitive. This pattern recurs across crypto-validation surfaces (XML signature wrapping; PDF nested objects; archive unpacking) — the family name is **algorithmic complexity attack**, and the structural defense is per-operation hard caps in every implementation.

8. **DNSBomb / CAMP (IEEE S&P + USENIX 2024) reframe amplification as a compositional product, not a single primitive**: Legacy mitigation reasoned about *one* amplification step at a time — RRL caps responses-per-source, BCP38 prevents source-spoofing, RFC 8482 deprecates ANY. DNSBomb composes query accumulation × response amplification × pulse concentration to achieve 20,000× BAF and 8.7 Gb/s pulse magnitude. **The staff-level shift**: when reviewing protocol composition (DNS+HTTP, DoH+CDN, recursive+authoritative chains), enumerate the amplification primitives at each hop and reason about their *product*, not their sum.

9. **Sitting Ducks (2024) shows the registrar/DNS separation is a structural primitive, not a misconfiguration**: ~1M domains exploitable; 30K+ confirmed hijacked since 2019; ALL conditions are by-design separations of registrar and DNS-provider responsibility. Eight years after Matthew Bryant's 2016 *Orphaned Internet* paper showed the same primitive, nothing structural had changed. **The takeaway for security teams**: registrar lock and DNSSEC do not protect against takeover via the DNS provider side. The defensive posture is continuous re-validation that NS records at the registrar still point to a zone that actually exists at the provider.

10. **The HTTP/2 attack family (Rapid Reset + CONTINUATION Flood) shows protocol-level DoS surface compounds with deployment scale**: Rapid Reset abuses stream cancellation; CONTINUATION Flood abuses header buffering; both work against every major HTTP/2 implementation simultaneously because the spec under-specified resource bounds. The 398M rps record (Google, October 2023) plus the 5.6 Tbps UDP record (Cloudflare, October 2024) plus Aisuru's 31.4 Tbps (Cloudflare, disclosed January 2026) collectively define a new operational baseline: **autonomous detect-and-mitigate at the scrubbing tier is the only viable defense shape**. The seconds-to-minutes attack duration leaves no time for human-in-the-loop response. Cross-link: `detection_engineering_expertise.md` for the autonomous-defense-tier design pattern.

11. **The 47-day cert trajectory (CA/B Forum SC-081v3, April 2025) is a forcing function on CD pipeline maturity**: By March 2029, every TLS cert must rotate every 47 days; DCV reuse drops to 10 days. Any pipeline that requires a human to renew a cert breaks at 47 days. Any service that pins certs (mTLS in microservice meshes, IoT firmware) needs out-of-band rotation. The ballot was framed as a security improvement (revocation-by-expiration), but its *real* downstream effect is to eliminate the long-tail of unrotated, forgotten, hard-coded certs that historically powered MitM-via-stolen-key attacks. Cross-link: `cryptography_expertise.md` for the key-rotation threat model; `cicd_supply_chain_expertise.md` for the ACME-in-pipeline pattern.

12. **The "where DNS resolution happens" boundary has moved up the stack three times**: kernel resolver → userland resolver → browser DoH client. Each move makes enterprise visibility harder. The CISA 2024 guidance ("agency DNS proxy then encrypted upstream") is the structural response: pull resolution back to a controlled hop before encryption, preserving telemetry and policy. Networks that allow direct application-layer DoH/DoQ to public resolvers have given up DNS-based detection entirely. Cross-link: `detection_engineering_expertise.md`; the analogous boundary shift in TLS happened with ECH (Encrypted Client Hello) and is covered in `cryptography_expertise.md`.
