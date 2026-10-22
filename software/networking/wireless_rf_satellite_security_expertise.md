# Wireless, RF, and Satellite Communications Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

### Mathy Vanhoef — KU Leuven / NYU Abu Dhabi

**Career arc**: PhD at KU Leuven DistriNet (2016); postdoc at KU Leuven, then NYU Abu Dhabi (2018–); now professor at KU Leuven. Sole author or co-author on every major WPA2 → WPA3 attack of the last decade. Wi-Fi Alliance Mission Specialist Award (2021) — an unusual industry acknowledgement of an adversarial researcher.

**Arc**: WPA2 4-way-handshake state-machine pathology → key reinstallation (KRACK, 2017) → WPA3 SAE side-channel and downgrade (Dragonblood, 2019) → fragment/aggregation framing pathology (FragAttacks, 2021).

**Key publications**:
- "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2" (CCS 2017, with Frank Piessens) — KRACK. Replays message 3 of the 4-way handshake; victim re-installs the already-in-use pairwise key with nonce counter reset to 0; breaks AES-CCMP / TKIP / GCMP confidentiality and integrity. ACM CCS Real-World Impact Award.
- "Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd" (S&P 2020, with Eyal Ronen). Five attacks: WPA2-transition-mode and security-group downgrades, timing and cache-based side-channels on SAE's hash-to-curve "hunting and pecking" (enabling offline password partitioning), and DoS via the anti-clogging mechanism.
- "Fragment and Forge" (USENIX Security 2021) — FragAttacks. Twelve CVEs in 802.11 fragment/aggregation logic. A-MSDU-flag-flip injection; mixed-key fragment reassembly; cross-session fragment cache.
- "Framing Frames" (USENIX 2023).

**Tools**: `krackattacks-scripts`, `fragattacks`, `dragonslayer`, `libwifi`. github.com/vanhoefm.

**References**: `https://www.krackattacks.com/`, `https://wpa3.mathyvanhoef.com/`, `https://www.fragattacks.com/`, `https://www.mathyvanhoef.com/p/publications.html`

---

### Daniele Antonioli — EURECOM

**Career arc**: PhD at SUTD (2019); postdoc at EPFL in Mathias Payer's HexHive group; Assistant Professor at EURECOM. The Bluetooth-side counterpart to Vanhoef's Wi-Fi corpus — sole author or co-author on every major Bluetooth-specification protocol attack since 2019.

**Key publications**:
- KNOB (USENIX 2019, CVE-2019-9506) — MITM downgrade of Bluetooth Classic encryption key entropy down to 1 byte via LMP_encryption_key_size_req manipulation; brute-force online in real time. Every certified BR/EDR chipset in scope pre-fix.
- BIAS (S&P 2020, CVE-2020-10135) — lack of mandatory mutual authentication + permissive master/slave role switching + authentication-procedure downgrade impersonates either side of an existing pairing.
- BLURtooth (ASIACCS 2022, CVE-2020-15802) — Cross-Transport Key Derivation lets BR/EDR pairing overwrite BLE keys (and vice versa) without consent.
- BLUFFS (CCS 2023, CVE-2023-24023) — six attacks on session-key derivation breaking both forward and future secrecy; fix requires a Bluetooth Core Spec change.

**Tools**: `knob`, `bias`, `blurtooth`, `bluffs` (github.com/francozappa). InternalBlue (Mantz et al.) is the de facto Broadcom-firmware patching framework used to mount these on commodity hardware.

**References**: `https://knobattack.com/`, `https://francozappa.github.io/publication/`, `https://dl.acm.org/doi/pdf/10.1145/3576915.3623066`

---

### Karsten Nohl — SRLabs

**Career arc**: PhD University of Virginia (2008, RFID / Crypto-1). Founded Security Research Labs (Berlin) in 2010; handed the SRLabs CEO role to Wolf Richter in 2025 and became Allurity's Chief Innovation Officer. Two-decade arc across RFID, GSM/3G/4G/5G, SS7, SIM cards, payments. CCC regular — most canonical European cellular results first surfaced at 24C3 → 36C3.

**Key disclosures**:
- 24C3 (2007, with Henryk Plotz): MIFARE Classic Crypto-1 reverse engineering by silicon de-layering and microscopy. Weak RNG + structural cipher weaknesses.
- 26C3 (2009): "GSM SRSLY?" — open A5/1 rainbow-table project; 2 TB of pre-computed tables released publicly.
- 31C3 (2014): "Mobile self-defense" — SS7-based call and SMS interception; released SnoopSnitch. (SS7 location tracking was Tobias Engel's companion 31C3 talk.) Catalyzed `60 Minutes` Australia and US Congressional response.
- 2019: Simjacker (AdaptiveMobile) / WIBattack (Ginno Security Lab), with SRLabs follow-up research — SIM Toolkit `S@T Browser` / `WIB` applets execute attacker SMS commands silently regardless of phone OS. ~1B phones across 30+ countries.

**Tools**: SnoopSnitch (Android IMSI-catcher / SS7-attack detection, Qualcomm-baseband, root required); `gnuradio-gsm`.

**References**: `https://www.srlabs.de/`, `https://media.frag-den-staat.de/files/foi/580223/Mifare.Cryptanalysis.pdf`

---

### Travis Goodspeed — Independent

**Career arc**: Independent (Tennessee). Created the GoodFET tool family. Long-time Dartmouth collaborator (Sergey Bratus). See `firmware_embedded_security.md` §I for full bio.

**RF work**:
- KillerBee (Joshua Wright, 2009–): canonical 802.15.4 / Zigbee toolkit. `zbid`, `zbdump`, `zbreplay`, `zbstumbler`, `zbgoodfind` (offline key-search via known-plaintext crib against captured ciphertext to recover network key from RAM dumps).
- "Promiscuity is the nRF24L01+'s Duty" (blog post, 2011) — abuses an undocumented Nordic nRF24L01+ mode to disable the hardware address filter for promiscuous sniffing. Direct ancestor of MouseJack.
- "Packets in Packets" (WOOT 2011, with Bratus et al.) — PHY-layer preamble patterns embedded in payload of one frame are interpreted as start-of-frame by desynchronized receivers; frame injection without transmitting.

**References**: `http://travisgoodspeed.blogspot.com/`, `https://github.com/riverloopsec/killerbee`

---

### Michael Ossmann — Great Scott Gadgets

**Career arc**: Founder of Great Scott Gadgets (Evergreen, CO). Hardware engineer who democratized SDR and Bluetooth research for two generations.

**Tools (all open-source hardware)**:
- **Ubertooth One** (2011): first practical open-source Bluetooth Classic sniffer. CC2400 + LPC microcontroller, USB. Hops with the piconet. One piconet at a time. Mike Ryan's `crackle` and BLE work built on it.
- **HackRF One** (2013 Kickstarter): 1 MHz – 6 GHz half-duplex SDR transceiver, 20 MSPS, 8-bit ADC. Most-deployed open SDR. ~$300 price + frequency range + open docs made it the standard platform for ~a decade.
- **YARDStick One**: sub-GHz half-duplex CC1111-based transceiver.
- **GreatFET One**: USB + GPIO multi-tool with daughterboard library; host for Goodspeed's Facedancer line.

**Educational impact**: Ossmann's "Software Defined Radio with HackRF" video course (free online) is the de facto entry-level SDR curriculum.

**References**: `https://greatscottgadgets.com/`, `https://greatscottgadgets.com/sdr/`

---

### Samy Kamkar — Independent / Openpath

**Career arc**: Self-taught, public figure since the Samy worm (2005, MySpace XSS). Broad RF / automotive portfolio.

**RF work (DEF CON 23, 2015)**:
- **OpenSesame**: brute-forces all 12-bit fixed-code garage-door codes in ~8 seconds via de-Bruijn-sequence overlap (down from ~29 minutes naive).
- **RollJam**: canonical replay-and-jam against rolling-code KeeLoq/HCS fobs. Jam the receiver's window so the user's first press appears to fail; capture; user re-presses; jam again and capture the second code while replaying the first. Attacker now holds an unused valid rolling code. ~$30 in parts.
- **KeySweeper**: mass-deployable Microsoft wireless keyboard sniffer disguised as a USB wall charger.

**References**: `https://samy.pl/`, `https://www.youtube.com/watch?v=UNgvShN4USU`

---

### Mike Ryan — ICE9 Consulting

**Career arc**: iSEC Partners; founded ICE9 Consulting in 2016. The BLE sniffer ecosystem largely traces back to his Ubertooth BLE work and `crackle`.

**Key work**:
- "Bluetooth: With Low Energy comes Low Security" (WOOT 2013) — first practical attack on BLE Legacy Pairing. Just Works TK = 0 (trivial); Passkey Entry TK is a 6-digit PIN (10^6 brute force). Once TK is recovered, the LTK derives.
- **crackle**: production tool implementing the WOOT 2013 attack. PCAP in, plaintext out. Still the standard tool 12+ years later.
- **ICE9 Bluetooth Sniffer**: SDR-based BLE sniffer that — uniquely among open tools — can sniff already-established connections (no connection-request capture required).
- CVE-2014-4428 (Apple Bluetooth stack, iOS/OS X/Apple TV).

**References**: `https://lacklustre.net/`, `https://www.usenix.org/system/files/conference/woot13/woot13-ryan.pdf`, `https://github.com/mikeryan/crackle`

---

### Todd Humphreys — UT Austin Radionavigation Lab

**Career arc**: Professor at UT Austin Aerospace Engineering; Director of the UT Radionavigation Laboratory. Single most-cited academic on civilian GPS spoofing.

**Key work**:
- 2012 White Sands drone spoof: first openly-acknowledged civilian-UAV spoof. UT team coaxed a DHS drone off course via counterfeit civilian GPS signals stronger than the real ones.
- 2013 superyacht spoof: $80M "White Rose of Drachs" in the Mediterranean. Bhatti and Pesyna broadcast counterfeit signals from a portable spoofer. The yacht's GPS reported drift; crew corrected; each correction set actual heading slightly off. Result: a parallel track hundreds of meters off the planned route, no alarms — slow spoofs are operationally undetectable to legitimate operators.
- 2012 Congressional testimony (House Homeland Security Subcommittee on Oversight, Investigations, and Management) — civilian-GPS-spoofing threat to maritime, smart-grid timing, financial-system clocks.
- Continuing PNT-resilience work: chip-scale atomic clocks, multi-constellation cross-check, spoofing detection via RSS / clock-bias inconsistency.

**References**: `https://radionavlab.ae.utexas.edu/`, `https://news.utexas.edu/2013/07/29/ut-austin-researchers-successfully-spoof-an-80-million-yacht-at-sea/`

---

### James Pavur — University of Oxford

**Career arc**: DPhil at Oxford as a Rhodes Scholar (CYSEC Lab). The 2020 satellite-eavesdropping research canonicalized that GEO satellite IP traffic is still largely unencrypted on the downlink and trivially eavesdroppable with a TV-grade Ku-band dish.

**Key publications**:
- "A Tale of Sea and Sky: On the Security of Maritime VSAT Communications" (S&P 2020).
- "Whispers Among the Stars: Perpetrating and Preventing Satellite Eavesdropping Attacks" (Black Hat 2020). With ~$300 of gear (Selfsat dish + TBS-6983 PCIe DVB-S2 receiver + EBSPro decoder), captured 4 TB of GEO downlink across 18 satellites. Targets included in-flight aircraft passenger WiFi. The headline: broadcast downlink + absent link-layer encryption + continent-scale footprint = continent-scale passive collection for $300. Built `GSE Extract` to reconstruct GSE frames from low-quality DVB-S2 recordings.

**References**: `https://www.cs.ox.ac.uk/people/james.pavur/`, `https://i.blackhat.com/USA-20/Wednesday/us-20-Pavur-Whispers-Among-The-Stars-Perpetrating-And-Preventing-Satellite-Eavesdropping-Attacks.pdf`

---

### Lennert Wouters — KU Leuven COSIC

**Career arc**: PhD at KU Leuven COSIC. Hardware-attack specialist; fault-injection attacks on commercial products that move quickly from academic disclosure to Black Hat demonstration.

**Key work**:
- TCHES 2019 — Tesla Model S DST-40 cipher cryptanalysis; full key-fob clone-from-RF.
- 2020 — Tesla Model X key: Bluetooth firmware-update vuln pushes arbitrary firmware to a key fob with no auth.
- "Glitched On Earth By Humans" (Black Hat 2022) — voltage fault injection during the Starlink dish's SoC ROM bootloader bypasses firmware-signature verification. Modchip (RP2040 + MOSFET crowbarring the power rail at signature-check time) costs ~$25. Reported through SpaceX bug bounty. Unfixable for shipped units (exploits ROM bootloader); newer SoC revisions added checks.

**References**: `https://homes.esat.kuleuven.be/~lwouters/`, `https://i.blackhat.com/USA-22/Wednesday/US-22-Wouters-Glitched-On-Earth.pdf`

---

### Adam Laurie ("Major Malfunction") — Aperture Labs

**Career arc**: Senior staff at DEF CON since 1997. Director of Aperture Labs. Canonical RFID researcher since the early 2000s. His BlueSnarf (2003) was among the first public Bluetooth security flaws; Martin Herfurt's BlueBug followed in 2004.

**Tools**:
- **RFIDIOt**: open-source Python library for RFID exploration. LF + HF readers (serial + PC/SC). Ships with Kali. Utilities for ePassport BAC, HID iCLASS analysis, MIFARE Classic key recovery.
- Long-running "RFIDIOts!!!" DEF CON / Black Hat series (2006–); ePassport reading-at-distance; satellite TV CAM cloning; GSM IMSI capture; EMV.

**References**: `http://adamsblog.rfidiot.org/`, `https://github.com/AdamLaurie`

---

### Marc Newlin — Bastille Networks / SkySafe / Independent

**Career arc**: Bastille Networks (2014–2018) → SkySafe → independent. Two canonical sub-GHz HID disclosures: MouseJack (2016), KeySniffer (2016). Both exploited Nordic `nRF24L`-family transceivers ubiquitous in wireless mice/keyboards.

**Key work**:
- **MouseJack** (2016): non-Bluetooth wireless HID devices fail to authenticate received packets. $15 nRF24L USB dongle + Bastille research firmware injects keystrokes into a victim's USB receiver from up to 100 m. The receiver believes the attacker is the paired mouse, but the attacker types keyboard commands. Logitech Unifying (patched, slowly), Dell, Lenovo, HP, Microsoft.
- **KeySniffer** (2016): wireless keyboards from HP, Toshiba, Kensington, Anker, GE etc transmit keystrokes unencrypted or with trivially-broken encryption.

**References**: `https://bastille.net/research/vulnerabilities-mousejack/`

---

### Ruben Santamarta — IOActive

**Career arc**: Principal Security Consultant at IOActive. Inside-the-terminal SATCOM research (firmware RE, command injection, hardcoded credentials) — complementary to Pavur's outside-on-the-downlink work.

**Key publications**:
- "SATCOM Terminals: Hacking by Air, Sea, and Land" (Black Hat 2014) — first systematic firmware analysis of Cobham, Harris, Hughes, Iridium, JRC, Thuraya. Identified hardcoded credentials, undocumented protocols, weak auth, backdoors, insecure firmware updates. Affected Cobham AVIATOR 700 in-flight terminals, maritime VSAT, and military-deployed terminals.
- "Last Call for SATCOM Security" (Black Hat 2018) — four-year follow-up. Hundreds of in-flight aircraft, military installations, maritime vessels reachable from the public Internet via SATCOM web interfaces. First public on-aircraft demonstration of remotely accessing the satellite data unit. Santamarta is careful to distinguish "reaching the SATCOM terminal" (demonstrable) from "reaching the avionics bus" (not demonstrated; air gap appears robust).

**References**: `https://blackhat.com/docs/us-14/materials/us-14-Santamarta-SATCOM-Terminals-Hacking-By-Air-Sea-And-Land-WP.pdf`

---

### Supporting Researchers

**Erik Tews** (TU Darmstadt → University of Twente): PTW attack (2007, with Pyshkin and Weinmann) broke 104-bit WEP in under 60 seconds — the algorithm aircrack-ng uses. Tews-Beck (2008) — first cryptanalytic attack on WPA-TKIP, MIC key recovery in 12–15 min on QoS-extended TKIP; implemented in tkiptun-ng.

**Stubblefield-Ioannidis-Rubin** (AT&T Labs, 2001): first public implementation of FMS against real WEP networks; established FMS as a practical threat.

**Roger Piqueras Jover** (AT&T Security Research → Bloomberg → Google Android Connectivity Security): canonical cellular protocol-exploit researcher. LTE pre-authentication abuse, IMSI catcher mechanics, 5G specification review.

**Stefan Viehbock** (December 2011): WPS PIN halves-checked-independently flaw reduces the 10^8 PIN space to 10^4 + 10^3. Reaver (Craig Heffner) and Bully became the de facto tools.

**Jens Steube ("atom", Hashcat)**: 2018 PMKID attack on WPA2-PSK. Many APs return a PMKID in the first RSN-IE message — derivable from PSK, AP-MAC, STA-MAC. No 4-way handshake capture required.

**Dominique Bongard** (Hack.lu 2014): offline WPS PIN brute force against routers with broken M3/M5 RNG.

**Armis (Ben Seri, Gregory Vishnepolsky)**: BlueBorne (Sept 2017) — eight Bluetooth-stack RCEs across Linux (CVE-2017-1000251), Android (CVE-2017-0781/0782/0785), Windows, iOS (CVE-2017-14315). No pairing required, no discoverable mode required. 5.3B exposed devices at disclosure. Canonicalized that Bluetooth-stack code is one of the highest-impact wireless attack surfaces.

**Pen Test Partners** (UK; Ken Munro et al.): long-running maritime / aviation SATCOM terminal disclosures (Cobham Fleet One, Inmarsat). Pen-test angle complementing Santamarta's RE work.

---

## II. The Wireless Threat Model

### "Within Range" Is the Trust Model

Wired protocols admit a clean threat model: attacker has physical access to the wire, or doesn't. Wireless collapses that. Any receiver within signal range can passively capture; any transmitter within range can actively inject. The trust boundary is no longer the building wall — it is the wavefront.

The economic consequence is asymmetric. The defender pays for an AP that radiates omnidirectionally out to ~50 m at 2.4 GHz. The attacker uses a $50 yagi or $200 parabolic dish, extending reception to ~5 km from outdoors — turning "the office building" into "the office building plus a 5-km radius public reception zone." Same asymmetry up the spectrum: BLE's ~10 m becomes ~1 km; cellular's ~5 km cell becomes ~50 km on a hill; satellite downlink is continent-scale.

### Range Ladder

| Protocol | Nominal range | Practical receive range with antenna gain | Practical inject range |
|----------|--------------|------------------------------------------|----------------------|
| RFID LF (125 kHz) | ~10 cm | ~1 m | ~1 m |
| RFID HF / NFC (13.56 MHz) | ~5 cm | ~30 cm | ~10 cm |
| RFID UHF (860–960 MHz) | ~5 m | ~50 m | ~5 m |
| BLE | ~10 m | ~1 km | ~100 m |
| Bluetooth Classic | ~10 m | ~100 m | ~30 m |
| Zigbee / 802.15.4 | ~30 m | ~500 m | ~100 m |
| Wi-Fi 2.4 GHz | ~50 m | ~5 km (parabolic) | ~1 km |
| Wi-Fi 5 GHz | ~30 m | ~2 km | ~500 m |
| Sub-GHz ISM (433/868/915 MHz) | ~100 m | ~5 km | ~1 km |
| Cellular | ~5 km | ~50 km | ~5 km |
| Satellite (downlink, GEO) | continent-scale | continent-scale | requires uplink licensing |
| Satellite (downlink, LEO) | regional | regional | requires uplink licensing |

The injection-range column is shorter than receive because injection requires reliable two-way handshake or beat-the-legitimate-signal timing, which is sensitive to noise and path loss.

### The SDR Revolution

Until ~2010, arbitrary RF transmission cost professional — Ettus USRP at $1,500–$5,000. HackRF One (2014, $300) collapsed that floor. RTL-SDR (~$30, RX-only) collapsed it further for monitoring. As of 2026:

- $30 (RTL-SDR): 24 MHz – 1.7 GHz passive surveillance for anyone with a USB port.
- $300 (HackRF One): half-duplex 1 MHz – 6 GHz TX/RX. Demodulates every consumer protocol; prototypes protocol attacks against most ISM-band, BLE, Zigbee, sub-GHz, pager systems.
- $1,000 (bladeRF 2.0, LimeSDR-USB): full-duplex with better dynamic range and instantaneous bandwidth; enables cellular and Wi-Fi protocol-stack research.
- $5,000+ (USRP X310): research-grade phase coherence; MIMO and AoA work.

Skill barrier dropped in parallel. GNU Radio + the open SDR receiver and decoder library (rtl_433, gr-iridium, gr-gsm, gr-lte) means the "first cut" at a new RF protocol — capture, demodulate, extract framing — is approachable by a determined undergraduate with $30 of hardware.

### Spectrum Is Shared

Most of the wireless attack surface lives in shared/unlicensed bands: 2.4 GHz ISM (Wi-Fi, BLE, Zigbee, microwave ovens, ZigBee, baby monitors), 5 GHz UNII (Wi-Fi), 433/868/915 MHz ISM (key fobs, weather stations, smart-meter telemetry), 13.56 MHz (NFC). Multiple coexisting protocols, no central arbitration, no "rogue device" detector. This is what enables both reception (any in-band signal is observable) and injection (any in-band transmitter is permitted by the FCC up to power limits) — and what makes detection of malicious RF activity genuinely hard in practice.

See `firmware_embedded_security.md` for the hardware-side companion (RF transceiver firmware, baseband processor security). See `mobile_security_expertise.md` §11 for baseband stack internals. See `cryptography_expertise.md` for the underlying authenticated-encryption primitives and key-exchange protocols the wireless layers wrap.

---

## III. Wi-Fi Security

### WEP — Broken by 2001

WEP was the 802.11-1999 link-layer encryption: RC4 with a 64-bit or 128-bit key, 24 bits of which were the per-packet IV, broadcast in the clear.

**FMS (Fluhrer-Mantin-Shamir, 2001)**: certain weak IVs `(3, 255, v)` leak RC4 keystream's relationship with the long-term key. ~4–6M weak-IV packets recovers 128-bit key.

**Stubblefield-Ioannidis-Rubin (2001)**: first practical FMS implementation against real networks.

**KoreK (2004)**: 17 additional IV-byte/key-byte correlations; ~10x fewer packets needed.

**PTW (Tews-Weinmann-Pyshkin, 2007)**: per-byte ranking algorithm using Klein's RC4 analysis. Recovers 104-bit WEP in <60 seconds with ~40,000 packets. The algorithm aircrack-ng ships.

**ARP-replay (2005)**: most WEP networks are quiet. Capture one ARP request, replay at ~500 pkt/s, harvest unique-IV ARP replies. ~10 minutes to PTW-recover.

Operationally: WEP cannot be securely deployed. Any AP still offering WEP is itself a finding.

### WPA1 / WPA-TKIP — Broken 2008

WPA1 retrofitted WEP hardware with TKIP — Michael MIC + per-packet keys derived from a master key + counter. Intended as a stopgap before WPA2/AES hardware.

**Tews-Beck (2008)**: first cryptanalytic attack on TKIP. On QoS-extended (802.11e) TKIP networks, combines `chopchop`-style byte-by-byte decryption oracle with QoS-class replay-counter separation. Recovers MIC key in 12–15 min, injects up to 7 forged packets per rekey interval. `tkiptun-ng`. **Ohigashi-Morii (2009)** extends to non-QoS networks, ~1 min on ARP.

Disable WPA-TKIP entirely. "WPA/WPA2 mixed mode" allows TKIP for backward compatibility — exposes the network even when WPA2-AES is preferred.

### WPA2 — Long-Standing Baseline

WPA2 (802.11i, 2004): AES-CCMP. Two shapes:
- **WPA2-PSK**: passphrase used as PMK via PBKDF2-HMAC-SHA1(passphrase, SSID). PMK → PTK via the 4-way handshake.
- **WPA2-Enterprise (802.1X)**: per-user PMK from EAP exchange (PEAP/TTLS/TLS) against backend RADIUS.

**Offline dictionary attack (WPA2-PSK)**: capture 4-way handshake (ANonce, SNonce, MACs, MIC). Offline-test candidates: PMK = PBKDF2(candidate, SSID); PTK = PRF(PMK, ANonces, MACs); verify MIC. ~2.5M candidates/sec on a single RTX 4090 (hashcat `-m 2500`). Defense: ≥12 random chars or Diceware-style passphrase.

**KRACK (2017)**: target message 3 of the 4-way handshake. Block message 4, replay message 3; station re-installs the same pairwise key with nonce counter reset to 0. Nonce reuse breaks AES-CCMP and TKIP confidentiality/integrity; against GCMP (WiGig/802.11ad), also enables forgery. 10 CVEs. wpa_supplicant 2.4+ Linux variant was worst — code path installed an all-zero key on second handshake, enabling trivial decryption.

**PMKID attack (Steube, 2018)**: the standard 2026 attack on WPA2-PSK. AP includes PMKID in first RSN-IE of EAPOL. PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP-MAC || STA-MAC). Single association request → PMKID; offline brute-force candidate PMKs. `hashcat -m 22000`. Removes the "must have a client connecting" precondition.

**FragAttacks (Vanhoef, 2021)**: 12 CVEs in 802.11 frame-aggregation / fragmentation logic. Three classes:
- A-MSDU flag inside the encrypted frame body is trusted; predict the encrypted payload, flip the A-MSDU flag, inject arbitrary frames.
- Mixed-key fragment reassembly: fragments encrypted under different pairwise keys get reassembled together — inject fragments under attacker's key.
- Fragment cache not cleared at disconnect: prior session fragments combine with attacker's later session.

### WPA3 — Modern Baseline

WPA3 (2018) addresses WPA2's two main weaknesses: offline-dictionary-attackable PSK exchange, and lack of forward secrecy.

**SAE (Simultaneous Authentication of Equals)**: PAKE replaces the password-derived key. Both sides commit to a password-derived candidate via hash-to-curve, then engage in a DH-style exchange yielding a fresh shared secret. Passive observers cannot offline-test passwords — each guess requires a new online exchange with the AP. With AP-side rate-limiting (1 SAE attempt per N seconds per client MAC), offline cracking becomes network-bound and observable.

**Forward Secrecy**: every SAE-derived PMK is fresh. Compromise of the password does NOT decrypt past sessions (which it does in WPA2-PSK).

**PMF (Protected Management Frames, 802.11w)**: WPA3 mandates 802.11w; WPA2 left it optional. PMF auth+encrypts deauth/disassoc/action frames via IGTK. Mitigates the deauth-flood DoS that has been a wireless staple since 2003.

**Dragonblood (Vanhoef-Ronen, 2019)**: SAE's early "hunting and pecking" hash-to-curve loop iterates a password-dependent number of times. Timing and cache side-channels leak info about the password. Combined with a downgrade window in WPA2/WPA3 transition mode, online password recovery is feasible at scale. Fix: constant-time Simplified SWU hash-to-curve, mandatory in newer deployments. Tool: `dragonslayer`.

### Deployment Hardening

WPA2/3-PSK deployment baseline:
- Passphrase ≥12 random chars or Diceware ≥6 words. Shorter is GPU-crackable from captured handshake or PMKID in hours.
- Disable WPS entirely. Viehbock 2011 PIN-halves flaw → ~4h brute force with `reaver` or `bully`; Bongard 2014 offline PIN recovery from broken-RNG implementations (`pixiewps`) is single-shot. WPS-PIN is dead in 2026.
- Disable WPA2-TKIP / WPA1 / WEP. Allow only WPA2-CCMP + WPA3-SAE.
- Enable 802.11w PMF (mandatory under WPA3, recommended under WPA2-Enterprise).
- Per-Station-PSK (Aerohive / Cisco / Ruckus) so PSK compromise on one device doesn't burn the network.

**WPA2/3-Enterprise (802.1X)** pitfall: client devices that don't validate the RADIUS server's TLS cert are subject to rogue-RADIUS attacks (`eaphammer`, `hostapd-wpe`). Rogue AP proxies to rogue RADIUS; client accepts unvalidated cert; sends MS-CHAPv2 hashes; offline-cracked via `asleap` / John (`netntlmv1` mode). Mandate: validate cert against explicit CA bundle AND match CN/SAN to specific value. Enforce via Intune / Jamf / GPO. **EAP-TLS** is the gold standard — mutual cert auth; PKI cost is the price.

### Evil Twin / Karma

**Evil Twin**: rogue AP with same SSID and higher signal. Victim associates; attacker harvests plaintext (if "open") or captures handshake/PMKID for offline crack (if "WPA2").

**Karma**: attacker auto-responds to all probe requests ("Yes, I am `HomeNetwork`"). Hak.5 Pineapple staple. Modern OSes (iOS 14+, Android 10+) randomize MACs and limit probes, but legacy/IoT devices remain vulnerable.

**Mitigation**: clients should validate the AP identity. Under WPA2-Enterprise, via 802.1X cert validation. Under WPA3-SAE, the SAE PAKE itself authenticates the AP — a rogue AP without the password cannot complete SAE.

---

## IV. Bluetooth and BLE

### Bluetooth Architecture: Classic vs Low Energy

**Bluetooth Classic (BR/EDR)**: 1 Mbps (1.0, 1999) and EDR up to 3 Mbps (2.0+, 2004). 79 1-MHz channels at 2.4 GHz, 1600 hops/sec. Audio (A2DP/HFP), HID, OBEX, PAN.

**Bluetooth Low Energy (BLE)**: introduced Bluetooth 4.0 (2010). 40 2-MHz channels; three advertising channels (37, 38, 39). Low duty cycle. HID, beacons (iBeacon/Eddystone), AirDrop discovery, phone-as-a-key, AirTag/Tile.

Two stacks share the radio but are otherwise separate protocols. Modern devices implement both ("dual mode"). Cross-Transport Key Derivation (CTKD), added in 4.2, lets keys established on one transport derive for the other — what BLURtooth attacks.

### Pairing Modes

Bluetooth Secure Simple Pairing (SSP, since 2.1) defines four association models:

1. **Just Works**: no user interaction; TK = 0; no MITM protection. Effectively unauthenticated; MITM during pairing wins.
2. **Numeric Comparison**: both display 6-digit code, user verifies they match. MITM-resistant.
3. **Passkey Entry**: one device displays a 6-digit code, user types into the other. MITM-resistant.
4. **OOB**: pairing material delivered via another channel (NFC tap, QR). Best when OOB channel is secure.

ECDH (P-192 in 2.1, P-256 since 4.1 for BR/EDR and 4.2 for LE) establishes a shared secret. The LTK (BLE) / Link Key (Classic) derives from that + the pairing model's verification step.

### KNOB / BIAS / BLURtooth / BLUFFS (Antonioli)

- **KNOB** (CVE-2019-9506, USENIX 2019): MITM downgrades BR/EDR key entropy via `LMP_encryption_key_size_req` rewrites. Each side thinks the other requested 1-byte entropy; the resulting key has ~256 effective values; brute force in ms. Fix: enforce ≥7-byte minimum. Most major chipsets now do.
- **BIAS** (CVE-2020-10135, S&P 2020): structural flaws combined — master/slave role-switchable after pairing, no mandatory mutual authentication, and an authentication-procedure downgrade. Attacker takes master role (target authenticates against attacker); role-switches to slave (no further auth required). Fix: mandate Secure Connections (4.1+); many IoT devices still don't.
- **BLURtooth** (CVE-2020-15802, ASIACCS 2022): CTKD lets a fresh pairing on one transport overwrite the other transport's keys *without user consent*. Attacker pairs Just-Works BLE against a target, then derives Classic keys without going through Classic pairing. Fix: only allow CTKD if the new pairing is at least as authenticated.
- **BLUFFS** (CVE-2023-24023, CCS 2023): BR/EDR session-key derivation uses a deterministic function of link key + attacker-influenceable nonces. Link Key compromise breaks both forward and future secrecy. Fix requires Core Spec changes; rollout is slow.

### BLE Pairing

BLE Legacy Pairing (4.0–4.1) is broken: Just Works has TK = 0, Passkey Entry has 10^6 brute-forceable TK. Mike Ryan's `crackle` operationalizes (Section I bio). BLE Secure Connections (4.2+, P-256 ECDH) is largely sound when implemented correctly; many embedded devices still ship with Legacy Pairing for compatibility.

**Operational rule**: any BLE pairing that uses Just Works is unauthenticated. Treat anything exchanged after as if it were over the open Internet.

### MouseJack and BlueBorne

**MouseJack (Newlin/Bastille, 2016)** — see Newlin bio. Affects Logitech Unifying (CVE-2016-10761 et al.), Dell, Lenovo, HP, Microsoft. Some unpatched in 2026 because firmware updates are user-initiated and rarely applied.

**BlueBorne (Armis, 2017)** — see supporting researchers. Eight RCEs across Linux (CVE-2017-1000251 — kernel stack BO in L2CAP), Android (CVE-2017-0781/0782/0785), Windows (PAN MITM), iOS (CVE-2017-14315 — Apple Low Energy Audio Protocol). No pairing required. ~5.3B devices at disclosure.

**Continued stream**:
- **BleedingTooth** (Andy Nguyen, Google, 2020) — Linux BlueZ RCE (CVE-2020-12351).
- **BrakTooth** (USENIX 2022, Garbelini et al.) — 16 vulns across 13 chipsets (Intel, Qualcomm, TI, Cypress, Silicon Labs) from a single fuzzer.
- **SweynTooth** (2020), **BlueFrag** (Android, CVE-2020-0022).

Bluetooth stack code is large, C, parses attacker-controlled framing, and runs in a privileged context. Expect continued disclosure rate.

### AirDrop / AWDL

Apple Wireless Direct Link underlying AirDrop / AirPlay / Sidecar. See `mobile_security_expertise.md` §11. Ian Beer's 2020 0-click iOS RCE chain through AWDL is the canonical wireless 0-click vuln of the modern era. Treat AWDL as Wi-Fi-Direct with all the parsing risks of 802.11 management frames.

### Passive Tracking

BLE advertising is in the clear. Pre-iOS 7 / Android 6, persistent MAC addresses enabled cross-venue tracking. Modern OSes rotate MACs (iOS ~15 min) but advertising payloads can still leak fingerprintable data. Apple AirTag / Find My demonstrates the dual-edge — anti-theft also enables stalking. Apple, Google, and the IETF (`draft-detecting-unwanted-location-trackers`) ship interoperable unwanted-tracker detection (2023+).

---

## V. Zigbee, Z-Wave, Thread, and Matter

### Zigbee (IEEE 802.15.4 + ZigBee Alliance app layer)

2.4 GHz, 16 channels, OQPSK 250 kbps. Mesh-routing app layer on 802.15.4 PHY/MAC. Industrial lighting (Philips Hue, Cree, Sengled), sensor networks, home automation. AES-128-CCM*; network key shared by all network devices; per-pair transport keys.

**Common attacks**:
- **Default Trust Center link key** (`"ZigBeeAlliance09"` ASCII): many vendors ship with the hardcoded ZigBee Alliance Trust Center Link Key — devices joining use it in cleartext.
- **Key transport over insecure preauth**: legacy profiles transport network keys during preauth; sniffable. Cognosec Black Hat 2015 Philips Hue takeover.
- Nonce reuse / counter weakness in low-cost implementations.

### Z-Wave (Sigma Designs / Silicon Labs)

908.42 MHz (US) / 868.42 MHz (EU). Star-mesh. Mostly residential locks / thermostats / sensors. S0 (legacy, 2013) used AES-128 but the inclusion handshake encrypted the network key under a hardcoded all-zero Temporary Key — sniffer-in-the-room captures. S2 (2016+) uses ECDH, mandatory for Z-Wave Plus since 2017. Pre-S2 inclusion sniffing remains the dominant attack against legacy networks.

### Thread

IEEE 802.15.4 PHY/MAC + IPv6 (6LoWPAN). Designed by Nest/Google (Thread Group, 2014). AES-128 link-layer + mandatory J-PAKE commissioning. A single network-wide MAC-layer key (as in Zigbee), distributed to joiners via the PAKE. Remaining attack surface: the border router (gateway between Thread and Wi-Fi/Ethernet) and weak commissioning passwords.

### Matter (Connectivity Standards Alliance)

Application-layer over Thread, Wi-Fi, or Ethernet. Formalized 2022. Unifies the fragmented smart-home protocol landscape. Device Attestation Certificates (DAC) under CSA-rooted PKI. Each commissioning establishes a fresh ECDH-derived session key via per-device PASE (PAKE). End-to-end encryption commissioner-to-device.

**Early attack surface**: vendor PKI compromise burns all that vendor's devices; 8-digit commissioning passcode offline-bruteforceable from a captured exchange if PASE is misimplemented; commissioner-side bugs (Apple Home, Google Home) under-researched in 2026. Structurally the best of the consumer-IoT protocols but young.

### IoT Maturity Reality

Common failure modes across Zigbee, Z-Wave, Thread, Matter, and proprietary protocols (LoRa, Sigfox, EnOcean, KNX, BACnet):

- Hardcoded defaults (admin passwords, network keys, TLS certs).
- Unsigned firmware updates over HTTP; no rollback prevention.
- Pre-association cleartext exposure during onboarding.
- Replay protection broken: timestamps without clock sync, counters reset on power cycle, out-of-order packets accepted.
- 20-year deployed lifetime + no patching path.

Defensive recommendation: VLAN segmentation with no path to corporate, monitored egress. See `firmware_embedded_security.md` for the firmware-side companion.

---

## VI. Cellular Beyond Baseband

This section covers cellular protocol-layer attacks: SS7, IMSI catchers, AKA pathology, 5G specification issues. For baseband-stack-internal memory-corruption bugs (the Beer/Project Zero / Bluefrag class), see `mobile_security_expertise.md` §11.

### 2G / 3G / 4G / 5G

**2G GSM**: A5/1 (Europe/US, 64-bit), A5/2 (export-weakened, broken in ms, 2003), A5/3 (KASUMI, no practical break), A5/4. Nohl's 2010 open rainbow-table project (2 TB) decrypts A5/1 in real time. Operationally: GSM A5/1 captured via HackRF + `gr-gsm` is decryptable in seconds. IMSI catchers actively force devices onto 2G to enable interception.

**3G UMTS AKA**: mutual authentication via long-term key Ki on the SIM and HLR/HSS. SIM verifies network MAC + sequence number. Broke the easy "IMSI-catcher impersonates network" attack. But pre-authentication messages (identity request/response, initial signaling) remain cleartext — IMSI catchers still extract IMSI via unprotected Identity Request before AKA.

**4G LTE**: EPS-AKA adds integrity on NAS/AS RRC. Pre-auth weaknesses persist (TMSI/GUTI not cryptographically bound to IMSI). Downgrade-to-2G/3G via RF interference + selective signaling remains practical.

**5G — SUPI vs SUCI**: permanent identifier SUPI (formerly IMSI) is encrypted with the home network's public key before transmission; encrypted form is SUCI. Kills classic IMSI catcher on properly-deployed 5G SA. Caveats:
- **5G NSA**: 5G NR radio over 4G core — uses 4G's IMSI-in-cleartext initial registration.
- **Fallback to 4G/3G**: when 5G is unavailable/jammed, phone falls back, exposing lower-security stack. Dominant practical attack vs 5G phones today.
- **SUCI catchers**: don't recover SUPI but track via GUTI; force re-registration to disrupt pseudonym persistence.

### SS7 — The Interconnect Underbelly

Signaling System 7 (1975) is the telco interconnect protocol stack: call setup, SMS routing, location queries, billing. Designed for trusted national operators — there is essentially no authentication between SS7 nodes.

**Nohl 31C3 2014** demonstrated that SS7 access (obtainable as a small telco or gray-market reseller) enables:
- **Location tracking**: query subscriber by number, get current cell tower to ~100m globally.
- **SMS interception**: a fake UpdateLocation claims "I'm the new MSC for this subscriber"; SMS routes to attacker.
- **Call interception**: similar via USSD / Camel.
- **DoS**: register subscriber in non-existent MSC; service lost until manual re-register.

Real-world abuse: Ukraine 2014 (subscriber location and calls obtained via SS7 from Russian-addressed nodes), Germany 2017 (bank accounts drained via SS7-intercepted OTP), continuing campaigns. **Diameter** (4G replacement) — improved auth but same trust-the-other-operator architecture; same attack patterns largely apply.

### IMSI Catchers / Stingrays

Cell-tower impersonators. Originally law-enforcement procurement (Harris Stingray, 6-figure); now $1,000 build-it-yourself (USRP + srsRAN or OpenAirInterface). Two modes:
- **Passive**: capture cleartext identity exchanges. Works because 2G/3G/4G initial registration leaks identity.
- **Active**: impersonate legitimate tower at higher signal; force re-registration; MITM downgrade to A5/0 or A5/1.

**Detection**: SnoopSnitch (Nohl/SRLabs, Qualcomm rooted Android — monitors baseband for forced 2G handover, cipher downgrade, paging anomalies, real but heuristic), AIMSICD (open source, more limited). 5G SA SUCI defeats the basic attack; SUCI catchers remain a research area.

### Simjacker / WIBattack

AdaptiveMobile + Nohl (2019): carrier SIM cards with the `S@T Browser` applet (obsolete WAP-era tech) silently execute commands carried in attacker-sent binary SMS — return device location via reverse SMS. WIBattack is the parallel attack on the `Wireless Internet Browser` applet. ~1B devices across ~30 countries at disclosure. Detection: SnoopSnitch.

---

## VII. GPS and GNSS

### How Civilian GPS Works

GPS satellites broadcast precisely-timed PRN signals on L1 (1575.42 MHz, C/A code) and L2 (1227.6 MHz). Receiver correlates against known per-satellite C/A codes, recovers navigation message (orbit + time), computes 3D position + clock bias from time-of-flight from ≥4 satellites.

Civilian L1 C/A has **no authentication**. Anyone with a modulator can broadcast indistinguishable signals. Military M-code on L1/L2 is authenticated; civilian receivers cannot use M-code.

### GPS Spoofing

Transmit counterfeit signal stronger than real; nearby receivers compute attacker-dictated position.

- **Humphreys 2012 drone spoof** (White Sands): first openly-acknowledged civilian-UAV spoof.
- **Humphreys 2013 yacht spoof**: see Section I bio. Hours of slow course drift, no alarms — slow spoofs are operationally undetectable.
- **Iran-RQ-170 (2011)**: disputed; technical consensus accepts spoof-based forced landing is at least technically possible.
- **Russian Black Sea (2017+)**: >20 ships off Novorossiysk simultaneously reported positions inland at Gelendzhik Airport. C4ADS "Above Us Only Stars" (2019) catalogued ~10,000 events across Russia / Crimea / Syria, correlated with Putin's travel — protecting VIPs from drones by inducing returning drones to "think they're at an airport."
- **Continuing Russian / Ukraine theater (2022–)**: ongoing GNSS jamming + spoofing; multiple commercial aviation GPS-loss incidents.

### GNSS Beyond GPS

- **GLONASS**: similar era, no civilian authentication.
- **Galileo (EU)**: now offers **OSNMA** — TESLA-based authentication of civilian Open Service nav messages. Initial Service operational July 2025. Receivers must be OSNMA-capable; commercial chipset rollout in progress.

### ADS-B (Aviation)

Aircraft broadcast identity, position, altitude, velocity on 1090 MHz; mandatory in US airspace since 2020. **No authentication.** $30 RTL-SDR receives; SDR transmitter injects "ghost aircraft" (demonstrated repeatedly at DEF CON). Risk model: ATC has primary radar (not fooled by ADS-B alone), but TCAS uses ADS-B inputs and ghost-aircraft injection induces nuisance Resolution Advisories.

### AIS (Maritime)

Ships broadcast on 161.975 / 162.025 MHz; mandatory for vessels >300 GT. **No authentication.** Trend Micro 2013 demonstrated full spoofing with ~€700 equipment: create fake vessels, hide real ones, draw arbitrary patterns ("PWNED" off Italian coast). Real-world abuse: AIS spoofing for sanctioned-vessel evasion (Iran / Venezuela / DPRK oil trade).

### Defensive Patterns for GNSS-Dependent Systems

- Multi-constellation receivers (GPS + Galileo + GLONASS + BeiDou): spoofing all four consistently is much harder.
- OSNMA-capable receivers as trust anchor.
- INS/IMU cross-check for impossible-physical-motion detection.
- Signal-strength anomaly (sudden 20+ dB jumps suspicious).
- Time-bias anomaly (sudden internal clock bias jump).
- Chip-scale atomic clocks for GPS-disciplined applications (cell base stations, smart grid, financial timestamping) — raise alarm on GPS-vs-CSAC disagreement.
- PNT-resilience programs (eLoran, vision, signals of opportunity).

See `dns_network_infrastructure.md` for time-protocol angles (NTP/PTP rely on GPS at large operators).

---

## VIII. Satellite Communications

### GEO Satellite (VSAT, BGAN, Inmarsat)

Geostationary at 35,786 km altitude; continent-scale footprints. Broadcast downlink → a single passive observer with a Ku-band dish receives traffic for any subscriber in the footprint.

**Pavur (Black Hat 2020)** — see Section I bio. The core issue: the satellite-to-ground link may be encrypted, but the IP traffic on top often is not. Customers (vessels, aircraft, oil rigs) assume the link is "private" — it isn't, and many vendors haven't deployed even minimal IPsec on top.

**Santamarta (Black Hat 2014, 2018)** — see Section I bio. Cobham, Hughes, Harris, JRC, Thuraya, Iridium terminals across all major manufacturers: hardcoded credentials, undocumented backdoors, command-injection bugs in web admin, unsigned firmware. 2018 demo: remote access to in-flight aircraft satcom from the public Internet.

**Pen Test Partners**: complementary maritime / aviation pen-test disclosures. Default admin/1234 terminals; unprotected telnet management; CRC-as-"signature" firmware updates.

### LEO Satellite (Starlink, OneWeb, Kuiper)

LEO constellations at 550–1,200 km. Lower latency (~25 ms vs ~600 ms GEO), smaller footprints, more satellites for global coverage. Newer architectures generally better-secured than legacy GEO operators.

**Starlink — Wouters (Black Hat 2022)** — see Section I bio. Gets one dish; does NOT get the Starlink core network (dish is treated as untrusted client; uplink auth isn't broken).

### Iridium Pager / SBD / Voice

66-satellite LEO constellation, L-band (1616–1626.5 MHz). 1998 service offered pager + sat-phone + SMS. Iridium NEXT (2017+) modernized but retained legacy SBD and pager protocols.

Stefan "Sec" Zehl et al — `gr-iridium`, `iridium-toolkit`: HackRF + L-band antenna passively receives. Pager service unencrypted; SBD weakly keyed; voice unencrypted at the air interface. ETH Zurich (2026) systematic security analysis confirms these properties and demonstrates arbitrary frame injection. Iridium's "security through complexity" position is not accepted by the cryptographic community.

### Maritime and Aviation Satcom

Inmarsat (Fleet Broadband; Classic Aero / SwiftBroadband; GovSat), Iridium Certus, Viasat (in-flight WiFi), Thuraya, Hughes, Cobham. Longest running public-disclosure list of any satellite domain — large customer base, long-lived equipment, hard-to-patch operational environment.

Public-policy crux: aviation cockpit / cabin separation. Santamarta demonstrated reaching the satcom terminal is feasible; whether cabin-to-cockpit air gap holds is contested. FAA: assume intact. Research community: don't make policy on that assumption.

### Quantum Key Distribution

Mentioned for completeness. China's Micius (2016) — satellite-to-ground entanglement distribution; 2017 Vienna-Beijing QKD videoconference. Operationally limited (atmospheric loss, tiny key rates, classical-auth-still-required trust anchor). "Does QKD secure anything conventional public-key crypto doesn't?" remains contested. See `cryptography_expertise.md` for post-quantum context.

---

## IX. RFID and NFC

RFID / NFC live across three frequency bands with sharply different physics and security profiles.

### LF (125 kHz)

Legacy access-control: EM4100, HID Prox, Indala. Cards have unique serial numbers (sometimes 26-bit Wiegand). **No cryptographic auth.** Trivially cloneable: Proxmark3 (~$300) or Flipper Zero (~$200) reads any LF badge in ~1 sec and writes a blank EM4305. Many corporate badge systems still use HID Prox in 2026. Treat LF badges as identifiers, not credentials.

### HF (13.56 MHz)

Dominant access-control / payment / transit band.

- **MIFARE Classic** (NXP): Crypto-1 stream cipher with 48-bit keys. Nohl + Plotz 2007 silicon-RE attack. Cipher has structural weaknesses (poor diffusion, recoverable LFSR) + weak RNG. Full key recovery in seconds with `mfoc` and `mfcuk`. Many transit cards still MIFARE Classic in 2026 because migration is expensive.
- **MIFARE DESFire (EV1/EV2/EV3)**: 3DES or AES (EV1 already supports AES). EV2+ is largely sound. Failure mode: key management (default keys, site-wide keys).
- **HID iCLASS (legacy Standard Security)**: 2012 Garcia/de Koning Gans/Verdult/Meriac attack ("Dismantling iClass and iClass Elite") exposed system-wide master keys; broken. HID iCLASS SE / Seos uses AES + per-card diversified keys and is much better.
- **ePassport (ICAO 9303)**: BAC key derived from passport number + DOB + expiration (all visible on the inside cover; brute-forceable for unconstrained number formats). PACE replaces BAC in newer passports — cryptographically sound. Read-at-distance demonstrated repeatedly (Adam Laurie).
- **Contactless EMV**: well-vetted card-side challenge-response. Dominant attack is relay.

### UHF (860–960 MHz)

Supply-chain tracking (EPC Gen2). Read at meters; tag cost ~$0.10. **No authentication.** Attackers read product tags from across a store; intelligence services correlate tag IDs to individuals carrying tagged items. Some Gen2v2 anti-counterfeiting features but not auth.

### NFC (Phone-as-Token)

13.56 MHz on phones: Reader/Writer, P2P (Android Beam, deprecated), Card Emulation (Apple Pay, Google Pay, hotel keys, transit, employee badges).

Apple Pay / Google Pay use EMV with phone Secure Element holding device-specific keys; tokenization gives merchant a Device Account Number, not the PAN. Touch ID / Face ID gates each transaction.

Tesla card key / hotel keys are NFC card emulation. Attack patterns are physical (steal phone/card) or BLE-relay (the BLE pairing enables Phone-as-a-Key — once BLE relay succeeds, NFC mode is irrelevant).

### Flipper Zero

Cultural moment 2022–2023. Multi-protocol pen tool: LF RFID + HF NFC + sub-GHz (CC1101, 300–928 MHz) + 433 MHz + infrared + GPIO. STM32WB55. ~$170. Brazil / Canada debated banning sales. Legal in US; not as transmitter in many EU markets.

Operationally important less for what new attacks it enables (mostly Proxmark3 + YARDStick equivalents) and more for what it makes accessible — script-kiddie-tier RF abuse is now a $170 consumer purchase. Assume your physical access control, key fobs, and garage doors are under daily Flipper-Zero attack in any public location.

---

## X. SDR (Software-Defined Radio) Research Tools

### Hardware

**Receivers**:
- **RTL-SDR ($30)**: 24 MHz – 1.7 GHz RX, 8-bit ADC. The democratization device.
- **Airspy HF+ ($200)**: high-dynamic-range narrow-band HF/VHF.
- **SDRPlay RSPdx ($250)**: 1 kHz – 2 GHz, 14-bit ADC, 10 MHz bandwidth.

**Transceivers**:
- **HackRF One ($300)**: 1 MHz – 6 GHz half-duplex, 20 MSPS, 8-bit ADC. Most-deployed open SDR.
- **bladeRF 2.0 micro ($720)**: 47 MHz – 6 GHz full-duplex, 12-bit, 2x2 MIMO.
- **LimeSDR ($200–$300)**: 100 kHz – 3.8 GHz full-duplex; used in srsRAN / OAI base-station emulation.
- **USRP B210 ($1,200) / X310 ($5,000+)**: research-grade, phase-coherent MIMO.

**Specialty**: Ubertooth One ($120, BT Classic sniffer), YARDStick One ($100, sub-GHz CC1111), Flipper Zero ($170), Proxmark3 ($300, RFID), ChipWhisperer-Lite ($250+, glitching; see `firmware_embedded_security.md`).

### Software Stack

- **GNU Radio + GNU Radio Companion (GRC)**: open block-based DSP framework; the standard tool for prototyping RF protocols.
- **SDR++ / SDR# / gqrx**: spectrum-display GUIs.
- **Universal Radio Hacker (URH)**: protocol-RE GUI — modulation identification → demodulation → framing → field annotation.
- **rtl_433**: ~200 sub-GHz device decoders out of the box.
- **inspectrum, gr-iridium, gr-gsm, gr-lte, srsRAN, OpenAirInterface**.

### Protocol-RE Workflow

1. Identify the band — spectrum sweep.
2. Capture clean (10s for ISM, ~1min for slow).
3. Identify modulation (OOK / FSK / GFSK / MSK / PSK / QAM) via URH's auto mode or visual inspection.
4. Demodulate to bits — GNU Radio flowgraph or URH.
5. Find framing — repeating preamble + sync word (8–32 bits).
6. Extract fields — ID, payload, CRC.
7. CRC RE — try CRC-CCITT, CRC-16-IBM, CRC-8 polynomials; tools: `RevEng` (G. Cook).
8. Replay + verify against real receiver.
9. Inject / fuzz; observe receiver behavior.

This gets you from "I bought a smart doorbell" to "I can replay arbitrary commands to it" in a few hours for most consumer protocols.

---

## XI. Real-World Incident Corpus

**Vehicle theft**:
- Tesla BLE relay (NCC 2022). Mitigation: PIN-to-Drive + disable passive entry.
- Tesla key-fob clone (Wouters 2018, DST-40), Tesla Model X BLE firmware push (Wouters 2020). Patched.
- KIA/Hyundai TikTok challenge (2022–23): not RF — missing immobilizer on 2011–2021 vehicles + USB-A in the ignition cylinder.
- RollJam / RollBack: KeeLoq + HCS rolling-code defeats via replay-and-jam. Modern BLE-UWB challenge-response is resistant.
- CAN injection (Toyota RAV4, Tindell 2023): bypass via headlight harness; not RF but illustrates the wireless layer isn't always the weakest link.

**Maritime / aviation**:
- 2017 Black Sea spoofing, ~20 vessels at Gelendzhik.
- 2018+ Russian EW in Syria / Ukraine, ongoing.
- 2023 Persian Gulf civilian aviation GPS loss — suspected Iranian or Russian EW.
- Trend Micro 2013 AIS spoof demonstrated; real-world abuse in sanctions-evasion shipping.

**Satellite**: Pavur 2020 (continent-scale passive GEO), Wouters 2022 (per-dish Starlink RCE), Santamarta 2014/2018 (dozens of vendors, thousands of remote-accessible terminals).

**Wi-Fi**: KRACK (2017) vendor patching cycle 6+ months, many embedded never patched; FragAttacks (2021) similar pattern; corporate WPA2-Enterprise hostile-portal exfiltration via `eaphammer` is a steady pen-test win.

**Bluetooth**: BlueBorne (2017) ~5.3B devices, patched over 1–2 years; NCC Tesla BLE relay (2022).

**Recurring disclosure venues**: DEF CON RF Village / Car Hacking Village / Aerospace Village; Black Hat USA/EU/Asia; CCC (European canonical, esp. Nohl / SS7 / Iridium / RFID); ShmooCon, REcon, Hardwear.io; USENIX Security, S&P, NDSS, CCS.

---

## XII. Defensive Patterns

### Air-Interface Authentication

Every wireless protocol in production must cryptographically authenticate the air-interface peer. **Do not deploy**: ADS-B, AIS, civilian GPS, WEP, Just-Works BLE for sensitive devices, ZigBee with default Trust Center key, MIFARE Classic. **Do deploy**: WPA3-SAE, Galileo OSNMA, EMV contactless, Matter, WPA2-Enterprise + EAP-TLS.

### Forward Secrecy

Long-term key compromise must not retroactively decrypt past traffic. WPA2-PSK lacks this; WPA3-SAE has it. BLE Secure Connections has it; BLE Legacy doesn't. Modern TLS does (ECDHE-only); static-RSA TLS doesn't. Always require ephemeral key exchange.

### Channel Binding (Relay Resistance)

Proximity-critical applications (keys, payments, locks) must bind crypto to a physical-layer measurement: UWB time-of-flight, angle-of-arrival, or round-trip-time threshold. Without this, the cryptographic challenge is forwardable any distance — NCC Tesla relay / EMV relay / RKE relay work. Bluetooth Core Spec 6.0 (2024) added Channel Sounding for secure fine ranging; Apple, Samsung, BMW are deploying UWB for car keys.

### Frequency-Hopping / Spread-Spectrum

Bluetooth FH, GPS DSSS, CDMA — raise cost of narrowband jamming. Do NOT protect against wideband jamming (power-bound for the jammer).

### Replay Protection (Nonces / Timestamps)

Every authenticated frame tagged with nonce/timestamp; receiver validates freshness. AES-CCMP, AES-GCM, ChaCha20-Poly1305 are nonce-misuse-detecting AEAD when framed correctly (KRACK was a framing failure). Sequence-number reset on rekey is fine; reset on every power cycle (common embedded mistake) is fatal.

### End-to-End Encryption Above the Wireless Layer

Don't trust the wireless layer as sole crypto. Wi-Fi/cellular/satellite encrypt the air interface; the operator (or downlink listeners in satellite's case) can see decrypted traffic. Always run TLS / Signal / WireGuard / IPsec on top. Pavur 2020 was trivial because customers ran HTTP/FTP/plaintext SMTP over assumed-private satellite links.

### Anti-Jamming / Anti-Spoofing for GNSS

Multi-constellation cross-check + OSNMA-capable Galileo + INS backup + chip-scale atomic clocks + eLoran where regulatorily supported. Spoofing detection: signal-strength anomaly, constellation disagreement, IMU disagreement.

### Code Review Checklist for Wireless Code

10-item checklist for wireless-protocol implementation review:

1. Is the peer cryptographically authenticated before any commands are honored? Reject Just-Works-equivalent for sensitive ops.
2. Is the air-interface encryption authenticated (AEAD)? Reject CBC-without-MAC, CTR-without-MAC, custom MAC.
3. Is the per-packet nonce/counter bounded and never reused? Search for nonce-reset paths (power cycle, rekey, handover). KRACK pattern.
4. Is fragment reassembly cleared between sessions? Are mixed-key fragments rejected? FragAttacks pattern.
5. Are parser inputs bounded? TLV parsers (BLE GATT, Wi-Fi mgmt frames, Bluetooth SDP) are canonical RCE surface. Fuzz them. Treat length fields as adversarial.
6. Is downgrade resistance enforced? Reject KNOB-style entropy negotiation below minimum (BT ≥7 bytes; Wi-Fi: no TKIP if CCMP available).
7. Is forward/future secrecy provided?
8. For proximity-critical: distance-bounding present? Relay otherwise unconditionally possible.
9. Is firmware update authenticated by signature, not CRC?
10. Is replay detected (sequence number/timestamp + acceptance window)? Does the window survive reboot?

See `code_review_expertise.md` for the general framework.

---

## XIII. Detection and Monitoring

### RF Anomaly Detection

For environments with predictable RF use (Wi-Fi-only floors, hospital med-tech, datacenter):
- Spectrum monitoring with SDR scans (Raspberry Pi + RTL-SDR sweep; alert on unexpected emissions).
- WIDS: Cisco, Aruba, Forescout, Mojo, Ruckus. Detect rogue APs, deauth floods, KARMA. Mature.
- Bluetooth surveillance harder — FHSS hopping makes broad-area monitoring difficult.

### IMSI-Catcher Detection

- **SnoopSnitch** (Nohl/SRLabs): rooted Qualcomm Android. Monitors baseband for forced 2G handover, cipher downgrade, paging anomalies. Real but heuristic, evadable.
- **AIMSICD** (open source, more limited).

### Wi-Fi Rogue AP Detection

WIDS + open-source Kismet (Mike Kershaw). Detection signals: BSSID inconsistency, RSSI anomaly, encryption downgrade, beacon-timing irregularity, RTS/CTS injection.

### Bluetooth Tracker Detection

iOS 17.5+ and Android 6+ ship interoperable AirTag-class unwanted-tracker detection (Apple+Google+IETF `draft-detecting-unwanted-location-trackers`). For physical security teams: sweep with AirGuard Android app; for serious threat models, RF-shielded conference rooms.

### GPS Spoofing Detection

- Receiver-side: signal-strength outliers, multi-constellation disagreement, IMU/INS disagreement, clock-bias anomaly.
- Network-side: NTP/PTP server disagreement, GPS-disciplined-oscillator drift.
- Specialized: u-blox NEO-M9 with built-in anti-spoofing; CRFS / TDOA networks (military / research).

See `detection_engineering_expertise.md` for the broader framework.

---

## XIV. Variant Analysis — Under-Explored Surfaces

Surfaces where public literature is thin and research is likely fruitful:

- **Drone / UAV C2**: commercial drone protocols (DJI OcuSync / AeroScope, Skydio, Parrot) have proprietary stacks with undocumented backdoors and proprietary ciphers. Hobby ELRS / Crossfire / FrSky is better-vetted.
- **Practical QKD**: BT London-Cambridge, Toshiba commercial QKD — classical auth still gates security, tiny key rates, awkward integration. Operational usefulness in 2030 contested.
- **6G**: 3GPP Release 19+ articulating terahertz channels, AI-native air interface, integrated sensing-and-communication. Each a new attack surface. Terahertz pencil-beams change broadcast-nature assumptions.
- **Mesh attacks (BLE Mesh, Thread, MANET)**: Sybil, wormhole, sinkhole — classical MANET attacks ported to BLE Mesh / Thread / Briar / Bridgefy / GoTenna are largely unstudied.
- **Smart Dust / Ambient Computing**: 30-year sensor lifetime + 5-year crypto primitive lifetime = forever-vulnerable installed base. Matter-rated 2026 devices will run on 2026 primitives in 2050.
- **AI-driven RF protocol RE**: LLM-assisted modulation classification, framing identification, CRC inference. Limited public work in 2026 but seems likely to commodify protocol RE.
- **Underwater Acoustic Networks**: JANUS, NATO STANAG 4748. RF-shaped attack surface at audio frequencies. Public research minimal.
- **Power-Line Communications**: G3-PLC, PRIME, IEEE 1901. Same attack patterns as RF; different threat model (line-attached, not in-range). Security lags Wi-Fi/Bluetooth.
- **Industrial RF**: ISA100, WirelessHART, legacy Modbus-over-radio. See `ics_ot_security_expertise.md`. Legacy proprietary radio links remain deployed-but-undefended in older OT.

---

## XV. References

**Wi-Fi**:
- Vanhoef, KRACK + Dragonblood + FragAttacks: `https://www.krackattacks.com/`, `https://wpa3.mathyvanhoef.com/`, `https://www.fragattacks.com/`, publications `https://www.mathyvanhoef.com/p/publications.html`
- FMS (2001): `https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack`
- Tews-Weinmann-Pyshkin PTW (2007): `https://eprint.iacr.org/2007/120`
- Tews-Beck WPA-TKIP (2008): `https://eprint.iacr.org/2008/472`
- Steube PMKID (2018): `https://hashcat.net/forum/thread-7717.html`
- Viehbock WPS (2011): `https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf`
- Bongard offline WPS (Hack.lu 2014): `http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf`

**Bluetooth**:
- Antonioli KNOB/BIAS/BLURtooth/BLUFFS: `https://knobattack.com/`, publications `https://francozappa.github.io/publication/`, BLUFFS `https://dl.acm.org/doi/pdf/10.1145/3576915.3623066`
- Ryan BLE (WOOT 2013): `https://www.usenix.org/system/files/conference/woot13/woot13-ryan.pdf`; `https://github.com/mikeryan/crackle`
- Armis BlueBorne (2017): `https://media.armis.com/pdfs/wp-blueborne-bluetooth-vulnerabilities-en.pdf`
- Garbelini BrakTooth (USENIX 2022)

**Cellular**:
- Piqueras Jover publications: `http://rogerpiquerasjover.net/`
- Nohl 31C3 SS7: `https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2493/original/Mobile_Self_Defense-Karsten_Nohl-31C3-v1.pdf`
- Nohl, Cryptanalysis of Crypto-1: `https://media.frag-den-staat.de/files/foi/580223/Mifare.Cryptanalysis.pdf`
- SRLabs SnoopSnitch: `https://opensource.srlabs.de/projects/snoopsnitch`
- ETSI / 3GPP TS 33.501 (5G Security): `https://www.etsi.org/`
- IEEE Spectrum SS7: `https://spectrum.ieee.org/alarming-security-defects-in-ss7-the-global-cellular-networkand-how-to-fix-them`

**GPS / GNSS**:
- Humphreys UT Radionav Lab: `https://radionavlab.ae.utexas.edu/`; yacht spoof: `https://news.utexas.edu/2013/07/29/ut-austin-researchers-successfully-spoof-an-80-million-yacht-at-sea/`
- C4ADS "Above Us Only Stars" (2019): `https://c4ads.org/reports/above-us-only-stars/`
- Galileo OSNMA: `https://www.gsc-europa.eu/galileo/services/galileo-open-service-navigation-message-authentication-osnma`; `https://insidegnss.com/galileo-osnma-looking-forward/`
- Maritime Executive Black Sea spoof (2017): `https://maritime-executive.com/editorials/mass-gps-spoofing-attack-in-black-sea`

**Satellite**:
- Pavur Whispers Among the Stars (BH 2020): `https://i.blackhat.com/USA-20/Wednesday/us-20-Pavur-Whispers-Among-The-Stars-Perpetrating-And-Preventing-Satellite-Eavesdropping-Attacks.pdf`
- Wouters Starlink (BH 2022): `https://i.blackhat.com/USA-22/Wednesday/US-22-Wouters-Glitched-On-Earth.pdf`
- Santamarta SATCOM (BH 2014): `https://blackhat.com/docs/us-14/materials/us-14-Santamarta-SATCOM-Terminals-Hacking-By-Air-Sea-And-Land-WP.pdf`; (BH 2018): `https://www.ioactive.com/article/ioactive-reveals-major-satellite-communication-and-operating-system-vulnerabilities-at-black-hat-usa-2018-def-con-26/`
- Iridium toolkit: `https://github.com/muccc/iridium-toolkit`, `https://github.com/muccc/gr-iridium`
- Pen Test Partners: `https://www.pentestpartners.com/`

**RFID / NFC**:
- Laurie RFIDIOt: `http://adamsblog.rfidiot.org/`
- NCC Tesla BLE relay (2022): `https://research.nccgroup.com/2022/05/15/technical-advisory-tesla-ble-phone-as-a-key-passive-entry-vulnerable-to-relay-attacks/`
- Trend Micro AIS (2013): `https://www.technologyreview.com/2013/10/18/82918/ship-tracking-hack-makes-tankers-vanish-from-view/`

**Sub-GHz / RKE / HID**:
- Kamkar Drive It Like You Hacked It (DC23): `https://www.youtube.com/watch?v=UNgvShN4USU`; `https://samy.pl/`
- Bastille MouseJack: `https://bastille.net/research/vulnerabilities-mousejack/`; KeySniffer: `https://keysniffer.net/`
- Wouters et al. CHES 2018 Tesla DST-40

**SDR / Tooling**:
- Great Scott Gadgets: `https://greatscottgadgets.com/`; SDR course: `https://greatscottgadgets.com/sdr/`; HackRF: `https://github.com/greatscottgadgets/hackrf`
- KillerBee: `https://github.com/riverloopsec/killerbee`; GoodFET: `https://github.com/travisgoodspeed/goodfet`
- GNU Radio: `https://www.gnuradio.org/`; gr-gsm: `https://github.com/ptrkrysik/gr-gsm`
- srsRAN: `https://github.com/srsran/srsRAN_4G`; OpenAirInterface: `https://openairinterface.org/`
- URH: `https://github.com/jopohl/urh`; rtl_433: `https://github.com/merbanan/rtl_433`; Flipper Zero: `https://flipper.net/`

**Standards**: IEEE 802.11, IEEE 802.15.4, Bluetooth Core Spec (`https://www.bluetooth.com/specifications/specs/`), 3GPP (`https://www.3gpp.org/`), ETSI, CSA Matter (`https://csa-iot.org/`), ITU-R.

### Cross-References Within This Library

- `firmware_embedded_security.md` — RF transceiver hardware, JTAG / SPI extraction of wireless devices, fault injection
- `mobile_security_expertise.md` — §11 baseband stack internals, AWDL, Beer's 2020 iOS 0-click
- `cryptography_expertise.md` — AEAD primitives, PAKE / SAE, ECDH, AES-CCM/GCM
- `dns_network_infrastructure.md` — time-protocol angles (NTP/PTP rely on GPS at large operators)
- `detection_engineering_expertise.md` — broader signals-based detection framework
- `ics_ot_security_expertise.md` — industrial RF (ISA100, WirelessHART, Modbus-over-radio)
- `code_review_expertise.md` — general code-review framework; the wireless surface adds the §XII checklist on top

---
