# WebRTC and Real-Time Communications Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

### Natalie Silvanovich (@natashenka)

Senior security researcher at Google Project Zero. The canonical real-time-comms 0-day researcher. Her "Adventures in Video Conferencing" series (five parts, Dec 2018) and "Zooming in on Zero-click Exploits" (Jan 2022) define the methodology: read the signalling state machine for logic bugs, then fuzz the parser-heavy media path. **Adventures in Video Conferencing** covered WebRTC, FaceTime, WhatsApp, state machines, remediation — eleven bugs total, majority found via <15 min of mutation fuzzing RTP, including FaceTime CVE-2018-4366, CVE-2018-4367, CVE-2018-4384. **The State of State Machines** (Jan 2021) audited seven video-conf apps; five vulnerabilities forcing callee to transmit audio/video before accepting (Signal, Google Duo, Facebook Messenger, JioChat, Mocha), generalising the FaceTime Family Bug into a class. **Zooming in on Zero-click Exploits** (Jan 2022): XMPP-handler analysis (`CXmppIMSession::handleMessage`) and RTP-path fuzzing of Zoom's MMR. **Street Party**: open-source RTP-stream tooling.

Doctrine: every RTC app is a parser plus a state machine; both need adversarial review. Mutation-fuzzing RTP payloads is the cheapest source of bug supply.

### Patrick Wardle (Objective-See)

Founder of Objective-See and Objective by the Sea conference. Former NSA. Focus: macOS-native exploitation, installer abuse, privilege escalation. Repeatedly broken Zoom on macOS — March 2020 disclosed installer abuse of `AuthorizationExecuteWithPrivileges` (local attacker replaces `runwithroot` script during install/upgrade for root) and Zoom's exception entitlement enabling library injection; DEF CON 30 (Aug 2022) disclosed CVE-2022-28756, cryptographic-verification flaw in Zoom's auto-updater. Repeated pattern: installer and updater paths are LPE sources because nobody fuzzes them, and they run as root.

### Bill Marczak (Citizen Lab)

Senior Research Fellow at Citizen Lab (Munk School, University of Toronto). Co-leads targeted-threat research on commercial spyware with John Scott-Railton and Ron Deibert. April 2020 **Move Fast and Roll Your Own Crypto** found Zoom advertised AES-256 but used AES-128 in ECB mode, with encryption keys for North American test calls transmitted from servers in Beijing. Same week: **Zoom Waiting Room vulnerability**. Authoritative analyst on the **Pegasus / NSO Group** zero-click chain through WhatsApp, iMessage, FaceTime; co-author of Pegasus discovery reports 2016-2024. Core contribution: for high-risk targets the threat model is not "someone might join my call" but "the call infrastructure is the lawful-intercept and unlawful-intercept platform."

### Eric Rescorla (@ekr)

Former CTO of Mozilla. Principal author of TLS 1.3 (RFC 8446); co-author of DTLS (RFC 6347, RFC 9147) and DTLS-SRTP (RFC 5764). Former chair of IETF TLS WG. Authored RFC 8827 (WebRTC Security Architecture). The DTLS-SRTP design — SRTP encrypts media payload; DTLS handshake (same UDP flow) establishes SRTP master keys via a DTLS extension — is why WebRTC media is genuinely E2EE at the transport layer even when signalling is observable. RFC 8827's framing of the trust boundary remains the canonical model.

### Justin Uberti (@juberti)

Designed Google Hangouts Video (first high-quality browser video conferencing), then ported it to WebRTC and VP8 — the foundation of Google Meet. ~13 years at Google as Distinguished Engineer. Now leads Realtime AI at OpenAI. Public commentary on libwebrtc complexity is the standard "this is too much attack surface" citation.

### Philipp Hancke (@hcornflower, fippo)

WebRTC practitioner researcher; at Meta on WebRTC at scale. Active contributor at [webrtcHacks.com](https://webrtchacks.com/); full-time on WebRTC since 2012. Practitioner reference for production RTC engineering — TURN traffic distributions, SFU architecture tradeoffs, regression-detection methodology, insertable-streams E2EE explainers.

### Sandro Gauci (Enable Security)

Founder and CEO of Enable Security (2008). Original developer of **SIPVicious** (canonical SIP security testing toolset). Maintains SIPVicious PRO, ESAP, DVRTC. Recurring themes: SIP enumeration at scale, RTP injection/hijacking, TURN abuse for tunnelling, DDoS against VoIP providers.

### Ben Nassi (Tel Aviv University)

Faculty at TAU School of Electrical and Computer Engineering; leads the AdMin research group. Canonical researcher for optical and acoustic side-channels: **Lamphone** (Black Hat USA 2020, real-time passive sound recovery from a hanging light bulb at 25m); **The Little Seal Bug** (WOOT 2023, sound from lightweight reflective objects); **Video-Based Cryptanalysis** (2024, ECDSA keys from standard video of target device's power LED). Lineage matters because every video call is also continuous audio capture, every speaker a vibrating surface, every webcam stream contains the LEDs of every device in frame.

### Citizen Lab Zoom Team

Beyond Marczak, the April 2020 Zoom audit was co-authored by John Scott-Railton. Methodology — traffic capture, client binary analysis, Censys server-fingerprinting, SEC-filing review — is the canonical "audit-an-RTC-vendor" recipe. Reports written for both technical and policy audiences, driving regulatory and procurement responses within weeks.

---

## II. The Real-Time-Comms Threat Model

### Why RTC Is Uniquely Tricky

RTC is not a normal HTTP stack with audio glued on. The combination of full-duplex media, sub-200-ms latency, mandatory NAT traversal, dynamic codec negotiation, and the tension between E2EE and server-mediated features (recording, transcription, dial-in, federation) produces a uniquely hostile design space. Concrete tensions:

1. **Latency vs. encryption.** TLS three-roundtrip is too slow for voice (perceived broken at >300ms). DTLS-SRTP solves this by overlapping the handshake with ICE checks, but the state machine is more complex than TLS 1.3.
2. **Latency vs. retransmission.** TCP retransmits; RTP does not. A lost audio packet is silence. Codec design embeds error concealment, and parser bugs reachable on one-off files are reachable by every dropped/corrupted packet. Why fuzzing RTP yields bugs cheaply.
3. **E2EE vs. server features.** True E2EE means the SFU forwards opaque bytes. Customers want recording, transcription, virtual backgrounds, captioning, AI summarisation — each incompatible with E2EE unless rebuilt client-side. Industry compromise: "encrypted in transit and at rest, server has keys when needed," marketed as E2EE.
4. **Heterogeneous endpoints.** Browser, iOS, Windows desktop, SIP hard-phone, PSTN dial-in must interoperate. Each has different trust assumptions; lowest common denominator drives posture.

### Every Video Call Is Also a Microphone

A video-conferencing client is a microphone-and-camera control plane permanently installed on every employee's laptop. Permission-gated by the OS, but inside its process boundary any compromise grants full media capture. The FaceTime "Family Bug" (Jan 2019; §V) demonstrated this with a state-machine bug activating the recipient's mic before pickup, no compromise required. A Pegasus-class actor with WhatsApp VoIP buffer-overflow (CVE-2019-3568) needed no recipient action — receiving the call installed spyware. Threat-model implication: every laptop running a video-conf client is one parser bug away from full audio/video surveillance. Defence is segmentation, not "trust the vendor."

### Trust Boundaries: Signalling vs. Media

WebRTC (RFC 8827, Rescorla) draws explicit boundaries. **Signalling**: server-mediated, app-defined. Carries SDP offers/answers, ICE candidates, call setup metadata. Server sees all metadata; can mount MITM by substituting SDP fingerprints; cannot decrypt media in flight. **Media**: peer-to-peer or via TURN, DTLS-SRTP-encrypted. Fingerprints in SDP. If both peers verify each other's DTLS fingerprint (signed identity assertion per RFC 8827, or out-of-band), signalling cannot wiretap. In practice browsers don't surface fingerprints; IdP integration is rarely deployed. Signalling is trusted by default.

### 0-Click vs. 1-Click vs. n-Click

Mirrors the [[reference-mobile-security]] taxonomy. **0-click**: incoming call setup payload (SDP, INVITE, signalling state) reaches a parser with a bug — compromise before device rings. WhatsApp Pegasus (May 2019) canonical RCE; FaceTime (Jan 2019) was 0-click eavesdropping. **1-click**: recipient accepts or doesn't decline within a short window; parses RTP-borne media. Most Silvanovich-class RTP fuzzing. **n-click**: recipient enables a feature (screen share, virtual background, file transfer) exposing a different parser; rare in research, common in toll-fraud abuse.

0-click in RTC is catastrophic because users cannot decline what they don't know is incoming. Defence is shrinking the pre-pickup parsing surface and sandboxing what remains.

---

## III. The WebRTC Protocol Stack

### Signalling Layer

WebRTC deliberately does not specify a signalling protocol. Applications choose: WebSocket-over-TLS, SIP-over-WebSocket (enterprise PBX integration), XMPP (Zoom historically), proprietary RPC over HTTPS (Meet, Teams, Slack Huddles). Carries SDP offers/answers (RFC 4566, RFC 8866) plus app-specific metadata. Attack surface: anything that parses SDP, trusts its contents, or authorises calls based on signalling state.

### ICE (RFC 8445)

Solves NAT traversal. Each endpoint collects candidates: host (local interfaces — LAN IP, VPN IP, IPv6 link-local); server-reflexive (public IP/port via STUN); relayed (TURN-server addresses). Peers exchange candidate lists via signalling, run connectivity checks (STUN binding requests across each pair) to find the highest-priority working path. RFC 8445 (July 2018) obsoletes RFC 5245. ICE checks carry an integrity tag (HMAC-SHA1 via the STUN short-term credential mechanism, keyed with the ICE password) preventing off-path forgery. ICE has no privacy property: candidate exchange leaks all endpoint network addresses (including LAN IPs) to the signalling counterparty. Basis of the WebRTC IP-leak class (§X).

### STUN (RFC 5389/8489) and TURN (RFC 5766/8656)

**STUN**: small UDP packet to STUN server; server responds with source IP/port observed. 20-byte header, optional attributes, no encryption except in STUN-over-TLS/DTLS inside ICE. Primary concern: amplification — spoofed-source STUN used in DDoS reflection.

**TURN**: fallback when ICE checks fail (symmetric NAT both ends, restrictive firewall). Allocates public IP/port both endpoints can reach. **Anonymous TURN must never be deployed** — open TURN is a free general-purpose internet relay abused for anonymized port scans, attacks on arbitrary destinations, C2 tunnelling. RFC 8656 requires TURN servers and clients to implement the STUN long-term credential mechanism. TURN sees plaintext IP/port endpoints but encrypted SRTP payload; cannot wiretap unless co-located with the SFU.

### SDP (RFC 4566/8866)

Plaintext-textual session description used as offer/answer payload. Contains version, originator, connection address, timing, media descriptors (`m=`), per-media attributes (`a=`: codec parameters, fingerprints, ICE credentials, DTLS setup, RTP extensions). Attacker-controllable in 0-click scenarios. The `a=fingerprint` is a hash (typically SHA-256) of the DTLS certificate presented during SRTP key exchange — substituting this is the MITM attack a signalling server could mount; verifying it (out-of-band or signed identity) is the defence.

### DTLS-SRTP (RFC 5764 + RFC 3711)

The mechanism that takes WebRTC media from "P2P-encrypted in theory" to "P2P-encrypted in practice." **SRTP** (RFC 3711, 2004): authenticated-encryption of RTP payload. Default cipher in WebRTC is AES-GCM (RFC 7714) or AES-128 counter with HMAC-SHA1-80. Also encrypts SRTCP. **DTLS-SRTP** (RFC 5764, 2010, McGrew/Rescorla): DTLS handshake over the same UDP flow as the media, with a DTLS extension deriving SRTP master keys from DTLS keying material.

Handshake follows ICE producing a connectivity-checked candidate pair. DTLS certificates are self-signed (no PKI); peers learn each other's fingerprint and verify against `a=fingerprint` in signalling. If signalling is honest, fingerprint match proves peer-to-peer completion. DTLS 1.3 (RFC 9147, April 2022) is modern; DTLS 1.2 remains widely deployed.

### RTP-over-QUIC and IdP Integration

QUIC (RFC 9000) is replacing TCP+TLS in HTTP/3. RTP-over-QUIC is in active IETF work. Promises better head-of-line-blocking properties, built-in encryption, connection migration. Security implication: fresh new parser — expect 0-days in the first 24 months of adoption.

**IdP integration** (RFC 8827): the rarely-deployed-but-critical feature binding an identity assertion (OAuth-style IdP token) to the DTLS fingerprint via SDP `a=identity`. If both peers verify, they prove the partner's identity even when signalling is malicious. Almost nobody deploys this — browsers don't ship built-in IdP integration; vendors won't build it because UX friction loses users. The standard's strongest privacy property is structurally unavailable to consumers.

---

## IV. WebRTC Implementation Vulnerabilities

### libwebrtc Is the Dominant Implementation

Google's `libwebrtc` ships in Chrome, Edge, Opera, Brave, Vivaldi, and many native apps (Signal, Discord, Slack, Zoom, MS Teams in some paths, almost every Android/iOS RTC client). The de-facto attack surface for the entire ecosystem. Implements ICE, DTLS-SRTP, all codecs (embedded libvpx, libaom, libopus, libyuv), RTP packetisers/depacketisers, jitter buffers, echo cancellation, noise suppression, JS-exposed PeerConnection API. A bug lands in every browser and dozens of native apps. Patching cascades take months; native apps bundling a snapshot are often year+ behind.

### Codec-Parser Bug Class

**Every codec is a parser; every parser is a fuzz target** ([[reference-fuzzing-discipline]]).

- **VP8/VP9 (libvpx)**: WebRTC's default video codecs. CVE-2023-5217 (Sept 2023, exploited in wild, Clément Lecigne/Google TAG): heap overflow in VP8 encoding path. CVE-2023-44488 (Sept 2023): VP9 width-mishandling crash.
- **H.264 (OpenH264)**: Cisco's open-source decoder; smaller surface than VP9.
- **AV1 (libaom)**: newer royalty-free codec; less mature, expect higher bug density per LOC.
- **Opus**: audio codec; comparatively tight C, few CVEs.
- **AAC**: enterprise paths and SIP/RTP gateways; long CVE history outside WebRTC scope.

Codec-via-attachment surface in messaging apps follows the BLASTPASS image-parsing class in [[reference-browser-js-engine-exploitation]] §7. The WebP flaw behind libwebp CVE-2023-4863 was first exploited as Apple CVE-2023-41064 in the iOS BLASTPASS Pegasus chain (Citizen Lab); the same libwebp ships inside Chromium's WebRTC paths.

### CVE-2023-7024 — Heap Overflow in WebRTC

Disclosed Dec 20, 2023. Heap buffer overflow in the Chromium WebRTC component (CVSS 8.8), exploited in the wild — the eighth actively-exploited Chrome 0-day of 2023. Reported by Clément Lecigne and Vlad Stolyarov (Google TAG). Fixed in Chrome 120.0.6099.129. Affected every Chromium-based browser plus native apps using the Chromium-derived WebRTC tree. Full exploit chain not publicly disclosed. The modern shape: the WebRTC component is a Chrome 0-day farm because every browser carries it and the attack surface is enormous.

### Other Recurring Bug Classes

**libsrtp** (Cisco): smaller codebase but recurring parser bugs in SRTP header handling, RTP extension processing, rekeying (e.g., CVE-2013-2139, CVE-2015-6360). **DTLS handshake parsing**: pre-handshake messages carry attacker-controllable lengths, extensions, cookies; mostly hardened by 2024 but surface remains. **ICE candidate parsing**: SDP candidates are attacker-controlled text; length checks, integer parsing for port numbers, IPv6 parsing are recurring lower-impact (DoS, info-leak) bugs.

For variant analysis: CVE-2023-5217, CVE-2023-44488, CVE-2023-7024, CVE-2023-4863, the Project Zero "Adventures in Video Conferencing" Part 1-3 CVE set, "State of State Machines" CVE set, Citizen Lab Pegasus chain analyses.

---

## V. Real-World Incidents — Video-Conferencing Platforms

### FaceTime "Family Bug" (CVE-2019-6223, January 2019)

The canonical 0-click eavesdropping bug. Discovered by Grant Thompson, age 14, in Tucson while setting up a group FaceTime call. Adding your own phone number to a Group FaceTime call as a third participant caused FaceTime's state machine to treat the call as accepted, activating the recipient's microphone before they answered. Pressing the lock button additionally activated the front-facing camera. Apple disabled Group FaceTime server-side Jan 28, 2019; patched in iOS 12.1.4 on Feb 7, 2019. Bug existed ~3 months before disclosure. Structural lesson: signalling-state-machine bugs are eavesdropping bugs even without RCE — the canonical example Silvanovich generalised in "The State of State Machines."

### WhatsApp / NSO Pegasus Chain (CVE-2019-3568, May 2019)

Buffer overflow in WhatsApp's VOIP stack reachable via specially crafted SRTCP packets to a target phone number. Triggered by placing the call; recipient need not answer. Even if recipient missed the call, spyware installed and the call log entry could be erased remotely. CVSS 9.8. Affected WhatsApp Android <2.19.134, iOS <2.19.51. Exploited in the wild by NSO Group to deliver Pegasus to human rights activists, journalists, lawyers per Citizen Lab. Meta sued NSO Oct 2019; Nov 2024 court filings revealed NSO continued exploiting variants after suit. The chain demonstrated the 0-click RTC class is operational, not theoretical. Defence: aggressive sandboxing of the VoIP parser process, no media parsing before user consent on ringing devices, rapid patch cadence.

### Citizen Lab Zoom Audit (April 2020)

Three findings within ten days during the COVID-19 Zoom surge:

1. **Roll-your-own crypto** (April 3): Zoom marketed AES-256 E2EE; reality AES-128 in ECB mode.
2. **Beijing key-routing**: encryption keys for North American test calls transmitted from servers in Beijing; SEC filings disclosed 700+ employees at Chinese subsidiaries.
3. **Waiting room key leak**: encryption keys and live video feeds available to all waiting-room users before host approval.

Zoom CEO publicly apologised April 1. The company paused feature work 90 days, hired Alex Stamos as consultant, delivered AES-256 GCM in May 2020 and true E2EE in October 2020.

### Zoom Installer LPE and Updater Bypass

Wardle, March 2020: deprecated `AuthorizationExecuteWithPrivileges` allowed a local non-privileged attacker to subvert install/upgrade and gain root. Library-injection via exception entitlement allowed malware to record meetings or activate camera/mic. DEF CON 30, Aug 2022: CVE-2022-28756, cryptographic-verification flaw in Zoom's auto-updater. Repeated pattern: video-conf installers and updaters are LPE sources because nobody fuzzes them, and they run as root.

### Zoom XMPP — Silvanovich (January 2022)

Project Zero's audit found two vulnerabilities: a buffer overflow (CVE-2021-34423) affecting both Zoom clients and the MMR (Multimedia Router), and an information leak (CVE-2021-34424) useful against MMR servers. Notable methodology: when RTP-payload modification failed (Zoom server filters traffic; RTP headers are unencrypted allowing the filter to detect tampering), Silvanovich pivoted to fuzzing the MMR's RTP-parsing code via `LD_PRELOAD` because the binary was not compiled relocatable.

### Microsoft Teams WebView2 / Electron Escape

Old Teams ran on Electron with several webview-escape vulnerabilities. The 2020 `ms-teams-rce` chain (Oskars Vegeris) bypassed webview filtering to load arbitrary preload scripts, gaining nodeJS context. Performed by guest users silently; yielded SSO authorisation tokens for Teams, Skype, Outlook, Office365. Teams 2.0 (GA October 2023) migrated to Edge WebView2; evergreen-Chromium delivery reduces patch lag for Chromium 0-days but adds new attack surface in WebView2 IPC and host-side .NET interop.

### Slack Huddles and Discord

Slack Huddles use WebRTC with DTLS-SRTP for media and TLS 1.2 over WebSocket for signalling. Huddles do **not** implement E2EE — only encryption-in-transit to/from Slack's media servers. Slack itself can theoretically access Huddle content. Meaningful distinction from Zoom's E2EE mode and Signal's voice calls; often not understood by enterprises onboarding Slack for sensitive use. Underexplored surface; no major CVEs yet. Slack AI integrations create emerging risk: prompt injection from a Huddle transcript can move sensitive data outside Slack's tenant.

Discord voice channels use a custom WebRTC-derived stack. Major surface is not voice/video parsing but **token theft**: infostealers harvest the Discord auth token from local storage, enabling impersonation. Attackers join voice channels, upload malware to Discord's CDN (served from trusted `cdn.discordapp.com`), perform social engineering, generate webhooks for C2. IBM X-Force Nov 2022 documented Discord channel messages as C2 in a POS-system attack. Broader API and CDN become C2 infrastructure for crimeware.

### Cross-Platform Pattern: Camera Activation Without Notification

Recurring: state-machine bugs where camera/mic activate without the indicator-light state matching. FaceTime (2019): activate before pickup. Zoom (March 2020, Wardle): library injection in trusted process. WhatsApp 2019 Pegasus: post-exploitation, attackers disable indicators via kernel privilege. Defence: trust the hardware LED only. Apple designs the Mac camera indicator so untrusted software, even with kernel privileges, cannot engage the camera without lighting it. Indicator-light-as-software is consistently bypassable.

---

## VI. SIP and Traditional VoIP

### SIP Protocol (RFC 3261)

Session Initiation Protocol — dominant signalling for traditional VoIP. Text-based request/response, methods `INVITE`, `ACK`, `BYE`, `CANCEL`, `REGISTER`, `OPTIONS`, `INFO`, `MESSAGE`. Carries SDP as body. Default UDP/5060, also TCP/5060 and TLS/5061. Typical flow: UAC `INVITE`; UAS `100 Trying` → `180 Ringing` → `200 OK` with SDP answer; UAC ACK; media P2P (or via RTP proxy); either side `BYE`.

Historical CVE corpus across Asterisk, FreeSWITCH, Kamailio, OpenSIPS reveals recurring classes: **digest-auth bypass** (nonce-handling, replay gaps, case-sensitivity); **header injection** (CRLF in attacker-controlled values — request smuggling, response splitting, log poisoning); **INVITE flooding / DoS**; **REGISTER hijacking** (register attacker contact for an existing user, redirecting incoming calls); **parser crashes** (SDP body, multipart, malformed `Contact`/`Via`).

### Toll Fraud and IRSF Economics

Shodan-discoverable Asterisk and FreeSWITCH installations are abundant. CFCA 2023 telecom fraud-loss estimate: $38.95 billion. Most common chain: Shodan/masscan finds exposed `5060/udp`; SIPVicious enumerates extensions; weak/default passwords cracked (extension number used as password is canonical); attacker registers as that extension; calls go to premium-rate international destinations the attacker controls via revenue-share. Victim's PBX is billed.

**IRSF** (International Revenue Share Fraud) is the canonical model. Attacker acquires/partners with a "high-tariff" destination (Caribbean with high termination fees, fake premium-rate ranges in Africa), routes calls through victim's PBX, splits revenue. Attack window is typically a weekend. A single compromised Asterisk can rack up $10K-$100K in fraudulent charges before carriers flag patterns.

### SIPVicious

Sandro Gauci's [SIPVicious OSS](https://pypi.org/project/sipvicious/): `svmap` scans for SIP devices, `svwar` enumerates extensions, `svcrack` dictionary-attacks passwords. Commercial SIPVicious PRO and ESAP extend to WebRTC fuzzing, TURN abuse testing, RTP-injection. DVRTC is Gauci's intentionally vulnerable lab.

### TLS Adoption for SIP

SIP-over-TLS (sips:) and SRTP remain poorly adopted in 2026: carrier-grade SIP trunks largely use unencrypted SIP between PBXes and carrier (TLS only at trunk-handoff); internal SIP between desk phone and PBX is often plaintext UDP; RTP is unencrypted by default. Anyone on the local network can capture and replay VoIP traffic with Wireshark and `voipmonitor`. The "CEO's office handset on the corporate VLAN unencrypted" problem is extant.

---

## VII. Voice Biometric and Voice Cloning Attack Surface

### The Voice-Cloning Industrial Complex

A handful of services produce convincing voice clones from seconds of source audio: **ElevenLabs** (canonical commercial API), **OpenAI Voice Engine** (announced March 2024, restricted; convincing clones from 15s samples), **Microsoft VALL-E / VALL-E 2** (research; 3s source), **Descript Overdub**, **Resemble.AI**, **Speechify**, **PlayAI**, **Lovo**. A March 2025 Consumer Reports investigation found ElevenLabs, Speechify, PlayAI, Lovo had no technical mechanism to confirm speaker consent — only check was a contractual click-through.

### The Arup $25M Deepfake Call (February 2024)

A finance employee at multinational engineering firm Arup, Hong Kong office, was deceived into transferring HK$200M (~US$25.6M) across 15 transactions to five bank accounts. Employee received an initial phishing email purporting to be from the UK CFO, was suspicious, and requested a video call to verify. The video call was held with "several members of staff" — all deepfake recreations built from publicly-available video and audio of the real executives. Satisfied by the visual and audio impersonation, the employee executed the wires. Fraud detected when the employee contacted UK HQ. Hong Kong police attribution: perpetrators built deepfakes from existing video and audio of online conferences. Sources: [CNN](https://www.cnn.com/2024/02/04/asia/deepfake-cfo-scam-hong-kong-intl-hnk), [Trend Micro](https://www.trendmicro.com/en_us/research/24/b/deepfake-video-calls.html). First publicly-documented multi-channel BEC plus video-deepfake fraud at this scale. Lesson: "verify on a video call" is no longer sufficient.

### Vishing 2.0 and Voice-Biometric Bypass

Canonical 2025-2026 patterns: **CEO call to AP/AR clerk** (voice clone + urgency + LinkedIn-derived context); **grandparent scam 2.0** ("I'm in jail/hospital, send bail money," clones built from public TikTok/Instagram); **romance-fraud verification** ("voice/video to prove I'm real"); **customer-support recovery** (impersonate customer to bypass voice-biometric). Q1 2025 deepfake-enabled fraud losses: $200M+ globally (Resemble AI). A UK energy firm lost €220,000 in 2019 to a single synthetic-voice CEO call.

Banks, brokerages, government services deploy voice biometrics as recognition factor. Default systems were designed against human-mimic, not neural cloning; synthetic voice from ElevenLabs and equivalents consistently bypasses (Group-IB 2024-2025). Defence: replace static voice-biometric with multi-factor — device-binding, behavioural patterns, live-challenge-response — or eliminate voice-biometric entirely. The static-voice-as-password model is broken. Cross-link: [[reference-anti-fraud-abuse-engineering]] §9.

### Apple Personal Voice — A Sanctioned Voice-Clone Surface

Apple's Personal Voice (announced May 2023, shipped iOS 17) lets users record 15 minutes of voice on-device and generate a synthetic voice mirroring their own. Intent: people facing progressive speech loss (ALS, head/neck cancer) preserve voice via Live Speech. Privacy claim: on-device ML, encrypted iCloud sync. Dual-use concern: the same technology packaged differently is voice-cloning-as-a-service. The accessibility framing creates a legitimate, supported, well-engineered voice-clone path inside Apple's privacy posture. Threat model assumes the user controls the recordings; device compromise allows exfiltration. Cryptography is strong but the policy boundary is the device.

---

## VIII. Real-Time Media Side-Channels

### Optical and Acoustic Recovery (Nassi Lineage)

**Visual Microphone** (Davis et al., MIT 2014; lineage's origin): recovers audio from minute vibrations of objects in a high-speed video camera frame — a potato-chip bag filmed through a closed window yields room audio. **Lamphone** (Nassi, Black Hat USA 2020): real-time passive optical sound recovery from a hanging light bulb at up to 25m via telescope + electro-optical sensor. **The Little Seal Bug** (WOOT 2023): audio from lightweight reflective objects. **Power-LED cryptanalysis** (Nassi, IEEE S&P 2024): standard video of target device's power LED at distance recovers ECDSA keys via subtle voltage-driven brightness fluctuations during crypto operations. **Reflections** in participant glasses or windows are well-known for extracting documents during video calls.

### Audio-Frequency Side-Channels

**DolphinAttack** (Zhang et al., CCS 2017): inaudible voice commands via ultrasonic carrier above 20 kHz, demodulated by microphone nonlinearity. Successfully activated Siri, Google Now, Cortana, Alexa, Samsung S Voice. Source: [arxiv 1708.09537](https://arxiv.org/abs/1708.09537). **NUIT** (2023): pre-recorded music on consumer speakers issues voice commands via the same path.

### "Your Conference Call Leaks More Than You Think"

Emerging research: **compression-artifact leakage** (codecs compress aggressively; artifacts leak which keys participant pressed via frame-by-frame finger-position changes); **background-noise fingerprinting** (identifies location; correlates participants across calls if in the same physical room); **network-traffic fingerprinting** (encrypted RTP packet rate correlates with speech-vs-silence; bitrate patterns identify specific spoken phrases against a training set). Cross-link: [[reference-hardware-side-channels]].

---

## IX. Privacy and Surveillance Vector

### Lawful Intercept and TURN MITM

Traditional telecom (PSTN, SIP trunk) is mandated to provide LI in most jurisdictions: US **CALEA** (1994) requires telcos to maintain a LI interface — SIP-trunk carriers comply via SIPREC (RFC 7245/7866) or proprietary mediation appliances. EU **ETSI LI** standards, per-country implementation. Consumer video conferencing (Zoom, Teams, Meet, WebEx) implements LI as server-side decryption-on-demand. The structural reason "end-to-end encrypted" claims need careful parsing: the platform may have an E2EE "mode" but the default is server-decryptable to enable LI.

If TURN-relay is the path, the TURN operator sees encrypted media stream pass through. Cannot decrypt SRTP (keys negotiated peer-to-peer) but learns IP addresses, timing, bitrate patterns. If the operator also runs signalling, they can substitute SDP fingerprints during offer/answer and mount transparent MITM — unless peers verify out-of-band. A TURN server in hostile jurisdiction is structural wiretap of every call routed through it.

### E2EE Claims vs. Reality

Cross-platform comparison (2026):

| Platform | E2EE by default? | E2EE optional? | What server can see |
|---|---|---|---|
| Signal (voice/video) | Yes | n/a | Metadata only |
| WhatsApp 1:1 / group | Yes | n/a | Metadata + SFU-side relay |
| FaceTime | Yes | n/a | Metadata |
| iMessage audio | Yes | n/a | Metadata; iCloud backup if enabled |
| Zoom meetings | No | Yes (paid+free with restrictions) | Audio/video/transcripts unless E2EE on |
| Microsoft Teams 1:1 | No | Yes (1:1 calls; meetings with Teams Premium) | All call content unless E2EE |
| Google Meet | No | Yes (client-side encryption requires customer KMS) | All call content |
| Slack Huddles | No | No | All Huddle content |
| Discord voice | Yes (DAVE; not Stage channels) | n/a | Metadata |
| Matrix (Element) | Yes (Olm / Megolm) | n/a | Metadata; depends on home-server trust |

Structural pattern: E2EE on-by-default in messengers built around 1:1 (Signal, WhatsApp, iMessage, FaceTime). E2EE opt-in or unavailable in collaboration/conferencing products. Business reason: E2EE breaks features customers value — recording, transcription, AI summarisation, PSTN dial-in, server-side virtual backgrounds, real-time captioning.

### Every Call Has at Least One Untrusted Hop

For high-risk targets, assume: signalling server is observable to platform operator; TURN server is in some jurisdiction subject to subpoena or coercion; endpoint device is compromisable (Pegasus and equivalent); the other party may be cooperating with surveillance. Defence: Signal-style E2EE with verified safety numbers, on hardened endpoint (iOS Lockdown Mode or equivalent), assumption any other channel is potential leakage. The full-stack threat model is what makes RTC security different from web security — a single bug in any layer becomes continuous surveillance.

---

## X. Real-Time Security on Web Platforms

### Same-Origin Policy in WebRTC

WebRTC's PeerConnection API is bound by SOP normally. But the DTLS-SRTP handshake is peer-to-peer (not browser-to-server), so the origin's TLS certificate doesn't bind the media path; IdP integration is rarely deployed, so the browser cannot natively confirm "I am talking to alice@example.com" — only "I am talking to whatever party signalling routed me to."

### getUserMedia and getDisplayMedia

Camera and mic access is permission-gated; Chrome and Firefox prompt on first access per-origin (red recording indicator, OS-level camera/mic LED on macOS). Bypass classes: permission-prompt fatigue; permission inheritance via iframes (parent page granted camera/mic embeds third-party iframes with `allow="camera; microphone"`); service-worker keep-alive abuse (modern browsers have hardened this).

`getDisplayMedia()` canonical info-leak: "Didn't realise I was still sharing." User shares screen, meeting ends, switches to bank login or HR portal — share is still live. Defence: persistent intrusive indicator while sharing; video-conf clients should stop sharing immediately when meeting ends.

### WebRTC IP-Leak Class

The canonical privacy bug: a malicious or compromised website creates a WebRTC PeerConnection (no user consent for connection setup, only for getUserMedia), runs ICE candidate-gathering, and reads local-IP and public-IP candidates from JS-visible PeerConnection state. Bypasses VPNs in the common configuration: VPN clients route layer-3 via tunnel, but the browser's WebRTC stack uses `getsockname()`-style OS APIs to enumerate local interfaces. Both VPN-tunnel IP and underlying physical-interface IP leak. In a VoidSec (Paolo Stagno) test, 16 of 70 VPN providers (23%) leaked users' IPs via WebRTC. Defence: browser-level WebRTC-disable (Firefox `media.peerconnection.enabled = false`, uBlock Origin toggle, Brave built-in), or VPN clients blocking local-network access at the OS firewall layer.

### Browser Fingerprinting via WebRTC

`RTCRtpReceiver.getCapabilities()` and similar APIs enumerate supported codecs, RTP extensions, browser-specific state. Combined with Canvas, WebGL, Audio API, contributes to high-entropy fingerprints. Cross-link: [[reference-browser-js-engine-exploitation]].

---

## XI. SFU and MCU Server-Side Architecture

### SFU vs. MCU

- **SFU (Selective Forwarding Unit)**: forwards encrypted media streams without transcoding. Each sender sends one stream up; SFU routes it to N receivers. Dominant modern architecture: Jitsi Videobridge, mediasoup, LiveKit, Janus, BigBlueButton, Daily.co, Zoom's MMR.
- **MCU (Multipoint Control Unit)**: receives all streams, transcodes into one composite. Legacy; used in WebEx (some paths) and enterprise telepresence.

SFUs do not need to decrypt media in SRTP if the application supports E2EE via Insertable Streams / SFrame. Without insertable streams, SFU terminates DTLS-SRTP, re-encrypts to each participant, and is a wiretap-by-design point. Structural reason "Zoom is E2EE" was contested before Oct 2020.

### Insertable Streams + SFrame for E2EE Over SFU

The application generates a per-meeting (or per-sender) symmetric key out-of-band. Sender's WebRTC encoder produces a video frame; before it is handed to SRTP, the application uses [Insertable Streams](https://www.w3.org/TR/webrtc-encoded-transform/) to apply an additional encryption layer using SFrame (RFC 9605, August 2024). Double-encrypted frame goes via SRTP to SFU. SFU decrypts the SRTP wrapper but sees only SFrame ciphertext inside, forwards re-wrapped in fresh SRTP. Receiver decrypts SRTP then SFrame.

True E2EE: SFU only ever sees SFrame ciphertext for frame contents. Can read SFrame headers (frame number, sender ID) for forwarding decisions but not frame content. [RFC 9605](https://datatracker.ietf.org/doc/rfc9605/) is payload-agnostic. Jitsi's E2EE implements a variant called JFrame using AES-128-GCM, with randomly generated per-participant keys distributed over Olm.

### SFrame Limitations and MLS

Published analysis (Isobe, Ito and Minematsu, IACR 2021/424) identifies the gap: SFrame does not provide per-sender authentication. Any sender can send media attributed to any other sender — symmetric encryption means any receiver also has the key to encrypt-as-sender. For E2EE multi-party with per-sender authentication, **MLS** (RFC 9420) is required — significantly more complex, with full asynchronous group-key-agreement and post-compromise security. Approved by IETF March 2023; provides forward secrecy, post-compromise security, async group key agreement scaling to thousands, TreeKEM tree giving O(log n) per group operation. Apple announced March 2025 it will support MLS in Apple Messages over RCS. Cross-link: [[reference-cryptography]].

### Key Rotation, Recording, Self-Hosted SFU

Three rotation models for E2EE conferencing: **per-meeting** (simple but breaks late-join); **per-join/leave** (MLS-aligned, expensive on churn); **periodic** (forward secrecy over time but no churn protection). Most products converge on MLS-aligned per-participant.

Server-side recording requires server-side decryption — terminating E2EE for the meeting. Must be surfaced clearly in UI; Zoom and Teams now show explicit "recording started" badges. Recording storage is its own threat model: vendor cloud subject to LI obligations; customer storage may be misconfigured (public S3 buckets are a recurring leak source).

Self-hosting (Jitsi Videobridge, mediasoup, Janus, BigBlueButton, LiveKit) lets the customer control the trust boundary. Operational complexity: public-facing SFU needs TURN in front for restrictive NATs; both need exposed UDP port ranges; TLS termination requires valid certificates and renewal automation; DTLS identity needs separate certificate management; libwebrtc CVEs land monthly. Most common failure: self-hosted Jitsi exposed with no authentication on room creation, allowing "Zoom-bombing" applied to self-hosted infrastructure.

---

## XII. Detection — Real-Time-Comms Anomaly

### Unusual Call Patterns (CDR-driven)

For orgs running their own PBX or SIP-trunk systems: **destination country/area-code anomaly** (typical office calls go to a stable set; sudden volume to premium-rate destinations `+881`, `+882`, specific Caribbean codes, `+225`, `+216`, `+211` is the toll-fraud signal); **off-hours outbound volume**; **per-extension volume spike** (10x normal is compromised or misconfigured auto-dialer); **repeated REGISTER attempts** (sequential extension registration is brute-force). Easy to capture from CDR logs — tools: `sec` (Simple Event Correlator), `fail2ban` with SIP regex rules, commercial products (SecAst, Sonus/Ribbon analytics).

CDRs are the canonical fraud-detection source — calling number, called number (E.164), start/end time, duration, routing path, disposition, per-call cost. A well-instrumented CDR pipeline produces toll-fraud alerts within minutes; many orgs only review CDRs after the carrier bill arrives — by which time fraud has been live for a month.

### Anomalous SIP Registration

Alert-worthy: REGISTER with `User-Agent` matching scanner tools (`friendly-scanner`, `sipsak`, `sipvicious`); REGISTER with `Contact` URI in different country/AS than expected; REGISTER from an IP that hasn't authenticated successfully in past 24h, even after the registration succeeds.

### TURN Traffic Anomaly

Open TURN abuse signals: traffic to destinations outside expected geographic footprint; bytes-relayed per tuple far exceeding voice/video profiles; long-lived allocations with low packet rate (looks like C2 tunnelling); allocations from clients that never establish a peer connection. Defence-in-depth: short-lifetime TURN credentials (5-min), bound to specific call ID, scoped to specific destination. Coturn's TURN REST API (`use-auth-secret` / `static-auth-secret`) provides time-limited credentials; many deployments use long-lived static credentials which makes abuse trivial.

### AI Voice Detection

Synthetic-voice classifiers attempt to distinguish AI-generated audio from human speech. Open research: ASVspoof Challenge (biennial since 2015). Commercial tools: Pindrop Deep Voice, ElevenLabs AI Speech Classifier. Cat-and-mouse: every new synthesis model defeats the previous detector. As of 2026, detection accuracy for SOTA clones is modest. Detection is part of the answer but cannot be the whole answer. Cross-link: [[reference-detection-engineering]] §3, [[reference-anti-fraud-abuse-engineering]] §9.

---

## XIII. Defensive Patterns

### End-to-End Encryption with Verified Keys

Default to E2EE where the product allows. 1:1: Signal Protocol or equivalent. Multi-party: SFrame (RFC 9605) inside Insertable Streams, or MLS (RFC 9420). **Verify the keys.** Safety-numbers (Signal), Security Codes (WhatsApp), DTLS fingerprint comparison (manual) are the only defences against signalling-server MITM. Mechanism only works if users actually compare. For high-risk targets, formal verification should be SOP.

### Display Verifiable Identity

The IdP-integration in RFC 8827 is the strongest model but rarely deployed. For enterprise, an internal IdP (Okta, Azure AD, Google Identity) could issue per-call identity assertions bound to DTLS fingerprints. Pragmatic alternative: display the caller's verified email or display-name from the signed JWT used for meeting access, alongside a "verified by your IdP" badge.

### Disable WebRTC IP-Leakage in Privacy-Sensitive Contexts

For high-risk users: browser-level WebRTC-disable is standard hygiene — Firefox `media.peerconnection.enabled = false`; Chrome via WebRTC Leak Prevent extension; Brave built-in controls; uBlock Origin toggle.

### Rate-Limit and Authenticate TURN

Never deploy an open TURN server. Required: short-term credentials (≤ 5 min, bound to specific meeting ID — Coturn `lt-cred-mech` with REST API hooks); rate limiting (per-client allocation count, per-allocation bandwidth caps); destination filtering (forward only to peers in valid meetings); bandwidth monitoring (alert on allocations exceeding RTC profiles — real call ~500 kbps - 3 Mbps; tunneling-abuse often 50+ Mbps for hours).

### Codec Library Hygiene and Sandboxing

libwebrtc, libvpx, libwebp, libavif, libaom, libopus, OpenH264 need tracking and patching ([[reference-supply-chain-provenance]]). For native apps bundling libwebrtc: tracking M-1 (one Chrome milestone behind) is the operational minimum; trunk is preferred for security-critical apps. Codec parsing and SRTP processing should run in a lower-privilege process. Chrome's renderer is sandboxed; Firefox's RDD isolates codec decode. Native apps should follow: split RTC parsing into a sandboxed subprocess with no filesystem or network access beyond what the parser requires ([[reference-browser-js-engine-exploitation]] §6).

### Lawful-Intercept Transparency

If your product supports lawful intercept (or your jurisdiction mandates it), disclose it. The transparency-report model (Apple, Google, Microsoft publish LI reports) is the consumer-facing standard.

### Anti-Voice-Cloning for High-Value Voice Authentication

For any system where a phone or video call authorises a financial transaction, identity change, or other high-impact action: **live-challenge-response** (caller repeats a randomly generated phrase the clone could not have been pre-trained on; real-time, not pre-recorded); **behavioural patterns** (speech rhythm, pause patterns vs. historical baselines — clones consistently fail behavioural mimicry); **multi-channel confirmation** (different channel: SMS to known number, in-person, internal-chat ack — Arup deepfake fraud succeeded because no OOB confirmation was required); **time-delay on novel destinations** (wire to a destination not on the historical whitelist triggers a 24-48h cancellable hold).

### Recording-Consent and Retention

Explicit consent before recording starts (many jurisdictions — California, EU — require all-party consent); persistent prominent UI indicator; short default retention (30-90 days); long-term retention requires explicit policy classification; access logging. Treat recordings as sensitive documents. Cross-link: [[reference-privacy-engineering]].

### Code Review Checklist

1. libwebrtc from a maintained tree, no more than 1 milestone behind Chrome stable?
2. Media parsing isolated in a sandboxed process or thread?
3. SDP fields validated for length/format before being passed to libwebrtc?
4. ICE candidates validated for plausibility (no internal-IP candidates from external peers)?
5. Application verifies peer's DTLS fingerprint against an authenticated source?
6. TURN credentials short-lived (≤ 5 min) and scoped to a specific meeting?
7. User consent required before any camera/mic access? Prominent hardware-tied indicator while active?
8. Signalling channel TLS-terminated with certificate validation enabled?
9. For multi-party: E2EE via SFrame or equivalent? Per-participant key rotation?
10. Recordings explicitly user-consented and surfaced in UI?
11. Codec library versions tracked in SBOM and monitored for CVEs?
12. Logged-out / signed-out path that cleanly tears down all media streams?

---

## XIV. Variant Analysis — Under-Explored Surfaces

### AI-Agent Voice Calls

LLM-driven agents placing phone calls or joining video calls on behalf of users — OpenAI's Realtime API (Uberti's charter), Vapi, Bland.ai, Hume's Octave, dozens of voice-agent startups launched 2024-2026. Threat surface: **prompt-injection from call audio** (remote party speaks an instruction the LLM interprets as user instruction — standard prompt-injection class, audio rather than text; [[reference-llm-agent-security]]); **tool-use chained from a call** (agent has access to tools — place orders, look up records, transfer money; malicious caller manipulates); **voice-spoofing the agent** (attacker plays recording of legitimate user's voice during call setup); **agent-on-agent** (two voice agents in conversation, each potentially manipulating the other — the "Operator calls customer support" pattern where neither party is human). Moving fast; expect the first major public incident within the year.

### AR/VR Multi-User Spaces

Apple Vision Pro's Persona (shipped early 2024) generates a 3D rendered face from a brief capture, animated during FaceTime. Meta Horizon Worlds and Microsoft Mesh similarly mediate multi-user AR/VR. Novel attack surface: **Persona-spoofing** (attacker manipulates Persona-generator input or uses high-quality recordings — Arup pattern applied to AR); **spatial-audio side-channel** (spatial audio in VR rooms leaks more about other participants' physical environments than 2D — where standing? what typing?); **gaze tracking** (AR/VR headsets capture continuous gaze data; an untrusted app observes what user is looking at).

### 5G Voice (VoNR / VoLTE)

4G voice was VoLTE using SIP within the IMS. 5G voice is VoNR over the same IMS architecture. IMS SIP signalling is largely unencrypted on the operator's own backhaul — adversary in the operator's network has same wiretap capability as PSTN. Inter-operator handoff introduces SS7-class trust assumptions ([[reference-dns-network-infrastructure]] §VIII). VoNR adoption is uneven; many networks fall back to VoLTE or 4G CSFB, each fallback weakening posture.

### Cross-App Real-Time-Comms Hijacking

Universal Link / App Link / deep-link hijacking on mobile can redirect a `tel:` or `facetime:` URI to an attacker-controlled app. Attacker publishes an app registered as handler; user clicks meeting link; attacker's app intercepts and displays UI mimicking the legitimate app, capturing credentials or proxying through attacker infrastructure. Both iOS and Android have hardened this (Universal Links require `apple-app-site-association` domain verification; App Links require Digital Asset Links), but surface remains for users who accept the attacker's handler.

### WebTransport and WebCodecs

**WebTransport** (over QUIC) replaces WebSockets for low-latency bidirectional comms — likely substrate for next-gen RTC stacks. Same parser-bug class as WebRTC, fresh codebase; expect 0-days as adoption rises. **WebCodecs** exposes browser-native codec decoders to JavaScript, adopted by some experimental WebRTC stacks. Security implication: codec parsing was previously confined to the browser media pipeline; WebCodecs exposes it as a JS-callable surface from a hostile origin. Decoders run sandboxed in the renderer but the bug-class is unchanged — codec parser bugs lead to RCE in renderer, prelude to sandbox escape.

---

## XV. References

### IETF RFCs

[RFC 3261 SIP](https://datatracker.ietf.org/doc/html/rfc3261), [RFC 3711 SRTP](https://datatracker.ietf.org/doc/html/rfc3711), [RFC 4566/8866 SDP](https://datatracker.ietf.org/doc/html/rfc8866), [RFC 5389/8489 STUN](https://datatracker.ietf.org/doc/html/rfc8489), [RFC 5764 DTLS-SRTP](https://datatracker.ietf.org/doc/html/rfc5764), [RFC 5766/8656 TURN](https://datatracker.ietf.org/doc/html/rfc8656), [RFC 7714 AES-GCM for SRTP](https://datatracker.ietf.org/doc/html/rfc7714), [RFC 8445 ICE](https://datatracker.ietf.org/doc/html/rfc8445), [RFC 8827 WebRTC Security Architecture](https://datatracker.ietf.org/doc/html/rfc8827), [RFC 8838 Trickle ICE](https://datatracker.ietf.org/doc/html/rfc8838), [RFC 9000 QUIC](https://datatracker.ietf.org/doc/html/rfc9000), [RFC 9147 DTLS 1.3](https://datatracker.ietf.org/doc/html/rfc9147), [RFC 9420 MLS](https://datatracker.ietf.org/doc/html/rfc9420), [RFC 9605 SFrame](https://datatracker.ietf.org/doc/rfc9605/), [RFC 9725 WHIP](https://datatracker.ietf.org/doc/rfc9725/).

### W3C Specifications

[WebRTC 1.0](https://www.w3.org/TR/webrtc/), [Encoded Transform / Insertable Streams](https://www.w3.org/TR/webrtc-encoded-transform/), [Media Capture and Streams](https://www.w3.org/TR/mediacapture-streams/), [Screen Capture](https://www.w3.org/TR/screen-capture/), [WebCodecs](https://www.w3.org/TR/webcodecs/).

### Project Zero — Silvanovich Series

[Part 1 WebRTC](https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-1.html), [Part 2 FaceTime](https://projectzero.google/2018/12/adventures-in-video-conferencing-part-2.html), [Part 5 Where Do We Go from Here?](https://projectzero.google/2018/12/adventures-in-video-conferencing-part-5.html), [Exploiting Android Messengers with WebRTC: Part 3](https://projectzero.google/2020/08/exploiting-android-messengers-part-3.html), [The State of State Machines](https://projectzero.google/2021/01/the-state-of-state-machines.html), [Zooming in on Zero-click Exploits](https://googleprojectzero.blogspot.com/2022/01/zooming-in-on-zero-click-exploits.html), [Street Party tooling](https://github.com/googleprojectzero/Street-Party).

### Incidents and Audit Reports

- Citizen Lab: [Move Fast and Roll Your Own Crypto](https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/), [Zoom Waiting Room Vulnerability](https://citizenlab.ca/2020/04/zooms-waiting-room-vulnerability/), [FAQ on Zoom Security Issues](https://citizenlab.ca/2020/04/faq-on-zoom-security-issues/)
- [Objective-See blog 0x56 — Zoom macOS vulnerabilities](https://objective-see.org/blog/blog_0x56.html); FaceTime Family Bug: [Washington Post](https://www.washingtonpost.com/technology/2019/02/08/apple-releases-facetime-fix-rewards-year-old-who-discovered-eavesdropping-bug/)
- WhatsApp Pegasus: [NVD CVE-2019-3568](https://nvd.nist.gov/vuln/detail/CVE-2019-3568), [Hacker News on NSO 2024 court filings](https://thehackernews.com/2024/11/nso-group-exploited-whatsapp-to-install.html)
- libvpx / libwebp CVEs: [Akamai Guidance](https://www.akamai.com/blog/security-research/guidance-on-critical-chrome-vulnerabilities-libwebp-and-libvpx), [Cloudflare on CVE-2023-4863](https://blog.cloudflare.com/uncovering-the-hidden-webp-vulnerability-cve-2023-4863/), [NVD CVE-2023-7024](https://nvd.nist.gov/vuln/detail/cve-2023-7024)
- SFrame / Insertable Streams: [webrtcHacks](https://webrtchacks.com/true-end-to-end-encryption-with-webrtc-insertable-streams/), [Meetrix Jitsi E2EE](https://meetrix.io/blog/webrtc/jitsi/end-to-end-encryption-on-jitsi.html), [Security Analysis of SFrame (IACR 2021/424)](https://eprint.iacr.org/2021/424.pdf)
- Arup deepfake: [CNN](https://www.cnn.com/2024/02/04/asia/deepfake-cfo-scam-hong-kong-intl-hnk), [Trend Micro](https://www.trendmicro.com/en_us/research/24/b/deepfake-video-calls.html), [Group-IB](https://www.group-ib.com/blog/voice-deepfake-scams/)
- Side channels: [Lamphone](https://www.nassiben.com/lamphone), [DolphinAttack arxiv 1708.09537](https://arxiv.org/abs/1708.09537)
- Tooling: [SIPVicious on PyPI](https://pypi.org/project/sipvicious/), [Enable Security blog](https://www.enablesecurity.com/blog/), [ms-teams-rce](https://github.com/oskarsve/ms-teams-rce), [Slack Huddles security](https://slack.com/help/articles/115003560786-Security-for-Slack-huddles), [Apple Personal Voice](https://www.apple.com/newsroom/2023/05/apple-previews-live-speech-personal-voice-and-more-new-accessibility-features/)

### Implementations Worth Studying

[libwebrtc](https://webrtc.googlesource.com/src/), [libvpx](https://chromium.googlesource.com/webm/libvpx/), [Jitsi Videobridge](https://github.com/jitsi/jitsi-videobridge), [mediasoup](https://github.com/versatica/mediasoup), [Janus](https://github.com/meetecho/janus-gateway), [LiveKit](https://github.com/livekit/livekit), [coturn](https://github.com/coturn/coturn), [Asterisk](https://github.com/asterisk/asterisk), [Kamailio](https://github.com/kamailio/kamailio).

### Cross-Reference

[[reference-http-web-security]] (TLS, WebSocket signalling), [[reference-cryptography]] (DTLS, SRTP, MLS), [[reference-browser-js-engine-exploitation]] (codec parsing, sandbox model), [[reference-mobile-security]] (FaceTime 0-click, WhatsApp Pegasus, iOS Lockdown Mode), [[reference-anti-fraud-abuse-engineering]] (voice cloning, multi-channel BEC), [[reference-privacy-engineering]] (recording consent, LI transparency), [[reference-detection-engineering]] (CDR anomaly, TURN monitoring, AI-voice classifiers), [[reference-fuzzing-discipline]] (codec / RTP mutation fuzzing), [[reference-supply-chain-provenance]] (libwebrtc / libvpx / libwebp SBOM), [[reference-dns-network-infrastructure]] (SS7, telco architecture), [[reference-hardware-side-channels]] (optical and acoustic side channels), [[reference-llm-agent-security]] (AI-voice-agent surface, prompt injection over audio).
