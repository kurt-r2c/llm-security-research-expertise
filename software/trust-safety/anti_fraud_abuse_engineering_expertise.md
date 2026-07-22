# Anti-Fraud, Anti-Bot, and Abuse Engineering
## Synthesized from Brian Krebs, Stefan Savage, Geoffrey Voelker, Damon McCoy, Vern Paxson, Niels Provos, Marcus Hutchins, Sam Curry, Troy Hunt, Sergi Isasi, Patrick Donahue, and Lily Hay Newman

> **Researchers and practitioners:**
> - **Brian Krebs** — Independent investigative journalist; founder of *KrebsOnSecurity*
>   (December 2009) after fourteen years at *The Washington Post* covering tech policy
>   and computer security. Author of *Spam Nation: The Inside Story of Organized
>   Cybercrime — from Global Epidemic to Your Front Door* (Sourcebooks, 2014; PROSE
>   Award 2015). His November 2008 investigative series on the bulletproof host
>   McColo led to upstream disconnection and a measurable global drop in spam
>   volume — one of the few cases in cybercrime journalism where the artifact moved a
>   measurable global signal. The Krebs beat is end-to-end fraud economics: who pays
>   the affiliates, where the money flows, what the take-rates are.
> - **Stefan Savage** — Professor of CSE at UC San Diego; MacArthur Fellow (2017);
>   elected to the National Academy of Engineering. Co-leads (with Geoffrey Voelker)
>   UCSD's long-running program on cybercrime economics, funded in part by a five-year
>   $10M NSF grant. The "value chain of spam" line of work — tracing the technical and
>   economic relationships that make spam profitable, and identifying the credit-card-
>   acquiring bottleneck — is the canonical empirical-economics-of-cybercrime artifact.
> - **Geoffrey Voelker** — Professor of CSE at UC San Diego; long-running collaborator
>   with Stefan Savage on cybercrime measurement. Developer of Spamscatter (which
>   followed spam URLs through redirection to destination servers) and co-author on
>   canonical analyses of phishing kits, malware distribution, and botnet
>   infrastructure economics.
> - **Damon McCoy** — Professor of CSE at NYU Tandon. Research focus: empirically
>   measuring the security, privacy, and abuse properties of technology systems.
>   Doctoral pedigree from the UCSD lineage; author of the first quantitative doxing
>   measurement and a body of work on election-official online harassment,
>   content-moderation metrics, and underground-market measurement. The
>   measurement-first stance — count the abuse, then design the defense — is the
>   through line.
> - **Vern Paxson** — Professor of CS at UC Berkeley; researcher at ICSI and Lawrence
>   Berkeley National Laboratory. Original author of Bro (now Zeek), the network
>   monitoring system used operationally since 1996. Co-founder of Corelight. Author
>   of seminal measurement studies on Twitter spam, account-trafficking underground
>   markets, and the domain-registration behavior of spammers.
> - **Niels Provos** — Distinguished Engineer at Google 2003–2018 working on security,
>   privacy, and abuse; joined Lacework (now Fortinet) as Head of Security Efficacy
>   in 2022. PhD from Michigan; author of *A Virtual Honeypot Framework* (USENIX
>   Security 2004), *Preventing Privilege Escalation* (USENIX Security 2003) on
>   OpenSSH privilege separation, and *A Future-Adaptable Password Scheme* (bcrypt).
>   His Google-scale abuse-fighting decade anchors much of what is publicly known
>   about abuse engineering as a discipline.
> - **Marcus Hutchins** ("MalwareTech") — Independent malware and threat-intel
>   researcher; registered the killswitch domain that halted WannaCry in May 2017.
>   Operates the *MalwareTech* blog with deep reverse-engineering of contemporary
>   malware and the fraud-economy tooling stack (Kronos banking-trojan family,
>   loader ecosystems, info-stealer corpus).
> - **Sam Curry** — Independent appsec researcher; founder of Palisade Security. Over
>   US$500,000 in cumulative bug-bounty rewards by 18. Lead author of *Web Hackers
>   vs. The Auto Industry* (January 2023), disclosing critical account-takeover
>   vulnerabilities affecting BMW, Rolls-Royce, Mercedes, Porsche, Ferrari, Honda,
>   Hyundai, Kia, Toyota, Nissan. His disclosure corpus is the modern reference for
>   "how account-takeover actually happens at production-grade companies."
> - **Troy Hunt** — Independent security researcher; founder (December 2013) and
>   maintainer of *Have I Been Pwned* (HIBP). Architect of the k-anonymity Pwned
>   Passwords API (with Cloudflare), now serving 2+ billion queries per month and
>   ingesting an FBI / UK National Crime Agency feed. The k-anonymity range-query
>   design is the canonical example of "let the world check credential exposure
>   without ever telling you which credential they checked."
> - **Sergi Isasi** — Former Director of Product (Bot Management) at Cloudflare and VP
>   of Product for Application Performance and Security; led Bot Management product
>   development through the period in which Cloudflare's ML-driven bot-score model
>   became the dominant public reference architecture for behavioral bot detection at
>   internet scale.
> - **Patrick Donahue** — VP of Product, Application Security at Cloudflare. Long-running
>   public voice for the integrated WAF-plus-bot-management-plus-fraud-detection
>   product family.
> - **Lily Hay Newman** — Senior Writer at *WIRED* covering information security,
>   digital privacy, and hacking. The contemporary general-purpose journalist most
>   consistently covering the production-engineering side of fraud and T&S
>   incidents — SIM farms, info-stealer markets, account-security feature rollouts,
>   regulatory frontiers.
>
> **Sources:** *KrebsOnSecurity.com*; UCSD Systems and Networking Group publications;
> Damon McCoy NYU publication list; Vern Paxson ICIR papers archive; Niels Provos
> Google Scholar profile; *MalwareTech* blog; samcurry.net disclosure archive;
> troyhunt.com and HIBP documentation; *The Cloudflare Blog* bot-management archive;
> *WIRED* security archive; TSPA Curriculum; Stripe Radar product documentation; the
> Twilio / Stytch / Sardine / Akamai SMS-pumping technical references; NIST SP
> 800-63B-4 (July 2025); C2PA specification v2.4; Kirchenbauer et al.
> *A Watermark for Large Language Models* (ICML 2023); *GLTR* (MIT-IBM Watson AI Lab
> / HarvardNLP) and *DetectGPT* (Mitchell et al., 2023); Microsoft PhotoDNA; Tech
> Coalition TRUST Framework; the 9th Circuit *hiQ Labs v. LinkedIn* opinion and
> December 2022 settlement; FoxIO's JA4+ specification; APWG quarterly reports;
> Meta Adversarial-Threat reports; public CSO/CISO reporting through May 2026.

---

## 1. The Threat Model — Abuse as a Security Discipline

### Anti-abuse is structurally distinct from traditional appsec

A traditional appsec program optimizes against bugs the developer wrote.
Authentication bypass, SQL injection, SSRF: each one is a defect in the code; the
fix is a patch; the cost-to-attack is bounded by attacker effort to find the next
bug. Anti-abuse is different in three ways that matter for program design.

First, **the attacker is not exploiting a bug**. A credential-stuffer is sending
real HTTP POSTs to your real login endpoint with real (stolen) credentials. The
endpoint is doing exactly what it was built to do. No CVE will issue.

Second, **the attacker's economic model is dollar-denominated**. Spam, carding,
scraping, ATO, fake accounts, SMS pumping — these all map directly to revenue.
The defense problem is *raising the cost curve until your platform is no longer
the cheapest target*, not removing the bug.

Third, **the defender operates at billion-event-per-day scale with sub-1% error
budget**. A WAF that blocks 1% of legitimate logins is unshippable; a WAF that
admits 1% of attacks is a disaster. Every defense decision is a multi-armed-bandit
problem with FN and FP both costed in money.

The discipline that has emerged from this — anti-fraud, anti-abuse, or T&S
engineering — is the runtime-economic dual of static appsec. It is to appsec what
[[detection_engineering_expertise]] is to static analysis: same hypothesis-testing
discipline, different substrate.

### The success-creates-abuse axiom

If your product is successful, it will be abused. This is structural, not
contingent. Any product that creates positive expected value for a user creates
positive expected value for someone who has not paid for it. Corollaries:

- **A signup form** is inventory for spam, fake-engagement, and SMS-pumping
  campaigns. Phone-verification is itself an abuse surface (toll fraud).
- **A login form** is reached by credential stuffing; the cost-of-attack is the
  cost of a credential dump (effectively zero) plus rotation hardware.
- **An API endpoint** is abuse surface whether you priced it or not.
- **A messaging feature** carries spam, harassment, CSAM, hate speech, CIB.
- **A payment feature** invites card-testing, refund fraud, chargeback fraud.
- **An LLM feature** is free GPU — see §10.

Abuse cost scales linearly with adoption and roughly quadratically with reputation.
Plan anti-abuse spend as a function of growth, not as fixed headcount.

### Adversary economics: moving the cost curve

The most important framing: **the attacker has a P&L**. The defender's job is not
to make attack impossible — that is infeasible — but to make it *unprofitable*.

Attacker expected profit per unit time:
`Profit = N × p_s × V_s - N × C_a`

where `C_a` is per-event attack cost, `p_s` the per-event success probability,
`V_s` per-success value, `N` events per unit time. Defender levers move three of
these four variables (you rarely move `V_s`):

- **Raise `C_a`**: rate limiting, CAPTCHAs, device-fingerprinting, JA4 friction.
- **Lower `p_s`**: 3DS2 step-up, MFA, behavior-anomaly blocking.
- **Cap `N`**: per-IP, per-account, per-device, per-cluster rate limiting.

The art is choosing which lever to pull for which traffic. Universal CAPTCHA
raises `C_a` for everyone including legitimate users — unshippable for most
consumer products. Adaptive CAPTCHA that fires only above a risk threshold
raises `C_a` for the suspect cluster while preserving legitimate-user UX.

### The scale-economics of abuse

Two further framings, load-bearing for program design.

**Small per-event × big N is the unique abuse failure mode**. A SQL injection
matters at one exploit; a credential-stuffing campaign matters at ten million.
The per-event win for the attacker is often pennies; the per-event cost for the
defender is often pennies. Total stakes are per-event × event-count, and
event-count is set by attacker infrastructure, not by your product. Defenses must
be cheap enough per-event that the defender can run them universally.

**The defender's tail risk is correlated, not idiosyncratic**. A single ATO is
a CS ticket. Ten thousand ATOs in four hours is a regulatory disclosure event,
a press cycle, and a churn driver. The distribution is heavy-tailed: the median
day is fine, the bad day is catastrophic. Staff for the tail, not the median.

### Abuse taxonomy

| Category | Per-event win | Typical scale | Section |
|---|---|---|---|
| Credential stuffing | Account access ($1–$50) | 10⁸–10⁹/day | §2 |
| Account takeover | $50–$500+ per account | 10⁵–10⁷/day | §3 |
| Bot scraping / API abuse | Data value (variable) | 10⁶–10⁹/day | §6 |
| Fake accounts (sybils) | Future-value-per-account | 10⁴–10⁷/day | §7 |
| Payment fraud (CNP) | $50–$5000 per success | 10⁴–10⁶/day | §5 |
| Spam / unsolicited messaging | $0.001–$1 per conversion | 10⁹/day at peak | §8 |
| CSAM / harmful content | (regulatory) | varies | §8 |
| AI-content abuse | (per-platform) | 10⁵–10⁹/day | §9 |
| Generation-cost amplification | Free compute ($) | 10³–10⁶/day | §10 |
| SMS toll fraud / pumping | $0.05–$0.50 per message | 10⁵/day per victim | §7 |

Cross-link to [[detection_engineering_expertise]] for the SOC-rule side and
[[threat_intel_methodology_expertise]] for the intel-feed side.

---

## 2. Credential Stuffing Defense

### The threat and its economics

Bulk replay of leaked credentials against a target's login endpoint to find
working accounts. The attacker does not need to break your authentication; the
attacker only needs to find users reusing passwords. Reuse rates remain 60–70%
across two-or-more services in 2026.

Input cost for the attacker is effectively zero — HIBP alone contains ~14B
compromised credentials. Specialized dumps on Telegram cost cents per thousand.
Infrastructure (residential proxies, IP rotation, TLS fingerprint randomization)
runs $1–$10 per million attempts. Per-success value is $1–$50 for consumer
services, much higher for financial. Break-even hit rates of 1-in-millions are
easy to clear; credential stuffing is structurally profitable.

### HIBP and password-rejection-at-signup

Troy Hunt's HIBP Pwned Passwords API is the canonical first-line defense via
k-anonymity range queries: client SHA-1 hashes the password, sends the first 5
hex characters to the API, gets back all matching hashes plus seen-counts, checks
locally. The API never learns the queried password. Use at signup (reject this),
at password-change (reject this new one), opportunistically at login (warn).
Free, sub-100ms, privacy-auditable. NIST SP 800-63B-4 (final July 2025) explicitly
endorses the pattern at AAL2 and above ("comparison against a list of compromised
values"). Any platform not blocking known-breached passwords in 2026 operates
below the industry baseline.

### Detection signal stack

Per-username: login velocity (>1/sec), failed-to-success ratio, geographic
anomaly. Per-IP: aggregate failure rate against many usernames (the attacker's
IP pool is too small), TLS fingerprint mismatch (JA3/JA4) vs claimed UA, HTTP/2
fingerprint mismatch. Behavioral: no browser-rendered preamble before POST,
millisecond-precision form-fill timing.

The classifier consuming these signals operates at the per-event level (line-rate
edge classification) and produces a calibrated risk score, not a binary verdict.
The score becomes the input to the challenge-decision layer in §4.

### Layered rate limiting

Per-username (any IP attempting alice@example.com shares the same budget),
per-IP, per-ASN/-network, per-UA, **per-behavioral-cluster** (the production-
grade key: hash the attacker's behavioral fingerprint, rate-limit on the hash).
The IP space is too cheap; behavioral-cluster space is where the cost sits.

### Adaptive challenges — never universal

The single most important doctrine in credential-stuffing defense: **challenge
only suspect traffic**. A universal CAPTCHA at login is product-suicide. The
right architecture:

1. **Always-on signals** fingerprint, score, and profile every request.
2. **Risk-threshold challenge** fires only on high-score traffic.
3. **Progressive challenge** — a failed challenge raises the threshold for the
   next attempt; a successful one lowers it.
4. **Differential per-action thresholds** — log-in is one threshold; password
   change is another; payment-add is another.

The metric is **friction budget**: total friction imposed on legitimate users
per unit time, measured in CAPTCHA-equivalents. Each product has a budget; the
goal is to spend it on the right events.

### Passkeys as the structural endgame

For passkey-enrolled users, credential stuffing is structurally impossible —
there is no password to leak. The defender's strategic question is **how to get
more users to enroll**: default-on at signup, prompt at signin after password
login, and design recovery flows that do not recreate the vulnerability. Every
consumer product should support passkeys by 2026; every B2B product should
require them by 2027. Cross-link to [[cryptography_expertise]] §passkeys for
the WebAuthn ceremony and attestation details.

### Cross-links

[[distributed_authz_expertise]] §6 (OAuth threat model);
[[detection_engineering_expertise]] §3 (Sigma rules on cluster anomalies);
[[saml_federation_expertise]] §6 (federation-layer session security).

---

## 3. Account Takeover (ATO) Protection

### The post-credential-compromise phase

ATO is what happens after the credential is valid: the attacker is now logged in.
Defense shifts from "is this login legitimate" to "is this session legitimate now
that it has authenticated."

The dominant ATO vector in 2026 is not password-stuffing but **session-cookie
theft via info-stealer malware** — Stealc, Lumma, RedLine, Atomic. Cookies,
autofill credentials, browser session storage are bundled and sold on Russian
Market, 2easy, and Telegram-native shops for $1–$50. The attacker replays the
session cookie and is logged in *without ever hitting the login endpoint*,
bypassing credential-stuffing defenses entirely. The log includes fingerprint and
IP, so the attacker can also approximate the victim's browser environment.

### Session-anomaly detection

- **Device-fingerprint change**: attacker has cookies, not the device (canvas /
  WebGL / font / audio fingerprints differ). Cheapest signal; spoofable.
- **Impossible travel**: same as §2 but post-login. Unambiguous when present.
- **Behavioral drift**: user reads emails slowly; session now bulk-downloads
  500 attachments and forwards externally.
- **IP reputation**: residential proxy or Tor exit. Contributory, not blocking.
- **Account-recovery pattern**: the attacker tries to change recovery email and
  password — the most reliable post-ATO signature.

### Risk-based step-up

The pattern that has converged across Google, Microsoft, Apple, GitHub, banks,
and major SaaS: the session is authenticated and active; when the user attempts
a **sensitive action** (password change, recovery-email change, payment-method
add, large transfer, OAuth-app authorization, data-export, account-deletion,
admin privileged operation), the risk model scores the current session; if the
score exceeds the threshold *for that action*, the user is challenged. Successful
challenge relaxes the score for N minutes.

The key is **action-specific thresholds**. A logged-in session reads email at
risk-score 0.9 (the trust budget for "the user is logged in" is mostly spent
there) but cannot change the recovery email at the same score. Friction is
concentrated on the attacker's payoff actions.

### Post-ATO forensic pattern

Once in, the attacker executes a stereotyped sequence — every step is a detection
rule:

- Email-rule injection (forward security alerts to external, delete from inbox).
- Recovery-email and recovery-phone change.
- Password change.
- MFA factor removal / replacement.
- Payment method add.
- OAuth-app authorization (long-lived tokens survive password reset).
- Data exfiltration.

Any two of these within 24 hours on a freshly-authenticated session is a strong
ATO signal regardless of login-time risk. See [[detection_engineering_expertise]]
§3 for Sigma-style encoding.

### Sam Curry's automotive ATO corpus

Sam Curry's January 2023 *Web Hackers vs. The Auto Industry* is the textbook
for "where ATO actually lives." Mercedes SSO permitting access to internal
applications; BMW/Rolls-Royce account takeover allowing remote vehicle control
by knowing only the VIN; Kia/Hyundai full takeover via a single API call. None
required password compromise. The Curry corpus generalizes: ATO at scale is
rarely about password strength — it is about misconfigured SSO, leaky API
gateways, OAuth scope misuse, and account-recovery flow bugs.

### Cross-links

[[saml_federation_expertise]] §6 (federation-layer session, token lifetime);
[[distributed_authz_expertise]] §6 (OAuth-app-grant vector);
[[detection_engineering_expertise]] §6 (identity-plane Sigma rules).

---

## 4. Bot Detection and CAPTCHA Economics

### CAPTCHA-as-tax

The 2001 "tell humans from computers" framing died around 2017 when commodity
vision models reached human-equivalent CAPTCHA-solving rates. The contemporary
framing is **CAPTCHA is a tax on attackers**. The attacker pays a solving-as-a-
service ($0.50–$3 per 1000 for reCAPTCHA v2, sub-cent per challenge for AI
solvers in 2026), runs an in-house ML solver, or quits.

The structurally valuable CAPTCHA is the *invisible* one that runs in the
background harvesting behavioral signals and escalates to a visible challenge
only for high-risk traffic.

### reCAPTCHA v2 → v3 → Enterprise; hCAPTCHA; Turnstile

reCAPTCHA v3 (2018) eliminated the visible challenge for most users and exposed
a 0.0–1.0 risk score; the integrator decides allow/MFA/block thresholds.
reCAPTCHA Enterprise (2020+) added ML-driven account-defender modules for
credential-stuffing, fake-account, and SMS-pumping detection.

hCAPTCHA (Intuition Machines, 2018) ships similar mechanics with explicit "we
don't train Google's ML" positioning; Cloudflare Turnstile (2022) provides the
zero-friction option for sites already behind Cloudflare. The three products are
fungible on technical effectiveness; choice is governance and policy.

### Behavioral biometrics

Mouse-movement smoothness, typing-rhythm variance, scroll patterns, touch-event
pressure variance, gyroscope drift. The signal is most powerful at the *session*
level: a session whose behavioral envelope is consistent with one human across
N minutes is real; a session that switches mid-flight is a hijack or bot-
handoff. BioCatch, BehavioSec (LexisNexis), Imperva ABP, Castle, ThreatMetrix
commercialize this stack.

### TLS and HTTP/2 fingerprinting

TLS fingerprinting works at the network layer before any browser JS runs. The
attacker's HTTP-level identity (UA string) is cheap to spoof; the TLS-level
identity is much harder.

**JA3** (Salesforce 2017) hashes the TLS Client Hello (version, ciphers,
extensions, curves, EC formats). Real Chrome has a known JA3; `requests` has a
different one; curl another. UA-claims-Chrome + JA3-says-Python = liar.

JA3's weakness is TLS extension permutation (Chrome since 110 shuffles extension
order). **JA4** (FoxIO, John Althouse, 2024) normalizes cipher and extension
orders into a stable form, adds TCP and HTTP/2 context, produces a 36-char
fingerprint of structural support rather than advertised-order.

**HTTP/2 fingerprinting** extracts a signature from SETTINGS frames (initial
window size, max concurrent streams, header table size), HEADERS priority hints,
and pseudo-header order. Real browsers emit stable orderings; scripted clients
vary. Combining JA4 + HTTP/2 fingerprinting catches a huge fraction of mass
scraping and credential-stuffing at near-zero FP cost — the cheapest
high-leverage signal in 2026. Cross-link to [[detection_engineering_expertise]]
§2.

### Bot-management architecture (Cloudflare / Akamai BMP / DataDome / HUMAN)

Convergent architecture:

1. **Edge fingerprinting**: IP reputation, ASN, JA3/JA4, HTTP/2 fingerprint,
   header order, request rate, UA, browser-feature presence.
2. **Behavioral telemetry from invisible JS challenge**: canvas/WebGL/audio/
   font fingerprints, headless-Chrome flag tests, mouse-and-timing entropy.
3. **ML scoring**: per-tenant model on the tenant's historical legitimate-vs-
   attack traffic. Cloudflare's 1–99 Bot Score is the canonical ML output.
4. **Decision layer**: customer rules act on the score per-route (login is
   stricter than homepage).
5. **Feedback loop**: customer-reported labels feed model retraining.
   Cross-tenant generalization is the vendor's moat.

Cloudflare's 25M+ protected properties constitute one of the largest single
observation points for bot traffic in 2026; the ML benefits from network effects.

### Puppeteer-Stealth as the attacker baseline; image-CAPTCHA is dead

The 2026 attacker baseline is headless Chrome driven by Puppeteer or Playwright
with the Stealth plugin (patches `navigator.webdriver`, mocks `chrome.runtime`,
fuzzes font enumeration, spoofs WebGL vendor strings, dozens more). Stealth and
detection vendors are in a continuous arms race. The attacker's escalation past
Stealth is real Chrome on real hardware plus residential proxies — the
structural defender's-nightmare in 2026.

By 2026, GPT-4o and Claude Sonnet 4 solve image CAPTCHAs at >95% accuracy for
under $0.001 per challenge, cheaper than human solvers. Image-CAPTCHA is
structurally dead; vendors lean on behavioral and fingerprint signals with image
or "press-and-hold" interactions as fallback gathering vehicles for continuous-
time mouse-motion data.

---

## 5. Payment Fraud

### CNP fraud as the dominant vector

Chip-and-PIN plus contactless NFC has nearly eliminated card-present fraud in
most geographies; ~90% of US card-fraud losses in 2025 were card-not-present.
CNP ecosystem: cards sourced from breaches, info-stealer logs (which contain
saved card data including CVV), Magecart-family checkout-skimmer malware, and
physical skimmers. The attacker validates cards via **card-testing** — small
charges ($0.50–$5) at low-risk merchants, often donation pages — then resells
validated cards on Russian Market or monetizes via gift cards, crypto, and
electronics reshipping.

### 3-D Secure 2.0 and dynamic linking

3DS2 (EMVCo 2016) transmits 100+ data elements to the issuing bank, which runs
**risk-based authentication**: low-risk transactions are approved frictionlessly,
high-risk escalate to step-up (biometric, SMS OTP). **Dynamic linking** is the
EU PSD2 requirement that the strong-customer-authentication ceremony be
cryptographically bound to the *specific transaction's amount and payee* —
3DS2.2 is the mechanism. In the EU, 3DS2 with dynamic linking is mandatory for
most CNP transactions over €30. When 3DS2 authenticates, fraud liability shifts
from merchant to issuer.

### Legacy controls — necessary but insufficient alone

**AVS** (Address Verification System): issuer compares billing address with
address-of-record. **CVV**: 3- or 4-digit code printed on card, not stored by
merchants per PCI-DSS. Both are bypassed by typical 2026 attack data: breaches
include addresses, info-stealer logs include CVV. The contemporary defense
combines AVS + CVV + 3DS2 + velocity/amount/merchant rules + ML.

### Velocity rules and card-testing detection

Velocity per card, per email, per shipping address; amount-clustering ($1 test
followed by $5000 charge); merchant-category mismatch. The card-testing pattern
is **highly detectable** — many cards, small amount, single low-risk merchant,
short time window, consistent attacker IP/device across the campaign. Stripe
Radar, Sift, Forter, Sardine, Riskified, Adyen RevenueProtect all detect this at
high confidence. The non-profit-donation-page victim case is the canonical
weak-link; the lever is donate-page CAPTCHA / Turnstile plus per-IP and
per-card-prefix rate-limiting.

### Refund fraud, chargeback fraud, and card-on-file risk

**Refund fraud** ("refunding"): social engineering CS to obtain refunds for
goods received. **Chargeback fraud** ("friendly fraud"): cardholder disputes
legitimate transactions; issuers heavily side with cardholders. Defense:
shipping signatures, delivery photos, behavioral history, 3DS2-authenticated
transactions (liability shifts), cross-merchant networks (Chargebacks911,
Riskified, Sift).

**Card-on-file** transactions (stored card + logged-in user) are dramatically
lower risk than **ad-hoc** (new card, guest checkout). Risk models discount
card-on-file aggressively; the shipping-vs-account-address match is the
first-order signal.

### Production landscape

Stripe Radar (embedded in Stripe, $1.9T+ annual TPV signal); Sift (independent
T&S-rooted); Forter (high-end commerce); Riskified (chargeback-guarantee);
Sardine (fintech-and-crypto, strong SMS-pumping); Adyen RevenueProtect (Adyen
in-house). The **ML + rules hybrid** is universal: ML produces a calibrated
score; human-authored rules override the ML on specifics ("block all
transactions from this BIN with this shipping ZIP"); CS feedback retrains.

---

## 6. Scraping Defense

### Your data wants to be scraped

Web-scraping is structurally indistinguishable between legitimate and abusive.
Googlebot is a scraper; Common Crawl is a scraper; your competitor's
price-intelligence tool is a scraper. The defender decides which scraping is
allowed and the line is rarely technical.

The 2026 reality is dominated by **AI training-data collection**. OpenAI's
GPTBot, Anthropic's ClaudeBot and CCBot, Google's Google-Extended, Meta's
facebookexternalhit and meta-externalagent, and a long tail of unidentified or
spoofed AI crawlers consume an estimated 30–50% of web traffic on content-heavy
sites. The strategic options: allow it (and negotiate licensing — the
2024–2026 wave produced multi-hundred-million-dollar deals with Reddit, NYT,
AP, Axel Springer), block it (robots.txt + active bot-mgmt blocking;
Cloudflare's "AI Crawler Block" toggle automates), or charge for it
(paywall + API + rate-card).

### Scraping vs API abuse

Two related categories: **scraping** is collection from public surfaces (lever:
UX + ToS), **API abuse** is misuse of authenticated endpoints (lever: API
key + rate limit + contract). Production patterns conflate them.

### Detection signals

Request volume per session; navigation patterns (scrapers traverse
breadth-first or sitemap-driven; humans browse depth-first with reading
pauses); request-header anomalies (missing Accept-Language, missing Referer on
internal pages, Accept-Encoding without gzip); JS-render-requirement (no JS =
empty page is the cheapest scraping defense but at major SEO and accessibility
cost); TLS / HTTP/2 fingerprint; header-order fingerprint.

The SSR vs CSR design choice is a scraping lever: **CSR (client-side-rendered)
content is harder to scrape than SSR**. Scrapers must execute JS or
reverse-engineer the API. The compromise pattern is SSR for search engines and
accessibility (UA-detection or selective prerender) + CSR for everyone else,
which LinkedIn, Twitter / X, and Glassdoor converge on.

### Rate limiting and WAF-layer mitigation

Per-IP rate limits are cheap and limited (residential proxies defeat them).
The modern stack is per-user-or-API-key, per-account-or-session, **per-
behavioral-cluster**. Most sites delegate the bot-management arms race to a
WAF + bot-mgmt vendor (Cloudflare, Akamai, Fastly Signal Sciences, DataDome,
F5/Distil, HUMAN) and amortize the cost across the vendor's customer base.

### Legal — hiQ Labs v. LinkedIn aftermath

The 9th Circuit (twice) held that scraping *public* websites does not violate
the federal CFAA, even when the site sends cease-and-desist letters. The
post-*Van Buren v. United States* (2021) CFAA scope does not cover "you scraped
data we'd rather you not." But hiQ also produced the **contract pathway**: when
the scraper logs in and accepts ToS, scraping in violation of those terms is
actionable. The December 2022 settlement entered $500K against hiQ under
California common-law trespass-to-chattels and misappropriation plus injunctive
relief.

The 2026 legal posture: **anti-scraping ToS clause + login-wall on protected
content** is the defensible architecture. Bare CFAA letters to public-site
scrapers do not work. Common-law theories work when ToS is accepted and harm is
documented. The Common Crawl exception remains carved out by most major sites
because most public AI training corpora derive from CC.

### AI crawler doctrine

Standard robots.txt entries (`User-agent: GPTBot / anthropic-ai / ClaudeBot /
CCBot / Google-Extended / PerplexityBot / cohere-ai / meta-externalagent`, all
`Disallow: /`) are the lightweight signal — honored by well-behaved crawlers,
ignored by spoofers. For those, JA4 / behavioral-fingerprinting bot detection
is the lever. Cloudflare's "Block AI Bots" toggle and per-vendor AI Audit
features automate this combination for most major content sites.

### Cross-links

[[detection_engineering_expertise]] §2 (network telemetry, JA4 in SOC rules);
[[adversarial_ml_model_security_expertise]] §10 (training-data poisoning);
[[privacy_engineering_expertise]] §PII-handling.

---

## 7. Fake Accounts, Sybils, and SMS Toll Fraud

### The sybil problem

John Douceur's 2002 *Sybil Attack* paper proved structurally: without a trusted
identity authority, no peer-to-peer system can reliably prevent sybils. The
SybilGuard (2006), SybilLimit (2008), and SybilRank (2012) lines of work moved
the problem to **social-graph-based detection**: assume the honest portion of
the network is fast-mixing and the sybil portion has a sparse cut with the
honest set; trust-propagation rooted in known-honest nodes ranks accounts by
sybil-probability. SybilRank has been deployed at production scale at Facebook
and Tuenti. The 2026 limitation is real: modern sybil rings cultivate
cross-following relationships before activating, producing dense cuts. Graph
defenses are necessary but not sufficient.

### Signup-time defense

Phone verification (SMS-OTP, ~$0.01–$0.20 per SMS for the platform, ~$0.01–$5
per disposable SIM/VoIP for the attacker). Email verification with temp-mail
blacklists, MX-record and domain-age reputation. Behavioral signals
(typing/mouse/form-fill timing). CAPTCHA at signup. Hard friction (video
selfie + ID document via FaceTec, Persona, Jumio, Onfido, Sumsub) for
high-value services. The tension is **conversion-rate vs sybil-prevention**;
the lever is again **adaptive friction** applied only to high-risk signups.

### SMS toll-fraud / pumping (2022–2026)

SMS toll fraud emerged as a major abuse vector in 2022–2023. Mechanic:

1. Fraudsters partner with complicit MNOs (typically in low-cost-routing
   geographies — parts of Indonesia, Vietnam, Africa, Eastern Europe).
2. They identify victim platforms with unprotected SMS endpoints (signup, OTP,
   reset, contact-form confirmations).
3. Bots request SMS to large pools on the complicit MNO's network.
4. The victim's SMS provider (Twilio, MessageBird, Vonage, AWS SNS) pays the
   MNO; MNO kicks back to the fraudster.

Musk's 2022 reveal that Twitter was losing $60M/year to SMS pumping put this
on the industry radar; Stripe, Discord, Reddit reported similar losses through
2023–2024.

Defenses: aggressive rate limits (3–5 codes/hour/number, 2–3 attempts before
MFA-fallback); country allow/blocklist; MNO-prefix rate limits (aggregate by
first 6–8 digits); OTP-conversion-rate monitoring (real conversion is 80–95%,
pumped is <5%); per-device-fingerprint OTP request limits; pivot to passkeys
(eliminates SMS as second factor); pivot to email-OTP (cheaper, harder to
pump); WhatsApp/Telegram OTP. Sardine "SMS pumping protection" and Twilio's
"Verify Fraud Defense" are named products; reCAPTCHA Enterprise added
SMS-pumping-specific protection in 2024.

### Network-graph fake-account detection

Post-signup, the platform watches for sybil signatures: dormancy-then-
activation (mass-creation + week-aging before activation); profile-
incompleteness; network-graph features (who they follow, who follows them,
content engagement clusters); content-similarity (pre-LLM strong; post-LLM
weakened, see §9); **coordinated-inauthentic-behavior** (groups amplifying the
same content at the same time, the signature of state-affiliated and
commercial influence operations documented in Meta's quarterly
Adversarial-Threat reports). The production stack is graph algorithms
(community detection, label propagation, SybilRank-style propagation) + ML +
human review for high-confidence clusters.

### AI-generated profile photos

StyleGAN3, Stable Diffusion, Flux Pro produce plausible avatars that defeat
"blank avatar" rules and reverse-image-search (because the photo doesn't exist
elsewhere on the web). Defender countermeasures: AI-image classifiers (Hive,
Optic ship 70–90% accuracy depending on source model); liveness check (defeats
most AI-photo flows; deepfake-video bypass is an emerging concern); C2PA
provenance (upgrade real-camera-captured photos; absence-of-manifest is too
common to be a hard negative signal at 2026 adoption levels).

### Platform-specific corpora

Discord (server-boost-token farming), Reddit (karma-farming with $5–$50 aged
accounts for vote manipulation and astroturfing), Twitter/X (the most-public
pre- and post-Musk-transition environment; Botometer is the public benchmark
dataset), LinkedIn (fake-recruiter accounts for social engineering, especially
North Korean state-aligned and commercial recruiter spam waves), Telegram and
Discord as marketplace layers for *other* platforms' sybils.

---

## 8. Content Abuse and Trust-and-Safety Operations

### CSAM — hash matching, classifiers, mandatory reporting

Child sexual abuse material detection is the most-regulated and most-mature
content-abuse subdiscipline. Architecture:

1. **Hash matching against known CSAM**: **PhotoDNA** (Microsoft 2009; Hany
   Farid co-developed it at Dartmouth; donated to NCMEC) is the de facto
   standard. Perceptual hashing with fuzzy-match catches re-encoded, cropped,
   watermarked variants. Used by Gmail, Twitter/X, Meta, Adobe, Reddit,
   Discord. Not facial-recognition; produces non-reversible image-identity
   hash. **PDQ** (Meta 2019) is the open-source perceptual hash; MD5/SHA-1 are
   exact-match first-pass.
2. **Classifier-based detection of novel CSAM** (Safer by Thorn; Google CSAI
   Match for video; Microsoft's classifier) for material not yet hashed.
3. **Human review** by trained moderators; verified CSAM reported to NCMEC.
4. **Mandatory reporting**: 18 USC § 2258A requires US electronic-service-
   providers to report detected CSAM. The Meta Transparency Report shows
   30M+ Content Action units against CSAM per quarter; human-review staff for
   those queues is well in the thousands.

For platforms below the Meta scale, integrate with NCMEC via PhotoDNA Cloud
Service (free for qualifying providers) + a classifier like Safer.

### Hate speech, harassment, CIB

Real-time classifiers (Jigsaw Perspective API or in-house transformer fine-
tunes) for text; image and video classifiers; user reports; trusted-flagger
programs (civil-society and government); human review for borderline; auto-
action for high-confidence; appeals (increasingly mandated by DSA in EU).
Damon McCoy's NYU lab has published the **prevented-dissemination** metric
(reach avoided by moderation action) as a more honest signal than raw
"content removed" counts.

**Coordinated inauthentic behavior** is detected via graph-based community
detection on engagement edges, temporal correlation (accounts posting within
seconds of each other), and campaign-level content-similarity clustering.
Meta's quarterly Adversarial-Threat reports document CIB takedowns from
state-affiliated actors (Russia, Iran, China most-disclosed) plus commercial
influence-for-hire.

### Spam and the LLM signal-shift

The 2026 dominant spam vector is LLM-generated content. Keyword filters,
"look for typos and Cyrillic substitutions," template-matching: largely failed
against fluent LLM output. The reframe: **shift detection from content to
behavior** (posting velocity, engagement patterns, account-age, network-graph
features). When content is indistinguishable from human-written, drop the
content signal.

### Deepfake and synthetic-media detection

Classifier-based detection (Hive, Optic, Reality Defender) is effective against
the training distribution and weak against novel generators or adversarial
edits. Forensic analysis (lighting inconsistencies, eye-reflection anomalies,
hand anatomy) is increasingly defeated by frontier video models (Sora 2,
Veo 3). The structural defense is **provenance via C2PA** — cryptographically-
signed manifests stating "this video was captured by a real camera at time T
at location L."

### C2PA

The Coalition for Content Provenance and Authenticity (founded Feb 2021 by
Adobe, Arm, BBC, Intel, Microsoft, Truepic) ships the open standard for
cryptographically-signed media-content metadata. The C2PA Manifest (Content
Credential) records creator identity, capture timestamp and location, tools
used for editing, AI involvement, edit history. Each manifest is signed with a
private key chained to an X.509-style CA. Spec v2.4 (May 2025) supports JPEG,
PNG, WebP, AVIF, HEIC, MP4, MOV, PDF, MP3, WAV.

The Leica M11-P (Oct 2023) was the first consumer camera with C2PA in
hardware; Sony Alpha 1/A9 III/A7S III/A7 IV followed; Nikon shipped firmware
updates; DALL-E 3, Midjourney, Sora sign with "AI-generated" assertions. The
2026 strategic limitation is adoption: trust C2PA when present, do not require
it. The EU AI Act (effective August 2026) requires AI-content transparency
labeling in regulated contexts; C2PA's AI assertion type is the
implementation-of-record.

### TSPA and the T&S profession

The Trust & Safety Professional Association (501(c)(6), launched 2020) is the
professional body. Its Curriculum (key-roles, glossary, fundamentals chapters
on policy, enforcement, content moderation, identity, incident response,
measurement) is the equivalent of "OWASP Top 10 + SANS Top 25" for the
discipline. The Tech Coalition's TRUST (Voluntary Framework for Industry
Transparency) standardizes CSEA transparency-reporting categories. Most major
platforms align reporting to TRUST.

### Regulatory pressure: DSA, OSA, KOSA

**EU DSA** (in force 2024) — mandates moderation transparency, appeal
mechanisms, illegal-content takedown timelines, VLOP audits, risk
assessments (Art. 34), mitigation documentation (Art. 35), Out-of-court dispute
settlement (Art. 21), researcher data access (Art. 40). **UK OSA** (Royal
Assent Oct 2023, phased through 2024–2026; Ofcom enforces) mandates
duty-of-care. **US KOSA** (passed Senate, House pending) mandates age-
appropriate-design for under-17. **Australia eSafety Act 2021** mandates
basic online-safety-expectations. T&S engineering headcount at major
platforms doubled or tripled between 2020 and 2025 in part to absorb this.

### T&S vs Security vs Privacy

Security protects platform from external attackers (AppSec, IR, detection).
Privacy protects user data from misuse and regulatory compliance. T&S protects
users from each other and from harmful content; protects the platform from
abuse-of-product. Boundaries are fuzzy in practice — credential stuffing is
"security" if framed as authn-bypass and "T&S" if framed as account abuse.
Most large platforms operate a dedicated T&S engineering team coordinating
with AppSec and Privacy. Cross-link to [[appsec_program_building_expertise]]
§4 (stakeholder mapping).

T&S incident response has **regulatory clocks** (NCMEC on detection, DSA
significant-incident reporting within hours), **press exposure** (high-profile
incidents become news), **policy escalation** (borderline content is a Policy-
team call, not engineering), and **external coordination** (NCMEC, ICE, FBI,
foreign regulators, civil-society groups). The 2026 best-practice is integrated
T&S-Security-Comms IR with predefined escalation paths.

---

## 9. AI-Content Abuse — the New Frontier

### LLM-generated spam at scale

LLMs remove the human-time-cost from abuse operations. Per-message content-
generation cost has fallen from $0.01–$0.10 (human-labor) to $0.0001–$0.001
(LLM-API). Linguistic quality is at native-speaker level across all major
languages. Personalization is feasible at scale (ingest the target's public
profile, generate custom spear-phish). A/B testing is automated. APWG quarterly
reports through 2024–2026 show sustained YoY phishing growth with the
fluency-axis being the 2024 inflection.

Defender response: **shift emphasis from content to behavior**. Content-based
filters (Bayesian-on-text, keyword, perplexity) work less well against LLM
output; behavioral filters (sender reputation, frequency, recipient-graph,
delivery-pattern) work equally well or better.

### AI-generated phishing — "no more typos"

Pre-LLM "look for typos and Cyrillic homoglyphs" is dead in 2026. LLM
phishing is fluent, contextual, personalized. Defender levers shift to email
authentication (SPF, DKIM, DMARC), URL analysis (newly-registered domains,
lookalikes, URL-shortener click-through analysis), behavioral inbox analysis
(this sender has never emailed you before, this email is part of a campaign
hitting 1000 of your peers). Microsoft Defender for Office 365, Google
Workspace Security, Mimecast / Proofpoint / Abnormal Security all rebuilt
detection stacks around post-content signals through 2024–2026.

### Deepfake voice impersonation — vishing 2.0

Voice cloning with three seconds of source audio (ElevenLabs, Resemble,
play.ht, Microsoft VALL-E, open-source XTTS) drove a wave of voice-phishing
fraud 2024–2026: CEO/BEC fraud with the CEO's voice; family-emergency fraud
with the voice of a son or daughter; customer-support impersonation against
voice-biometric authn. The 2024 Hong Kong CFO who wired $25M after a deepfake
video call is the canonical incident.

Defenses: out-of-band confirmation for any unusual financial request;
code-words for family-emergency scenarios; voice-biometric retirement (by
2026, no major bank treats voice-print as sole factor); caller-ID-and-call-
pattern analysis from cell-network signaling.

### Synthetic-identity fraud at scale

AI-face + AI-voice + chatbot-conversation onboarded to financial services to
pass KYC. Reference incidents: crypto-exchange KYC bypass (Reuters October
2024, $50M+ across mid-tier exchanges); synthetic mortgage applications
(real SSN + fake everything-else); B2B SaaS fake-company onboarding. Defenses
(Persona, Plaid Identity, Onfido, Jumio, Trulioo, Sumsub): active liveness
check (random head-movement / blink / smile on command, defeats simple
deepfake replay); document forensics (hologram, microprint, NFC chip read);
cross-source identity validation (SSN + name + DOB + address match against
credit bureau, government records, telco); behavioral pattern over time
(synthetic identities have characteristic post-onboarding patterns — no
organic transactions, characteristic build-credit-then-bust-out timeline).

### AI scraping and the competitive-substitution concern

Beyond load, the strategic concern is **competitive substitution**: if an AI
model is trained on your content, users may consult the AI instead of visiting
you, collapsing your revenue model. Cloudflare's 2024 reporting framed this:
marginal cost of training-scraping per crawl is low for the AI company,
non-zero for the site, long-term substitution effect is high. The 2026 norm
for high-quality content is paid licensing (Reddit-OpenAI, NYT-OpenAI
eventually-settled, AP-OpenAI, Axel Springer-OpenAI) or hard block
(Cloudflare AI Audit licensing platform; robots.txt + JA-fingerprint-block for
smaller players).

### Text detection — GLTR, DetectGPT, watermarking

**GLTR** (Gehrmann, Strobelt, Rush, 2019; MIT-IBM Watson AI Lab + HarvardNLP)
computes per-token probability rank under a reference language model; LLM
text uses low-rank (high-probability) tokens at higher rates than human text.
Visual color-coding makes the pattern visible to humans.

**DetectGPT** (Mitchell, Lee, Khazatsky, Manning, Finn, 2023) uses the
probability-curvature of the model's output: LLM text sits at local maxima
of the probability surface; perturbing the text drops probability sharply,
while human text is less peaked.

State of the art in 2026: **classifier-based detectors fail adversarially**.
Modest fine-tunes or paraphrase passes defeat them. Detectors retain value
against naive attackers, are bypassed by determined ones.

**Watermarking** (Kirchenbauer et al., *A Watermark for Large Language
Models*, ICML 2023): partition the model's vocabulary at each step into a
pseudo-randomly-selected "green list" and "red list"; bias generation toward
green-list tokens; a detector statistically checks green-list use rates over
50–100 tokens. Invisible to readers, output quality approximately preserved.
2024–2026 status: OpenAI prototyped text watermarking, did not deploy
(adversarial-paraphrase defeat concerns); Google Gemini deployed SynthID for
images and audio, then text; Anthropic has not publicly deployed text
watermarking at scale. The detection-arms-race outcome: **content-based
detection of AI output is a losing fight**; spend the detection budget on
behavioral signals.

### Cross-links

[[adversarial_ml_model_security_expertise]] §10 (watermarking, output
filtering, training-data poisoning);
[[llm_agent_security_expertise]] §3 (MCP, agent-as-attacker);
[[detection_engineering_expertise]] §3 (Sigma for AI-content workflows).

---

## 10. Generation-Cost Amplification Attacks

### Your AI feature is free GPU

The new abuse vector unique to the AI era: the platform's AI feature is a free
GPU for the attacker. Per-invocation costs: LLM chat $0.001–$1+; RAG query
$0.01–$0.10; text-to-image $0.01–$0.05; voice TTS $0.0001–$0.001/sec; video
generation $0.10–$1+/sec (the most expensive surface). An attacker running 10⁶
free-tier requests/day costs the platform $10k–$1M+ in inference spend. This is
**denial-of-wallet**.

### Prompt-injection to maximize spend

Strategies the attacker uses to maximize the platform's token spend:

- **Force long context retrieval** in RAG (craft queries that pull
  max-length documents).
- **Force long generation** ("respond with a 10,000-token exhaustive
  analysis").
- **Force expensive tool use** (run expensive computations via code-exec).
- **Force model-routing escalation** (craft queries that escalate from Haiku
  to Opus, GPT-3.5 to GPT-4).

The defender's lever is **cost-aware rate limiting** rather than event-count
limiting. Counting requests-per-minute under-counts the attacker; counting
cost-per-minute captures the right signal.

### Vector-DB query amplification

RAG systems with dense retrievals can be amplified by queries that score
similar to many documents, triggering full-corpus reranking and blowing
per-query latency and cost. Defenses: cap top-K retrieval depth; sparse-then-
dense (BM25 first, dense-rerank only top candidates); per-user embedding-
compute budget.

### Image-gen as Bitcoin-mining-by-proxy

Image-generation has a particularly bad cost profile (inference cost is
fixed-per-image regardless of requestor tier). Attacker pattern: free signup
(disposable email + temp phone), burn free-tier credits, sell generated
images on stock-image sites or NFT platforms or directly to clients. The
attacker has converted the platform's GPU credits into attacker-revenue.
Defenses: tighten the free tier (lower limits, longer trial, more friction at
signup); watermark free-tier outputs (raises per-image monetization cost);
detect-and-suspend high-velocity-low-payment accounts (free user at
free-tier-max with no upgrade is highly likely abuse).

### Detection — every user looks legitimate

The unique difficulty: the request shape is indistinguishable from a real
user's. No "malicious payload" to detect. Signals are aggregate: per-account
volume; per-account diversity (one topic at max-rate is more suspicious than
many topics); account-age vs volume; cross-account correlation (1000
accounts from same /24, similar fingerprints, similar content = campaign).
The countermeasure is **cost-aware rate limiting** — budget platform spend per
account per day regardless of request count — combined with adaptive friction
at the moment the budget is exceeded.

### Stolen LLM API keys

A growing 2024–2026 surface: stolen OpenAI / Anthropic / other LLM-provider
keys from GitHub leaks, info-stealer logs, stolen browser tabs, breached
cloud accounts. The attacker runs abuse traffic; the legitimate account
holder gets the bill.

Provider patterns: velocity-based key revocation; geographic-pin keys to
source-IP range; required rotation; email-on-anomaly. Customer hygiene
patterns: never commit keys to source (use secret-managers); scope-limit
keys (per-feature, per-environment); monitor your bill (last-line defense;
many customers discover compromise on the next invoice). Both OpenAI and
Anthropic ship usage-anomaly detection in 2026, but customer-side hygiene
remains primary. Cross-link to [[cryptography_expertise]] §key-management.

### Framing — business-logic flaw at the AI layer

Generation-cost amplification is a **business-logic flaw**, the same shape as
ZIP-bomb DoS, billion-laughs XML expansion, or regex catastrophic backtracking.
Mechanism differs; defender posture is identical: **bound per-request resource
consumption**. The pre-LLM analogues (decompression-ratio limits, XML
expansion caps, regex input rejection) are the model. The LLM analogue is
cap context-window, cap generation length, cap tool-use steps, cap retrieval
depth, cap model-routing escalation. Every LLM feature should ship with these
caps from day one.

---

## 11. Trust and Safety as Engineering Practice

### The policy-enforcement-measurement cycle

T&S engineering operates on a four-phase cycle structurally distinct from
AppSec's vulnerability-management cycle:

1. **Policy** — what behaviors are prohibited; who decides; how is it expressed
   in machine-actionable rules.
2. **Enforcement** — detection of violations; actions (warning, content
   removal, account suspension, termination, law-enforcement referral).
3. **Measurement** — violation frequency, enforcement precision and recall,
   policy ambiguity rate.
4. **Policy revision** based on measurement; cycle repeats.

This is **policy-as-software**. Every meaningful T&S team operates under it,
explicitly or not. The boundary with AppSec: AppSec rarely engages with policy
(a SQLi bug is a bug regardless), while T&S requires constant policy engagement
because the detected behaviors are policy-defined, not code-defined.

### TSPA Fundamentals as the shared curriculum

The TSPA Curriculum (Industry Overview, Policy Development, Detection,
Enforcement, Operations, Measurement) is the discipline's "OWASP Top 10."
For an AppSec engineer rotating into T&S, it is the assumed shared baseline.

### Regulatory-engineering requirements

DSA Articles 34/35/24/42/20/21/40 (risk assessments, mitigation documentation,
transparency, appeals, dispute settlement, researcher data access); UK OSA
duty-of-care; US KOSA age-appropriate-design (if enacted). Compliance is
audit-grade documentation, end-to-end traceability from policy to enforcement
to outcome. The 2026 staffing reality at major platforms: T&S engineering
roughly matches AppSec headcount, with overlapping toolchains.

### Incident response

T&S IR has regulatory clocks (NCMEC on detection; DSA significant-incident
within hours), press exposure, policy escalation (Policy team decides
borderline calls), and external coordination (NCMEC, ICE, FBI, foreign
regulators, civil-society, victim-advocacy groups). The 2026 IR shape:

1. **Trigger** — classifier match, hash match, user report, trusted-flagger,
   regulator inquiry, press inquiry.
2. **Triage** — severity, scope, regulatory-clock status.
3. **Contain** — content takedown, account suspension.
4. **Investigate** — forensic, account-graph traversal, campaign-scope
   determination.
5. **Communicate** — internal (Policy, Comms, Legal, Eng), external
   (regulators, NCMEC, victims as required).
6. **Remediate** — campaign-wide takedown, rule updates, policy revisions.
7. **Post-mortem** — lessons, transparency-report contributions, policy
   evolution.

Cross-link to [[appsec_program_building_expertise]] §4 (stakeholder roles in
IR).

### The Policy-Engineering-Operations triangle

Three legs. Policy writes rules, defines edge-case rulings, engages Legal and
Comms on policy evolution. Engineering builds detection, enforcement, and
measurement systems; operates classifiers; runs appeal-flow software.
Operations is the human moderators who review borderline cases, process
appeals, and produce labels feeding classifiers. Omit any leg and the team
fails predictably. The moderator-well-being problem (CSAM and graphic-
violence exposure has documented psychological-impact rates) is the
under-discussed cost; the 2026 industry practice — rotation, in-house
counseling, exposure-time limits, opt-in queues by category — is imperfect
but materially better than the pre-2018 norm.

---

## 12. Detection — Practical SOC and Fraud-Ops Patterns

### The fraud-operations dashboard

Production fraud-ops aggregates signal across channels: transactions
(payment, settlement, refund, chargeback), accounts (signup, password change,
MFA change, OAuth-app authorization), logins (auth events with risk scores),
sessions (high-risk session signals), customer-support (tickets tagged
"fraud," "ATO," "unauthorized," "chargeback"), external intel (cards in fresh
dumps, info-stealer logs matching platform users, threat-actor TTPs from
partners). Each feed is queryable, joinable, alertable. The fraud-ops analyst
is a SQL-fluent SOC analyst with payment-data context.

### Real-time vs batch — layered

Real-time at transaction time (latency budget <200ms; cannot use heavy ML or
wide aggregations); near-real-time pattern detection (5-min windows; catches
card-testing campaigns); daily batch (slow-moving fraud, multi-hour ATO);
weekly analysis (longest-cycle abuse, refund-fraud rings). Each layer has its
own clawback/response mechanism — real-time blocks; near-real-time refunds;
daily batch freezes accounts; weekly feeds retraining.

### Graph-based investigation

Fraud investigation is graph: which accounts are connected by what edges
(shared payment instrument, shipping address, device, IP, follow-graph,
message exchange). Pull a starting node and expand neighborhoods until the
campaign is mapped. Production tooling: in-house graph DBs (Neo4j,
JanusGraph, Neptune, ArangoDB) with custom UIs; vendor consoles (Sift
investigator UI); Maltego for ad-hoc work. The shared-tooling overlap with
threat-intel is significant; cross-link to
[[threat_intel_methodology_expertise]].

### Centralize in the warehouse

The 2026 production pattern: send everything to BigQuery / Snowflake /
Databricks. Rule-based detection and ML scoring run as SQL or PySpark jobs
over warehouse data. SQL-fluent analysts iterate on rules; ML training data
is co-located. Real-time decisioning runs separately (Flink, proprietary
in-memory); everything else lives in the warehouse.

### Sigma-shaped rules for fraud

The detection-engineering rule format works for fraud:

```yaml
title: Credential Stuffing Burst on Single Username
id: fraud-cs-001
status: stable
description: |
  >5 failed login attempts on a single username within 60s, from rotating
  IPs/different user-agents. Common credential-stuffing campaign signature.
logsource:
  product: auth-service
  service: login-events
detection:
  selection:
    event_type: 'login_failed'
  timeframe: 60s
  condition:
    selection | count(username) by username > 5
    AND
    selection | count(distinct(source_ip)) by username > 3
fields:
  - username
  - source_ip
  - user_agent
  - ja4
falsepositives:
  - Single user with bad password retrying from multiple devices
  - Corporate NAT with multiple users
level: high
```

Sigma is the canonical detection-engineering format. The fraud-team rule
corpus can and should be Sigma; this enables sharing rules with the SOC and
reuse of pySigma converters for native SIEM queries. Cross-link to
[[detection_engineering_expertise]] §3.

### Customer-support feedback loops as gold

The highest-quality fraud signal is the customer who calls saying "I didn't
do that." Every such call is a labeled fraud event. The CS-to-ML pipeline:

1. CS agent tags the ticket "unauthorized transaction" / "account takeover"
   / "did not place this order."
2. Metadata (user ID, transaction ID, event window) flows to the fraud
   warehouse.
3. Corresponding warehouse events are labeled `fraud = true` with CS-source.
4. Labels feed the next training cycle.
5. Improvement is measured against held-out CS labels.

The 2026 best-practice CS-label feedback latency is <24 hours. Each day of
latency is a day of model staleness while the attacker pivots.

---

## 13. Defensive Patterns and Program Design

### Layered defenses with uncorrelated failure modes

No single tool stops everything. The cumulative survival rate across N layers
is the product of per-layer pass rates. Pick layers with **uncorrelated
failure modes** — CAPTCHA and JA4 are correlated (both defeated by real-
Chrome-on-real-hardware); CAPTCHA and velocity-rate-limit are uncorrelated.

Concrete six-layer stack for credential stuffing: HIBP-block known-breached
passwords; per-username velocity rate-limit; TLS/HTTP-2 fingerprint check at
edge; bot-management ML risk score; risk-based CAPTCHA / step-up MFA for
suspect traffic; passkey adoption as the endgame. The attacker who pays for
residential-proxy fleet (defeats layers 3 and 4) still hits 1, 2, 5 and is
structurally incapable of beating 6 without compromising the user's device.

### Friction-budget — each challenge costs UX

The single most important design constraint is the **friction budget**: total
user friction the product can tolerate, measured in CAPTCHA-equivalents per
session per user. A consumer e-commerce site might have 0.05; a bank 0.3; a
national-security application unlimited. Risk-based-CAPTCHA on the top-1%
riskiest sessions consumes 0.01 of budget; universal-CAPTCHA on every signup
consumes 1.0 and is unshippable for almost any modern consumer product.

**Measure your friction.** Most teams cannot articulate their budget. They
should. The metric is the conversion rate at each funnel step; the budget is
the conversion delta the product can tolerate.

### Adaptive challenges; behavior-based detection in the LLM era

Restating §2 doctrine: challenge only suspect traffic. Universal challenges
burn the friction budget; adaptive challenges spend it on attackers.

Restating §9 thesis: content-based detection of abuse is adversarially-fragile
against LLM-generated content. Spend the detection budget on behavioral
signals: who is the account, what have they done over time, what is the
network-graph context.

### Threat-intel feedback

The fraud team feeds the threat-intel team feeds the fraud team. Abuse signals
discovered in production (new TTPs, infrastructure, monetization channels)
flow to intel, which enriches them with external corpora (Telegram, dark-web,
partner-shared). Enriched intel flows back as new detection signals.
Cross-link to [[threat_intel_methodology_expertise]].

### A/B testing of defenses

Every defense layer should be A/B-testable. Holdouts (a small percentage with
the defense disabled) measure counterfactual abuse rate; treatments measure
actual; effectiveness is the delta. A defense without a holdout cannot be
quantified — the team will overestimate impact, underestimate cost, and miss
when the defense is defeated. Holdouts are uncomfortable but the only honest
measurement.

### Vendor selection — buy vs build

**Buy** when the problem is well-understood industry-wide (credential stuffing,
card fraud, bot management) and the vendor's training data generalizes; when
arms-race cost is amortizable across the vendor's customer base; when
compliance overhead is high and vendors provide audit-ready artifacts.
Examples: Cloudflare/Akamai/DataDome/HUMAN for bot management; Stripe Radar /
Sift / Forter for payments; Persona / Onfido / Jumio for ID verification.

**Build** when the abuse is platform-specific (unique product surface);
signal exists in proprietary data; vendor pricing scales poorly with volume;
integration would expose sensitive customer data. Examples: Twitter/X, Meta,
Google, TikTok in-house bot-detection; large banks in-house fraud-detection
alongside vendor products; specialized fraud (Reddit karma-farming, Discord
boost-fraud).

The hybrid is universal at >100-engineer-platform scale: vendor for commodity
layer, in-house for platform-specific.

### Code-review checklist for anti-abuse-sensitive features

For any new login flow, API endpoint, content-submission feature, payment
integration, or AI feature:

1. **Rate limits** — per-IP, per-user, per-cluster, per-cost? What rate?
2. **Authentication** — at what NIST AAL level?
3. **Authorization** — permission for this action on this resource?
4. **MFA / step-up** — does this action warrant step-up?
5. **Input validation** — expected shape, size, character set?
6. **Cost amplification** — can small input trigger expensive backend?
7. **Edge fingerprinting** — TLS, HTTP/2, behavioral signals captured?
8. **Bot management** — endpoint in scope for WAF/bot-mgmt?
9. **Logging** — every meaningful event with user/IP/device/action/outcome?
10. **Velocity tracking** — per-user / per-account / per-cluster?
11. **CS hook** — can a CS agent label this as fraud?
12. **A/B testability** — measurable holdout?
13. **Friction budget** — how much does this consume?
14. **Regulatory** — in scope for DSA / OSA / KOSA / GDPR / sectoral?
15. **IR runbook** — runbook for abuse-of-feature with owners and escalation?

A senior anti-abuse engineer reviewing the checklist's output catches 70–80%
of predictable abuse issues.

---

## 14. Variant Analysis — Under-Explored Frontiers

### AI agents abusing your API

The 2025–2026 emerging category: LLM-driven agents acting on a user's behalf
abusing your platform. The agent is configured to "research this topic" or
"find the best price"; hits your API at high volume on the user's
authenticated credentials. User has consented; platform has not.

Defender questions: is the UA distinguishing (Anthropic ClaudeBot and OpenAI
GPTBot identify themselves; private agents often do not); does the request
volume make sense for the user; is the ToS clear on agent use (most ToS were
written pre-LLM-agent and need updating). Strategic question: whether to
allow agent traffic at all — for some platforms the answer is "yes, this is
the use case"; for consumer products "no, build your own client" is
reasonable.

### Adversarial AI — agent vs agent

When an attacker uses an AI agent against your AI agent: crafted inputs
target weaknesses in your classifier; targeted prompt-injection at scale;
the attacker's agent observes your responses and adapts. Defenses:
output-filtering on your own AI (cross-link to
[[adversarial_ml_model_security_expertise]] §10); treat the AI feature's
input as untrusted always; rate-limit agent traffic even from authenticated
users. Cross-link to [[llm_agent_security_expertise]] §3 (MCP, agent-as-
attacker).

### Voice-AI-driven abuse

Whisper + ElevenLabs (cheap real-time STT + cheap voice cloning) enables AI-
conducted vishing at $0.10–$1 per call, bank-IVR-bypass at scale via voice-
channel password reset, AI-conducted CS social engineering. The structural
defense is **never use voice as a sole authentication factor**; voice-
biometric on top of other factors is fine; voice-only is dead.

### Embedded-LLM-in-extension abuse

Chrome / Edge / Firefox extension marketplaces increasingly host
LLM-powered extensions. Compromised or malicious extensions read every page
the user visits (legitimately, because they're AI assistants), exfiltrate
session cookies, and conduct in-browser fraud. Platform-side defenses: detect
extension-injected behavior (extensions inject detectable scripts); treat
browser-extensions as a threat actor (don't trust the browser to be exactly
Chrome-as-shipped); HTTPOnly + Secure cookies minimize extension-cookie-
access. User-side: audit extension permissions; Manifest V3 (Chrome) limits
some-but-not-all vectors.

### Cross-platform fraud rings

The 2025–2026 pattern: fraud rings operate across platforms in coordinated
ways. The classic example: buy on Amazon with stolen card, resell via eBay,
generate clean money on eBay while Amazon takes the chargeback. Neither
platform alone sees the full pattern. Defender responses: cross-platform
fraud intel sharing (Sift Network, Sardine Network, Forter Network); industry
working groups (Visa / Mastercard long-running cross-merchant data sharing).

### Web3 / crypto-asset fraud overlap

The crypto ecosystem produces fraud patterns overlapping with traditional
payment fraud: pig-butchering scams (long-cycle romance / investment fraud
ending in fake crypto-investment platforms, documented extensively by Krebs,
Hutchins, Reuters / WSJ); DeFi rug pulls and exit scams; stolen-wallet-key
drainers (Inferno Drainer, Angel Drainer, MS Drainer; 2024 takedowns plus
successors); cross-chain laundering. Skill-set transfers (graph analysis,
money-flow tracking) but substrate differs. Chainalysis, TRM Labs, Elliptic
are the blockchain-forensics vendors; traditional fraud teams partner with one
of these for crypto-overlap detection.

### Cross-links

[[llm_agent_security_expertise]] §3 (MCP, agent-as-attacker);
[[adversarial_ml_model_security_expertise]] §10 (output filtering,
watermarking, training-data poisoning);
[[cryptography_expertise]] §passkeys (voice-AI bypass posture).

---

## 15. References

### Researchers and primary sources

- Brian Krebs, *KrebsOnSecurity*: https://krebsonsecurity.com/
- Brian Krebs, *Spam Nation: The Inside Story of Organized Cybercrime* (Sourcebooks, 2014): https://www.amazon.com/Spam-Nation-Organized-Cybercrime-Epidemic/dp/1402295618
- Stefan Savage, UC San Diego: https://cseweb.ucsd.edu/~savage/
- Stefan Savage, MacArthur Fellow citation: https://www.macfound.org/fellows/class-of-2017/stefan-savage
- Geoffrey Voelker, UC San Diego: https://cseweb.ucsd.edu/~voelker/
- Damon McCoy, NYU Tandon publications: https://damonmccoy.com/pubs.html
- Vern Paxson, ICIR papers: https://www.icir.org/vern/papers.html
- Niels Provos, Google Scholar: https://scholar.google.com/citations?user=CoUBt08AAAAJ
- Niels Provos et al., *A Virtual Honeypot Framework* (USENIX Security 2004): https://research.google/pubs/pub1/
- Niels Provos, Friedl, Honeyman, *Preventing Privilege Escalation* (USENIX Security 2003): https://research.google/pubs/preventing-privilege-escalation/
- Niels Provos, Mazières, *A Future-Adaptable Password Scheme* (bcrypt, USENIX 1999): https://research.google/pubs/pub24145/
- Marcus Hutchins, *MalwareTech* blog: https://malwaretech.com/
- Sam Curry, *Web Hackers vs. The Auto Industry* (Jan 2023): https://samcurry.net/web-hackers-vs-the-auto-industry
- Troy Hunt, *Have I Been Pwned*: https://haveibeenpwned.com/
- Troy Hunt, *Understanding HIBP's Use of SHA-1 and k-Anonymity*: https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/
- Cloudflare, *Validating Leaked Passwords with k-Anonymity*: https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/
- Sergi Isasi, Cloudflare archive: https://blog.cloudflare.com/author/sergi/
- Patrick Donahue, Cloudflare archive: https://blog.cloudflare.com/author/patrick/
- Lily Hay Newman, WIRED archive: https://www.wired.com/author/lily-hay-newman/

### Bot management and detection

- Cloudflare Bot Management: https://www.cloudflare.com/application-services/products/bot-management/
- Cloudflare Bot Management docs: https://developers.cloudflare.com/bots/
- John Althouse / FoxIO, JA4+ spec: https://github.com/FoxIO-LLC/ja4
- JA3/JA4 fingerprint (Cloudflare): https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- Google reCAPTCHA: https://developers.google.com/recaptcha
- hCAPTCHA: https://www.hcaptcha.com/
- Cloudflare Turnstile: https://www.cloudflare.com/products/turnstile/

### Authentication and identity

- NIST SP 800-63B-4 (final July 2025): https://csrc.nist.gov/pubs/sp/800/63/b/4/final
- NIST SP 800-63 v4 consolidated: https://pages.nist.gov/800-63-4/
- W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Alliance Passkeys: https://fidoalliance.org/passkeys/

### Payment fraud

- Stripe Radar: https://stripe.com/radar
- Stripe Dev Blog, *How we built it: Stripe Radar*: https://stripe.dev/blog/how-we-built-it-stripe-radar
- EMVCo 3-D Secure: https://www.emvco.com/specifications/3-d-secure-specifications/
- Sift: https://sift.com/
- Forter: https://www.forter.com/
- Riskified: https://www.riskified.com/
- Sardine: https://www.sardine.ai/

### Scraping legal and technical

- *hiQ Labs, Inc. v. LinkedIn Corp.* (9th Cir., April 2022): https://cdn.ca9.uscourts.gov/datastore/opinions/2022/04/18/17-16783.pdf
- *Van Buren v. United States* (Supreme Court 2021): https://www.supremecourt.gov/opinions/20pdf/19-783_k53l.pdf
- Cloudflare, *Declaring AIndependence — Block AI Bots*: https://blog.cloudflare.com/declaring-your-aindependence-block-ai-bots-scrapers-and-crawlers-with-a-single-click/

### SMS toll fraud / pumping

- Twilio, *What Is SMS Pumping Fraud and How to Stop It*: https://www.twilio.com/en-us/blog/sms-pumping-fraud-solutions
- Stytch, *SMS Toll Fraud*: https://stytch.com/docs/guides/passcodes/toll-fraud/overview
- Sardine, *SMS Pumping Protection*: https://www.sardine.ai/blog/sms-pumping
- Akamai, *SMS Pumping*: https://www.akamai.com/glossary/what-is-sms-pumping

### Content moderation, CSAM

- Microsoft PhotoDNA: https://www.microsoft.com/en-us/photodna
- NCMEC: https://www.missingkids.org/
- Meta PDQ (open-source perceptual hash): https://github.com/facebook/ThreatExchange/tree/main/pdq
- Thorn Safer: https://safer.io/

### AI-content and provenance

- C2PA spec v2.4 (May 2025): https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html
- C2PA: https://c2pa.org/
- Content Authenticity Initiative: https://contentauthenticity.org/
- Kirchenbauer et al., *A Watermark for Large Language Models* (ICML 2023): https://arxiv.org/abs/2301.10226
- Mitchell et al., *DetectGPT* (2023): https://arxiv.org/abs/2301.11305
- Gehrmann, Strobelt, Rush, *GLTR* (ACL Demo 2019): https://arxiv.org/abs/1906.04043 and http://gltr.io/
- Google DeepMind SynthID: https://deepmind.google/technologies/synthid/

### Trust and Safety governance

- Trust & Safety Professional Association: https://www.tspa.org/
- TSPA Curriculum: https://www.tspa.org/curriculum/
- Tech Coalition TRUST Framework: https://www.technologycoalition.org/knowledge-hub/trust-voluntary-framework-for-industry-transparency
- EU Digital Services Act: https://commission.europa.eu/strategy-and-policy/priorities-2019-2024/europe-fit-digital-age/digital-services-act_en
- UK Online Safety Act 2023: https://www.gov.uk/government/publications/online-safety-act-explainer

### Sybils, fake accounts

- John Douceur, *The Sybil Attack* (IPTPS 2002): https://www.microsoft.com/en-us/research/publication/the-sybil-attack/
- Cao et al., SybilRank (NSDI 2012): https://www.usenix.org/conference/nsdi12/technical-sessions/presentation/cao
- Yu, Kaminsky, Gibbons, Flaxman, *SybilGuard* (SIGCOMM 2006): https://dl.acm.org/doi/10.1145/1159913.1159945
- Yu, Gibbons, Kaminsky, Xiao, *SybilLimit* (S&P 2008): https://www.comp.nus.edu.sg/~yuhf/yuh-sybillimit.pdf

### Industry reporting

- Anti-Phishing Working Group reports: https://apwg.org/trendsreports/
- Spamhaus: https://www.spamhaus.org/
- Recorded Future research: https://www.recordedfuture.com/research
- Meta Adversarial-Threat reports: https://about.fb.com/news/tag/coordinated-inauthentic-behavior/
- Cloudflare Radar: https://radar.cloudflare.com/

### Cross-discipline references

- Detection engineering sibling: [[detection_engineering_expertise]]
- Threat intel methodology: [[threat_intel_methodology_expertise]]
- Distributed authz (OAuth threat model): [[distributed_authz_expertise]]
- SAML / federation (session security): [[saml_federation_expertise]]
- Adversarial ML / model output: [[adversarial_ml_model_security_expertise]]
- LLM agent security: [[llm_agent_security_expertise]]
- Cryptography (passkeys, WebAuthn): [[cryptography_expertise]]
- AppSec program building: [[appsec_program_building_expertise]]
- Privacy engineering: [[privacy_engineering_expertise]]
