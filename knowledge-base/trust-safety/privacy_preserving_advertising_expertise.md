# Privacy-Preserving Advertising — Privacy Sandbox, SKAdNetwork, and Attribution
## Staff-Level Privacy-Preserving Advertising Guiding Principles

> **Framework:** Privacy-preserving advertising as a discipline emerged from a decade-long
> compounding of regulatory pressure, browser-vendor policy, and primary research into
> the inadequacy of third-party-cookie-based identity. It sits at the intersection of
> privacy engineering, web standards, mobile platform policy, and ad-tech business
> structure. The discipline's central question is whether interest-based advertising
> measurement can survive without ambient cross-site identifiers. As of 2026 the answer
> is contested: Google retired the bulk of Chrome's Privacy Sandbox in October 2025;
> Apple continues to ship App Tracking Transparency and the AdAttributionKit lineage;
> Mozilla and Meta pursue cryptographic multi-party attribution; the EU's DSA and DMA
> reshape gatekeeper obligations from the regulatory side.
>
> **Foundational researchers and institutional actors in scope:**
> - **Michael Kleber** (Google Chrome Privacy Sandbox team, principal engineer) —
>   lead architect for the Topics API and the Protected Audience API (formerly
>   FLEDGE / TURTLEDOVE).
> - **John Wilander** (Apple WebKit Security and Privacy team lead) — Intelligent
>   Tracking Prevention (Safari 11, September 2017); Storage Access API; Private
>   Click Measurement (PCM); USENIX Security 2019 "Privacy by Default on the Web."
> - **Eric Rescorla** (formerly Mozilla CTO, Firefox; subsequently Chief Technologist,
>   U.S. CDC Center for Forecasting and Outbreaks Analytics) — TLS 1.3 editor (RFC 8446);
>   privacy-preserving measurement architect; co-author on Mozilla DAP / PPA design.
> - **Aaron Roth** (Henry Salvatori Professor, University of Pennsylvania) — co-author
>   with Cynthia Dwork of *The Algorithmic Foundations of Differential Privacy*; the
>   canonical DP textbook underlying every aggregate-reporting design in this domain.
> - **Adam Smith** (Professor of Computer Science and Engineering, Boston University) —
>   co-author of *Calibrating Noise to Sensitivity in Private Data Analysis* (TCC 2006,
>   2017 Gödel Prize); shuffle-model DP (EUROCRYPT 2019) underlying aggregated attribution.
> - **Bruce Schneier** — *Data and Goliath* (2015); long-running critique of the
>   surveillance-advertising business model as a security and democracy externality.
> - **Cory Doctorow** (EFF special advisor) — *enshittification* theory of platform
>   decay; argues surveillance advertising does not work (P&G cut $100M+ in digital ads with flat sales);
>   ad-tech-as-surveillance framing in *Pluralistic* and Medium essays 2023-2026.
> - **Electronic Frontier Foundation (EFF)** — Privacy Badger (heuristic third-party
>   tracker blocking since 2014); Cover Your Tracks (formerly Panopticlick) fingerprint
>   surface measurement; Do Not Track standardization advocacy.
> - **W3C Privacy Community Group (PrivacyCG) and Web Platform Incubator Community
>   Group (WICG)** — incubator for CHIPS, FedCM, Storage Access API, Fenced Frames,
>   Shared Storage, Private State Tokens (formerly Trust Tokens), Global Privacy
>   Control; the Private Advertising Technology Community Group (PATCG) is the
>   industry venue for IPA-class attribution proposals.
> - **IAB Tech Lab (Interactive Advertising Bureau Technology Laboratory)** —
>   industry consortium that authored the *Privacy Sandbox Fit Gap Analysis* (February
>   and June 2024) flagging that only a small fraction of 44 critical ad-tech use
>   cases survived the Sandbox transition; TCF (Transparency and Consent Framework)
>   v2.2 for IAB-Europe consent signaling.
> - **Internet Security Research Group (ISRG) / Divvi Up** — operator of the
>   production DAP (Distributed Aggregation Protocol) deployment used by Mozilla's
>   Privacy-Preserving Attribution; sibling project to Let's Encrypt.
> - **Cookie consent platform vendors (OneTrust, TrustArc, Sourcepoint, Didomi,
>   CookieYes)** — implementation surface that translates GDPR / ePrivacy / state-law
>   consent obligations into the consent banners and signal-propagation that ad-tech
>   actually consumes.
>
> Sources: developer.chrome.com/docs/privacy-sandbox; webkit.org/blog (Wilander);
> blog.mozilla.org/en/mozilla/news/privacy-preserving-attribution-for-advertising;
> cis.upenn.edu/~aaroth/privacybook.html; cs-people.bu.edu/ads22; schneier.com;
> pluralistic.net; eff.org/pages/privacy-badger; w3.org/TR/gpc; iabtechlab.com;
> developer.apple.com/documentation/apptrackingtransparency; datatracker.ietf.org/doc/draft-ietf-ppm-dap;
> privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies.

---

## 1. The Transition — Why This Discipline Exists

Privacy-preserving advertising is the engineering response to a structural collision
between three forces: (1) the consumer-privacy movement codified in GDPR (2018), CCPA
(2020), and state-by-state US privacy laws (2021-2026); (2) browser-vendor product
decisions to deprecate or restrict third-party cookies as a defensible competitive
position; and (3) the underlying weakness of cookie-based identity as an honest
identifier in the presence of cross-site tracking. The discipline did not exist as
a coherent field in 2015; by 2026 it spans browser specifications, mobile platform
SDKs, multi-party cryptographic protocols, regulatory frameworks, and a contested
industry consensus on what "measurement" should mean when the user is not directly
identifiable.

### 1.1 The third-party cookie deprecation timeline

The third-party cookie was the de facto cross-site identity primitive for the
ad-tech industry from approximately 2000 to 2017. Its removal has proceeded at
substantially different speeds across browser vendors, with the resulting
fragmentation being a load-bearing fact of the discipline.

**Safari (Apple).** Intelligent Tracking Prevention (ITP) was introduced in
September 2017 with Safari 11 on macOS High Sierra and iOS 11. Initial ITP
1.0 used an on-device machine-learning classifier to identify cross-site
trackers and partitioned their cookies unless the user had interacted with
the site as a first party within the last 24 hours. Subsequent revisions (ITP 1.1, 2.0, 2.1, 2.2, 2.3) tightened
the heuristics, downgraded `document.referrer`, capped `localStorage` lifetime
for classified trackers, and ultimately moved Safari to **full third-party
cookie blocking by default in March 2020** (Safari 13.1). Wilander's WebKit
blog posts are the canonical primary-source record of this evolution; see
[webkit.org/blog/author/wilander/](https://webkit.org/blog/author/wilander/).

**Firefox (Mozilla).** Mozilla shipped Enhanced Tracking Protection (ETP) in
Firefox 63 (October 2018), blocking trackers from a Disconnect-curated list.
ETP "Standard" became the default protection level in June 2019; the rollout
of third-party cookie blocking by default for all users completed September 3,
2019. Mozilla also pioneered the Total Cookie Protection (state-partitioned
storage) shipped in Firefox 86 (February 2021) and extended to all users in
mid-2022.

**Chrome (Google).** Google announced in January 2020 that Chrome would phase
out third-party cookies "within two years," repeatedly slipped the date (June
2021 → 2023, July 2022 → 2024, April 2024 → 2025), and ultimately reversed
course. The April 22, 2025 [Privacy Sandbox blog post](https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies)
confirmed that Chrome would no longer deprecate third-party cookies and would
maintain existing user controls; on October 17, 2025, Google announced the
retirement of the bulk of the Privacy Sandbox technology stack (Attribution
Reporting, Protected Audience, Topics, Private Aggregation including Shared
Storage, Related Website Sets, SelectURL, Protected App Signals, On-Device
Personalization, SDK Runtime, IP Protection) while preserving a smaller
platform set (CHIPS, FedCM, Private State Tokens, Storage Access API).

**Edge (Microsoft).** Edge inherits Chromium's behavior with Tracking Prevention
ranging from Basic to Strict; the Strict mode blocks third-party trackers
aggressively. Edge's design choices generally track Chrome's with delay and
its own UI surface; the post-Sandbox-retirement design space remains in flux.

**Brave, Vivaldi, DuckDuckGo, Tor.** These browsers ship aggressive default
tracking-protection postures (Brave Shields, DuckDuckGo Smarter Encryption +
tracker blocking, Tor Browser's resist-fingerprinting mode) that pre-date and
exceed the mainstream-vendor positions. Brave specifically ships its own
ad-tech protocol stack (BAT, Brave Rewards) as a structural alternative.

### 1.2 The mobile lineage — Apple's ATT

The June 2020 iOS 14 announcement and the April 26, 2021 ATT rollout
(via iOS 14.5) introduced the most consequential mobile privacy change of the
decade. Apple's [App Tracking Transparency framework](https://developer.apple.com/documentation/apptrackingtransparency)
requires explicit user consent — via the system-rendered ATT prompt — before
an app may access the IDFA (Identifier for Advertisers) or otherwise track
the user across apps and websites owned by other companies. Without consent,
the IDFA returns all-zeros and the data is no longer cross-app-joinable.

Meta CFO David Wehner estimated in 2022 that ATT cost Meta approximately
**$10 billion in annual revenue** (about 9% of total); Snap, YouTube,
Twitter, and Facebook collectively reported approximately $9.85 billion in
shortfall in the second half of 2021 (Lotame). The downstream effect was the
acceleration of three trends: (1) industry adoption of SKAdNetwork for
install attribution; (2) walled-garden first-party measurement (Meta's
Conversions API, Google Enhanced Conversions) as a substitute for pixel-based
measurement; (3) the broader push toward server-to-server attribution.

### 1.3 Regulatory pressure — GDPR, CCPA, state laws

GDPR (General Data Protection Regulation, in force May 25, 2018) introduced
the lawful-basis framework (Article 6), the data-minimization principle
(Article 5(1)(c)), and Article 25's data protection by design and by default.
The ePrivacy Directive's Article 5(3) (the "cookie law") additionally requires
prior consent for storage of and access to information on terminal equipment
not strictly necessary for the requested service — the basis of Europe's
ubiquitous cookie banners.

CCPA (California Consumer Privacy Act, in force January 1, 2020) and CPRA
(California Privacy Rights Act, in force January 1, 2023) introduced opt-out
rights for sale and sharing of personal information; CPRA created the
California Privacy Protection Agency. By 2026, twenty-plus US states have
enacted comprehensive consumer-privacy statutes (Virginia, Colorado, Connecticut,
Utah, Texas, Oregon, Montana, Iowa, Indiana, Tennessee, Florida, and others),
producing the fragmented compliance surface that Global Privacy Control aims
to unify.

### 1.4 Why this matters for security

Privacy-preserving advertising overlaps with security on multiple axes:

- **Cross-site tracking is data leakage.** A third-party cookie or
  cookie-syncing infrastructure that observes a user across N sites is, in
  the information-theoretic sense, a covert channel between those sites.
  The ad-tech identity graph is one of the most extensive cross-organization
  data-sharing arrangements ever built; its disassembly is therefore a
  large reduction in cross-site identity inference.
- **Tracking infrastructure is influence-op infrastructure.** Ad-tech
  targeting primitives are also propaganda-targeting primitives; see
  [misinformation_influence_ops_expertise.md](misinformation_influence_ops_expertise.md)
  on how ad-tech surfaces have been co-opted for IRA-style influence
  campaigns, Cambridge Analytica, and political microtargeting.
- **Privacy-preserving APIs are themselves attack surface.** The Topics
  API, Attribution Reporting API, and Protected Audience API are large
  pieces of new browser surface that have been subjected to academic
  re-identification analysis (§7); poorly parameterized DP budgets are an
  exploitable failure mode.
- **Malvertising remains.** The deprecation of cookie-based tracking does
  not by itself reduce ad-network exposure to malicious creatives, click
  injection, or browser-runtime drive-by exploitation.

### Cross-references

- See [privacy_engineering_expertise.md](privacy_engineering_expertise.md)
  for the underlying differential privacy, MPC, and zero-knowledge primitives
  that the protocols in this document are built on.
- See [anti_fraud_abuse_engineering_expertise.md](anti_fraud_abuse_engineering_expertise.md)
  for click fraud, conversion fraud, and bot detection in a privacy-preserving
  measurement world.
- See [adversarial_ml_model_security_expertise.md](adversarial_ml_model_security_expertise.md)
  §5 for membership inference attacks adjacent to the Topics API re-identification
  research.
- See [misinformation_influence_ops_expertise.md](misinformation_influence_ops_expertise.md)
  for ad-tech as an influence operation surface.
- See [browser_js_engine_exploitation_expertise.md](browser_js_engine_exploitation_expertise.md)
  for Spectre-class side channels that motivated origin-keyed isolation,
  which in turn shapes the threat model for Fenced Frames and cross-site
  shared storage.
- See [cryptography_expertise.md](cryptography_expertise.md) for the
  RSA blind signature, OPRF, and verifiable distributed aggregation function
  (VDAF) primitives this domain depends on.
- See [llm_agent_security_expertise.md](llm_agent_security_expertise.md)
  for AI-agent-driven ad consumption and the prompt-injection / browsing-agent
  threat model that interacts with ad surfaces.

---

## 2. Chrome Privacy Sandbox — The Protocol Family

The Chrome Privacy Sandbox was Google's attempt, beginning August 2019, to
construct a portfolio of browser APIs that would provide ad-tech use cases
(interest-based targeting, remarketing, conversion measurement, fraud
detection, federated identity) without cross-site identifiers. The portfolio
was developed primarily in the W3C Web Platform Incubator Community Group
(WICG) and the Private Advertising Technology Community Group (PATCG), with
Michael Kleber as the public technical voice for the design.

The retrospective framing as of 2026: the portfolio shipped technically, the
ad-tech industry did not adopt it at scale, and the bulk of the stack was
retired in October 2025. The technical contributions remain influential —
particularly as a forcing function on the design of Mozilla's PPA and as a
public reference for how interest-based advertising could be reconstituted
on-device. The retired components are described below with their post-mortem
context; the surviving platform components (CHIPS, FedCM, Storage Access API,
Private State Tokens) continue under W3C standardization.

### 2.1 Topics API (retired October 2025)

The [Topics API](https://privacysandbox.google.com/private-advertising/topics)
returned a small number of interest topics drawn from a browser-curated
taxonomy (initial taxonomy: 349 categories; the updated taxonomy has 469
topics). Topics are derived on-device from the user's
browsing history over a one-week epoch; up to three topics — one per epoch
for the prior three weeks — are returned to callers via the `document.browsingTopics()`
JavaScript API or via the `Sec-Browsing-Topics` HTTP header on outbound
`fetch()` and iframe requests.

Privacy parameters:

- **Top-five sampling.** The topic returned for each epoch is sampled
  randomly from the user's top five topics of that epoch (so any individual
  observation is one of five, not deterministic).
- **5% noise.** With 5% probability the returned topic is sampled uniformly
  from the full taxonomy, not from the user's actual top-five — this is
  the local-DP-style randomization that bounds inference per epoch.
- **Caller-only observation.** Only topics that were observed for the user
  on a site where the calling third party was loaded are returned to that
  caller. This prevents callers from learning the user's interests on sites
  they were never present on.
- **Three-week retention.** Topics are kept on-device for three weeks and
  then expire.

The API was designed to be drop-in for interest-based targeting use cases
that had historically used cookie-based segments, and the API was retired.

### 2.2 Protected Audience API (retired October 2025; formerly FLEDGE, TURTLEDOVE)

The [Protected Audience API](https://developers.google.com/privacy-sandbox/relevance/protected-audience-api)
addressed the remarketing use case: showing an ad on site B for a product
the user viewed on site A, without site B learning that the user visited
site A or what product they viewed. The mechanism is an **on-device
auction**: the user's interest groups (advertiser-defined cohort memberships
recorded by the browser on the advertiser's site) are kept in the browser
and surfaced only at auction time through bidding and scoring scripts
running in isolated worklets. The auction result is rendered into a fenced
frame to prevent the embedder from inspecting the winning ad's contents.

The lineage:

- **TURTLEDOVE** (Two Uncorrelated Requests, Then Locally-Executed Decision
  On Victory) — original 2020 proposal.
- **FLEDGE** (First Locally-Executed Decision over Groups Experiment) —
  Chrome's prototype 2022-2023 Q2.
- **Protected Audience API** — renamed April 2023 to signal
  the privacy intent.

Adjacent proposals merged into the design: SPARROW (Criteo's trusted
execution environment service model), TERN (NextRoll's buyer/seller role
split), PARRROT (Magnite's seller-led auction model).

Auction flow:

1. Advertiser's site records the user in an `interestGroup` via
   `navigator.joinAdInterestGroup({ owner, name, ... })`.
2. Publisher's site (or its SSP) calls `navigator.runAdAuction(auctionConfig)`
   when an ad slot is available.
3. The browser invokes each interest group's `generateBid()` script in a
   worklet; bidders cannot observe the publisher context except through
   restricted contextual signals.
4. The seller's `scoreAd()` script ranks bids.
5. The winning bid is rendered into a fenced frame; the URL of the creative
   is opaque to the publisher.

Threat model: prevents the embedder from learning interest-group membership;
prevents the bidder from learning the publisher context beyond what the
seller's `auctionSignals` explicitly pass through; prevents cross-site
identity reconstruction by forcing the auction onto the device.

### 2.3 Attribution Reporting API (retired October 2025)

The [Attribution Reporting API](https://developer.chrome.com/docs/privacy-sandbox/attribution-reporting/)
provided two report types for measuring conversions:

- **Event-level reports.** Associate an ad-side event (impression or click)
  with a small coarse conversion-side payload (typically 3 bits for clicks,
  1 bit for views); reports are noised and delayed (sent at the end of report
  windows, by default 2 days, 7 days, and source expiry for clicks) to disassociate ad and conversion in time.
- **Aggregatable reports.** Submit rich conversion metadata as encrypted
  contributions to an aggregation service; the service computes histograms
  over the contributions under a configurable DP budget (epsilon) and
  returns aggregate counts. The aggregation service is a trusted third
  party operating in a TEE (trusted execution environment); the API was
  designed around the AWS Nitro Enclaves attestation model.

The API was the most cryptographically sophisticated part of the Sandbox;
its retirement leaves cross-site conversion measurement without a non-cookie
production-grade alternative on Chrome.

### 2.4 Private Aggregation API + Shared Storage API (retired October 2025)

[Private Aggregation](https://privacysandbox.google.com/private-advertising/private-aggregation)
provided a general-purpose aggregate-only reporting primitive: callers could
contribute encrypted values to an aggregation service that enforced a DP
budget. [Shared Storage](https://wicg.github.io/shared-storage/) provided
unpartitioned-but-isolated key-value storage usable from worklets, with the
constraint that any cross-site signal could only leave the worklet via
Private Aggregation (so the storage is fundamentally write-many-read-aggregate-only).
Together these primitives generalized the Attribution Reporting model to
support frequency capping, A/B testing, and lift measurement.

### 2.5 CHIPS — Cookies Having Independent Partitioned State (surviving)

[CHIPS](https://developers.google.com/privacy-sandbox/cookies/chips) introduces
the `Partitioned` cookie attribute, which causes the cookie to be double-keyed
on the (origin that sets the cookie) and (the top-level site of the embedding
page). The result is that a third-party cookie set in an iframe on site A
is not readable from the same iframe on site B — the third party retains
session state per top-level partition without retaining a cross-site
identifier. Use cases: third-party chat widgets, embedded payment frames,
embedded maps with per-user state.

Specification: IETF draft `draft-cutler-httpbis-partitioned-cookies`;
Chromium support by default since Chrome 114. The
[MDN documentation](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Privacy_sandbox/Partitioned_cookies)
specifies the requirements: `Partitioned` must be combined with `Secure`,
and `__Host-` prefix is recommended.

CHIPS is one of the few Sandbox technologies that survived the October 2025
retirement and has been adopted across browser vendors (Firefox uses
state-partitioned cookies by default; Safari partitions third-party storage
under ITP).

### 2.6 Storage Access API (surviving)

The [Storage Access API](https://privacycg.github.io/storage-access/)
provides a `document.requestStorageAccess()` call that lets a third-party
iframe request access to its first-party cookies in the top-level site's
context, with user-mediated or browser-policy-mediated approval. Use case:
federated login flows that need to read the identity provider's cookies in
the embedding context. The API ships in Safari, Firefox, and Chrome with
slightly different gating behavior.

### 2.7 Fenced Frames

[Fenced Frames](https://wicg.github.io/fenced-frame/) are an embedded-content
primitive that renders a URL whose contents are completely isolated from
the embedder — the embedder cannot read the frame's URL, the frame's
storage, or any data passed between them via channels like `postMessage`.
Fenced frames were designed as the rendering surface for Protected Audience
auction winners and for some Shared Storage outputs; with PAAPI retired,
fenced frames lose their primary use case, though the implementation
remains in Chrome.

### 2.8 Shared Storage API (retired October 2025)

Covered in §2.4. The retirement removes the Sandbox's general-purpose
cross-site aggregation primitive.

### 2.9 Related Website Sets (retired October 2025)

A browser-policy mechanism for declaring that a set of sites belong to the
same operational entity (e.g., google.com, google.co.uk, youtube.com); used
to permit certain cross-domain primitives without third-party-cookie semantics.
Retired with the rest of the Sandbox.

### 2.10 The Sandbox-retirement narrative

The post-mortem on the Sandbox shutdown is well-documented in industry trade
press and the IAB Tech Lab Fit Gap Analyses. Three contributing factors:

1. **Insufficient utility for the use cases.** Of 44 critical ad-tech use
   cases the IAB Tech Lab identified, only a small handful were supported
   to a degree that ad-tech operators considered usable. Frequency capping,
   video measurement, viewability measurement, audience-creation reach, and
   cross-channel attribution all had significant gaps. See [iabtechlab.com](https://iabtechlab.com/iab-tech-lab-releases-final-privacy-sandbox-fit-analysis/).
2. **Regulatory pressure.** The UK Competition and Markets Authority (CMA)
   imposed commitments on Google in February 2022 requiring industry
   consultation on Sandbox design and an effective veto over deprecation
   timing; the antitrust overlay made Google unable to simply force the
   Sandbox down the throat of ad-tech.
3. **DOJ antitrust ruling.** Judge Brinkema's April 17, 2025 ruling found
   Google had monopolized the publisher ad-server and ad-exchange markets;
   ad-tech remedies are ongoing and shape the structural environment in
   which a Sandbox successor would operate.

The result is that, as of 2026, Chrome continues to ship third-party cookies
by default, the cross-browser convergence on Sandbox-style designs has not
materialized, and the regulatory and industry energy has shifted to
Mozilla's PPA, Apple's AdAttributionKit, server-side measurement, and the
post-DSA / post-DMA gatekeeper-obligation regime.

---

## 3. Apple's Advertising-Privacy Stack

Apple has shipped the most consequential set of advertising-privacy
mechanisms over the past decade. The stack is a layered set of frameworks
that interact: ITP at the browser, ATT at the OS, SKAdNetwork / AdAttributionKit
at the StoreKit-attribution layer, PCM at WebKit, plus secondary services
(Hide My Email, iCloud Private Relay). Apple's framing is privacy-as-product;
the implicit competitive overlay — Apple's own ad business benefits from
making cross-tracking harder for third parties — is real and is discussed
in §3.8.

### 3.1 ITP — Intelligent Tracking Prevention

ITP launched in Safari 11 (September 2017) and has shipped roughly six
named revisions through 2024. The mechanism is a machine-learned classifier
applied to cross-site tracking heuristics:

- Identify domains that appear as third-party trackers across multiple
  first-party contexts.
- Partition or delete third-party storage for classified trackers.
- Cap the lifetime of `Storage` and `IndexedDB` data for classified
  origins (down to seven days, then twenty-four hours in some revisions).
- Downgrade `document.referrer` for cross-site navigation.

ITP 2.0 (Safari 12, 2018) removed the 24-hour cookie access window after
user interaction, leaving the Storage Access API as the path to cross-site
cookie access. ITP 2.1-2.3 progressively
tightened. The March 2020 announcement (`Full Third-Party Cookie Blocking
and More`) committed Safari to blocking all third-party cookies by default,
making Safari the first mainstream browser to do so. Wilander's WebKit blog
is the canonical primary-source record. See [webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/).

### 3.2 ATT — App Tracking Transparency

Covered in §1.2. The framework lives at `AppTrackingTransparency` in
`AppTrackingTransparency.framework`; the canonical API is
`ATTrackingManager.requestTrackingAuthorization(completionHandler:)`. Four
status values: `authorized`, `denied`, `restricted`, `notDetermined`. The
`authorized` state grants access to the IDFA (Identifier for Advertisers,
`ASIdentifierManager.advertisingIdentifier`); any other state returns
all-zeros.

App Store review enforces ATT compliance: apps that engage in tracking
without showing the system prompt risk rejection. Apple's definition of
"tracking" is in the App Store policies and explicitly includes data
linked to a user or device for advertising purposes, sharing data with
data brokers, and using third-party SDKs that perform tracking.

### 3.3 SKAdNetwork

[SKAdNetwork](https://developer.apple.com/documentation/storekit/skadnetwork/)
(introduced in iOS 11.3, materially upgraded in iOS 14 to v2.0, in iOS 14.5
to v2.2, and in iOS 16.1 to v4.0) is Apple's privacy-preserving install
attribution framework. The mechanism: the ad network presents a signed ad,
the user clicks or views the ad, the user later installs the app from the
App Store, and Apple sends a postback to the ad network that the install
happened — without exposing the user identity.

Key elements:

- **Six-bit conversion value.** The advertiser can update a 6-bit value
  (0-63) within a 24-hour window post-install. The conversion value is
  included in the postback to encode minimal downstream-event information
  (e.g., a hierarchical encoding of revenue tiers and feature engagements).
- **Crowd anonymity threshold.** SKAdNetwork 4.0 introduces fine-grained
  vs. coarse-grained conversion values: if the install count for the
  (campaign, source-app, source-event-domain) tuple is below an Apple-set
  threshold, the postback returns only coarse buckets (Low / Medium /
  High); above threshold, the fine 6-bit value is returned. This is a
  k-anonymity defense against using the conversion value as a side
  channel for user identification.
- **Randomized postback delay.** Postbacks are delayed and randomized to
  break the correlation between install time and click time.
- **Multiple postback windows.** SKAdNetwork 4.0 supports three measurement
  windows (0-2 days, 3-7 days, 8-35 days), each producing its own postback
  with its own crowd-anonymity-gated conversion value.

### 3.4 AdAttributionKit

[AdAttributionKit](https://developer.apple.com/documentation/AdAttributionKit)
(iOS 17.4, March 2024) is the successor framework that builds on the
SKAdNetwork foundation while broadening the model. Key additions:

- **JWS-signed ad impressions.** Ad impressions are encoded as JSON Web
  Signature compact JWS; the signing key is associated with the ad
  network's enrollment.
- **Re-engagement attribution.** The `conversion-type` field on postbacks
  distinguishes `download`, `redownload`, and `re-engagement` conversions.
- **Click and view attribution.** Both click-through and view-through
  attribution are supported.
- **Interoperability with SKAdNetwork.** Networks already enrolled for
  SKAdNetwork are automatically enrolled for AdAttributionKit; the
  postback semantics are designed to coexist.

Industry coverage in *AdExchanger* and at Apple's WWDC24 framed AdAttributionKit
as the replacement for SKAdNetwork over the medium term, though SKAdNetwork
itself continues to receive postbacks for legacy campaigns.

### 3.5 PCM — Private Click Measurement

[Private Click Measurement](https://webkit.org/blog/11529/introducing-private-click-measurement-pcm/)
(Safari 14.5, iOS 14.5, April 2021) is the WebKit-side analog to SKAdNetwork
for web-to-web and app-to-web click attribution. Mechanism:

- Click events on a publisher site annotate the navigation target with
  attribution metadata (`attributionsourceid`, `attributiondestination`).
- The destination (advertiser) site triggers a conversion via a redirect to a
  `/.well-known/private-click-measurement/trigger-attribution/` endpoint.
- Safari sends an attribution report to a publisher-side endpoint after
  a randomized 24-48 hour delay, with limited data (8-bit click source
  ID + 4-bit conversion data) and no cookies attached.

PCM is the conceptual ancestor of Chrome's Attribution Reporting API
(event-level reports). Its data envelope is intentionally smaller; its
threat model is correspondingly stronger but its utility for richer
attribution is more limited.

### 3.6 Hide My Email

iCloud+ subscribers can generate per-site alias email addresses that forward
to their actual iCloud account. The mechanism is straightforward
mail-forwarding; the privacy property is that the user's real email is not
disclosed to the site, and the user can revoke the alias unilaterally to
sever the relationship. The threat model: email addresses are a stable
cross-site identifier in ad-tech identity graphs (LiveRamp's RampID, The
Trade Desk's UID 2.0); per-site aliases break that linkage.

### 3.7 iCloud Private Relay

[iCloud Private Relay](https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/)
is a two-hop proxy network that obscures the user's IP address and DNS
queries from both Apple and from the destination site. Architecture:

- The user's Safari traffic is encrypted to an ingress relay operated by
  Apple; the ingress relay sees the user's real IP but not the destination.
- The traffic is re-encrypted and forwarded to an egress relay operated by
  a third party (Akamai, Cloudflare, and Fastly); the egress relay sees
  the destination but not the user's real IP.
- The destination site sees an egress IP from a Private Relay pool, with
  the region preserved but the city-level location coarsened.

Cryptographic primitives:

- **QUIC over UDP/443** with TLS 1.3.
- **RSA blind signatures** for anonymous authentication: the user's device
  obtains blind-signed tokens from Apple proving subscription status; the
  tokens are presented one-time to the ingress relay without revealing the
  user's identity. This is conceptually identical to the Privacy Pass
  protocol family that also underlies Private State Tokens.

The privacy property is end-to-end: no single party (not Apple, not the
egress operator, not the destination) can simultaneously observe the user's
identity and the destination URL.

### 3.8 The competitive overlay

Apple's advertising-privacy stack has a structural side effect: it harms
competitors (Meta, Google, third-party ad networks, mobile measurement
platforms) more than it harms Apple itself. Apple's own ad business
(Apple Search Ads, Apple News Ads) is exempt from ATT under Apple's
classification of first-party data; Apple's Search Ads grew its
share-of-wallet by approximately 5 percentage points from Q2 2021 through
Q2 2022 (Appsumer), while Facebook's share-of-wallet dropped 4 percentage
points. The regulatory consequence: the German Federal Cartel Office and
the French Autorité de la concurrence both opened ATT-related
investigations, and the EU DMA explicitly addresses asymmetric obligations
on gatekeepers.

---

## 4. Mozilla Privacy-Preserving Attribution

Mozilla's [Privacy-Preserving Attribution (PPA)](https://support.mozilla.org/en-US/kb/privacy-preserving-attribution),
introduced as an experimental Firefox 128 feature in July 2024 that was
never activated and was later removed,
takes a fundamentally different technical approach than Chrome's Attribution
Reporting API: rather than relying on a single trusted aggregator (or a TEE
attestation thereof), PPA uses **multi-party computation** via the IETF's
[Distributed Aggregation Protocol (DAP)](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/).
The collaboration with Meta on the [Interoperable Private Attribution (IPA)](https://github.com/patcg-individual-drafts/ipa)
proposal in the W3C Private Advertising Technology Community Group (PATCG)
is the design venue.

### 4.1 The DAP protocol

DAP is an IETF standards-track protocol (current draft `draft-ietf-ppm-dap-20`,
October 2026) for privacy-preserving aggregate measurement. Architecture:

- **Two aggregation servers** operated by mutually distrustful parties
  (typically the measurement publisher and an independent third party such
  as ISRG / Divvi Up).
- Clients submit their measurement reports **secret-shared** across the
  two aggregators: each aggregator receives only a share that is
  information-theoretically meaningless on its own.
- Aggregators perform MPC over the shares to compute aggregate statistics
  (histograms, sums, mean) without either aggregator ever seeing the
  individual client reports.
- The aggregate result is published to a collector (the data consumer)
  with optional differential-privacy noise added by the aggregators.

DAP is built on **VDAFs (Verifiable Distributed Aggregation Functions)**,
specified in `draft-irtf-cfrg-vdaf-13`. The Prio3 VDAF family (used for
sum, count, and histogram queries) is itself a refinement of Henry Corrigan-Gibbs
and Dan Boneh's 2017 Prio system.

See [privacy_engineering_expertise.md §6](privacy_engineering_expertise.md)
for the broader MPC primitives the DAP family builds on.

### 4.2 IPA and the Mozilla-Meta collaboration

Mozilla and Meta jointly proposed IPA (Interoperable Private Attribution)
in the PATCG in 2022. The design extends DAP-style MPC attribution with
specific affordances for ad measurement: source-events (impressions and
clicks) and trigger-events (conversions) are joined across the user's
devices using a privacy-preserving match-key construction. The MPC
preserves match-key secrecy while still permitting aggregate join.

The collaboration is notable because Meta is the canonical ad-tech actor
that ATT and Privacy Sandbox were designed to constrain; the joint design
work signals that the ad-tech industry has accepted MPC-based attribution
as a viable replacement for cookie-based attribution if it can be
operationalized at scale. As of 2026, IPA has not shipped in any production
browser.

### 4.3 Mozilla Privacy-Preserving Telemetry

Mozilla also operates an internal privacy-preserving telemetry system using
DAP for Firefox-internal metrics that aggregates across the Firefox
user population without retaining per-user signals. This was the practical
testbed for DAP that preceded the PPA prototype's exposure to advertisers.

### 4.4 Firefox's tracker-blocking lineage

Beyond PPA, Firefox ships:

- **Enhanced Tracking Protection (ETP)** — Disconnect-curated tracker
  blocklist, ships since Firefox 63 (October 2018).
- **Total Cookie Protection** — state-partitioned cookies by default
  since Firefox 103 (mid-2022).
- **Fingerprinting Protection** — blocks known fingerprinting scripts
  and adds randomization to fingerprint-relevant APIs in Strict mode
  and Private Browsing.

Firefox's market share (single-digit percentages) limits the structural
influence of its design choices, but the influence on the W3C standards
process is substantial.

---

## 5. Microsoft Edge, Brave, DuckDuckGo, and Others

### 5.1 Microsoft Edge

Edge inherits Chromium's design surface but operates its own Tracking
Prevention with three levels: Basic, Balanced (default), and Strict. Strict
blocks harmful trackers and most trackers from all sites. Edge participated in Privacy Sandbox testing through the Chromium
collaboration; following the Sandbox retirement, Edge's post-Sandbox
roadmap remains in flux. Microsoft Advertising operates its own
privacy-preserving measurement APIs (`Universal Event Tracking` evolution
toward server-side measurement), targeted toward Bing search and Microsoft
properties.

### 5.2 Brave

Brave Software ships an aggressive default privacy posture: Brave Shields
block third-party trackers, third-party cookies (always, regardless of
Sandbox), and fingerprinting scripts; HTTPS by Default upgrades HTTP sites
to HTTPS; canvas and Web Audio outputs are randomized ("farbling"). Brave's structural alternative is **Brave Rewards** + **BAT
(Basic Attention Token)**: the browser observes ad attention on behalf of
the user, the user receives BAT for opt-in attention, and advertisers
purchase ad placements via the BAT marketplace. The on-device computation
of attention metrics is conceptually adjacent to Privacy Sandbox's Topics +
Attribution Reporting but implemented as a closed system. Brave reported
approximately 70 million monthly active users in 2024.

### 5.3 DuckDuckGo

The DuckDuckGo browser (mobile since 2018, desktop since 2022) bundles
search, tracker blocking via the Tracker Radar dataset, and "Smarter
Encryption" HTTPS upgrading. App Tracking Protection (Android only) extends
tracker blocking from web to native app traffic by acting as a local VPN
that filters known tracker endpoints. DuckDuckGo Tracker Radar is published
under a CC BY-NC-SA 4.0 license and used as a reference dataset for academic
tracker measurement.

### 5.4 Tor Browser

Tor Browser (Mozilla Firefox ESR fork) is the gold-standard reference for
anti-fingerprinting design: it actively flattens the user-agent, screen
resolution, font list, timezone, canvas, audio context, and WebGL outputs
to a homogeneous baseline shared across all Tor users. Tor's threat model
is far stronger than commercial-browser privacy modes; it is the canonical
reference design for resist-fingerprinting.

### 5.5 Vivaldi and Opera

Vivaldi (Chromium-based) ships built-in tracker blocking via the DuckDuckGo
Tracker Radar dataset; Opera (Chromium-based) bundles a "VPN" (technically
an HTTP proxy) for free users. Both are minor-share browsers whose
design choices follow the leaders.

---

## 6. Cross-Site Tracking Attack Surface

Before the cookie-deprecation era, cross-site identity reconstruction
relied on a small set of explicit techniques: third-party cookies, cookie
syncing across DSPs / SSPs, and pixel-based ID-graph construction. Those
techniques are now partially deprecated. The surviving and substitute
techniques operate at lower layers of the stack and are correspondingly
harder to defend against.

### 6.1 Cookie syncing and ID graph reconstruction

The pre-deprecation pattern: when site A loads tracker T1 (via a
third-party iframe), T1 reads its own cookie and learns the user's T1-ID;
T1 then loads tracker T2 (cookie-sync), T2 reads its own cookie and
learns the user's T2-ID; the two trackers exchange the IDs via URL
parameters and now share an identity mapping. Repeated across hundreds
of trackers and millions of sites, the result is the **identity graph**
that LiveRamp, Acxiom, and Oracle have monetized as the substrate of
ad-tech identity resolution. The graph is also accessible to malicious
actors who participate in any node of the ad-tech ecosystem; the same
graph is used by data brokers, surveillance vendors, and law-enforcement
data brokers (a documented practice in the Mobilewalla / X-Mode
controversies).

Defense (browser side): third-party cookie blocking + CHIPS + partitioned
storage break direct cookie syncing. The defense is incomplete because
the same identity can be reconstructed via other mechanisms.

### 6.2 Fingerprinting — canvas, audio, font, WebGL

Browser fingerprinting reconstructs cross-site identity from device-level
signals that the site is permitted to observe directly. The canonical
techniques:

- **Canvas fingerprinting.** Render a known text or shape into a
  `<canvas>` element with specified font and styling; extract the rendered
  pixels via `toDataURL()` and hash them. Different combinations of OS,
  GPU, font version, and anti-aliasing settings produce different pixel
  outputs; the hash becomes a stable per-device identifier.
- **Audio context fingerprinting.** Construct an `OfflineAudioContext`,
  feed a known sine wave through a known filter graph, and extract the
  output sample buffer. Slight differences in the device's audio
  processing pipeline (sample-rate conversion, floating-point rounding)
  produce different output buffers; the hash is stable.
- **Font enumeration.** Iterate a list of fonts and measure rendered
  widths; the set of installed fonts is highly identifying.
- **WebGL fingerprinting.** Query the GPU vendor / renderer strings,
  shader precision, supported extensions; combined with rendered-pixel
  hashes of GPU-rendered content.
- **Hardware concurrency, screen resolution, color depth, timezone,
  preferred language.** Individually low-entropy; combined high-entropy.

Academic measurement (the canonical reference is the Panopticlick / Cover
Your Tracks dataset from EFF, plus Princeton's OpenWPM crawls) has
demonstrated that browser fingerprinting can re-identify approximately
80-95% of unique browsers on the open web. Apple's Safari 17 (September
2023) introduced [randomization of `AudioContext` outputs in Private
Browsing](https://webkit.org/blog/14443/news-from-wwdc23-web-platform-features-in-safari-17-beta/);
Firefox Strict mode and Tor Browser actively randomize or homogenize
fingerprint-relevant outputs.

See [browser_js_engine_exploitation_expertise.md](browser_js_engine_exploitation_expertise.md)
for the Spectre-class side channels that motivated origin isolation, which
in turn shapes the constraints on what fingerprinting JavaScript can
observe across origins.

### 6.3 IP-address-as-identifier

Even without cookies or fingerprinting, the IP address remains a relatively
stable cross-site identifier (modulo mobile carrier-grade NAT and changing
home networks). iCloud Private Relay, residential VPNs, and Tor are the
primary user-side defenses. Server-side, the IP is increasingly less
useful: VPN adoption, CGN, and IPv6 privacy extensions degrade its
identifying power.

The Google Chrome IP Protection proposal — itself retired in
October 2025 as part of the Sandbox shutdown — would have hidden the IP
from third-party origins by routing through Google-operated proxies.

### 6.4 First-party data and walled gardens

The aftermath of cookie deprecation has been a shift of advertising value
toward **first-party data**: the data an advertiser collects directly from
its own users. Walled gardens (Meta, Google, Amazon, TikTok) are the
primary beneficiaries because they have the most first-party data and the
most users. The conversion-measurement substitute is **server-to-server**
attribution: the advertiser sends conversion events directly to the
ad-tech provider via API (Meta's Conversions API, Google Enhanced
Conversions), with the advertiser doing its own user-identity matching
on its own data. From a privacy-engineering standpoint, server-to-server
attribution is not privacy-preserving — it simply moves the joining to a
different layer — but it is the practical industry response.

### 6.5 The tracker-as-detection inversion

A useful research lens: the tools built to defeat trackers (Privacy
Badger, uBlock Origin, Disconnect, DuckDuckGo Tracker Radar) are also
the most comprehensive published catalogs of tracker infrastructure.
Reverse-using these catalogs is how academic researchers (Princeton CITP,
Mozilla Research, EFF) have measured the third-party-tracking surface at
web scale. The catalog data is also useful for defenders mapping their
own organization's exposure to ad-tech identity graphs.

---

## 7. Adversarial Considerations

The privacy-preserving APIs themselves are large new attack surfaces.
The defense properties asserted by Sandbox, PPA, SKAdNetwork, and PCM
depend on specific privacy parameterizations; mis-parameterization is
the most common failure mode.

### 7.1 Re-identification attacks on the Topics API

Multiple academic papers in 2023-2024 have analyzed the Topics API for
re-identification risk. Notable findings:

- *A Public and Reproducible Assessment of the Topics API on Real Data*
  (Beugin & McDaniel, arXiv:2403.19577, 2024) — finds on real browsing
  data that the API does not provide the same privacy guarantees to all
  users, with cross-site re-identification probabilities of 2%, 3%, and
  4% after 1, 2, and 3 observations.
- *Re-Identification Attacks against the Topics API* (Jha et al., ACM
  Transactions on the Web, 2024) — finds that a user's topic profile can
  remain unique within a website's audience, letting an attacker match
  the same user across sites; correct re-identification can reach 50%
  for a pool of 1,000 users.
- *The Privacy-Utility Trade-off in the Topics API* (Alvim, Fernandes,
  et al., ACM CCS 2024) — uses Quantitative Information Flow to analyze
  the re-identification risk the API introduces; shows that Topics has
  better privacy than third-party cookies and leaves utility analysis to
  future work.

The take-away is that **5% global noise is not a strong privacy bound** in
the presence of repeated observations and a top-five sampling scheme that
exposes the user's actual top-five distribution over time. The local-DP
formulation of Topics is not differentially private at any usable epsilon
under composition across multiple epochs and multiple callers.

### 7.2 Protected Audience side channels

The Protected Audience auction is run in worklets that have restricted
inputs and outputs; the privacy invariant depends on the bid-and-score
scripts not leaking interest-group membership to the publisher via timing,
network behavior, or auction-result-rendering. Specific concerns:

- Timing side channels: the auction's wall-clock duration depends on which
  interest groups are present; a publisher that observes the auction
  duration can infer membership in the user's interest-group set.
- Auction-result fingerprinting: a winning ad's URL is opaque to the
  publisher (rendered in a fenced frame), but observable side effects
  (resource fetches initiated by the ad creative, navigation patterns) can
  leak information about the creative's source.
- Bid-script-controlled trusted-bidding-signals fetches: the seller and
  buyer fetch contextual signals from external endpoints; the request
  pattern can correlate to interest-group membership.

The reduced relevance of these concerns post-October-2025 (PAAPI retired)
does not eliminate them — the conceptual issues recur in any on-device
auction design and are relevant to PATCG / IPA-class proposals that retain
on-device computation.

### 7.3 Attribution Reporting privacy budget management

The Attribution Reporting API's aggregatable reports operate under a
per-source (ad click or view) **L1 contribution budget** that bounds the
total contribution across reports. Sites and reporting origins must
allocate the budget across measurement use cases; over-allocating any
single use case starves the others, and the budget is finite over a
rolling window. From an adversarial standpoint, the budget mechanism is
both the privacy property and the operational fragility: a misconfigured
budget (epsilon too large, or query repetition not deduplicated) admits
membership inference; the aggregation service's TEE attestation is also
a load-bearing trust assumption.

See [adversarial_ml_model_security_expertise.md §5](adversarial_ml_model_security_expertise.md)
for the broader membership-inference threat model.

### 7.4 Small-population deanonymization in SKAdNetwork

SKAdNetwork's crowd-anonymity threshold is the defense against small-population
deanonymization: if the (campaign, source-app, source-event-domain) install
count is below threshold, the postback drops to coarse buckets. The threshold
is set by Apple and is not publicly documented in detail; the empirical
behavior is that small advertisers and niche campaigns regularly receive
only coarse conversion values, which is the intended privacy property but
which severely limits utility for small-population campaigns. The corresponding
attack: a sophisticated advertiser running many small narrow campaigns can,
in aggregate, accumulate signal that approaches fine-grained per-user
identification — Apple's threshold defends against the obvious-case attack
but not against the aggregating-across-campaigns attack.

### 7.5 K-anonymity, l-diversity, t-closeness

The aggregation defenses across this domain (Topics' top-5 sampling, SKAdNetwork's
crowd-anonymity threshold, the aggregation services' DP budgets, DAP's MPC
output) all rest on aggregation primitives that have a long literature in
privacy engineering. See [privacy_engineering_expertise.md §5](privacy_engineering_expertise.md)
for the canonical k-anonymity → l-diversity → t-closeness progression and the
limitations of each. The salient observation for this domain: most production
deployments rely on k-anonymity or simple DP noise; few deploy proper
t-closeness or composition-aware DP accounting; the gap between deployment
practice and the underlying theory is wide.

### 7.6 Differential-privacy budget at scale

DP budgets must be accounted across queries; naïvely treating each query
as independent leaks epsilon proportional to the query count. RDP (Rényi
DP, Mironov 2017) and zCDP (zero-concentrated DP, Bun-Steinke 2016) are
the canonical accounting frameworks. Apple's local-DP deployments use epsilon 4 per day for emoji
and 2 per day for Health Type Usage.

---

## 8. Real-World Deployments and Adoption

### 8.1 Privacy Sandbox adoption (2023-2025)

Chrome shipped Topics, Protected Audience, and Attribution Reporting to
general availability in Chrome 115 (Q3 2023). The IAB Tech Lab Fit Gap
Analysis (February 2024) reported that of 44 critical ad-tech use cases,
the Sandbox supported only a small handful at the granularity required;
adoption was correspondingly low. Per the October 17, 2025 Privacy
Sandbox retirement announcement, "low levels of adoption" was a
primary cited reason for retirement.

### 8.2 SKAdNetwork / AdAttributionKit adoption

SKAdNetwork is the de facto industry-standard install-attribution
mechanism for iOS post-ATT; all mobile measurement platforms (Adjust,
AppsFlyer, Singular, Branch, Kochava) support SKAdNetwork ingestion.
AdAttributionKit (iOS 17.4+, March 2024) adoption is gradual: the
backward-compatible coexistence with SKAdNetwork postbacks reduces the
urgency of migration for ad networks. The signal-loss debate continues:
mobile measurement platforms typically combine SKAdNetwork postbacks
with last-click ID-graph-resolution (where consent permits) and
walled-garden first-party data.

### 8.3 Mozilla PPA adoption

PPA was enabled in Firefox by default in July 2024 (a controversial
opt-out rather than opt-in choice that noyb and others criticized); the
prototype's aggregator was Divvi Up / ISRG. The experiment was intended
to run only on two Mozilla-operated websites, was never activated, and
was later removed. The PATCG / IPA collaboration with Meta is
the longer-term industry on-ramp.

### 8.4 Walled-garden measurement transitions

Meta's Conversions API (CAPI), Google's Enhanced Conversions, TikTok's
Events API, Snap's Conversion API, and Pinterest's Conversion API all
became substantial adoption-pull post-ATT. The structural effect: ad-tech
measurement increasingly happens **server-to-server** between advertiser
and platform, with the user-identity-matching done by the platform on
its own first-party data. From a privacy-engineering standpoint, this is
not an improvement in user privacy; it is a consolidation of the
user-identity-matching into the walled gardens.

### 8.5 Industry impact metrics

Reported industry-wide impact of cookie-deprecation and ATT (2021-2024):

- Meta: approximately $10B annual revenue impact attributed to ATT
  signal loss (2022 CFO commentary).
- Snap: approximately $29B market-cap drop in October 2021 following
  Q3 earnings call attributing slowdown to ATT.
- Google Search ads: comparatively insulated due to the lack of
  cross-app tracking dependency; Google Ad Network products had more
  exposure.
- TikTok: continued growth through the ATT transition by leveraging
  first-party signals and creator-driven measurement.

The five-year retrospective (2026) is that the ad-tech industry has
substantially adapted: server-to-server measurement, walled-garden
consolidation, AI-driven contextual targeting (where the targeting is
recomputed per-impression from the visible page context), and the
rise of clean-room infrastructure (Snowflake Data Clean Rooms, AWS Clean
Rooms, Habu) for inter-organization measurement collaboration.

---

## 9. Regulatory Landscape 2024-2026

### 9.1 EU DSA — Article 26 (advertising transparency)

The [Digital Services Act](https://digital-strategy.ec.europa.eu/en/policies/digital-services-act)
(Regulation (EU) 2022/2065, fully in force February 2024) imposes
advertising-transparency obligations on online platforms. Article 26
requires that for each advertisement, the recipient must be able to
identify in a clear and unambiguous manner: (a) that it is an advertisement;
(b) the legal person on whose behalf the ad is presented; (c) the legal
person who paid for the ad (if different); (d) meaningful information
about the main parameters used to determine the targeting, with the
ability to change those parameters.

Article 26(3) prohibits advertising based on profiling using special
categories of personal data (Article 9 GDPR data: race, political
opinion, religious belief, health, sexual orientation, biometric
identifiers, genetic data, trade union membership).

IAB Europe and EDAA have published implementation guidelines (the
Advanced Advertising Transparency Programme, AATP) and technical
specifications for compliance. The DSA's ad-transparency repository
requirement also produced public dashboards exposing political-ad
spending across VLOPs (Very Large Online Platforms).

### 9.2 EU DMA — Article 5 (gatekeeper obligations)

The [Digital Markets Act](https://digital-markets-act.ec.europa.eu/index_en)
(Regulation (EU) 2022/1925, in force March 2024) targets "gatekeeper"
platforms (Google, Apple, Meta, Microsoft, Amazon, ByteDance, Booking).
Article 5(2)(a) prohibits gatekeepers from processing personal data from
third-party services for advertising purposes without explicit user
consent; Article 5(2)(b) prohibits combining personal data from the
gatekeeper's core platform service with data from other gatekeeper-owned
services or third-party services without consent; Article 5(2)(c) and (d)
restrict cross-service data sign-in and cross-service ad targeting.

The DMA's interaction with ATT is structurally interesting: Apple's ATT
imposes consent on third parties using IDFA; the DMA imposes consent on
gatekeepers (including Apple) combining data across services. The French
competition authority fined Apple €150 million over ATT in March 2025,
and the German Bundeskartellamt closed its ATT proceeding with binding
commitments in August 2026.

### 9.3 California — CCPA / CPRA / CalOPPA

CCPA (in force January 2020) created the right to know, delete, and
opt out of "sale" of personal information; CPRA (in force January 2023)
created the additional right to opt out of "sharing" for cross-context
behavioral advertising and established the California Privacy Protection
Agency. Cross-context behavioral advertising is a CCPA-specific term that
maps roughly to third-party advertising in EU parlance; the opt-out
right is the legal basis for honoring Global Privacy Control signals.

### 9.4 Other US state laws

By 2026 the patchwork of comprehensive state laws includes: Virginia
CDPA (2023), Colorado CPA (2023), Connecticut CTDPA (2023), Utah UCPA
(2023), Texas TDPSA (2024), Oregon OCPA (2024), Montana MCDPA (2024),
Iowa ICDPA (2025), Indiana INCDPA (2026), Tennessee TIPA (2025),
Florida FDBR (2024), New Jersey NJDPA (2025), New Hampshire NHDPL (2025),
Delaware DPDPA (2025), and additional state activity ongoing. The
variation across statutes — opt-in vs. opt-out, sensitive-data definitions,
data-broker registration regimes, private rights of action — produces a
complex compliance surface that consent-management platforms (OneTrust,
TrustArc, Sourcepoint, Didomi) operationalize.

### 9.5 Global Privacy Control

[Global Privacy Control](https://globalprivacycontrol.org/) is a W3C
specification (W3C Privacy Working Group as of November 2024) for a
machine-readable opt-out signal sent by user agents to web servers,
operationalizing the CCPA "Do Not Sell or Share My Personal Information"
opt-out and other state-level analogs. Two surfaces: an HTTP header
(`Sec-GPC: 1`) and a JavaScript property (`navigator.globalPrivacyControl`).
California Attorney General guidance has confirmed GPC as a valid CCPA
opt-out mechanism; Colorado, Connecticut, Texas, and other state laws
similarly recognize universal opt-out signals.

GPC's adoption status (2026): supported by Firefox (default in Private Browsing,
toggleable elsewhere), Brave (default), DuckDuckGo (default); Safari and
Chrome require an extension.
Server-side enforcement is uneven; the CCPA's actionability of GPC has
been validated in several California AG enforcement actions.

### 9.6 COPPA + KOSA + state children's privacy

COPPA (Children's Online Privacy Protection Act, 1998, FTC-enforced)
remains the federal baseline for under-13 data collection in the US.
State-level expansions (California Age-Appropriate Design Code 2022,
Utah Social Media Regulation Act 2023, Maryland Kids Code 2024) extend
protections beyond COPPA's age threshold and introduce default-private
settings, age-appropriate-design obligations, and design-pattern
restrictions on minors' experiences. KOSA (Kids Online Safety Act) is
the federal proposal that has cycled through multiple Congresses without
enactment as of 2026.

### 9.7 DOJ Google ad-tech ruling

Judge Brinkema (E.D. Va.) ruled April 17, 2025 that Google had
monopolized the publisher ad-server and ad-exchange markets in violation
of Sherman Act sections 1 and 2. In September 2026 Brinkema
rejected the DOJ's structural remedies, including AdX divestiture, and
imposed six years of behavioral remedies overseen by a monitor. The 2024 ruling in *United States v.
Google* (search monopolization, Judge Mehta D.D.C.) and the 2025 remedy
order in that case (search-distribution-deals constraints) are the
broader antitrust context.

See [privacy_engineering_expertise.md §9](privacy_engineering_expertise.md)
for GDPR / CCPA operationalization patterns at the engineering layer.

---

## 10. Detection and Abuse Considerations

### 10.1 Malvertising

The deprecation of cookie-based tracking does not reduce the malvertising
attack surface. Ad networks remain a high-fidelity distribution channel
for drive-by exploitation, scam ads, fake-update ads (FakeBat, SocGholish,
ClearFake), and tech-support-fraud landings. Detection occurs at the
ad-network level (Google Ads ad-policy enforcement, Confiant) and at the browser level (Safe Browsing, SmartScreen,
content security policy). The Privacy Sandbox's fenced-frame rendering
slightly reduces some classes of advertiser-side JavaScript abuse by
isolating creatives but does not address malicious ads in general.

### 10.2 Click injection and conversion fraud

Click injection (registering a phantom click before a legitimate install
to claim attribution) and conversion fraud (fabricating conversions to
extract attribution payouts) remain active. SKAdNetwork's signed-ad-impression
model and randomized postback delay reduce the surface for naive click
injection; sophisticated fraud operations adapt by clicking on
real-creative-impressions before installs. AdAttributionKit's JWS-signed
impressions raise the bar further. See [anti_fraud_abuse_engineering_expertise.md](anti_fraud_abuse_engineering_expertise.md)
for bot detection and click fraud at scale.

### 10.3 Privacy Sandbox API abuse

Even-retired-API abuse: the Topics API was investigated for side-channel
inference of user interest from topic returns (the 5% noise can be
filtered statistically across observations); the Protected Audience API
auction-timing channel; the Attribution Reporting API budget-management
mis-configuration leading to membership inference. These are documented
in the academic literature cited in §7.

### 10.4 The bot-detection / privacy-preservation tension

A real tension: bot detection at the ad-impression layer historically
relies on cross-site identity, fingerprinting, and behavioral analysis
that overlap with the techniques privacy-preserving advertising aims to
constrain. Private State Tokens (formerly Trust Tokens) was Privacy
Sandbox's answer: a Privacy-Pass-protocol-based mechanism for transferring
a small amount of anti-abuse signal across contexts without identity.
The PST mechanism survives the October 2025 Sandbox retirement.

Mechanism: an issuer (e.g., a captcha provider) issues blind-signed
tokens to a user after a positive bot-check; a different relying party
later redeems a token to verify the user has been positively-checked,
without learning which user or which check was performed. The
cryptographic construction is the Privacy Pass protocol family
(`draft-ietf-privacypass`), which is also the basis of Cloudflare's
Privacy Pass extension.

### 10.5 Fraud in privacy-preserving environments

The general principle: privacy-preserving measurement aggregates over
populations and adds noise; small-volume fraud (low-volume claim
injection) survives the aggregation as long as it falls within the
noise envelope. Detection accordingly moves up the stack: from
per-impression cross-site fingerprinting (now harder) to publisher-side
behavioral analysis, server-side traffic-shape analysis, and post-hoc
campaign-level anomaly detection. Industry practice is increasingly to
combine privacy-preserving measurement with non-privacy-preserving
fraud detection that operates on the publisher's first-party data —
the privacy-preserving guarantee applies to the cross-site measurement,
not to the publisher's internal abuse detection.

---

## 11. Variant Analysis — Under-Explored Areas

### 11.1 AI agent-driven advertising

When an LLM-driven browsing agent traverses web pages on behalf of a
user, who is the recipient of the advertising signal? The Topics API's
per-week-of-browsing topic derivation is conceptually broken when the
"user" is actually a research-agent fan-out across hundreds of pages
that do not reflect the user's interests. The Protected Audience
auction's interest-group recording is similarly distorted. As of 2026,
the agentic-web specs (Anthropic Model Context Protocol, OpenAI Operator,
Google Project Mariner) do not have an opinion on ad-handling; the de
facto behavior is that agent traffic mixes with user traffic and pollutes
the user's interest profile.

The structural questions:

- Should browsing agents have a separate ad-identity scope from the
  user, so that agent-driven browsing does not pollute the user's
  Topics, interest groups, or attribution budgets?
- Should ads served to agents be priced or measured differently? IAB
  Tech Lab's Agentic Advertising Management Protocols (AAMP) work
  (2025-2026) is early-stage.
- Privacy: an agent that browses on behalf of the user has access to
  the user's identity and may be tricked (via prompt injection in ad
  creative) into exfiltrating it. See
  [llm_agent_security_expertise.md](llm_agent_security_expertise.md).

### 11.2 AR/VR advertising privacy

Privacy-preserving advertising for spatial computing (Vision Pro, Quest,
Pico) is largely greenfield. The platforms' eye-tracking, hand-tracking,
and room-mapping data is a substantial new privacy surface; Apple's
visionOS does not share eye input with Apple, third-party apps, or
websites; only final selections are transmitted. The advertising
primitives have not yet been defined: spatial ad placement, attention-based
measurement, gaze-target measurement are research-stage; the privacy
properties have not yet been worked out at the spec level.

### 11.3 Server-side measurement evolution

Server-side tagging (Google Tag Manager Server-Side, Facebook CAPI,
LinkedIn Insight Tag server-side) is the practical industry response to
browser-level deprecation. From an engineering standpoint:

- Server-side measurement moves the user-identity-resolution to the
  advertiser's server, where it is harder for the browser or OS to
  interpose.
- The pseudonymization, hashing, or salted-hashing of identifiers (email,
  phone, IDFA) before sending to the platform partially mitigates direct
  identifier leak but does not prevent join when the platform has the
  hashing key.
- Clean rooms (Snowflake Data Clean Room, AWS Clean Rooms, Habu, AppsFlyer
  Data Clean Room) operationalize multi-party data-sharing with
  query-level access control and DP-like output noise.

The privacy properties of server-side measurement are not generally
auditable from the user's perspective; the regulatory response (GDPR
controller / processor responsibility, DSA / DMA obligations) is the
primary defense.

### 11.4 Walled-garden vs. open-web measurement disparity

A persistent inequality: walled gardens have the user's first-party data
(login, purchase, in-app behavior) and therefore can measure ad
effectiveness without cross-site tracking; the open web does not have
first-party data on the same population and depends on the privacy-
preserving primitives. The deprecation of cookies therefore systematically
favors the walled gardens against the open web; the post-cookie measurement
gap is the structural concern of publisher-advocacy organizations (IAB).

### 11.5 Privacy-preserving advertising for children

Post-COPPA + state children's-privacy laws + UK Online Safety Act + the
California Age-Appropriate Design Code, the advertising surface for
minors is heavily restricted. Practical engineering: age-estimation
mechanisms (the Yoti / Privately demos, the proposed device-attested age
signal), default-private setting cascades, and the prohibition of
behavioral advertising to known-minors. The intersection with
privacy-preserving advertising is that the technical primitives have to
allow zero-data-collection contextual targeting paths for minor traffic.

### 11.6 Contextual advertising as the AI-era substitute

Pre-cookie-era advertising was largely contextual (the ad chosen for the
visible page content); the rise of programmatic display ads shifted the
paradigm to audience-based. The post-deprecation industry conversation
has substantially returned to contextual: per-impression page-content
analysis (now AI-driven, classifying page sentiment, topic, brand-safety
tier) replaces audience-based targeting for the open web. Vendors
(Seedtag, GumGum, Captify, Integral Ad Science, DoubleVerify) operate
the contextual analysis layer. The privacy property is that no user
data is required — the targeting is purely on the visible content.
The trade-off is targeting precision.

### 11.7 The unresolved question — is interest-based advertising recoverable?

The 2026 state of the discipline is unresolved. The Privacy Sandbox
retired; the IAB Tech Lab analysis found that the privacy-preserving
primitives could not deliver the granularity required by the existing
ad-tech industry; the walled gardens consolidated; the open web's
measurement substrate degraded. The competing positions:

- **The walled-garden view:** Interest-based advertising is recoverable
  on first-party data within walled gardens; the open web's measurement
  problem is a market-power problem, not a technical problem.
- **The MPC / cryptographic view:** Interest-based advertising is
  recoverable through DAP / IPA / DP-protected aggregation, given time
  for adoption and tooling; Mozilla's PPA is the test case.
- **The contextual / AI view:** Interest-based advertising is being
  replaced by AI-driven contextual targeting; the privacy-preserving
  measurement question is downstream and less urgent.
- **The structural critique (Schneier, Doctorow, EFF):** Surveillance
  advertising does not work well enough to justify the privacy cost;
  the question is not how to preserve interest-based advertising under
  privacy constraints but whether to preserve it at all.

No consensus has emerged across these positions as of 2026.

---

## 12. References

### 12.1 Chrome Privacy Sandbox — primary

- Privacy Sandbox developer portal — https://privacysandbox.google.com/
- Topics API specification — https://patcg-individual-drafts.github.io/topics/
- Topics API explainer — https://github.com/patcg-individual-drafts/topics
- Protected Audience API specification — https://wicg.github.io/turtledove/
- Protected Audience API explainer — https://github.com/WICG/turtledove/blob/main/FLEDGE.md
- Attribution Reporting API — https://github.com/WICG/attribution-reporting-api
- CHIPS specification (IETF draft) — https://datatracker.ietf.org/doc/draft-cutler-httpbis-partitioned-cookies/
- CHIPS explainer (W3C PrivacyCG) — https://github.com/privacycg/CHIPS
- Fenced Frames specification — https://wicg.github.io/fenced-frame/
- Shared Storage API — https://wicg.github.io/shared-storage/
- Private State Tokens API — https://wicg.github.io/trust-token-api/
- Privacy Sandbox October 2025 retirement announcement — https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies
- Chrome developer documentation — https://developer.chrome.com/docs/privacy-sandbox/

### 12.2 Apple — primary

- App Tracking Transparency — https://developer.apple.com/documentation/apptrackingtransparency
- SKAdNetwork — https://developer.apple.com/documentation/storekit/skadnetwork
- AdAttributionKit — https://developer.apple.com/documentation/AdAttributionKit
- SKAdNetwork-AdAttributionKit interoperability — https://developer.apple.com/documentation/adattributionkit/adattributionkit-skadnetwork-interoperability
- Private Click Measurement intro — https://webkit.org/blog/11529/introducing-private-click-measurement-pcm/
- Private Click Measurement fraud prevention — https://webkit.org/blog/12566/private-click-measurement-conversion-fraud-prevention-and-replacement-for-tracking-pixels/
- Full Third-Party Cookie Blocking (Safari) — https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/
- Wilander WebKit blog index — https://webkit.org/blog/author/wilander/
- USENIX 2019 "Privacy by Default on the Web" — https://www.usenix.org/conference/usenixsecurity19/presentation/wilander
- iCloud Private Relay overview — https://www.apple.com/icloud/docs/iCloud_Private_Relay_Overview_Dec2021.pdf
- Mobile Advertising and the Impact of ATT — https://www.apple.com/privacy/docs/Mobile_Advertising_and_the_Impact_of_Apples_App_Tracking_Transparency_Policy_April_2022.pdf

### 12.3 Mozilla and DAP — primary

- Mozilla Privacy-Preserving Attribution announcement — https://blog.mozilla.org/en/mozilla/news/privacy-preserving-attribution-for-advertising/
- Mozilla PPA explainer — https://support.mozilla.org/en-US/kb/privacy-preserving-attribution
- Mozilla PPA testing update — https://blog.mozilla.org/netpolicy/2024/08/22/ppa-update/
- IETF DAP specification — https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/
- DAP GitHub — https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap
- IPA proposal (PATCG) — https://github.com/patcg-individual-drafts/ipa
- Divvi Up — https://divviup.org/
- W3C PATCG — https://patcg.github.io/

### 12.4 Standards bodies and consortia

- W3C Privacy Community Group — https://privacycg.github.io/
- W3C Federated Identity Working Group (FedCM) — https://www.w3.org/TR/fedcm/
- W3C Global Privacy Control — https://www.w3.org/TR/gpc/
- WICG (Web Platform Incubator) — https://wicg.io/
- IETF Privacy Pass Working Group — https://datatracker.ietf.org/wg/privacypass/
- IETF Privacy Preserving Measurement Working Group — https://datatracker.ietf.org/wg/ppm/

### 12.5 Industry analysis

- IAB Tech Lab Privacy Sandbox Fit Gap Analysis (February 2024) — https://iabtechlab.com/wp-content/uploads/2024/02/Privacy-Sandbox-Fit-Gap-Analysis-PUBLIC-COMMENT-RELEASE.pdf
- IAB Tech Lab Privacy Sandbox Final Fit Analysis (June 2024) — https://iabtechlab.com/iab-tech-lab-releases-final-privacy-sandbox-fit-analysis/
- IAB Europe DSA Implementation Guidelines — https://iabeurope.eu/
- IAB Tech Lab — https://iabtechlab.com/
- Center for Democracy and Technology post-mortem — https://cdt.org/insights/googles-privacy-sandbox-is-dead-the-fight-for-real-online-privacy-continues/

### 12.6 EFF and privacy-advocacy

- EFF Privacy Badger — https://privacybadger.org/
- EFF Privacy Badger page — https://www.eff.org/pages/privacy-badger
- EFF Cover Your Tracks (formerly Panopticlick) — https://coveryourtracks.eff.org/
- Global Privacy Control initiative — https://globalprivacycontrol.org/

### 12.7 Regulatory primary

- EU Digital Services Act (Regulation 2022/2065) — https://digital-strategy.ec.europa.eu/en/policies/digital-services-act
- EU Digital Markets Act (Regulation 2022/1925) — https://digital-markets-act.ec.europa.eu/index_en
- California Office of the Attorney General GPC guidance — https://oag.ca.gov/privacy/ccpa/gpc
- US v. Google ad-tech ruling DOJ press release — https://www.justice.gov/opa/pr/department-justice-prevails-landmark-antitrust-case-against-google

### 12.8 Academic — Topics API and re-identification

- "A Public and Reproducible Assessment of the Topics API on Real Data" (Beugin & McDaniel, arXiv:2403.19577, 2024) — https://arxiv.org/abs/2403.19577
- "The Privacy-Utility Trade-off in the Topics API" (Alvim, Fernandes, et al., ACM CCS 2024) — https://dl.acm.org/doi/10.1145/3658644.3670368
- "Re-Identification Attacks against the Topics API" (Jha et al., ACM TWEB 2024) — https://dl.acm.org/doi/full/10.1145/3675400
- "Differentially Private Synthetic Data Release for Topics API Outputs" (2025) — https://www.researchgate.net/publication/393184716

### 12.9 Fingerprinting and tracking research

- OpenWPM (Princeton CITP) — https://github.com/openwpm/OpenWPM
- "Learning to Detect Browser Fingerprinting Behaviors" (Iqbal et al., S&P 2021) — https://web.cs.ucdavis.edu/~zubair/files/fpinspector-sp2021.pdf
- "Browser Fingerprinting: A Survey" (Laperdrix et al., TWEB 2020) — https://www-sop.inria.fr/members/Nataliia.Bielova/papers/Lape-etal-20-TWEB.pdf

### 12.10 DP, MPC, ZK foundational

- Dwork, McSherry, Nissim, Smith — "Calibrating Noise to Sensitivity in Private Data Analysis" (TCC 2006, Gödel Prize 2017) — https://www.iacr.org/archive/tcc2006/38760266/38760266.pdf
- Dwork & Roth — *The Algorithmic Foundations of Differential Privacy* (2014) — https://www.cis.upenn.edu/~aaroth/privacybook.html
- Mironov — "Rényi Differential Privacy" (CSF 2017) — https://arxiv.org/abs/1702.07476
- Cheu, Smith, Ullman, Zeber, Zhilyaev — "Distributed Differential Privacy via Shuffling" (EUROCRYPT 2019) — https://eprint.iacr.org/2019/245
- Corrigan-Gibbs & Boneh — "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics" (NSDI 2017) — https://www.usenix.org/conference/nsdi17/technical-sessions/presentation/corrigan-gibbs

### 12.11 Critical / policy

- Schneier — *Data and Goliath* (2015)
- Doctorow — "Big Tech's 'attention rents' / Enshittification" essays — https://doctorow.medium.com/
- Doctorow — *Pluralistic* "Ad-tech is fascist tech" — https://pluralistic.net/2026/03/10/ice-tech/
- Center for Democracy and Technology — https://cdt.org/

---

*End of document.*
