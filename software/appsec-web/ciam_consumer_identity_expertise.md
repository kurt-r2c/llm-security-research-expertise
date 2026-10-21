# Customer Identity and Access Management (CIAM)
## Identity architecture for consumer-facing products: scale, friction, recovery, and the soft underbelly that workforce IAM never sees

> **Primary researchers and teams cited in this document:**
>
> - **Reed McGinley-Stempel** + **Julianna Lamb** (co-founders, Stytch). Long-form
>   product + blog corpus on passwordless CIAM, magic-link threat-modeling, fraud
>   prevention at the identity layer, and the structural case for moving consumers off
>   password+SMS. https://stytch.com/blog
> - **Colin Sidoti** (co-founder + CEO, Clerk). The Clerk product corpus and Sidoti's
>   writing on B2C identity UX, organization-modeling, and the friction-vs-security
>   trade-off curve specific to self-signup products. https://clerk.com/blog
> - **Stian Thorgersen** + **Bill Burke** (Keycloak, Red Hat). Keycloak project leads.
>   Thorgersen's blog and Burke's RESTful-Java work anchor the OSS CIAM realism around
>   running an IdP yourself. https://www.keycloak.org/
> - **Aeneas Rekkas** (Ory). Author of Ory Kratos (identity),
>   Hydra (OAuth2 server), and Keto (Zanzibar-style permissions). The OSS CIAM stack
>   that splits identity / OAuth / authorization into composable services.
>   https://www.ory.sh/
> - **Rick Song** + **Charles Yeh** (co-founders, Persona). KYC / identity-verification
>   product corpus, with public writing on liveness detection, deepfake-resistance, and
>   the trade-offs in regulated-CIAM onboarding. https://withpersona.com/blog
> - **Frans Rosén** (Detectify Labs). Long-running OAuth/SSO bug-bounty corpus including
>   the 2017 Slack token-theft bug (missing postMessage origin check). The
>   account-linking and redirect-uri validation taxonomy in §5 and §13 is downstream of
>   Rosén's research. https://labs.detectify.com/
> - **Sam Curry** (independent). Bug-bounty corpus — Apple (2020) and the
>   Web-Hackers-vs-Auto-Industry research (2023). https://samcurry.net/
> - **Bhavuk Jain** (independent researcher, India). May 2020 disclosure of the Sign In
>   with Apple zero-day — JWT token mint as arbitrary user via the email-as-subject
>   confusion. Anchor for the "social IdP as keys-to-kingdom" pattern.
>   https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/
> - **Mike Jones**. Co-editor of OIDC Core,
>   JWT (RFC 7519), JWS (RFC 7515), JWE (RFC 7516), JWK (RFC 7517). The token formats
>   that CIAM IdPs mint sit on Jones's specs. https://self-issued.info/
> - **Aaron Parecki** (Okta). Co-author OAuth 2.1 draft; maintainer of oauth.net; author
>   of "OAuth 2.0 Simplified." Modern OAuth practice as deployed in consumer-facing
>   social-login. https://aaronparecki.com/oauth/
> - **Allison Nixon** (Unit 221B). Long-running research on the sim-swap criminal
>   ecosystem and Lapsus$/Sim-Swappers attribution. https://www.unit221b.com/
> - **Brian Krebs** (KrebsOnSecurity). Journalism corpus on Lapsus$, 23andMe credential
>   stuffing, sim-swap rings, and consumer-side ATO incidents. https://krebsonsecurity.com/
>
> **`[unverified]` markers in this doc** flag specific dates, CVE IDs, acquisition
> completion dates, passkey adoption percentages, and Lapsus$ Sim-Swappers
> attribution-detail that the author cannot ground in a single primary-source citation
> at authoring time. Treat them as "directionally correct, specifics need confirmation."

---

## 1. Why this doc exists — CIAM is not workforce IAM with a different logo

Workforce IAM and CIAM (Customer Identity and Access Management) look adjacent on a
vendor pitch deck. They are structurally different problems. Treat them the same and
you will ship a consumer product that bleeds accounts to credential stuffing while
making your retention numbers go off a cliff because legitimate users cannot log in.

The divergence axes:

**Scale.** Workforce identity covers hundreds to (at the F500 end) hundreds of
thousands of users. CIAM covers millions to hundreds of millions. The operational
economics are different. A help-desk-mediated account recovery that costs $5 per
incident is acceptable for 50,000 employees with maybe 2% recovery rate per year. The
same cost structure applied to 50 million consumers at the same recovery rate is
$50M/year in support cost. CIAM must self-service or it does not survive.

**Trust model on the device.** Workforce IAM can mandate managed devices through MDM
(Jamf, Intune, Workspace ONE), require device attestation, and refuse logins from
unenrolled hardware. CIAM has no such lever. Consumer devices are unmanaged. There is
no corporate-issued baseline. Device-binding in CIAM means platform attestation (Apple
App Attest, Android Play Integrity, Pixel StrongBox) and is opt-in at
best.

**Onboarding.** Workforce IAM has an HR ground truth: someone got hired, their identity
was verified at hire, a manager approved an account-creation ticket. CIAM has
self-signup with email-only verification as the default baseline. The identity
assurance level is roughly "this signup controls the inbox at this address" — which
is to say, near-zero outside of regulated KYC flows.

**Friction tolerance.** Workforce users tolerate mandatory MFA, step-up authentication
on sensitive actions, and 60-day password rotation because their employer mandates it.
CIAM users do not. Every friction point in a CIAM flow costs conversion. Adding a
mandatory MFA setup step at signup can drop activation by 20-40% depending on the
product `[unverified specific percentage]`. The friction budget is brutally limited
and must be spent where it actually reduces risk.

**Recovery.** Workforce recovery routes through IT helpdesk plus manager re-issue. CIAM
recovery is self-service or it does not exist. **The self-service recovery flow is the
actual authentication strength of any CIAM product.** A product can ship WebAuthn
mandatory primary auth, then back-door it with "email me a reset link" recovery, and
the actual security posture is "email account compromise = product account
compromise." §6 covers this in depth.

**Anti-fraud posture.** Workforce IAM users are mostly trusted (insider-risk is real
but bounded). CIAM faces an adversary 24/7 — credential stuffing bots, fake-account
farms, fraud rings, scam operators. The defense is fundamentally an arms race against
a motivated adversary. Cross-link to `[[reference-anti-fraud-abuse-engineering]]` for
the adversary-economics framing.

**Compliance.** Workforce IAM compliance is SOX / HIPAA / internal controls. CIAM
compliance is GDPR / CCPA / CPRA / COPPA in consumer-general; KYC / AML / PSD2 SCA /
3DS2 in fintech; HIPAA / Part 11 in health; PCI-DSS at any product that touches card
data. The legal substrate shapes what data must be collected, retained, deleted,
exported, and re-consented.

**Customer ownership of identity.** Workforce identity is org-owned: the employer owns
the account, can disable it, can read its data subject to internal policy. CIAM
identity is customer-owned under GDPR Article 20 (portability), Article 17 (erasure),
and analogous CCPA provisions. The consumer has a legal right to export and delete.
This shapes data model design: you cannot pretend the identity record is yours.

The rest of this document covers the CIAM-specific architecture, threat model,
recovery flows, KYC layer, and incident corpus. Workforce-side identity work belongs
in `[[reference-zero-trust-workload-identity]]`.

---

## 2. CIAM vendor landscape

The CIAM market is segmented along buyer-type and integration-depth. Map your product
to the right tier before evaluating vendors.

### Enterprise tier (high-touch sales, multi-year contracts)

- **Okta CIAM** (Auth0 acquisition completed May 2021).
  Auth0 remains the developer-facing surface; Okta CIC (Customer Identity Cloud) is
  the enterprise SKU. Strongest at large-B2B-with-end-consumers shape (e.g., a SaaS
  company offering both workforce SSO and end-user accounts).
- **ForgeRock** (acquired by Thoma Bravo, merged into Ping Identity August 2023). Heritage in telco + government + financial-services CIAM. On-prem
  + hosted; not developer-friendly out of the box.
- **Ping Identity** (Thoma Bravo, merged with ForgeRock). PingOne for Customers is the
  CIAM SKU. Enterprise federation strength.
- **Microsoft Entra External ID** (Microsoft's next-generation successor to Azure AD
  B2C; B2C itself was not renamed). Strongest where the
  org is already Azure-native.
- **IBM Verify CIAM** (formerly IBM Security Verify, formerly Cloud Identity).
  Enterprise + regulated industries.

### Developer-first / mid-market

- **Auth0** (Okta-owned). Long the default for early-stage consumer products. SDK
  ergonomics, Universal Login, Actions/Rules for custom logic. Pricing scales hard
  past free tier.
- **Stytch** (Reed McGinley-Stempel, Julianna Lamb). Passwordless-first; magic links,
  OAuth, SMS OTP, passkeys, M2M auth. Strong developer ergonomics and a clear
  product-thesis position against password-as-primary.
- **Clerk** (Colin Sidoti). Drop-in React/Next.js components for full auth UX. The
  "auth-as-component-library" pattern. Strong for fast-shipping B2C products.
- **Descope** (Slavik Markovich, ex-Demisto). Drag-and-drop flow builder; aims to make
  identity flows configurable by non-engineers.
- **Frontegg**. B2B-with-end-user-accounts (the "B2B2C" shape). Multi-tenant
  organization modeling baked in.
- **FusionAuth**. Self-hostable + hosted; downloadable artifact + commercial license
  for enterprise features. The "you can run it yourself" alternative.

### Hyperscaler-native

- **AWS Cognito** (User Pools + Identity Pools). Cheap at scale; SDK-driven; the
  developer experience has lagged versus the developer-first vendors. Persistent
  complaints about lockout-risk and limited customization.
- **Firebase Authentication** (Google). Phone-OTP and OAuth social are the default
  primary auth. Tight integration with Firestore + Cloud Functions. Common in
  early-stage mobile B2C.
- **Azure AD B2C → Microsoft Entra External ID**. Already noted above; included here
  as the Azure-native option.

### OSS

- **Keycloak** (Stian Thorgersen, Bill Burke, Red Hat; CNCF Incubating). The dominant OSS IdP. OIDC + OAuth + SAML; SPI
  extension model for custom logic; federation; brokering. Operational cost is real —
  Keycloak benefits from in-house identity-engineering knowledge.
- **Ory** (Aeneas Rekkas). Composable stack: Kratos (identity +
  user-management), Hydra (OAuth2 + OIDC server), Keto (Zanzibar-style permissions),
  Oathkeeper (zero-trust proxy). The "build your own CIAM out of focused services"
  approach.
- **Authelia**. Single-binary 2FA / SSO portal; often deployed in front of homelabs
  and small-scale CIAM workloads.
- **Authentik**. SAML + OIDC IdP; gaining adoption 2023-2026 as a Keycloak alternative
  with more modern UX.
- **Casdoor**. Chinese-origin OSS CIAM; growing OSS contributor base.

### Specialty: identity verification / KYC

These sit alongside (not replacing) the primary CIAM platform. They handle
identity-proofing during onboarding for regulated workloads:

- **Stripe Identity**. Photo-ID + selfie + liveness verification. Tightly integrated
  with Stripe Connect for marketplaces.
- **Persona** (Rick Song, Charles Yeh). Configurable KYC flows; strong developer
  experience; growing share against legacy KYC vendors.
- **Plaid**. Financial-account-linking-as-identity for fintech. Account ownership
  verification, Income, Identity (consumer-permissioned data).
- **Onfido** (acquired by Entrust 2024). Long-time
  KYC vendor; AI-driven document verification + liveness.
- **Veriff**. Estonian-origin KYC; strong document-coverage matrix.
- **Jumio**. Enterprise KYC; broad regulatory-compliance coverage.
- **Berbix** (acquired by Socure 2023), **iDenfy**, **Sumsub**, **Trulioo**,
  **Socure**. Mid-market and enterprise KYC players with overlapping feature sets.

Evaluate vendors against your scale, integration-depth requirements, and the
regulated-or-not workload mix. Do not pick a vendor whose strength is the workload
you do not have.

---

## 3. Modern authentication patterns

The CIAM primary-authentication menu in 2026:

**Password + MFA.** Still the dominant primary auth despite a decade of "the password
is dead" decks. Passwords persist because they are universal, no-device-dependency,
and have well-understood UX. The 2026 baseline: bcrypt or argon2id at the storage
layer, length minimum 15 for single-factor passwords or 8 within MFA (NIST SP 800-63B-4),
breach-corpus check against Have I Been Pwned k-anonymity API at signup and reset,
optional MFA layered on top. Treat password-only authentication as table stakes that
ships with a planned deprecation trajectory, not as your end state.

**OAuth social login.** Google / Apple / Facebook / Microsoft / GitHub / Twitter-X /
LinkedIn / Discord. The pattern: user clicks "Sign in with Google" → OIDC dance →
ID-token returned with `email` claim → RP creates/links account. The compromise
surface: a breached IdP account compromises every RP that federates to it. Apple App
Store guideline 4.8 requires apps that use a third-party social login for the primary
account to also offer an equivalent login that limits data collection to name and
email, lets users keep their email private, and does not collect app interactions for
advertising without consent (Sign In with Apple qualifies). The "linked email" attack class (§5) is endemic
to this pattern.

**Magic links and email OTP.** UX-friendly, passwordless, phishable. The replay window
matters: a 15-minute single-use device-bound link is structurally different from a
24-hour multi-use link that any inbox-reader can click. Stytch, Clerk, Magic, Auth0,
Notion, Slack, Substack, Vercel all ship variants. §4 covers the threat model.

**SMS OTP.** Six-digit code to the user's phone. Convenient, universal, structurally
broken. Sim-swap rings (§7) port the phone number to attacker-controlled SIMs. NIST SP
800-63B Rev. 3 and Rev. 4 (final July 2025) classify PSTN/SMS out-of-band
authentication as "restricted"; it is still permitted. Treat SMS-as-2FA as a soft factor — useful
for friction reduction, not for high-assurance authentication.

**TOTP.** RFC 6238. Google Authenticator, Authy, 1Password, Bitwarden, Microsoft
Authenticator. Time-based 6-digit codes from a shared secret. Phishable via real-time
attacker-in-the-middle (AitM): victim enters TOTP code on attacker proxy, attacker
relays to real site, captures session cookie. Better than SMS; not phishing-resistant.

**Push notifications.** Duo Mobile, Okta Verify, Microsoft Authenticator push. User
approves a login attempt on their pre-bound device. When implemented with
number-matching (user must enter a 2-digit code displayed on the login screen into
the push approval), it raises the bar against MFA-fatigue / push-bombing attacks. With
naive yes/no approval, it is vulnerable to push-bombing (Lapsus$ Uber-IT-helpdesk
playbook).

**WebAuthn / passkeys.** The phishing-resistant primary-auth target state for consumer
CIAM. Apple Keychain, Google Password Manager, Microsoft, 1Password, Bitwarden,
Dashlane all support passkey storage 2023-2026. Adoption is mixed: developer-savvy
products and Apple-platform-first products have passkey rates of 10-40% of active
users `[unverified specific percentage]`; long-tail consumer products are well under
5%. The cross-link is `[[reference-webauthn-fido2-passkeys]]`.

**Biometric on-device with platform authenticator.** Apple Face ID / Touch ID, Android
BiometricPrompt, Windows Hello. From the RP perspective these are WebAuthn platform
authenticators with biometric-unlock; the biometric never leaves the device. This is
the consumer-friendly face of WebAuthn — what most users actually interact with when
they "use passkeys."

### Account model: identity-substrate choices

Decide up front:

- **Is email the primary identity-substrate, or just one auth-method?** If email-only,
  you are tying account-life to email-account-life forever. If email is one of many
  auth methods, you can detach.
- **Is phone the primary identity-substrate?** Common in markets with low email
  penetration (India, Indonesia, parts of LatAm) and in many mobile-first products.
  Inherits sim-swap exposure.
- **Is the OAuth IdP `sub` claim the identity-substrate?** Apple `sub` is stable and
  opaque; Google `sub` is stable; Facebook user-id is stable but Facebook has changed
  it for privacy reasons in some flows. Do not key your accounts on email when the
  OAuth `sub` is available — emails change.
- **Is there a separate stable internal user-ID?** Yes. Always. Mint your own UUID;
  do not key joins in your database on the external identifier.

---

## 4. Magic links and passwordless: the threat model

Magic links are the developer-darling of 2020-2024 consumer auth: no password to
forget, no MFA setup friction, fast onboarding. The threat model is non-trivial.

**The flow:** user enters email → RP sends email containing time-bounded link → user
clicks → RP creates session.

**The replay window.** How long is the link valid? Single-use or multi-use?
Device-bound or any-device-clickable? Each of these is a knob, and the defaults across
vendors differ:

- Stytch: configurable (5 minutes to 7 days), defaults to 60 minutes.
- Hand-rolled implementations: often 24 hours, multi-use, no device-binding — the
  worst end of the configuration space.

**Email account as keys-to-kingdom.** If the consumer's email account is compromised
(phishing, credential stuffing on the email provider, ATO via the email IdP's
recovery flow), every magic-link-based service registered to that email is
compromised. Magic-link consumers have effectively delegated their full auth surface
to the email provider's security posture. For Gmail / Microsoft 365 consumers this is
strong-but-phishable; for users on regional providers with weaker 2FA enforcement, it
is the soft underbelly.

**AitM phishability.** Modern AitM frameworks (Evilginx, Modlishka, Muraena) proxy the
legitimate login flow. The attacker tricks the victim into entering their email on the
attacker's proxy → real RP sends magic link to real email → victim clicks → real RP
returns session cookie to the proxy → attacker captures cookie. **Magic links are not
phishing-resistant.** Stytch and similar vendors mitigate with device-binding (the
link is only valid when clicked from the same device that requested it), but
device-binding has UX costs (cross-device flows break) and is not universal.

**Cross-device flow.** A common UX is: user requests magic link on desktop → opens
email on phone → clicks link on phone → expects to be authenticated on desktop. This
requires either (a) the session is created on the device that clicked, not requested,
or (b) the magic link delivers a code that the requesting device polls for. Either
shape has its own trade-offs around replay and session-fixation risk.

**Mitigations:**

- Short replay window (60 minutes or less).
- Single-use links (consumed on first click, invalidated thereafter).
- Device-binding where the UX tolerates it.
- Visible "you requested this from device X at time Y" framing in the email so the
  user can spot unauthorized requests.
- Step-up to a passkey or TOTP for sensitive actions, treating magic-link auth as a
  lower-assurance factor.
- Risk-based decisions: flag clicks from a different ASN / device / geography than
  the original request and challenge for additional verification.

**Where magic links are an acceptable primary:** low-stakes consumer products where the
account does not protect money, regulated data, or identity-graph value, and where
the user friction of remembering a password genuinely outweighs the ATO risk.

**Where magic links are not acceptable as primary:** any product that holds payments
data, regulated data (health, finance, government services), or has high
identity-graph value (social-graph products are routinely abused via ATO'd accounts).

---

## 5. Social login and federated CIAM

Social login is the dominant CIAM auth method by user-count at consumer scale. It is
also where account-linking bugs live.

### The OAuth IdP integration matrix

Mainstream consumer IdPs: Google, Apple, Facebook, Microsoft, GitHub, Twitter-X,
LinkedIn, Discord, Yahoo, Amazon, Spotify (for music apps). Regional: Naver, Kakao
(Korea); WeChat, QQ, Weibo (China — note the data-sovereignty implications); Yandex,
VK (Russia); LINE (Japan, SEA).

Per IdP, decide:

- Which IdPs do you offer?
- Does Apple App Store guideline 4.8 force you to offer a privacy-preserving login
  such as Sign In with Apple? (Yes, if you offer a third-party social login for the
  primary account on iOS, unless an exception applies.)
- What claims do you trust from each IdP? Email-verified? Domain?
- What happens when the OAuth flow fails midway? (See "missing-state CSRF.")

### The "linked email" attack class

The canonical CIAM account-linking bug: if your account model says "log in via any
IdP that reports the same email," then an attacker who can register at IdP-A with the
victim's email — without IdP-A verifying ownership of that email — can use IdP-A to
log into the RP's account that the victim created via IdP-B.

The Sign In with Apple May 2020 zero-day (Bhavuk Jain, awarded $100k) was a variant:
Apple's JWT-mint flow allowed an attacker to request a token for an arbitrary email,
and Apple would mint it because the email-as-`sub` confusion in the token issuance
path did not verify that the requester controlled the email. The RP would receive an
ID token signed by Apple, with the victim's email, and would create or link an account
accordingly.

### Account uniqueness modeling

Decide:

- Is your `users` table keyed on email? (Avoid this — emails change.)
- Is it keyed on a globally unique internal ID, with a `user_identities` join table
  listing all IdP `sub` values associated with that user? (Yes.)
- When two IdPs report the same email but one says `email_verified: true` and the
  other says `false` (or doesn't say), what is the linking semantics? (Require
  verification; treat unverified-email-from-IdP as untrusted for linking.)
- When a consumer wants to add a second IdP to an existing account, what's the
  challenge flow? (Re-authenticate via the existing IdP, then start the new-IdP flow.
  Never link based on email-claim alone.)

### Post-auth account-linking flows

The dangerous flow: user is logged in via IdP-A. UI offers "link your Google account."
User clicks. New OAuth flow to Google. Google returns ID token with email X. RP links.

The bug: the email X reported by Google does not have to match the account's primary
email. If the RP links any Google account to the current session, an attacker who
gets a session for victim-A can link their attacker-Google to victim-A's RP account —
and then sign in via attacker-Google to victim-A's RP account on any other device.

Mitigation: only link Google accounts whose verified email matches the RP account's
primary email, **or** require email-ownership verification (send a code to the RP
account's primary email, require entering it) before linking.

### OAuth-flow integrity

The OAuth integrity issues that affect CIAM specifically:

- **`state` parameter.** RFC 6749 §10.12 requires CSRF protection, for which `state` is RECOMMENDED. Missing
  or unvalidated `state` permits a logged-in-attacker → logged-in-as-attacker
  account-linking CSRF.
- **PKCE.** RFC 7636. For public OAuth clients (mobile + SPAs), PKCE prevents
  code-interception. Modern OAuth 2.1 makes PKCE mandatory.
- **`redirect_uri` validation.** Exact-match, not prefix-match, not wildcard-match.
  The OAuth bug-bounty literature documents `redirect_uri`
  validation bypass as one of the highest-impact recurring CIAM bugs.
- **Implicit flow deprecation.** OAuth 2.1 deprecates the implicit flow. SPAs should
  use authorization code with PKCE, not implicit. Many older CIAM integrations still
  ship implicit.

Cross-link to `[[reference-saml-federation]]` for the broader OAuth/OIDC threat model
and to `[[reference-session-management]]` §11 for the redirect-uri taxonomy.

---

## 6. Self-service account recovery — the CIAM soft underbelly

**The recovery flow is the actual authentication strength of your CIAM product.**

If primary auth is WebAuthn passkey + step-up, but recovery is "click here, we'll
email you a link" — your effective auth strength is "email account control." If
primary is password + TOTP MFA but recovery is "answer your security questions" — your
effective auth strength is "knowledge of mother's maiden name, available in any
data-broker lookup."

Audit recovery flows with the same rigor as primary auth. They are the same surface
to the adversary.

### Recovery patterns and their weaknesses

**Email-based reset.** The canonical pattern: user enters email, RP sends a
reset-password link or magic-login link. Failure mode: email account compromise.
Mitigation: require additional factor (existing TOTP, existing passkey) before
honoring the reset link, even though the link itself proves email control.

**SMS-based reset.** "Text me a code to reset." Failure mode: sim-swap. Sim-swap rings
have become an industrial-scale criminal ecosystem since ~2018, with Lapsus$ Sim
Swappers (UK/Brazil cluster, 2022) as a prominent anchor incident
`[unverified specific attribution detail]`. Allison Nixon at Unit 221B has tracked
this ecosystem extensively. The defense: do not use SMS as a sole recovery channel.

**Security questions.** "What was your first pet's name? What is your mother's maiden
name?" Knowable via social engineering, public records, social-media OSINT, and
breach-corpus lookup. NIST 800-63B Rev. 3 explicitly deprecates knowledge-based
authentication. **Stop shipping security questions.** They are worse than no recovery —
they signal recovery exists and lower the bar.

**Photo-ID-based recovery.** "Upload a photo of your driver's license to verify
identity." Pre-2023, this was reasonably strong. 2024-2026, AI deepfake tools
(Stable-Diffusion-derived, OpenAI Sora-class video generation, commercial
deepfake-as-a-service) have made selfie-with-ID and liveness-check bypass tractable
for motivated attackers `[unverified specific incident corpus]`. Active liveness
detection (motion challenges, eye tracking, real-time-randomized prompts) is the
arms-race response. Passive liveness is being defeated at scale.

**Multi-factor recovery.** Require 2+ pre-registered recovery channels. Microsoft
consumer accounts use this — "we'll send a code to your phone AND your backup email."
Both channels must be compromised, raising the bar substantially. The trade-off is
setup friction and user-confusion-driven support load.

**Pre-registered trusted devices.** "Authorize this recovery from a device you've
previously logged in on." Cross-checks against the user's session history. Effective
when the user has another active device, useless when they've changed all hardware.

**Recovery codes.** One-time codes printed at MFA setup time, intended to be stored
offline. Most users do not store them. Where they are used, they are an excellent
backstop. Where they are not, they do not help.

**Human-mediated recovery / support agent.** "Call our support line, prove who you
are." The failure mode: the support agent's verification procedure is the actual auth
strength, and social engineering of support agents is rampant. The MGM Resorts
ransomware incident (September 2023) reportedly started with a social-engineering
call to MGM's IT helpdesk by Scattered Spider operators. Lapsus$ used the same shape
repeatedly. Do not let support agents disable MFA without out-of-band identity
verification.

### The trade-off

Strong recovery flow = legitimate users get locked out + support cost spikes.
Weak recovery flow = ATO at scale.

The right point on the curve depends on the asset behind the account. A casual
consumer product can tolerate weaker recovery; a fintech product cannot. Pick the
point deliberately. Do not let "easy recovery" be a default without naming the ATO
risk that goes with it.

### Anti-patterns to refuse

- "Forgot password" emails the actual password in plaintext. (Implies you store it
  reversibly. Stop.)
- "Reset via knowledge of last 4 digits of credit card." (Knowable.)
- "Skip MFA on this device for 30 days" with persistent cookie. (Defeats MFA.)
- Recovery flow that completes without re-authenticating but re-enables MFA-bypass.
  (Allows lateral compromise.)
- Support-agent override that disables MFA without out-of-band verification.

---

## 7. Account-takeover (ATO) attack patterns

### Credential stuffing

The dominant ATO vector at consumer scale. Attacker has a corpus of `(email,
password)` pairs from prior breaches (Collection-#1, RockYou2021, recurring leaks).
Automation tries each pair against the target login endpoint. Hits at 0.1-2% rate
typically `[unverified specific rate]`.

**Snowflake credential stuffing 2024.** ~165 Snowflake customer organizations
potentially exposed via credentials harvested from infostealer malware (Lumma Stealer, RedLine), used to
log into customer Snowflake instances that had not enforced MFA. The Snowflake
platform itself was not breached; the customer accounts were. Anchor incident for the
"MFA must be enforced, not just available" lesson. Mandiant tracks the actor as
UNC5537.

**23andMe credential stuffing late 2023.** ~6.9M customers' data exposed via
credential-stuffed accounts that then exposed connected-relatives' profile data
through the DNA-relatives feature. ~14,000 accounts directly stuffed; ~6.9M relatives'
profile data reached via the social-graph cascade. The amplification factor is the
load-bearing detail: 23andMe's product design meant a single stuffed account exposed
hundreds of relatives' data. Cross-link to `[[reference-privacy-engineering]]` for the
consumer-genetics-data sensitivity question.

**DraftKings 2022.** ~68,000 user accounts compromised via credential stuffing; some
funds withdrawn before detection. Anchor for consumer-fintech-as-CIAM-failure shape.

Defense:
- Breach-corpus check at signup and password change (HIBP k-anonymity API or
  equivalent). Reject known-leaked passwords.
- Rate-limiting per-IP, per-account, per-account-cluster, with adaptive thresholds.
- MFA enforcement, not just availability.
- Risk-scoring on every login: device fingerprint, IP reputation, ASN, geo,
  behavioral biometrics. Step up on anomaly.
- Account-lockout-with-recovery on N failures, balancing DoS-by-lockout risk.

Cross-link to `[[reference-anti-fraud-abuse-engineering]]` for the bot-detection layer.

### Phishing + AitM (attacker-in-the-middle)

Modern AitM toolkits (Evilginx, Modlishka, Muraena, EvilProxy as a service) proxy the
legitimate login flow. Victim visits the phishing site, enters credentials, completes
MFA (TOTP, push, SMS), and the AitM proxy captures the session cookie issued by the
real RP. **MFA is bypassed without attacking MFA** — the session cookie is what the
attacker exfiltrates.

Defense: phishing-resistant authentication. WebAuthn / passkeys bind the assertion
to the real-RP-origin and refuse to issue from a different origin. The AitM proxy is
on a different origin and cannot complete the WebAuthn flow. This is the structural
case for moving CIAM to passkeys.

Cross-link to `[[reference-webauthn-fido2-passkeys]]` and `[[reference-session-management]]`
§14 for the session-cookie-theft taxonomy.

### Sim-swap

Social-engineering of the mobile carrier results in the victim's phone number being
ported to an attacker-controlled SIM. Any subsequent SMS OTPs, voice-OTPs, or
SMS-based recovery codes go to the attacker.

The Lapsus$ Sim-Swappers cluster (UK + Brazil, 2022) is the prominent anchor incident
`[unverified specific attribution and arrest detail]`; Allison Nixon at Unit 221B has
publicly tracked the ecosystem. The criminal market for sim-swaps is industrial:
insiders at mobile carriers are paid for SIM-port-out actions.

Defense: do not use SMS as a high-assurance factor. NIST 800-63B Rev. 3 and
Rev. 4 (final July 2025) classify SMS as a "restricted" authenticator. Use passkeys / TOTP / authenticator-push as
primary MFA; offer SMS only as a low-assurance fallback with explicit
sensitivity-tiered access controls (i.e., SMS-only consumers cannot perform sensitive
actions without step-up).

### Adversary-in-the-middle for OAuth code exchange

Variant of AitM specific to OAuth: attacker intercepts the OAuth `code` returned to
the victim's browser, replays it from an attacker-controlled client to the IdP's
token endpoint, and gets a token. PKCE (RFC 7636) prevents this by binding the code
exchange to a per-session secret. CIAM products that ship OAuth integrations without
PKCE on public clients are vulnerable.

### Pass-the-cookie

Post-auth session cookie theft. Two main vectors:

1. **XSS** in the RP application. Attacker exfiltrates session cookie (if not
   HttpOnly) or executes API calls as the victim (if HttpOnly).
2. **Infostealer malware** on the victim's device. Lumma Stealer, RedLine, Vidar,
   Aurora, MetaStealer exfiltrate browser cookies, password-manager exports, and
   crypto-wallet secrets. The Snowflake 2024 incident's credential source was
   infostealer malware on customer-employee devices.

Defense: token-binding (sender-constrained tokens, DPoP RFC 9449), device-bound
sessions, short cookie lifetimes with sliding refresh, anomaly detection at the
session layer. Cross-link to `[[reference-session-management]]` §14.8 for the
pass-the-cookie taxonomy.

### Magic-link interception

If the email account is compromised (via phishing, ATO of the email IdP, or
infostealer-harvested IMAP credentials), every magic-link-based product is
compromised. The threat surface is whoever can read the victim's email. The defense
is to not make magic links the sole authentication primitive for high-value accounts.

---

## 8. Bot defense at the identity layer

CIAM faces adversarial automation at every stage: signup, login, password reset,
profile-update, content-creation, API access. Defense is multi-layered and an arms
race.

### Signup-bot defense

- **CAPTCHA.** reCAPTCHA v2 (image challenges), reCAPTCHA v3 (invisible behavioral
  scoring), hCaptcha (privacy-positioned alternative), Cloudflare Turnstile
  (CAPTCHA-less challenge using TLS + browser fingerprinting). University of Maryland's
  unCaptcha research documented an audio-CAPTCHA bypass via speech-recognition APIs. CAPTCHA is partial defense, not solution.
- **Privacy Pass (RFC 9576).** Token-based attestation that the user is human, issued
  after one challenge, redeemable elsewhere. Adopted in limited deployments
  (Cloudflare, Apple Private Access Tokens) `[unverified specific deployment scope]`.
- **Phone verification at signup.** Raises the cost: attacker must rent burner SIMs
  or VoIP numbers. Effective against low-tier abuse, defeated by industrial-scale
  SIM-farms (the Eastern European and Southeast Asian SIM-farm ecosystem).
- **Email verification at signup.** Baseline. Disposable-email-domain blocklists
  (Mailinator + thousands of clones) raise the bar; large attackers register their
  own throwaway domains.
- **Behavioral biometrics.** Castle.io, Sift, Sardine, BioCatch, BehavioSec score the
  signup as bot-vs-human based on mouse movement, typing cadence, scroll patterns,
  device-motion data. Effective against scripted abuse; less so against
  human-operated abuse and against AI-generated input simulators.

### Login-bot defense

- **Rate limiting.** Per-IP, per-account, per-IP-cluster, global-velocity. Adaptive
  thresholds. Do not key only on IP — credential-stuffing botnets rotate IPs through
  residential proxy services (Bright Data, Smartproxy, IPRoyal).
- **IP reputation.** Spamhaus DROP, MaxMind GeoIP, Cloudflare bot management.
  Residential-proxy IPs have measurably different reputation distributions than
  datacenter IPs.
- **JA3/JA4 TLS fingerprinting.** Salesforce's JA3 and FoxIO's JA4 fingerprint the
  TLS handshake. Browsers and tools produce stable JA3/JA4 values; popular automation
  frameworks (selenium, puppeteer, playwright, undetected-chromedriver) have
  signatures, though 2024-2026 evasion frameworks (curl-impersonate, puppeteer-extra
  stealth plugins) increasingly defeat naive fingerprinting.
- **Device fingerprinting.** FingerprintJS, ThreatMetrix, Iovation, Sift score the
  device on a stable identifier derived from browser canvas, audio context, WebGL,
  font-list, plugin list. Effective against scripted abuse on disposable browsers.
- **Behavioral biometrics at login.** Same vendor pool as signup. Score the login
  attempt's keystroke dynamics + mouse movement.

### Account-creation abuse

Fake-account farms for fraud, spam, content abuse, fake reviews, romance scams. The
attacker creates thousands or millions of accounts and ages them before use to defeat
new-account-flagging.

Defense at scale:
- Velocity controls (N signups from IP/ASN/device-cluster per window).
- Cross-signal correlation: phone-number sharing across accounts, payment-instrument
  reuse, behavioral patterns, IP overlap.
- Aging detection: a "human-aged" account behaves differently than a fake-aged one.
- Risk-scoring at every meaningful action, with progressive verification (the account
  can sign up easily, but the first attempt to do anything valuable triggers KYC).

### API-abuse at the identity layer

Adversaries scrape `check-email-exists` and `check-username-exists` endpoints to
build target lists for credential stuffing, social engineering, or scam targeting.

The classic CIAM anti-pattern: the signup flow tells the user "this email is already
registered." Defense: **verify but don't leak.** If the user enters an existing email,
send a "click here to log in if it's you, or click here to ignore" email and tell the
UI "if this email is registered, you'll get a message." Make the response time
identical between exists/doesn't-exist.

### 2024-2026 escalation: LLM-driven account creation

LLM-driven automation can defeat naive bot-defense challenges: solve text CAPTCHAs,
write plausibly-human profile bios, respond conversationally to KYC video chats. The
arms race has tilted toward the attacker for low-friction challenges. The structural
response is biometric and device-binding signals that the LLM cannot easily synthesize
(a real device with a real attestation key, real phone-number provisioning costs).

Cross-link to `[[reference-anti-fraud-abuse-engineering]]` for the broader bot-defense
discipline and to `[[reference-misinformation-influence-ops]]` for the
LLM-generated-content abuse vector.

---

## 9. KYC, AML, identity verification for regulated CIAM

For fintech, crypto, gaming, healthcare, and regulated marketplaces, self-signup is
not enough. Regulatory regimes require **identity proofing** — verification that the
account corresponds to a real human with a real legal identity.

### Definitions

- **KYC (Know Your Customer).** Verify identity at onboarding. Typically photo-ID +
  selfie + liveness check. Required by FinCEN (US), FCA (UK), BaFin (Germany), MAS
  (Singapore), and analogous regulators.
- **AML (Anti-Money Laundering).** Ongoing monitoring of transactions and behavior;
  sanctions screening (OFAC, EU sanctions list, UN sanctions); suspicious-activity
  reporting (SAR). The lifecycle layer on top of KYC.
- **KYB (Know Your Business).** Equivalent for business customers — verify the legal
  entity, beneficial owners (UBO), and authorized representatives.

### Regulatory anchors

- **NIST SP 800-63A** (US) defines identity-proofing IAL (Identity Assurance Level)
  1/2/3. IAL2 is the typical commercial standard; IAL3 requires in-person or
  supervised remote.
- **eIDAS (EU)**. Regulation (EU) No 910/2014. Defines electronic identification
  trust levels: Low / Substantial / High. The **eIDAS 2.0** revision (Regulation (EU)
  2024/1183 `[unverified specific number]`) introduces the European Digital Identity
  Wallet with adoption deadline 2026 `[unverified specific date]`.
- **PSD2 SCA (Strong Customer Authentication).** EU directive 2015/2366; SCA mandate
  effective September 2019 for EEA payment services. Two factors from
  knowledge/possession/inherence; transaction-level for payments over €30.
- **3DS2 (3-D Secure 2).** Card-payment authentication standard from EMVCo; PSD2 SCA
  compliance mechanism for cards.
- **PSD3 (draft as of 2026)** `[unverified specific status]`. Successor to PSD2 with
  refined SCA + open-banking framework.
- **AMLD6 (EU Sixth Anti-Money Laundering Directive)** and the upcoming AMLR
  (Anti-Money Laundering Regulation) consolidating cross-EU rules.
- **BSA (US Bank Secrecy Act)** + **Customer Identification Program (CIP)** + **CDD
  rule** (FinCEN Customer Due Diligence Rule).
- **COPPA (US, Children's Online Privacy Protection Act).** Parental consent for
  users under 13. FTC has stepped up enforcement 2023-2026 against products that
  failed age-gating.

### KYC vendor landscape

Already covered in §2's specialty list. Each vendor has strengths:

- **Onfido + Veriff + Jumio**: enterprise, broad document coverage, regulatory
  certifications across many jurisdictions.
- **Persona**: developer experience and flow customization.
- **Stripe Identity**: integration with Stripe Connect marketplaces.
- **Plaid**: financial-account-linking-as-identity, common in US consumer fintech.
- **Berbix / iDenfy / Sumsub**: regional and price-competitive alternatives.
- **Trulioo / Socure**: data-broker-driven verification (cross-reference with credit
  bureau and public-records data) — typical in US bank-tier KYC.

### 2024-2026 deepfake threat to KYC

AI-generated images and video defeat naive liveness checks. The arms race:

- **Passive liveness** (analyze frames for telltale generation artifacts) is being
  defeated by 2024 generation models.
- **Active liveness** (real-time random prompts: turn head, blink on cue, follow a
  finger) raises the bar; defeated by real-time video-generation models in 2025-2026
  research `[unverified specific demonstrations]`.
- **Device attestation** (Apple Managed Device Attestation, Android Play Integrity,
  Pixel StrongBox) provides a hardware-rooted signal that the verification request
  came from a real device with a real camera, not a server-side AI generator. This is
  the structural migration path.
- **In-person verification** for IAL3-equivalent assurance, with all the cost that
  implies. Common for crypto exchanges' high-tier verification.

Persona, Veriff, Jumio, Onfido all publish escalating-defense roadmaps reflecting
this arms race.

### KYC data-retention and privacy tension

KYC data — passport scans, driver's-license images, selfies — is highly sensitive
PII. Retention requirements vary: BSA requires 5 years post-account-closure (US);
GDPR requires "data minimization" and explicit retention justification (EU); some
fintech regulators require longer retention. The intersection of GDPR Article 17
(erasure) and BSA retention is a known compliance-tension point — typically resolved
by retaining minimal KYC artifacts (hash + verification result) and deleting raw
documents per a defined schedule.

---

## 10. Privacy and GDPR for CIAM

CIAM operates at the intersection of identity, marketing, and product analytics. The
privacy substrate matters.

### GDPR core operational obligations

- **Article 5 principles.** Lawfulness, fairness, transparency; purpose limitation;
  data minimization; accuracy; storage limitation; integrity and confidentiality;
  accountability.
- **Article 6 lawful bases.** Consent, contract, legal obligation, vital interests,
  public task, legitimate interest. Pick one and document it for every processing
  activity.
- **Article 7 consent.** Must be freely given, specific, informed, unambiguous.
  Pre-ticked boxes don't count; bundled-consent doesn't count. The granular reality:
  the CIAM signup flow must offer separable consent for marketing, analytics,
  third-party-sharing, etc.
- **Article 17 erasure.** "Right to be forgotten." Subject can request deletion;
  controller must comply within a month barring lawful retention requirements.
- **Article 20 portability.** Subject can request their data in a "structured,
  commonly used, machine-readable format." In practice: JSON export.
- **Article 25 privacy by design and by default.** Default settings minimize data
  collection.
- **Articles 33-34 breach notification.** 72 hours to supervisory authority; notify
  data subjects when high risk.

### CCPA / CPRA (California)

- Right to know what's collected and shared.
- Right to delete.
- Right to opt out of sale or sharing (CPRA expands "sale" to include sharing for
  cross-context advertising).
- Right to correct.
- Right to limit use of sensitive personal information.
- Private right of action limited to data breaches involving specified categories.

### COPPA (US, under-13)

- Verifiable parental consent before collecting personal information from children
  under 13.
- FTC enforcement: $275M Epic Games COPPA penalty 2022 (Fortnite; separate $245M dark-patterns order);
  $5.7M Musical.ly (now TikTok) settlement 2019; renewed enforcement focus 2023-2026 against
  social-media and EdTech products `[unverified specific recent action list]`.
- Age-gating mechanisms: parental email verification, payment-card verification (used
  as a proxy for adulthood), photo-ID verification for higher confidence.

### Consent management platforms

OneTrust, TrustArc, Cookiebot, Didomi, Iubenda, Usercentrics. These plug into the
CIAM signup flow to collect, version, and document consent. They generate the
"cookie banner" UX that every EU-facing product ships, and they maintain the
audit-trail of consent versions per user. Compliance theater at the cookie-banner
layer is rampant — many implementations darkpattern-default users into "accept all."

### Right-to-portability in practice

GDPR Article 20 requires "structured, commonly used, machine-readable format." There
is no schema standard. Each vendor ships its own export format. Many exports are
partial — missing inferred data, missing relationships to other users, missing
historical state. **Right-to-portability is mostly broken in practice.** §14
revisits this in the failure-mode catalog.

### Pseudonymization vs anonymization

GDPR Article 4(5) defines pseudonymization as "the processing of personal data in
such a manner that the personal data can no longer be attributed to a specific data
subject without the use of additional information." Pseudonymized data is still
personal data (reversible). Anonymized data is not personal data (irreversible),
which is harder to achieve than vendors claim — re-identification attacks against
"anonymized" datasets are well-documented in the privacy literature. Cross-link to
`[[reference-privacy-engineering]]` for the deanonymization corpus.

---

## 11. Real-incident corpus

### Snowflake credential-stuffing campaign, 2024

~165 Snowflake customer accounts compromised across multiple breach disclosures
(AT&T, Ticketmaster/Live Nation, Santander, Advance Auto Parts, Neiman Marcus,
LendingTree, Pure Storage, others). The Snowflake platform itself was not breached.
Customers' credentials had been harvested by infostealer malware (Lumma Stealer,
RedLine, others) on employee devices over years, then bought-and-sold on
underground markets and used to log into customer Snowflake instances that had not
enforced MFA.

Mandiant tracks the actor as UNC5537 `[unverified specific designation]`. The lesson:
**MFA must be enforced, not just available.** Snowflake's product permitted password-
only access until customers opted into MFA enforcement. Post-incident, Snowflake
announced MFA-mandatory-by-default for new customers and aggressive MFA-pushback for
existing.

CIAM lesson: any product where the account holds value (payments, regulated data,
trusted graph access) must enforce MFA, with passkey or TOTP as the primary factor.
SMS-only is not enough.

### Microsoft Storm-0558 token-signing key compromise, May 2023

Attacker (PRC-aligned actor designated Storm-0558 by Microsoft) obtained a Microsoft
consumer-account signing key and used it to forge access tokens for Exchange Online
mail. ~25 organizations compromised including US State Department and Commerce
Department mailboxes.

Root cause per Microsoft's September 2023 analysis (walked back in a March 2024
addendum: no crash dump containing the key was found): a crash dump containing the
signing key was migrated from an isolated production environment to an internet-
connected debugging environment, where it was later accessed by the actor. A
separate validation bug allowed the consumer-account key to mint tokens accepted by
the enterprise tenant.

CIAM lesson: token-signing key compromise is the apex CIAM disaster scenario — the
attacker can mint tokens for arbitrary users without touching their credentials.
Defense-in-depth at the IdP itself, key-rotation discipline, and detection of
unusual token-issuance patterns are the mitigations.

### Okta sub-processor / support-system breaches, 2022-2023

- **January 2022 (disclosed March 2022):** Lapsus$ obtained access to a Sitel customer-support engineer's
  workstation. Lapsus$ posted screenshots claiming access to Okta's internal
  Superuser tooling. Okta initially downplayed; later put the maximum potential
  impact at 366 customers; its concluded investigation found two customer tenants
  accessed.
- **October 2023:** Okta disclosed that customer-support-system files containing
  HAR-file uploads (which had captured customer session tokens) had been exfiltrated.
  Affected customers included BeyondTrust, 1Password, Cloudflare. The HAR-files-with-
  active-session-tokens shape was the load-bearing detail.

CIAM lesson: **the CIAM vendor is a single point of failure.** A breach at the IdP
propagates to all customers. Mitigations: multi-IdP failover for critical workloads;
direct passkey storage (where the RP holds the credential, not the IdP); careful
HAR-file handling discipline at customer-support boundaries.

### Sign In with Apple zero-day, May 2020 (Bhavuk Jain)

Apple's JWT-mint flow for Sign In with Apple permitted an attacker to request a token
with an arbitrary email address. Apple would mint the token (signed by Apple's
private key, accepted by any RP) without verifying the requester controlled the
email. An attacker could obtain an Apple-signed token for victim@example.com and use
it to log in to any RP that federated to Sign In with Apple.

Bhavuk Jain disclosed responsibly; Apple paid a $100k bug bounty.

CIAM lesson: **trust the IdP no more than the IdP trusts itself.** Apple is a
high-assurance IdP; a token-mint bug at Apple still happened. Mitigations: do not
auto-link Apple sign-in to existing accounts based on email-claim alone — require
ownership proof.

### 23andMe credential stuffing, October-December 2023

~14,000 23andMe accounts directly compromised via credential stuffing. Through the
DNA-relatives feature, the connected-relatives profile data of ~6.9M users was
exposed. The amplification factor (1:500) is the load-bearing characteristic.

23andMe initially blamed users for password reuse, which was technically accurate but
PR-poor. Class-action litigation followed; settlement $30M announced 2024
`[unverified specific amount]`. A UK ICO investigation followed.

CIAM lesson: **think about social-graph amplification.** A single ATO'd account in
your product may expose data of many other users through product features. Audit
product features for this amplification.

### DraftKings credential stuffing, November 2022

~67,000 user accounts compromised via credential stuffing; some funds withdrawn
before detection. ~$300k total losses across users.

CIAM lesson: consumer fintech with no MFA is a target. DraftKings did not enforce MFA
pre-incident; post-incident, MFA enrollment was incentivized.

### Mailchimp social-engineering breach, January 2023

Attackers used social engineering to compromise Mailchimp customer-support employee
credentials, then accessed ~133 Mailchimp customer accounts. The downstream effect:
phishing campaigns sent through compromised Mailchimp customers' lists.

CIAM lesson: support-agent compromise is a recurring threat. Apply zero-trust
principles to internal-support tooling.

### Other incidents worth knowing

- **Twitter / X 2022:** ~5.4M users' email-phone-to-username mapping exposed via API
  abuse. Identity-enumeration as harvested intelligence.
- **Lapsus$ campaign 2021-2022:** Okta, Microsoft, Nvidia, Samsung, T-Mobile (sim
  swaps), Globant. The "social engineering + sim-swap + insider-purchase" playbook.
- **MGM Resorts / Caesars Entertainment, September 2023:** social-engineering of IT
  helpdesk by Scattered Spider. ~$100M MGM impact; Caesars reportedly paid $15M
  ransom `[unverified specific ransom figure]`. Anchor for support-agent-as-soft-
  underbelly.

---

## 12. 2024-2026 currency

### Passkey consumer adoption

- Apple iOS 16 / macOS Ventura (2022) introduced platform-passkey support with
  iCloud Keychain sync.
- Google Password Manager added cross-device passkey sync 2022.
- Microsoft personal account + Entra began rolling passkey support 2023-2024.
- 1Password, Dashlane, Bitwarden added third-party passkey vault storage 2023.
- WhatsApp, X, GitHub, Best Buy, Kayak, eBay, Cloudflare, Adobe, Amazon, Shopify,
  TikTok, Microsoft, Google, Apple, Yahoo, Robinhood, PayPal, Coinbase shipped
  consumer-facing passkey support in 2023-2024.

Adoption rates `[unverified specific percentages]` vary: developer-savvy products
report 10-40% of active users on passkeys; long-tail consumer products well under
5%. The FIDO Alliance publishes adoption surveys.

### NIST SP 800-63 Rev. 4

The fourth revision of NIST's Digital Identity Guidelines was published as final
in July 2025. Notable changes:

- Reduced AAL2-acceptable factors with SMS further restricted.
- Phishing-resistance requirements for AAL3.
- Updated identity-proofing IAL definitions including remote-supervised flows.
- Updated guidance on biometric authenticators.

`[unverified specific language pending Rev. 4 final publication]`.

### EU eIDAS 2.0 and the European Digital Identity Wallet

Regulation (EU) 2024/1183 `[unverified specific reg number]` (eIDAS 2.0) mandates a
European Digital Identity Wallet for EU citizens, with member-state adoption deadlines
through 2026 `[unverified specific dates]`. The wallet is intended to be the
cross-border-recognized consumer identity for accessing public and private services.
Implementation reference work is at https://github.com/eu-digital-identity-wallet/.

CIAM implication: consumer products serving EU users will increasingly federate to
member-state wallet-based credentials. The wallet substrate is hardware-backed,
phishing-resistant, and revocation-aware — structurally an upgrade over current
consumer credentials.

### PSD3 draft

Successor to PSD2 in EU payments regulation. Refined SCA (Strong Customer
Authentication) requirements, open-banking framework expansion, fraud-data-sharing
mandates. `[unverified specific draft status as of 2026]`.

### AI-voice-cloning attacks on call-center identity verification

2023-2025 saw documented attacks where attackers used voice-cloning AI to defeat
voice-biometric authentication and to socially engineer call-center agents
(impersonating the legitimate customer). Specific incident corpus
`[unverified, multiple anecdotal but few publicly attributed]`. The mitigation: do
not use voice biometric as a high-assurance factor; treat call-in identity claims
with the same skepticism as helpdesk-mediated recovery.

### LLM-driven account farms

Bot-driven account creation increasingly uses LLMs to:
- Generate plausible profile bios that defeat naive "is this a bot" classifiers.
- Solve text and image CAPTCHAs.
- Respond conversationally to KYC video chats (with voice cloning and lipsync video
  generation).
- Run age-verification dialogues that defeat keyword-based filters.

The structural defense is device-attestation signals (Apple/Android), not behavioral
or content classifiers. Cross-link to `[[reference-anti-fraud-abuse-engineering]]`
for the adversary-economics framing.

### Account-takeover via cookie-theft via infostealer

The 2024-2026 ATO economy increasingly routes through infostealer malware on victim
devices. The supply chain: malware operator → log marketplace (Russian Market,
2easy.shop, Genesis Market until April 2023 takedown) → ATO operator buys logs for
specific target accounts. The Snowflake campaign credentials originated this way.

The defense is sender-constrained tokens (DPoP) and device-bound sessions — see
`[[reference-session-management]]` §14.

---

## 13. CIAM-specific anti-patterns

Refuse to ship:

**Email as sole identity anchor.** If email compromise = product-account compromise,
the actual auth strength is the email provider's security posture. Layer additional
factors at sensitive actions.

**SMS-only MFA on regulated workloads.** NIST classifies it as a restricted authenticator. Sim-swap rings are
industrial. SMS is fine as a low-assurance fallback; not as the sole MFA on a fintech
or healthcare workload.

**No anomaly detection at login.** Risk-based authentication is the modern standard:
score every login on device fingerprint, IP reputation, geographic distance from last
login, behavioral signals. Step up on anomaly. Treating every login as equally
trusted is naive.

**Self-service account recovery weaker than primary auth.** If primary is passkey,
recovery should require either another pre-registered phishing-resistant factor or
out-of-band high-friction verification (KYC re-verification). If recovery is
"email me a link" and primary is passkey, you have email-account-strength auth.

**Logout that doesn't terminate OAuth grants and refresh tokens.** Many CIAM
implementations terminate the session cookie on logout but leave OAuth-issued refresh
tokens active. A token harvested before logout still works. Full logout requires
explicit revocation of refresh tokens via the IdP revocation endpoint.

**Account-linking without verification.** Linking a new IdP credential to an existing
account based solely on the email-claim from the new IdP. Audit the linking flow.

**"Forgot password" reveals whether the email is registered.** Enumeration leak.
Modify the flow: always say "if this email is registered, you'll receive a message."
Make response timing identical.

**MFA disabled by support agent without out-of-band ID verification.** Social-
engineering of support agents is the canonical CIAM bypass. Treat MFA-disable as a
sensitive operation requiring KYC-grade verification.

**Storing recovery codes alongside primary credentials.** Recovery codes should be
displayed once at setup, never recoverable from the account, and ideally never stored
in the same trust boundary as the primary credential.

**Passwords that can be reset to the same password.** Some products forbid password
reuse on reset; many do not. Forbidding reuse-of-current-password is table stakes.

**OAuth `redirect_uri` validated by prefix or wildcard match.** Exact-match only.
Rosén's and Curry's corpus is a long list of wildcard-validation bypasses.

**Implicit OAuth flow for SPAs.** Deprecated. Use authorization code + PKCE.

**Email change without re-verification of the new email AND notification to the old
email.** Anti-pattern: attacker changes the victim's email, then triggers recovery
via the attacker-controlled email.

**Persistent "trust this device for 90 days" cookies that survive password reset.**
Reset should invalidate trusted-device markers.

---

## 14. Honest failure modes — load-bearing section

Read this section as the failure ceiling on CIAM as a practice in 2026. Each item is a
limitation worth knowing before you ship.

**The recovery flow is the actual authentication strength.** Audit it as such, with
the same threat-modeling rigor you apply to primary auth. If primary is passkey and
recovery is email-link, your auth strength is email-account-control. Most CIAM
products underweight this in their threat-modeling.

**Self-signup CIAM has no device-attestation baseline.** Workforce IAM can refuse
logins from unenrolled devices. CIAM cannot. Layer device-attestation signals where
possible (Apple MDA, Android Play Integrity), but understand that consumers using
older or non-mainstream platforms will not have strong device signals available. Your
risk-based authentication must function without device-attestation as ground truth.

**SMS-as-2FA is structurally broken** — sim-swap ecosystem, signaling-layer
interception (SS7), insider-at-mobile-carrier risk. It is still deployed because
passkey adoption is partial and SMS is universal. Layer additional signals; do not
treat SMS as high-assurance.

**Pass-the-cookie defeats MFA at the session layer.** Even passkey-mandatory auth
ships a post-auth session token. If the token is stolen (XSS, infostealer malware,
SSRF leak, log-aggregation leak), the attacker bypasses MFA. The structural defense
is sender-constrained tokens (DPoP, RFC 9449) and device-bound sessions, both of which
have limited 2026 deployment. Cross-link to `[[reference-session-management]]` §14.8.

**OAuth account-linking is rife with bugs.** Curry's and Rosén's bug-bounty corpus
documents recurring shapes: implicit-trust of email claim, missing `state`, prefix-
match `redirect_uri`, post-auth-linking without re-verification, IdP-mint bugs (Sign
In with Apple 2020). Audit account-linking flows with adversarial threat-modeling.

**Magic links are not phishing-resistant.** Modern AitM frameworks (Evilginx,
Modlishka, Muraena, EvilProxy) intercept them. Time-bounding and device-binding raise
the bar but do not close the gap. For high-value accounts, passkeys are the
structural defense.

**Bot defense is an arms race that adversary economics favors.** The attacker pays
once per signup-attempt; the defender pays per false-positive in lost legitimate users.
The asymmetry is built in. Cross-link to `[[reference-anti-fraud-abuse-engineering]]`.

**GDPR right-to-portability is mostly broken in practice.** Exports are partial,
missing inferred data, missing the relational context that gives the data meaning. The
right exists on paper; the operational reality is closer to compliance theater. The
Data Transfer Initiative (formerly Data Transfer Project) is the multi-vendor attempt
at a real interop standard `[unverified specific status as of 2026]`.

**KYC liveness detection is being deepfaked 2024-2026.** Passive liveness defeated by
generation-time artifacts; active liveness defeated by real-time generation. The
migration path is hardware-rooted device attestation, which is opt-in and platform-
limited. The KYC industry is in an active arms race; expect step-changes both ways
through 2026.

**CIAM-vendor-as-single-point-of-failure.** Okta sub-processor (2022-2023), Microsoft
Storm-0558 (2023), Auth0 incidents `[unverified specific incident detail]`. A breach
at the IdP propagates to all customers. Multi-IdP failover is operationally
expensive; few products deploy it. Direct passkey storage at the RP (rather than
through the IdP) is one structural mitigation — you hold the credential, not the
vendor. Progressive disclosure of vendor-dependency is another (e.g., the IdP issues
short-lived tokens; the RP requires re-authentication for sensitive actions and can
fall back to direct-credential paths during IdP outages).

**Self-service password reset is the canonical SSRF for ATO.** Where SSRF is "the
attacker abuses the server to make outbound requests," ATO-via-reset is "the attacker
abuses the recovery flow to take the account." The structural reason both exist:
internal trust assumptions that don't hold when the actor on the other side is
adversarial.

**Account-takeover detection is mostly post-hoc.** Anomaly signals fire after the
ATO has happened; pre-emptive prevention is dominated by friction-vs-conversion
trade-offs. The realistic state: detect within hours, contain within a day, recover
the user within a week. Faster requires sacrificing conversion or accepting more
false positives.

**The CIAM product is part of the company's marketing surface.** Identity flows are
optimized by growth teams, A/B tested, and shipped with conversion targets. This
creates structural pressure to weaken authentication for activation. Hold the line:
the long-term cost of an ATO breach exceeds the short-term cost of conversion
friction at the high-value-account tier.

**KYC false-rejects are a discrimination vector.** Underrepresented-group photo-ID
verification has documented higher false-reject rates. The civil-rights implications
are real. Audit your KYC pipeline for disparate impact.

**Consumer-identity data is a poaching target.** The 23andMe genetic-data exposure
illustrates: identity data persists, can be combined with other breaches, and has
secondary uses (insurance discrimination, blackmail, targeted scams). Plan
retention deliberately; do not collect more than you need.

---

## 15. Cross-link cluster

The CIAM problem space sits at the intersection of authentication, session, privacy,
abuse, and incident response. The relevant sibling docs:

- `[[reference-zero-trust-workload-identity]]` — workforce + workload identity.
  CIAM's sibling problem with different scale, trust, and recovery dynamics.
- `[[reference-saml-federation]]` — SAML XSW, OAuth flows, OIDC threat model. The
  protocols CIAM uses for IdP federation.
- `[[reference-webauthn-fido2-passkeys]]` — WebAuthn / passkeys as the phishing-
  resistant primary auth target state. The structural answer to AitM.
- `[[reference-session-management]]` — what happens after authentication. Cookie /
  token / refresh-rotation / revocation discipline. CIAM's session layer.
- `[[reference-secrets-management-discipline]]` — the IdP's signing keys are the
  apex secret. Key rotation and protection sit on the secrets discipline.
- `[[reference-anti-fraud-abuse-engineering]]` — adversary economics, bot detection,
  ATO, credential stuffing. The CIAM threat-model layer for abuse.
- `[[reference-misinformation-influence-ops]]` — fake-account farms and LLM-generated
  content abuse intersect with CIAM signup defense.
- `[[reference-privacy-engineering]]` — DP, pseudonymization, deanonymization. The
  privacy substrate for CIAM data.
- `[[reference-privacy-preserving-advertising]]` — Chrome Privacy Sandbox, Apple
  ATT/ITP. Privacy-respecting marketing layers downstream of CIAM identity.
- `[[reference-dfir-methodology]]` — incident response when ATO and credential-
  stuffing campaigns happen at scale. CIAM-specific IR has additional consumer-
  notification obligations.
- `[[reference-ai-incident-response-playbook]]` — when the ATO uses AI deepfakes
  against KYC, the IR playbook adapts. Cross-link for the AI-in-CIAM threat surface.
- `[[reference-threat-modeling-discipline]]` — applying STRIDE / LINDDUN to a CIAM
  product. Identity-spoofing as the dominant T in STRIDE.
- `[[reference-code-review-expertise]]` — auditing CIAM code for the recurring
  anti-patterns in §13. Click-count severity is unusually high for identity code:
  one missing check on `redirect_uri` is a one-click ATO.

---

## 16. Operational checklist for AppSec leads working on CIAM

1. **Map the identity-substrate decision.** Is email the primary anchor? Phone?
   OAuth `sub`? Internal UUID with multiple linked identities? Document it.
2. **Audit the recovery flow with the same rigor as primary auth.** It is your actual
   auth strength.
3. **Enforce MFA on accounts with value.** Not just "available" — enforced. Snowflake
   2024 is the canonical lesson.
4. **Treat SMS as low-assurance.** Fine as a low-friction backup; not as sole MFA on
   sensitive workloads.
5. **Move sensitive actions behind step-up authentication.** Risk-based at minimum;
   passkey or TOTP for highest-value actions.
6. **Audit OAuth integration for `state`, PKCE, exact-match `redirect_uri`, and
   account-linking verification.** Rosén bug shapes recur.
7. **Verify-but-don't-leak on enumeration endpoints.** Identical response timing for
   exists/doesn't-exist.
8. **Score every login.** Risk-based authentication with device, IP, geo, behavioral
   signals. Step up on anomaly.
9. **Deploy phishing-resistant primary auth where the user population permits it.**
   Passkeys are the migration target.
10. **Audit the support-agent override flows.** Social engineering of support agents
    is the canonical CIAM bypass.
11. **Plan for vendor breach.** Your IdP can be compromised. Have a containment plan
    for IdP-side incidents (token-rotation, session-invalidation, customer
    notification).
12. **Audit KYC for deepfake resistance.** Active liveness + device attestation are
    the 2026 baseline; passive liveness is being defeated.
13. **Measure recovery-flow security.** Run periodic adversarial exercises against
    your own recovery flow. The hardest part of CIAM is finding the time to do this.

CIAM done well is invisible: users sign up, sign in, recover when they need to, and
never think about it. CIAM done badly is the lead item in next quarter's breach
disclosure. The difference is mostly in the recovery flow and in the discipline
around the soft underbelly.
