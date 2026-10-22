# WebAuthn, FIDO2, and Passkeys
## Synthesized from the W3C WebAuthn Spec, the FIDO Alliance CTAP2 Corpus, and the Passkey Production Deployment Record

> **Primary researchers, spec editors, and teams:**
>
> - **Dirk Balfanz** (Google; long-time identity spec contributor). Co-author of the original
>   FIDO U2F protocol and a foundational contributor to the WebAuthn / CTAP2 design. The
>   asymmetric-crypto-per-origin model — sign a fresh challenge with a domain-bound key, with
>   no shared secret to phish — descends from his U2F work at Google.
> - **Vijay Bharadwaj** (Microsoft; former W3C WebAuthn editor). Listed as a former editor on WebAuthn
>   Level 1, Level 2, and Level 3. The Microsoft-side Windows Hello + WebAuthn integration
>   reflects his spec work directly.
> - **Mike Jones** (Self-Issued Consulting; formerly Microsoft Identity Standards Architect).
>   W3C WebAuthn co-editor; JOSE / JWT / OIDC spec history covered in
>   [[reference-saml-federation]]. The COSE algorithm registry used by WebAuthn
>   `pubKeyCredParams` flows from his JOSE work. https://self-issued.info/
> - **Emil Lundberg** (Yubico, Software Engineer). Maintainer of Yubico's
>   `java-webauthn-server` library; co-editor of WebAuthn
>   Level 2 and Level 3. The practitioner counterweight to the spec-author side: when an RP
>   library is wrong, it is usually wrong in a way that Lundberg has already documented.
>   https://github.com/Yubico
> - **John Bradley** (Yubico; long-time federation spec author). Co-author of RFC 7519 (JWT)
>   with Mike Jones and Nat Sakimura; FIDO2 spec contributor; the practitioner who carries the
>   OIDC/JWT history into the WebAuthn working group.
> - **Adam Langley** (Google, BoringSSL / Chrome security). Wrote much of the Chrome WebAuthn
>   implementation and the corresponding caBLE / hybrid-transport protocol; the imperialviolet.org
>   blog is the canonical practitioner-side primary source for WebAuthn cryptographic decisions.
>   https://www.imperialviolet.org/
> - **Tim Cappalli** (Okta). FIDO Alliance contributor and Passkeys
>   Working Group member. The cross-vendor passkey UX work (autofill / Conditional UI /
>   recovery flows) reflects his coordination across Apple, Google, and Microsoft.
> - **Akshay Kumar** (Microsoft) and **Christiaan Brand** (Google). Brand is the
>   long-time Google FIDO2 product lead; his presentations are the load-bearing primary source
>   for the Google Password Manager + Chrome passkey rollout shape.
> - **Nick Steele** (Duo Labs, then 1Password; W3C WebAuthn invited expert). The
>   webauthn.guide / webauthn.io maintainer; the practitioner-grade introduction documentation
>   that most RP integrators read first. https://webauthn.guide/
> - **Matthew Miller** (`MasterKale`; SimpleWebAuthn maintainer). The TypeScript/Node WebAuthn
>   RP library used by a large fraction of production deployments. The library's documentation
>   pages cover spec subtleties — signCount semantics, RP ID scoping, attestation verification
>   — at the level a working RP engineer needs. https://simplewebauthn.dev/
> - **Matus Nemec, Marek Sys, Petr Svenda, Dusan Klinec, and Vashek Matyas** (Masaryk
>   University). The 2017 ROCA disclosure
>   (CVE-2017-15361): factorable RSA keys from Infineon TPMs, which directly affected hardware
>   tokens generating RSA keys on Infineon RSALib chips. The canonical anchor for "authenticator
>   firmware crypto bugs are catastrophic" in the WebAuthn / FIDO2 corpus.
>   https://crocs.fi.muni.cz/public/papers/rsa_ccs17
> - **Thomas Roche** (NinjaLab). The EUCLEAK side-channel disclosure (2024) on Infineon
>   SLE78-class secure elements, affecting YubiKey 5 firmware versions below 5.7. ECDSA-nonce
>   side-channel extraction via electromagnetic measurements; requires physical access to the
>   device and specialized equipment. The canonical real-world example of an FIDO2-certified roaming key falling to a
>   hardware-level cryptographic side-channel.
>   https://ninjalab.io/eucleak/
> - **Kurt Boberg (`kurt-r2c`)** — Semgrep staff researcher. Cross-link to the broader
>   authentication-protocol corpus at [[reference-saml-federation]] (SAML/OIDC/OAuth/JWT/SCIM)
>   and to the authentication-vs-authorization scoping discussion at
>   [[reference-distributed-authz]].
>
> **Audience:** security engineer or auth architect evaluating passkey rollout, auditing a
> WebAuthn/FIDO2 deployment, or building enterprise FIDO compliance. The protocol is solid;
> the implementations vary. This doc covers both.

---

## 1. What "WebAuthn / FIDO2 / passkeys" means in 2026

Three layers, often conflated.

**FIDO2** is the joint spec family produced by the W3C and the FIDO Alliance. It has two
public-facing components: the **WebAuthn** browser API (W3C Recommendation) and the
**Client-to-Authenticator Protocol** (CTAP2, FIDO Alliance). WebAuthn is the JavaScript
surface that `navigator.credentials.create()` and `navigator.credentials.get()` live on;
CTAP2 is the wire protocol the browser uses to talk to an external authenticator over USB,
NFC, or BLE.

**WebAuthn Level 1** reached W3C Recommendation status in March 2019. **Level 2** followed
in April 2021, adding large-blob storage and the `credProps` extension. **Level 3** was a Working Draft through
2025, became a Candidate Recommendation in January 2026, and a W3C Recommendation in
August 2026; it adds Conditional UI (autofill), the
`backupEligibility` and `backupState` flags, and the `prf` extension.

**Passkeys** are not a separate spec. The word names a deployment shape: FIDO2 credentials
that are **discoverable** (the authenticator stores the credential ID and the RP can request
authentication without sending the credential ID first) and **synced** across a user's
devices via a platform keychain. Apple, Google, and Microsoft co-launched the consumer
"passkey" brand in 2022; the underlying protocol is unchanged. The cross-device sync is the
new operational property.

The distinction matters in audits. "WebAuthn is phishing-resistant" is true at the protocol
layer; "passkeys are phishing-resistant" is true only if the passkey-sync vendor's threat
model permits the claim — and any RP can hold a credential that has been synced to a
managed device family. Cross-link [[reference-saml-federation]] for broader authentication
protocol context; this doc covers only the credential-binding layer.

---

## 2. The three-layer architecture

WebAuthn separates three trust boundaries.

**Relying Party (RP).** The web application performing authentication. The RP runs the
WebAuthn JS API in the browser and talks to its own server over the application's normal
authenticated channel. The RP holds the per-user public key and the credential ID; it never
holds the private key.

**Client (browser + platform).** The user agent that mediates between the WebAuthn API and
the authenticator. The client enforces the **origin binding** (the WebAuthn ceremony fails if
the calling origin does not match the RP ID's scope) and routes the request to the right
authenticator. The platform provides the credential-manager UI: which credential to use,
biometric prompts, the QR code scan for cross-device sign-in.

**Authenticator.** The thing that holds the private key. Two structural classes:

- **Roaming authenticators** — external devices that talk CTAP2 over USB-HID, NFC, or BLE.
  YubiKey 5 series, Google Titan, SoloKey 2, Nitrokey 3 FIDO2, Token2 PIN+. Hardware-bound;
  the private key cannot leave the device.
- **Platform authenticators** — built into the device. Windows Hello (TPM-backed on Windows
  10+), Touch ID / Face ID (Secure Enclave-backed on macOS / iOS), Android biometric +
  StrongBox-backed Keymaster on supported hardware. Private keys are bound to the platform's
  secure-element subsystem; cross-link [[reference-mobile-security]] for the per-platform
  secure-storage internals.

A roaming authenticator can be used across devices but is hardware-bound to itself; a
platform authenticator is bound to the device, but with **passkey sync** the credential is
replicated (under end-to-end encryption) to other devices in the same vendor account. This
trade-off — portability vs hardware-bound-ness — is the load-bearing 2026 deployment
decision.

---

## 3. The wire-level protocol

### 3.1 Registration ceremony

The RP wants to bind a new credential to a user account. The full ceremony:

```javascript
// RP server generates registration options
const options = {
  challenge: crypto.randomBytes(32),           // 32-byte minimum, fresh per ceremony
  rp: {
    id: "example.com",                          // RP ID — see §3.3 scoping
    name: "Example Service",
  },
  user: {
    id: opaqueUserHandle,                       // 64-byte opaque, NOT email or PII
    name: "alice@example.com",
    displayName: "Alice Doe",
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7  },           // ES256 (ECDSA P-256 + SHA-256)
    { type: "public-key", alg: -8  },           // EdDSA (Ed25519)
    { type: "public-key", alg: -257 },          // RS256 (legacy; for Windows Hello older HW)
  ],
  attestation: "direct",                        // "none" | "indirect" | "direct" | "enterprise"
  authenticatorSelection: {
    authenticatorAttachment: "platform",         // or "cross-platform" for roaming keys
    residentKey: "required",                     // discoverable credential
    userVerification: "required",
  },
  timeout: 60000,
  excludeCredentials: existingCredentials,       // prevent double-registration
};

// Client (browser) routes to authenticator
const credential = await navigator.credentials.create({ publicKey: options });

// Returned PublicKeyCredential:
//   credential.id              — Base64url credential ID
//   credential.rawId           — ArrayBuffer of credential ID
//   credential.response.clientDataJSON
//   credential.response.attestationObject  (CBOR-encoded)
//   credential.response.transports         — ["usb", "nfc", "ble", "internal", "hybrid"]
```

The **clientDataJSON** is a JSON object the client constructs:

```json
{
  "type": "webauthn.create",
  "challenge": "base64url-encoded-32-bytes",
  "origin": "https://example.com",
  "crossOrigin": false,
  "tokenBinding": { "status": "supported" }
}
```

The **attestationObject** is CBOR-encoded and contains the authenticator data plus the
attestation statement. The authenticator data is a flat byte string:

```
RP ID Hash (32 bytes, SHA-256 of RP ID)
Flags (1 byte): ED AT 0 BS BE UV 0 UP
Sign Count (4 bytes, big-endian)
[ AT=1 → attestedCredentialData ]
   AAGUID (16 bytes)
   Credential ID Length (2 bytes)
   Credential ID (variable)
   Credential Public Key (COSE_Key, CBOR-encoded)
[ ED=1 → extensions (CBOR map) ]
```

Flag bits (least to most significant): **UP** (User Presence — the user touched the key /
authenticator). **UV** (User Verification — the user satisfied a PIN, biometric, or other
verification). **BE** (Backup Eligibility — the credential is permitted to be synced).
**BS** (Backed up — the credential has already been synced to a cloud account). **AT**
(Attested credential data present). **ED** (Extension data present). The `BE` + `BS` flags are the
load-bearing 2024-2026 addition; RPs use them to distinguish hardware-bound from synced
credentials.

The RP-side verification:

1. Parse `clientDataJSON`. Verify `type == "webauthn.create"`, `challenge` matches the
   server-issued one, `origin` matches the expected scheme+host+port, `tokenBinding` is
   absent or matches the connection's binding ID.
2. Verify SHA-256(RP ID) matches the first 32 bytes of authenticator data.
3. Verify flags: UP=1 always; UV=1 if the RP required user verification.
4. Verify `sign count == 0` is acceptable here (it's a fresh credential); store the count.
5. Extract the AAGUID and credential public key.
6. Verify the attestation statement against the configured root CAs (or accept self
   attestation, depending on policy — see §4).
7. Persist: user_handle → (credential_id, public_key, AAGUID, sign_count, transports,
   backup_eligibility, registered_at).

### 3.2 Authentication ceremony

```javascript
const options = {
  challenge: crypto.randomBytes(32),
  rpId: "example.com",                   // omit for cross-device (use RP ID from server)
  allowCredentials: [                    // empty for discoverable / Conditional UI
    { type: "public-key", id: credId1, transports: ["usb", "nfc"] },
  ],
  userVerification: "required",
  timeout: 60000,
};

const assertion = await navigator.credentials.get({ publicKey: options });

// Returned:
//   assertion.response.authenticatorData  (raw bytes)
//   assertion.response.clientDataJSON
//   assertion.response.signature           (ECDSA / EdDSA / RSA signature)
//   assertion.response.userHandle          (the opaque user ID, returned only for discoverable)
```

The signature is over `authenticatorData || SHA-256(clientDataJSON)`. The RP verifies it
using the stored public key, then:

- Verifies `clientDataJSON.type == "webauthn.get"`.
- Verifies challenge match, origin match, RP ID match, UP flag, UV flag if required.
- Verifies the **sign count** moved monotonically forward (or is 0, which the authenticator
  may use to signal it does not maintain a counter — common for synced passkeys, where the
  counter cannot be meaningfully maintained across devices).
- Verifies `BE` and `BS` flags match the registered credential's expected sync state (a
  credential registered with `BE=0` flipping to `BE=1` is a hard fail).

### 3.3 RP ID scoping

The RP ID is a domain name. The browser enforces that the calling origin's host is the RP
ID or a subdomain of it. `https://accounts.example.com` calling with `rpId: "example.com"`
is allowed; `https://accounts.example.com` calling with `rpId: "example.org"` is forbidden;
`https://accounts.example.com` calling with `rpId: "auth.example.com"` is also forbidden
(you can ascend toward the eTLD+1 boundary but not descend). The eTLD+1 boundary is the hard
ceiling; the browser uses the Public Suffix List to refuse `rpId: "co.uk"`.

This scoping is the protocol-layer phishing defense. An attacker on `examp1e.com` cannot
present a WebAuthn ceremony with `rpId: "example.com"`; the browser rejects the call before
the user sees any prompt.

---

## 4. Attestation chains

Attestation proves to the RP that the authenticator is what it claims to be. The WebAuthn
spec defines seven standard attestation statement formats plus `none`.

| Format | Used by | Chain anchor |
|---|---|---|
| `none` | Any (opt-out) | No chain; AAGUID may be zero |
| `packed` | Modern roaming keys (YubiKey 5+) | Vendor attestation root CA |
| `fido-u2f` | Legacy U2F-only roaming keys | Vendor attestation CA (per-batch) |
| `tpm` | Windows Hello (TPM 2.0) | TPM EK (Endorsement Key) root |
| `android-key` | Android StrongBox-backed credentials | Google Hardware Attestation Root |
| `android-safetynet` | Android software-backed credentials | SafetyNet attestation API |
| `apple` | Touch ID / Face ID platform authenticators | Apple WebAuthn Root CA |

**Packed format** is the generic FIDO2 default. The attestation statement contains a
signature (over the authenticator data plus the client-data hash), an algorithm identifier,
and an optional X.509 certificate chain. The chain anchors to a vendor root that the FIDO
Alliance publishes in the **FIDO Metadata Service (MDS)**.

**Self-attestation** is a special case of `packed` with no certificate chain: the
authenticator signs the attestation with the same private key that the RP is registering.
This proves the credential is freshly generated but says nothing about hardware backing.
It's the default for some roaming keys configured with attestation disabled, and for some
platform authenticators when the user has not granted device-identity disclosure.

**AAGUID** — Authenticator Attestation GUID — is a 128-bit identifier baked into the
authenticator firmware. Each authenticator model has one AAGUID across all units (so the
AAGUID is not a per-device identifier; it's a per-make/model identifier). The FIDO Alliance
MDS publishes the AAGUID database with per-entry metadata: vendor name, certification level,
supported transports, supported algorithms, key protection class, attestation root CAs. An
enterprise RP can pin its accepted set: `if (aaguid in allowed_set) accept else reject`.

A note on **enterprise attestation**. WebAuthn defines `attestation: "enterprise"` for
deployments where the RP wants per-device serial-number-grade identity, not just per-model.
Enterprise attestation is permitted only when the authenticator is enrolled to a specific
RP ID list maintained on the device; consumer YubiKeys do not return enterprise attestation
by default.

---

## 5. The passkey ecosystem in 2026

Passkeys are FIDO2 credentials with three operational properties: **discoverable**
(authenticator stores the credential ID), **synced** (cloud-backed across the user's
devices), and **resident** in some form on each synced device. The cloud-sync layer is
vendor-specific.

### 5.1 Apple iCloud Keychain

Passkeys created on iOS / iPadOS / macOS sync to iCloud Keychain. The sync stream is
end-to-end encrypted using the iCloud Keychain key hierarchy (a per-user master key derived
from device-PIN-protected escrow records). Apple's published threat model describes the
sync layer as end-to-end encrypted, with recovery through an HSM-protected escrow record
that requires the iCloud account password, an SMS to a registered phone number, and the
device passcode. The credential is bound to the iCloud account, not to the device.

### 5.2 Google Password Manager (Android + Chrome)

Android passkeys (Android 9+ on capable hardware) sync via Google Password Manager. The
sync stream is end-to-end encrypted; a new device needs the Google Password Manager PIN or
the screen lock of an existing Android device to access synced passkeys. Chrome on desktop (Linux/macOS/Windows)
participates in the same sync via the Google account credential manager.

### 5.3 Microsoft

Windows Hello supports both **hardware-bound** (TPM-backed, not synced) and **synced**
passkey storage via the Microsoft Account credential manager. The Microsoft Authenticator
app on iOS / Android provides cross-device passkey use for Entra ID and consumer Microsoft
account scenarios.

### 5.4 Third-party password managers as passkey providers

1Password, Bitwarden, Dashlane, Proton Pass, and KeePassXC (as of 2024+ releases) all
implement passkey storage. The integration shape is either a browser extension that
intercepts the WebAuthn API or a platform credential-provider plugin (iOS 17+ Credential
Provider Extensions, Android 14+ Credential Manager API, macOS Sonoma Credential Provider
framework). The threat model is: the password manager's vault becomes the holder of
passkeys, with the same encryption-at-rest and unlock-PIN protections as for passwords.

### 5.5 Cross-device authentication via hybrid transport (caBLE)

The "I'm signing in on a desktop but my passkey lives on my phone" case is solved by
**hybrid transport**, formerly named caBLE (Cloud-Assisted Bluetooth Low Energy) during
development. The desktop browser displays a QR code containing an ephemeral handshake
keypair and tunnel coordinates; the user's phone scans the QR with the platform
authenticator's deep-link handler. The phone establishes BLE proximity to the desktop
(proving physical co-location) and then opens a Noise-protocol-encrypted tunnel through a
relay server operated by Google or Apple. The actual CTAP2 GetAssertion flows through the tunnel.

The hybrid transport has three load-bearing properties: the QR contains a fresh handshake
keypair (the tunnel server cannot read the assertion); BLE proximity proves the phone is
near the desktop (defeating remote relay over the open internet); the tunnel server is
operated by Google or Apple (a centralization point, but with no plaintext access).

### 5.6 Honest 2026 framing on passkey sync

Passkey sync moves the credential from "hardware-bound to this device" to "available across
the user's account-bound device family." RPs cannot determine from the assertion which
vendor's sync layer holds the credential; they see only the `BE` / `BS` flags. Enterprise
deployments that need hardware-bound assurance must require `BE=0` at registration and
reject any subsequent assertion with `BE=1`. Consumer deployments routinely accept synced
credentials as the default.

The sync layer is a new trust dependency: a compromise of an iCloud account, a Google
account, or a password-manager vault now propagates to every RP the user authenticates to
with that vault. The threat model is closer to "compromised password manager" than to
"stolen YubiKey."

---

## 6. Known attacks and bypasses

### 6.1 Downgrade to weaker auth methods

The most common WebAuthn bypass is structural: the RP supports WebAuthn **and** password,
**and** SMS-OTP, **and** TOTP. The attacker drives the user toward the weakest path. WebAuthn
provides no protocol-layer defense against the RP's own fallback flow.

Defense: WebAuthn-only authentication for sensitive paths. NIST SP 800-63B-4
requires a phishing-resistant authenticator at AAL3; at AAL2 it only requires that a
phishing-resistant option be offered. Practical patterns: passkey-only login with account recovery
gated on identity proofing, not on a back-channel weaker factor.

### 6.2 Hardware key supply-chain attacks

Counterfeit YubiKeys, NFC-implanted skimmers in keyboard-format security keys, modified
firmware on white-label keys. The FIDO Metadata Service AAGUID database is the operational
defense — pin to known-good AAGUIDs and reject unknown ones at registration. Cross-link
[[reference-supply-chain-provenance]] for the broader hardware-attestation discipline.

The EUCLEAK side-channel disclosure (Roche, NinjaLab, 2024) on Infineon SLE78-class secure
elements affected the YubiKey 5 firmware family below 5.7. The attack extracts an ECDSA
private key via electromagnetic side-channel measurements during the signature operation,
with physical access to the device. The
disclosure shape — a hardware-side-channel attack on the cryptographic primitive of a
FIDO2-certified authenticator — anchors the "hardware authenticator firmware is the
load-bearing trusted code path" failure mode catalogued in §13.

### 6.3 Bluetooth proximity exploits on hybrid transport

Hybrid transport uses BLE proximity as a binding signal. BLE-layer attacks (KNOB, BIAS,
BLUFFS — covered in [[reference-wireless-rf-satellite]]) can disrupt the proximity
verification or extend the practical range of the proximity check. The Noise-protocol
tunnel itself does not depend on BLE for confidentiality; the BLE handshake provides
authenticated key agreement specifically for the relay-defense property.

A practical attack shape: phone in the user's pocket, attacker controls a BLE relay over a
longer distance, attacker triggers the hybrid ceremony on a controlled desktop that the
user's phone is socially induced to authenticate to. The proximity binding still requires
the user's phone to authorize the assertion via biometric or PIN, so this is not a silent
attack — it is a "trick the user into approving a prompt for the wrong site" attack.

### 6.4 Origin-binding bypasses

The browser enforces origin binding for WebAuthn. Documented bypass surfaces:

- **Subdomain trust**. An RP using `rpId: "example.com"` accepts ceremonies from any
  subdomain. A compromised subdomain (`tracking.example.com` controlled by a marketing
  vendor) can drive WebAuthn ceremonies that the RP's main flow accepts. Defense: use the
  narrowest viable RP ID; do not collapse multiple business units into a single eTLD+1 RP
  ID.
- **Cross-origin iframe** scenarios. Level 1 rejected ceremonies from cross-origin frames
  (`sameOriginWithAncestors`). Level 2 introduced the `publickey-credentials-get` Permissions
  Policy / Feature Policy directive; Level 3 added `publickey-credentials-create`. The default
  allowlist is `self`, so a cross-origin frame can run a ceremony only when the embedding page
  delegates it with an `allow` attribute or Permissions-Policy header.
- **Mixed-content scenarios**. WebAuthn requires a Secure Context (HTTPS / localhost). RPs
  that serve their login flow under HTTPS but have a misconfigured CSP allowing HTTP iframe
  inclusion can break the trust assumption in subtle ways.

### 6.5 Phishing-resistant but not phishing-immune

WebAuthn defeats credential-phishing at the protocol layer: the browser refuses to sign a
challenge for the wrong RP ID. It does not defeat **consent-phishing**: an OAuth flow where
the user is induced to grant a malicious OAuth client access to a resource server, with
the WebAuthn authentication itself being legitimate.

The OAuth flow that follows a WebAuthn assertion still needs `state` parameter validation,
PKCE, and the RFC 9700 best-current-practice mitigations. WebAuthn is phishing-resistant
for the credential; it does not phishing-resist the authorization decision that follows.
Cross-link [[reference-saml-federation]] §RFC-9700 for the OAuth side of this.

### 6.6 InfoStealer-class attacks on passkey vaults

Modern info-stealers (RedLine, Lumma, StealC, and successors) target browser-resident
credential stores. Passkey storage in browser-integrated password managers (1Password
extension, Bitwarden extension, Chrome / Edge built-in) is a target. The mitigation depends
on the vault's threat model: if the passkey vault decrypts on session unlock and resides in
process memory in cleartext during use, an info-stealer with code execution in the browser
process can exfiltrate active credentials. Hardware-bound platform authenticators (Secure
Enclave, TPM, StrongBox) defeat this class; software-vault passkeys do not.

This is the load-bearing operational reason enterprises that have moved to passkeys for
SSO often still mandate hardware-bound roaming keys for break-glass accounts.

### 6.7 Side-loading attestation bypass on Android

Android Play Integrity (the 2023+ replacement for SafetyNet) returns a signed token
attesting the device state. Researcher-published bypasses (Magisk hide, modified ROMs with
re-signed boot images, GrapheneOS-compat shimming) exist for SafetyNet historically; Play
Integrity raised the bar by binding the attestation to hardware-backed key attestation on
capable devices. The bypass surface for Play Integrity is narrower but not zero —
specifically on older devices that still depend on the software-evaluated `BASIC` integrity
verdict rather than `STRONG`. Enterprise RPs requiring high assurance should pin to
`MEETS_STRONG_INTEGRITY` and reject `MEETS_BASIC_INTEGRITY` or `MEETS_DEVICE_INTEGRITY` only.

### 6.9 Authenticator firmware bugs

The 2017 ROCA disclosure (CVE-2017-15361) on Infineon RSALib affected TPM-generated RSA
keys and any FIDO key issuing RSA via affected Infineon parts. The 2024 EUCLEAK side-channel
on Infineon SLE78 affected YubiKey 5 below firmware 5.7. The pattern: hardware
authenticators are the trusted code path; firmware crypto bugs in them are catastrophic and
unfixable for issued units (you replace the hardware). Cross-link
[[reference-supply-chain-provenance]] for the upgrade-path discipline.

---

## 7. Enterprise deployment patterns and certification

### 7.1 FIDO Alliance certification

The FIDO Alliance runs the FIDO Functional Certification (interoperability) and the FIDO
Authenticator Certification (security). Authenticator levels:

- **L1** — basic. The authenticator implements the FIDO specifications; protects against
  phishing and credential abuse.
- **L2** — software protection plus protections against malware on the host.
- **L3** / **L3+** — hardware-backed key protection with attestation chain to a hardware
  root of trust.

`[unverified specific advisory]` — the FIDO Alliance maintains the list of
certified-and-still-trusted parts at https://fidoalliance.org/certification/, which an
enterprise procurement should consult before bulk purchase.

### 7.2 NIST SP 800-63B Authenticator Assurance Levels

NIST SP 800-63B-3 (June 2017, plus the 800-63B-4 draft cycle through 2024-2025) defines
three Authenticator Assurance Levels:

- **AAL1** — single-factor authentication with low confidence.
- **AAL2** — multi-factor authentication with moderate confidence. WebAuthn with a passkey
  satisfying user verification (PIN, biometric) generally maps to AAL2.
- **AAL3** — hardware-backed multi-factor with high confidence and phishing resistance.
  WebAuthn with a hardware-bound authenticator (cross-platform USB key, or platform
  authenticator with proven hardware key isolation) and user verification maps to AAL3.

The NIST 800-63B-4 draft cycle treats synced passkeys as AAL2-eligible but not AAL3-eligible
because the credential portability undermines the "in-the-physical-possession-of" property
AAL3 requires. The published Federal-government guidance lands the same way: AAL3 contexts
(e.g., privileged-access management) require hardware-bound keys; AAL2 contexts permit
passkey sync. NIST published the final SP 800-63B-4 in July 2025 — consult the
latest revision directly.

### 7.3 Enterprise allowlist via AAGUID

The cleanest enterprise-deployment control is AAGUID pinning. At registration, the RP
inspects the AAGUID from the attestation and refuses to register a credential from an
unapproved make/model. A canonical allowlist pattern:

```python
APPROVED_AAGUIDS = {
    # YubiKey 5 series (FIDO2)
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 USB",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 NFC",
    # ... and so on, from FIDO MDS
}

def verify_registration(attestation):
    aaguid = extract_aaguid(attestation.authenticator_data)
    if aaguid not in APPROVED_AAGUIDS:
        raise RegistrationRefused(f"Unapproved authenticator {aaguid}")
    if attestation.format == "none":
        raise RegistrationRefused("Attestation required for enterprise enrollment")
    verify_attestation_chain(attestation, FIDO_MDS_ROOTS)
```

The AAGUID values above are illustrative — the canonical source is the FIDO Metadata
Service download (https://mds.fidoalliance.org/). Do not hard-code AAGUID values without
periodically refreshing from MDS.

### 7.4 Attestation requirement at registration

Three RP-side choices for the `attestation` field:

- `attestation: "none"` — RP does not want any attestation. The browser returns a stripped
  AAGUID (all-zero) and an empty attestation statement. The credential is still cryptographically
  bound; the RP just has no idea what made it.
- `attestation: "indirect"` — the browser is allowed to anonymize the attestation by
  re-signing through a per-batch certificate. Useful for consumer flows that want some
  attestation but not user-trackable per-device identity.
- `attestation: "direct"` — the RP receives the raw attestation statement signed by the
  authenticator's batch certificate. AAGUID is populated. This is the enterprise default.

Note that "user trackability via AAGUID" is fundamentally a per-make-model identifier, not
a per-device one. The privacy concern is about narrowing the user's device fingerprint; it
is not a per-device tracking identifier.

### 7.5 Conditional UI vs modal UI

WebAuthn Level 3 added **Conditional UI**, the "passkey autofill" experience: the RP calls
`navigator.credentials.get()` with `mediation: "conditional"`, and the browser surfaces
matching credentials in the username-field autofill dropdown rather than as a modal dialog.

```javascript
const assertion = await navigator.credentials.get({
  mediation: "conditional",
  publicKey: { challenge, rpId, allowCredentials: [], userVerification: "preferred" },
});
```

Conditional UI lowers friction (the user does not see a modal until they pick a credential
from the autofill list) at the cost of a wider attack surface: any credential matching the
RP ID can be presented for autofill, and a misconfigured RP ID (subdomain over-share) means
unrelated business-unit credentials surface to the user. The Conditional UI flow is the
default for consumer passkey rollouts; enterprise rollouts often disable it in favor of
explicit modal flows that constrain the user's choice.

### 7.6 Account recovery — the soft underbelly

Every account-recovery flow weakens the authentication property of the underlying
authenticator. Practical patterns observed in production:

- **Secondary passkey** — at registration, require the user to enroll at least two
  authenticators (one platform, one roaming) and accept either at sign-in. Defeats device
  loss without weakening the protocol.
- **Recovery code** — high-entropy recovery code shown once at registration, persisted by
  the user out of band. Equivalent to a long password; phishable.
- **Magic-link to email** — recovery via email-account access. Inherits the security of the
  email provider; usually weakens the overall posture.
- **Identity-proofing-based recovery** — re-establish identity through a human flow
  (government-ID verification, video call, in-person visit). Slow and expensive but
  preserves the AAL3 property.

The NIST 800-63B guidance treats recovery as an authentication event at the same AAL as the
primary; deployments that gate AAL3 access behind passkeys but allow AAL1 recovery have
compromised the access decision.

---

## 8. Cross-device caBLE / hybrid transport deep-dive

### 8.1 Mechanism

The RP server, via the desktop browser, calls `navigator.credentials.get()` without
specifying a transport. The browser, knowing the user has no local platform authenticator
matching the RP ID, displays a QR code containing:

- A fresh ECDH P-256 public key (the desktop browser's tunnel handshake key).
- A 16-byte random QR secret and the number of assigned tunnel server domains.
- Optional fields: the current time, a state-assisted-transaction flag, and a user-flow hint.

The QR is encoded as a `FIDO:/` URI followed by digit-encoded data (seven-byte chunks written as 17-digit base-10 numbers). The user
scans the QR with the platform authenticator's deep-link handler (iOS Camera app, Android
Camera app, or the platform credential manager's scan-QR action). The phone:

1. Decodes the `FIDO:/` URI.
2. Generates its own ECDH P-256 keypair.
3. Connects to the indicated tunnel server, identified by the tunnel
   ID, and opens a Noise-protocol-encrypted channel to the desktop side.
4. Establishes BLE proximity to the desktop — broadcasts an ephemeral BLE advertisement that
   the desktop scans for. The advert is encrypted and authenticated with keys derived from the
   QR secret, proving physical co-location.
5. Performs the CTAP2 GetAssertion over the Noise tunnel.
6. Returns the assertion to the desktop, which returns it from the WebAuthn API call.

### 8.2 Why caBLE matters

Before caBLE, "I have a passkey on my phone, I'm on a desktop" required either pairing the
phone as a Bluetooth keyboard, or installing a desktop credential helper, or moving the
passkey to a roaming USB key. caBLE removes the cross-device passkey friction at the cost
of two new dependencies: a centralized tunnel server and the BLE proximity binding.

The desktop and phone use the tunnel server only as a relay; the Noise tunnel terminates at
the two endpoints, so the tunnel server has no plaintext access to the assertion. The BLE
proximity check provides the relay-defense property — without it, a remote attacker could
proxy the QR scan from a legitimate phone to an attacker desktop.

### 8.3 Attack surface

- **BLE relay**. The proximity binding is the load-bearing defense. A BLE relay extending
  the range of the proximity check defeats it. Published BLE relay research (WiSec 2022)
  relayed signals over 90 m with low-cost hardware. The user still has to
  authorize the assertion on the phone (biometric / PIN), so the attack is "trick the user
  into approving a prompt for the wrong site" rather than silent.
- **QR phishing**. The attacker displays a `FIDO:/` QR generated against an attacker
  desktop the user thinks is the legitimate site. The phone authenticates to the
  attacker-controlled tunnel; if the attacker's desktop relays to the real RP, the user's
  authentication completes on the attacker's session. The Noise tunnel and the RP-side
  origin check do **not** prevent this — the phone authenticator does not know which RP
  the attacker desktop is talking to; only that the desktop is requesting authentication
  for some RP ID, which the phone shows on its UI. The user-visible prompt on the phone is
  the load-bearing defense; users skipping past it is the failure mode.
- **Tunnel server compromise**. The tunnel server is a
  centralization point. Compromise does not yield plaintext access (Noise tunnel is
  end-to-end), but does enable traffic analysis (which user is authenticating to which RP,
  inferred from tunnel-coordination metadata) and selective denial of service.

### 8.4 Honest framing on caBLE in 2026

caBLE has shipped at production scale for Apple, Google, Microsoft, and 1Password / Bitwarden /
Dashlane passkey implementations. The trade-off (centralized tunnel + BLE proximity check) is
the price of cross-device passkeys without device-pairing. The threat model is documented
publicly; enterprises with strict hardware-bound requirements should use roaming USB keys
and disable hybrid transport at the platform credential-manager level.

---

## 9. Browser implementation surface

The WebAuthn JS API runs in the browser; the implementation is part of the browser engine.

### 9.1 Chrome (Blink + Chrome WebAuthn implementation)

Chrome implements WebAuthn Level 3, including Conditional UI, hybrid transport, and the
`prf` extension. Chrome's WebAuthn surface is the most-deployed; Chrome on macOS routes
platform-authenticator requests to Touch ID via the Apple WebAuthn API; Chrome on Windows
routes to Windows Hello / TPM via the platform WebAuthn API; Chrome on Linux supports
roaming keys and stores passkeys in Google Password Manager. Chrome on Android binds to the Google
Password Manager. The Chromium WebAuthn unit tests are public and worth consulting for
edge-case behavior.

### 9.2 Firefox (Gecko)

Firefox implements WebAuthn Level 2 plus parts of Level 3, including Conditional UI and the
`prf` extension (Firefox 135 on Windows / Linux, Firefox 139 on macOS).
Firefox's platform-authenticator support depends on the host OS's WebAuthn integration;
Firefox on macOS supports Touch ID via the platform API.

### 9.3 Safari (WebKit)

Safari implements WebAuthn Level 3 with Apple-specific integration: iCloud Keychain
passkey storage, Touch ID / Face ID platform authentication, the AutoFill flow that
includes passkey credentials alongside passwords. Safari's WebAuthn implementation is the
load-bearing one for iOS passkey UX.

### 9.4 Edge (Chromium-based)

Edge inherits the Chrome WebAuthn implementation plus Windows-specific extensions: Windows
Hello platform authenticator integration, Microsoft account passkey sync, the Entra ID
enterprise SSO bridge.

### 9.5 Per-browser quirks and bug history

- **Site isolation interactions**. Per-origin process isolation interacts with the
  WebAuthn API in subtle ways; cross-origin frame ceremonies require correct Process
  Isolation handling to avoid the WebAuthn API leaking origin information across processes.
- **Extension-injection attacks on the WebAuthn DOM API**. A malicious browser extension
  with `<all_urls>` permission can hook `navigator.credentials.create` / `get` and either
  block ceremonies or, in unpatched extension-bridge bugs, observe the ceremony. The
  browser-vendor mitigation is to make the credential-manager UI live in the browser-chrome
  process, not the page process, so extension code cannot interpose between the user and
  the credential decision.
- **Fingerprinting via authenticator enumeration**. `getClientCapabilities` and
  `isUserVerifyingPlatformAuthenticatorAvailable()` leak whether the user has a platform
  authenticator. This is fingerprintable; modern browsers gate these calls behind the
  Secure Context requirement and consider tighter restrictions.

Cross-link [[reference-browser-js-engine-exploitation]] for the broader browser-engine
exploitation surface; the WebAuthn API is one surface among many.

---

## 10. Library and SDK landscape

The protocol is solid; the implementations vary. Server-side RP library bugs are the
persistent source of operational vulnerabilities — a 2026 audit that finds nothing wrong
with the protocol layer should still inspect the RP library carefully.

### 10.1 SimpleWebAuthn (TypeScript / Node.js)

`@simplewebauthn/server` and `@simplewebauthn/browser` by Matthew Miller. The community
standard for Node-based RPs. Documentation at https://simplewebauthn.dev/ covers spec
subtleties — origin-verification, RP ID scoping, attestation parsing — at the right level
for an integrating engineer.

### 10.2 py_webauthn / python-fido2 (Python)

Yubico-maintained. `python-fido2` covers both the RP side (server-side ceremony) and the
CTAP2 wire format (useful for hardware-key debugging). `py_webauthn` is a separate
community library focused on the RP side. The two are largely compatible but not
interoperable as Python packages.

### 10.3 webauthn4j (Java)

Java RP library by Yoshikazu Nojima. `com.webauthn4j:webauthn4j-core`. Spring Security
integrations are community-maintained. Used widely in enterprise Java back-ends.

### 10.4 go-webauthn (Go)

Community-maintained at `github.com/go-webauthn/webauthn`. Used by Gitea and
other Go-stack production deployments.

### 10.5 Fido2NetLib (.NET)

The primary .NET WebAuthn RP library. `github.com/passwordless-lib/fido2-net-lib`. Microsoft
itself uses internal libraries for Entra ID server-side WebAuthn; Fido2NetLib is the
community-maintained option that most ASP.NET / .NET Core RPs build against.

### 10.6 Rust

`webauthn-rs` is the community-maintained Rust crate. Used by Kanidm and various Rust-stack
identity providers. The crate is well-typed and the test suite is thorough; the maintainer
has documented attestation verification subtleties in upstream tickets.

### 10.7 Honest 2026 framing

Implementation bugs to look for in any RP library audit, regardless of language:

- **Challenge validation**. The challenge must be exactly the one issued for this ceremony,
  not "any recently issued challenge for this user."
- **Origin validation**. The origin must exactly match (scheme + host + port); historical
  bugs accept partial matches.
- **RP ID hash verification**. The first 32 bytes of authenticator data must equal
  SHA-256(RP ID); historical bugs skip the verification or use the wrong RP ID.
- **Sign-count comparison**. The new count must be strictly greater than the stored count
  (or both must be 0 for synced credentials). Bugs that accept "equal or greater" allow
  replay across simultaneous-use scenarios.
- **Attestation chain verification**. The certificate chain must validate to a configured
  root; bugs that accept any chain or that skip the chain entirely are common.
- **Flag enforcement**. UV=1 must be enforced if the RP requires user verification;
  historical bugs accept `userVerification: "preferred"` and then never check the flag.
- **Resident-key handling**. Discoverable credential ceremonies return a `userHandle`; the
  RP must use it to identify the user, not infer from session state.

---

## 11. Post-quantum migration

WebAuthn currently uses classical signature algorithms via the COSE algorithm registry:

- **ES256** (`alg: -7`) — ECDSA with P-256 + SHA-256. The most common.
- **ES384** (`alg: -35`) — ECDSA with P-384 + SHA-384. Less common, used in some FIPS profiles.
- **ES512** (`alg: -36`) — ECDSA with P-521 + SHA-512. Rare.
- **EdDSA** (`alg: -8`) — Ed25519. Increasing adoption; supported by Yubico modern keys.
- **RS256** (`alg: -257`) — RSA-PKCS1-v1_5 with SHA-256. Legacy; required for older Windows
  Hello and some TPM-backed scenarios.
- **PS256** (`alg: -37`) — RSASSA-PSS with SHA-256. Less common; used in some FIDO profiles.

The NIST PQC standardization (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, all
finalized August 2024) is the upstream input for the FIDO Alliance PQC roadmap. Cross-link
[[reference-post-quantum-cryptography]] for the full PQC landscape.

### 11.1 FIDO Alliance PQC roadmap

The FIDO Alliance has published roadmap discussion documents through 2024-2025 outlining
the path to PQC WebAuthn. The expected shape:

- New COSE algorithm identifiers for ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) added to
  the COSE registry.
- Authenticator firmware updated to support PQC signature generation.
- Hybrid signatures (co-sign with classical + PQ) as the transition mechanism — the
  WebAuthn `pubKeyCredParams` list already allows clients to advertise multiple algorithm
  preferences, so a hybrid deployment is structurally possible without spec changes.
- Certification update for L1 / L2 / L3 to incorporate PQC primitives.

Concrete delivery timelines are not yet locked in; treat any specific date claim as
`[unverified specific advisory]` and consult the FIDO Alliance Member-side roadmap at
https://fidoalliance.org/ for the current status.

### 11.2 Hardware constraint

Many roaming keys in active deployment (YubiKey 5, older Titans, SoloKey 2 v1) have
insufficient flash and RAM for ML-DSA (Dilithium): the signature is large (~2-4 KB), the
key is large (~1-2 KB public, ~3-4 KB private), and the signing operation uses significant
RAM. SLH-DSA (SPHINCS+) is more flash-tolerant but slower. The practical implication: PQC
WebAuthn requires hardware refresh for most current roaming keys.

Platform authenticators (Secure Enclave, TPM 2.0, StrongBox) generally have more headroom
but still require firmware updates to support PQC primitives. The TPM 2.0 spec is being
updated to include PQC algorithm identifiers; vendor firmware lag will be substantial.

### 11.3 Migration planning

The PQC migration discipline is the same as for TLS or for OIDC JWT signing — cross-link
[[reference-pqc-migration-playbook]] for the full migration framework. WebAuthn-specific
notes:

- Inventory the deployed authenticator AAGUIDs; cross-reference against vendor PQC support
  roadmaps.
- Add PQC algorithm identifiers to RP `pubKeyCredParams` lists ahead of authenticator
  support — clients select what they can do, so adding new options is backward-compatible.
- Plan a credential-re-registration window for the moment a user's authenticator firmware
  gains PQC support — the existing credential's classical-only public key is still on
  record, so the migration is per-credential, not per-RP.
- Account for the credential-portability semantics — PQC passkey sync requires the sync
  vendor to roll out PQC encryption-in-transit and -at-rest in the sync layer.

---

## 12. Detection and monitoring

The WebAuthn protocol carries enough metadata in each assertion that an RP can monitor for
operational and adversarial signals without server-side observability tooling beyond the
RP's own audit log.

### 12.1 Sign-count anomalies

The authenticator data includes a 4-byte sign count. The RP should:

- Store the highest count seen per credential.
- Reject assertions where the new count is not strictly greater than the stored count
  (with the exception of count=0, which signals a counter-less synced credential).
- Alert on a count regression for a credential that previously had a non-zero count — this
  indicates either a stolen credential, an authenticator firmware reset (rare), or a sync
  semantic violation (the synced credential is being used from a device that has not
  received the latest sync state).

### 12.2 AAGUID drift

A given credential ID is bound to a specific authenticator make and model. If a credential
ID re-attests under a different AAGUID, something is wrong: a stolen credential ID
re-registered to a different authenticator, or an attestation forgery, or a credential
re-creation flow that bypassed the original device.

### 12.3 Attestation chain failures

These should be hard rejections at registration, not warnings. The chain either validates
to a trusted root or it does not; "validate and log if it fails" is a recipe for accepting
forged attestations from poorly-tested code paths.

### 12.4 Conditional UI anomalies

Credentials presented through Conditional UI from an unexpected device family (the user has
never used a roaming USB key, suddenly a YubiKey-AAGUID credential surfaces) flag for review.

### 12.5 Authentication-velocity anomalies

A single passkey credential authenticating from geographically distant IPs within minutes
indicates either passkey-sync to a new device or a stolen credential being used in parallel.
Distinguishing the two requires correlating with `BE` / `BS` flags and with the user's
device-management state.

### 12.6 Runtime telemetry shape

Cross-link [[reference-detection-engineering]] §10 for the runtime detection rule corpus.
WebAuthn-specific signals to forward to the SIEM:

- Registration ceremonies with `attestation: "none"` (if policy requires attestation).
- Attestation chain validation failures.
- Sign-count regressions.
- AAGUID values outside the approved allowlist.
- Conditional UI assertions from unexpected device families.
- Hybrid-transport (caBLE) assertions, with the relay region and the user's expected
  geographic state.
- User-verification bypasses (UV=0 where the RP required UV=1).

---

## 13. Honest failure modes

A clean enumeration of the known-bad outcomes a WebAuthn / FIDO2 / passkey deployment can
land in. None of these are protocol bugs; all of them are deployment-shape consequences.

### 13.1 Credential portability vs phishing resistance

Passkey sync trades the "credential bound to physical device" property for usability. The
trade-off is publicly documented by Apple, Google, and Microsoft, but enterprises adopting
passkeys often inherit the trade-off without considering its consequences. A compromised
iCloud / Google / Microsoft account now propagates to every RP the user authenticates to.
Hardware-bound roaming keys defeat this; synced passkeys do not.

### 13.2 Account recovery is the soft underbelly

Every account-recovery flow weakens the underlying authentication. SMS-OTP recovery on top
of a passkey is no stronger than SMS-OTP. The recovery path is the phishing target; the
primary path being phishing-resistant does not help if the user is driven to recovery.

### 13.3 Enterprise SSO integration inherits SSO bugs

When WebAuthn fronts SAML / OIDC, the SSO flow inherits any SSO bugs catalogued in
[[reference-saml-federation]]. The WebAuthn ceremony succeeded; the SAML XSW that followed
still allowed authentication bypass. WebAuthn is one layer; the SSO that follows is
another. Audit them separately.

### 13.4 Cross-RP credential sharing via subdomain trust

Credentials are bound to RP ID. If two services share an RP ID (because they share an
eTLD+1 boundary and the RP chose the eTLD+1 as the RP ID), they share credentials,
intentionally or not. A credential registered for one business unit's app can authenticate
to another business unit's app on the same eTLD+1. The narrowest viable RP ID is the
correct deployment choice; expanding the RP ID later is structurally impossible without
breaking existing credentials.

### 13.5 Authenticator firmware bugs are catastrophic

The trusted code path of a hardware authenticator is the firmware. ROCA (2017,
CVE-2017-15361) on Infineon RSALib affected TPM-generated RSA keys at scale. EUCLEAK (2024)
on Infineon SLE78 affected YubiKey 5 below firmware 5.7. Firmware bugs in the cryptographic
primitive class are unfixable for issued units — you replace the hardware, not the firmware
(on FIDO-certified roaming keys, firmware is generally not field-updatable for security
reasons). Plan for the hardware-replacement scenario at procurement; budget for periodic
fleet refresh.

### 13.6 Implementation bugs in RP libraries

A correct WebAuthn protocol and a broken RP library is an authentication bypass. Audit the
RP library every time you upgrade it; do not trust transitive dependency updates to
preserve security properties. The 2022-2024 corpus of WebAuthn RP library bugs spans
challenge-reuse, RP-ID-not-verified, attestation-skipped, UV-flag-not-enforced — none of
which the protocol can defend against.

### 13.7 Browser implementation bugs

The browser's WebAuthn implementation is part of the TCB. A browser bug that misroutes a
ceremony to the wrong authenticator, that fails to enforce origin binding, that leaks
credential IDs across origins — none of these are RP-side detectable. The browser-vendor
security record is good, but it is not zero; cross-link
[[reference-browser-js-engine-exploitation]] for the broader browser TCB threat model.

### 13.8 The user pressing the button anyway

WebAuthn defeats credential phishing at the protocol layer. It does not defeat a user who
presses the biometric prompt because the social engineering told them to. The phone-side
prompt on a hybrid-transport ceremony shows the RP ID; users who dismiss the prompt
without reading it have authenticated to the attacker. No protocol fixes this; user
training, prompt-design, and time-of-day / unusual-location signals do.

---

## 14. Cross-link cluster

- [[reference-saml-federation]] — broader auth-protocol context (SAML XSW, JWT
  alg-confusion, OAuth, OIDC, SCIM); WebAuthn lives below this layer and is often fronted
  by SAML / OIDC SSO in enterprise deployments.
- [[reference-distributed-authz]] — AuthN vs AuthZ scoping; WebAuthn is AuthN-only and
  does not produce authorization decisions on its own.
- `cryptography_expertise.md` — ECDSA P-256, EdDSA Ed25519, RSA-PKCS1-v1_5 primitives used
  by WebAuthn.
- [[reference-mobile-security]] — iOS Secure Enclave, Android Keystore, StrongBox-backed
  platform authenticator internals.
- [[reference-browser-js-engine-exploitation]] — browser implementation surface; the
  WebAuthn API lives in browser TCB.
- [[reference-post-quantum-cryptography]] — NIST PQC primitives (ML-KEM, ML-DSA, SLH-DSA);
  WebAuthn PQC migration depends on this.
- [[reference-pqc-migration-playbook]] — the migration framework for moving WebAuthn /
  TLS / signing to PQC.
- [[reference-supply-chain-provenance]] — hardware authenticator supply chain, the FIDO
  Metadata Service, hardware-attestation discipline.
- [[reference-detection-engineering]] — runtime detection rule shapes; SIEM-side
  monitoring of WebAuthn signals.
- [[reference-bug-hunting-first-principles]] — first-principles audit lens applied to a
  WebAuthn deployment.
- [[reference-wireless-rf-satellite]] — BLE-layer attacks relevant to caBLE / hybrid
  transport (KNOB, BIAS, BLUFFS).
- [[reference-hardware-side-channels]] — the EUCLEAK side-channel and the broader hardware
  side-channel discipline.
