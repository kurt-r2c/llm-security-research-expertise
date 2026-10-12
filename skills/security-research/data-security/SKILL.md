# Data Security Audit

Audit the codebase for 5 data protection vulnerability classes: credential storage,
key management, data encryption at rest, data transport security, and weak cryptography.

---

## Quick Scope

- Configuration files: `*.env`, `*.json`, `*.yaml`, `*.yml`, `*.toml`, `*.xml`, `*.properties`
- Source files in all languages; focus on files containing `password`, `secret`, `key`,
  `token`, `encrypt`, `hash`, `cipher`, `tls`, `ssl`, `digest`, `sign`
- Database schema and migration files for field definitions
- Logging setup files and log-output call sites
- Dependency manifests (`package.json`, `pom.xml`, `go.mod`, `requirements.txt`, `Gemfile`)
- Secrets manager integration code (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- Infrastructure-as-code and Dockerfile/compose files

Use the Semgrep rule sets `auth_credentials`, `crypto_keys`, `crypto_at_rest`,
`data_transport`, and `crypto_weak` from the `rules/` directory to generate an
initial candidate set, then perform an LLM-native pass over every flagged site to
confirm or dismiss each finding.

---

## Pre-Pass: Sensitive Data Inventory

Before running any data-security check, build a Sensitive Data Inventory across
all data model definitions in the codebase. Checks 1–5 operate on confirmed
sensitive fields from this inventory rather than repeating heuristic field-name
matching inside each check.

**Step 1 — Locate data containers.** Find ORM model definitions, struct and
class definitions, DTO and schema types, and database migration files. Focus on
`models/`, `entities/`, `schema/`, `dto/`, `types/`, `migrations/` and any file
defining a class or struct that persists to a database or is serialized over a
network.

**Step 2 — Extract and classify fields.** For each container, extract field
names and types. Classify each field into one or more sensitivity categories:

| Category | Representative field names | Risk if exposed |
|---|---|---|
| `credential` | `password`, `token`, `secret`, `api_key`, `private_key`, `pin` | Auth bypass, account takeover |
| `pii` | `email`, `phone`, `ssn`, `dob`, `name`, `address`, `passport_number` | Identity theft, regulatory |
| `financial` | `card_number`, `cvv`, `iban`, `bank_account`, `balance`, `stripe_token` | Fraud, regulatory |
| `health` | `diagnosis`, `medication`, `health_condition`, `biometric_hash` | Regulatory, discrimination |
| `linkable_id` | `device_id`, `tracking_id`, `session_id`, `ip_address`, `fingerprint` | Re-identification |

Also flag fields that are sensitive by context even without obvious names
(e.g., a `value` column in a `secrets` table; a `data` field in a
`payment_methods` model).

**Step 3 — Record the inventory.** Produce a compact Sensitive Field Inventory:

```
Sensitive Field Inventory:
- User.password_hash      — credential  — models/user.py:14
- User.email              — pii         — models/user.py:16
- PaymentMethod.card_last_four, .stripe_token — financial — models/payment.py:8
- Session.token           — credential  — models/session.py:22
```

Do not begin Check 1 until the inventory is complete. Each check must reference
confirmed entries from this inventory rather than re-running field-name
heuristics.

---

## Check 1: Credential Storage — Password hashing algorithm

**Find:** Every location where a password or long-term credential is persisted. Look
for calls to hash, digest, or encrypt functions whose output is stored in a database
column, file, or cache. Common patterns:

- `md5(password)`, `sha1(password)`, `sha256(password)`, `hashlib.md5(...)`,
  `hashlib.sha1(...)`, `hashlib.sha256(...)` used on credential input
- `MessageDigest.getInstance("MD5")`, `MessageDigest.getInstance("SHA-1")`,
  `MessageDigest.getInstance("SHA-256")` in Java
- `crypto.createHash('md5')`, `crypto.createHash('sha1')` in Node.js
- `password_hash($password, PASSWORD_DEFAULT)` — verify the constant resolves to bcrypt
  or Argon2, not `PASSWORD_MD5`
- Any call to `base64_encode`, `base64.b64encode`, `Buffer.from(...).toString('base64')`
  on a credential before storage
- `AES.encrypt(password, ...)`, `Cipher.getInstance("AES/ECB/...")` or any symmetric
  cipher applied to a credential before storage

**Evaluate:**

1. Confirm the value being hashed/encoded is a credential (password, PIN, recovery key,
   API secret), not arbitrary data.
2. Classify the algorithm:
   - Non-adaptive hash (MD5, SHA-1, SHA-256, SHA-512) → raise as risk regardless of
     salting; these are not suitable for passwords.
   - Plaintext or base64/hex encoding only → raise as risk.
   - Symmetric encryption (AES, DES, 3DES) → raise as risk; reversibility makes it
     unacceptable for credential storage.
   - Argon2, bcrypt, or scrypt → check cost parameter against project minimum:
     - bcrypt: work factor >= 10
     - Argon2id: memory >= 64 MB, iterations >= 3
     - scrypt: N >= 32768
     - Cost below minimum → raise as risk; cost at or above minimum → pass.

**Severity:** HIGH if a non-adaptive hash or plaintext/base64 encoding is used; HIGH if
symmetric encryption is used; MEDIUM if an adaptive algorithm is used but the cost
parameter is below the project minimum.

**Common false positives:** Non-security hashes of user-supplied data for cache keys or
ETags (no credential involved). Checksums of binary artifacts. `sha256` used for
message integrity rather than password storage — confirm the input is a credential.

---

## Check 2: Key Management — Hardcoded secrets and logging

**Find:** Every location where a secret value appears as a literal in source code or is
written to a log. Look for:

- String literals matching common key patterns: `AIzaSy...` (Google), `sk-...` (OpenAI),
  `AKIA...` (AWS), `ghp_...` (GitHub), `xoxb-...` (Slack), `-----BEGIN RSA PRIVATE KEY-----`,
  `-----BEGIN EC PRIVATE KEY-----`
- Variables named `api_key`, `apiKey`, `secret`, `password`, `token`, `private_key`,
  `client_secret` assigned to string literals
- Configuration files containing plaintext credentials not referenced from a secrets
  manager path (e.g., `password: "hunter2"` in YAML, `SECRET_KEY = "abc123"` in Python)
- Log statements that include secret variables: `log.info("token=" + token)`,
  `console.log(apiKey)`, `logger.debug(f"key={key}")`, `fmt.Printf("secret: %s", secret)`
- Environment variable population without a secrets manager: `os.environ["SECRET"]` or
  `process.env.SECRET` read directly without a call to Vault, AWS SSM, or equivalent
- Long-lived secrets (database passwords, signing keys, API keys) with no rotation
  mechanism visible in the codebase or referenced infrastructure config

**Evaluate:**

1. For each literal value: determine whether the string is a real credential (entropy
   test: >= 20 characters, mixed character classes, no placeholder pattern like
   `your-key-here` or `<REPLACE>`).
2. For each log statement: confirm the variable is actually a secret value, not a
   sanitized placeholder or a log-safe surrogate (e.g., last-4 digits of a card).

   For secrets written to log files: apply the information-disclosure
   actionability check from `../triage/SKILL.md` (Check 8). If the log output
   is accessible only to operators or system administrators who already hold
   equivalent or greater privilege than the secret grants, downgrade the finding
   to MEDIUM. Document the log access path (file permissions, log aggregation
   service access controls, or cloud logging IAM policy) as part of the finding.

3. For environment variable consumption: search the codebase and deployment manifests
   for how the variable is populated. A `.env.example` template is not a risk; a
   committed `.env` with a real value is.
4. For rotation: search for scheduled jobs, TTL configurations, or infrastructure
   rotation policies referencing the secret. Absence of any rotation mechanism for a
   long-lived secret is a risk.

**Severity:** HIGH if a real secret literal is committed to source or config; HIGH if a
secret is written to a log; MEDIUM if a secret is consumed via a raw environment variable
without a secrets manager intermediary; MEDIUM if no rotation mechanism exists for a
long-lived secret.

**Common false positives:** Example or template values explicitly marked as placeholders.
Test fixtures with obviously fake keys. Secrets injected at build time via CI variables
that never appear in committed files. Log statements that print only the key name or a
masked version.

---

## Check 3: Data Encryption at Rest — Unencrypted sensitive fields and co-located keys

**Find:** Every location where PII, payment data, health data, or credentials are
persisted to a database, file system, or object store. Look for:

- ORM model definitions containing fields named `ssn`, `social_security`, `dob`,
  `date_of_birth`, `credit_card`, `card_number`, `cvv`, `iban`, `health`, `diagnosis`,
  `password` (if stored hash is absent), `api_secret` without an `encrypted_` prefix or
  a custom type indicating encryption
- File write operations (`open(..., 'w')`, `fs.writeFileSync`, `FileOutputStream`) for
  sensitive data without a preceding encryption call
- Object storage upload calls (S3 `put_object`, GCS `upload_from_string`) with
  `ServerSideEncryption` absent or set to `None`
- Encryption key material stored in the same database table or file as the data it
  protects (e.g., `encryption_key` column in the same row as `encrypted_value`)
- Key derivation from low-entropy sources: `kdf(hostname)`, `kdf("hardcoded-seed")`,
  `pbkdf2(password, "static-salt", ...)` where the salt is a constant string or
  application configuration value
- Deprecated ciphers for at-rest encryption: `AES/ECB/...`, `DES/CBC/...`,
  `3DES/...`, `RC4`, `Blowfish`

**Evaluate:**

1. Confirm the field or data being written is genuinely sensitive (PII, financial,
   health, or authentication material), not generic application data.
2. For missing encryption: verify there is no transparent encryption layer at the
   infrastructure level (e.g., database TDE, encrypted EBS volume) that would cover
   this gap. If infrastructure encryption exists and is confirmed in IaC, note it but
   still raise field-level encryption absence as MEDIUM.
3. For co-located keys: confirm key and ciphertext are in the same logical store (same
   DB, same file, same S3 bucket with no access separation). A KMS key ARN stored
   alongside ciphertext is acceptable (the ARN is not the key material).
4. For key derivation: confirm the entropy source. A hostname or a fixed string literal
   is low-entropy. A cryptographically random value fetched from a secrets manager is
   acceptable.

**Severity:** HIGH if sensitive data is persisted with no encryption at any layer; HIGH
if key material is co-located with the ciphertext it protects; HIGH if a deprecated
cipher (DES, 3DES, RC4, AES-ECB) is used for at-rest encryption; MEDIUM if a strong
cipher is used but the key is derived from a low-entropy source; MEDIUM if
field-level encryption is absent but infrastructure-level encryption is confirmed.

**Common false positives:** Public or non-sensitive data written without encryption.
KMS key ARNs stored alongside ciphertext. Log files for non-sensitive operational data.
Test fixtures with synthetic data.

---

## Check 4: Data Transport — Authentication and deserialization of remote input

**Find:** Every location where the application receives data over a network connection.
Look for:

- HTTP client calls (`requests.get`, `axios.get`, `http.Get`, `fetch(...)`,
  `HttpClient.execute`) that consume responses without validating the server's TLS
  certificate: `verify=False`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
  `ssl._create_unverified_context()`
- Inbound HTTP endpoints or message queue consumers that read a body and immediately
  deserialize it into an object or struct without authenticating the caller first:
  `json.Unmarshal(body, &obj)`, `ObjectInputStream.readObject()`, `pickle.loads(data)`,
  `YAML.load(input)` (unsafe loader), `Marshal.load(data)` without an authentication
  gate
- WebSocket or raw TCP handlers that accept and trust data from unauthenticated connections
- Webhook endpoints that do not verify a shared secret or HMAC signature before
  processing the payload
- gRPC or Thrift endpoints with `insecure.NewCredentials()` or no transport credentials

**Evaluate:**

1. For TLS verification disabled: confirm the flag is present in production code, not
   only in a test helper or local dev override.
2. For unauthenticated deserialization: trace the request path from the transport
   handler back to the authentication middleware. If authentication is enforced by a
   framework-level guard applied before the handler, it is not a risk. If the handler
   deserializes before any auth check, raise it.
3. For webhook handlers: verify that the handler reads a signature header, recomputes
   the HMAC over the raw body, and performs a constant-time comparison before acting on
   the payload.
4. For deserialization of remote data into objects or structs: even if the transport is
   authenticated, flag it if the deserialized type is a polymorphic or generic container
   (e.g., Java `Object`, Python `Any`, Go `interface{}`) that could trigger gadget chains.

**Severity:** HIGH if TLS certificate verification is disabled in production code; HIGH
if an unauthenticated endpoint deserializes remote data into an object or struct; HIGH
if a webhook processes payloads without HMAC signature verification; MEDIUM if
authenticated transport deserializes into a polymorphic type without type constraints.

**Common false positives:** `InsecureSkipVerify` in test files or integration test
helpers that target localhost. `pickle.loads` in offline data-pipeline scripts with no
network-sourced input. gRPC `insecure` credentials used only on a loopback inter-service
channel behind a service mesh that provides mTLS.

---

## Check 5: Weak Cryptography — Broken algorithm usage

**Find:** Every location where a cryptographic algorithm is selected by name. Look for:

- Hash functions: `md5`, `sha1`, `SHA-1`, `MD5`, `MessageDigest.getInstance("MD5")`,
  `MessageDigest.getInstance("SHA-1")`, `hashlib.md5`, `hashlib.sha1`,
  `crypto.createHash('md5')`, `crypto.createHash('sha1')`
- Symmetric ciphers: `DES`, `3DES`, `TripleDES`, `RC4`, `Cipher.getInstance("DES/...")`,
  `Cipher.getInstance("DESede/...")`, `RC4` stream cipher instantiation
- Block cipher mode: `AES/ECB/`, `Cipher.getInstance("AES/ECB")`, `mode=ECB`,
  `AES.new(key, AES.MODE_ECB)`
- RSA key generation: `RSA.generate(1024)`, `RSA.generate(512)`,
  `KeyPairGenerator.getInstance("RSA")` followed by `initialize(1024)` or smaller
- ECDSA/ECDH curves: `secp112r1`, `sect113r1`, `prime192v1`, `secp160r1` (curves below
  256 bits)

**Evaluate:**

1. Confirm the algorithm is used for a security-sensitive purpose: confidentiality,
   integrity protection, authentication, digital signing, or key derivation. MD5 used
   to generate a cache key for a non-security purpose is lower priority (flag as MEDIUM).
2. For MD5 and SHA-1: raise as a risk for any security-sensitive use. Document the
   specific purpose (integrity, authentication, signature, password hashing).
3. For DES, 3DES, RC4: raise as a risk for any encryption use regardless of context.
4. For ECB mode: raise as a risk for any block cipher use. ECB reveals plaintext block
   patterns regardless of the underlying cipher strength.
5. For RSA: raise as a risk if key size is below 2048 bits.
6. For each finding, record: location, algorithm name, purpose (confidentiality,
   integrity, or authentication).

**Severity:** HIGH if MD5 or SHA-1 is used for authentication or digital signatures;
HIGH if DES, 3DES, or RC4 is used for encryption; HIGH if AES-ECB is used for
encryption of sensitive data; HIGH if RSA key size is below 2048 bits; MEDIUM if MD5
or SHA-1 is used for integrity checks on non-authentication data; MEDIUM if MD5 is
used as a cache key or non-security identifier.

**Common false positives:** MD5 or SHA-1 computed for compatibility with a third-party
protocol specification that mandates the algorithm (document the constraint). CRC32 or
Adler-32 used for non-security checksums. Format-detection magic bytes compared with
a SHA-1. Git object IDs (not a security primitive).

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading a data-security
finding without completing the full evidence chain:

- **"The secret is in an env var"** does not mean it is unexposed — trace how
  the variable is populated and whether its value appears in committed `.env`
  files, CI logs, Dockerfile layers, or deployment manifests.
- **"It's hashed"** does not mean the algorithm is acceptable — identify the
  specific hash function and confirm it is an adaptive password-hashing algorithm
  (bcrypt, Argon2id, scrypt) before closing a credential-storage finding.
- **"The key is rotated periodically"** does not resolve a hardcoded-credential
  finding — confirm the literal value in the codebase cannot be used to access
  any current or recently valid production resource.
- **"TLS is enforced at the load balancer"** does not cover `InsecureSkipVerify`
  or `verify=False` in outbound client calls — those flags affect the client's
  own certificate validation, not what the load balancer does for inbound traffic.

## Output Format

For each confirmed finding:

- **[DATA-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code or config showing the pattern
- **Purpose:** the security-sensitive purpose the algorithm or storage mechanism serves
- **Impact:** what an attacker gains (e.g., offline cracking of passwords, decryption
  of ciphertext, credential theft from logs)
- **Fix:** specific remediation (e.g., "Replace `hashlib.md5` with `argon2.hash` with
  memory_cost=65536, time_cost=3"; "Move secret from `.env` to AWS Secrets Manager and
  reference via `boto3.client('secretsmanager').get_secret_value`")

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "DATA",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For data security findings the most dispositive checks are:
cryptographic-weakness actionability (apply the prerequisite-severity check for weak
crypto — confirm the algorithm is reachable in production and serves a security-sensitive
purpose), credential validity (for hardcoded secrets — verify the secret value is real
and unexpired before escalating), and information-disclosure actionability (for secrets
in logs — confirm the log output is reachable by an attacker who does not already hold
the secret).
