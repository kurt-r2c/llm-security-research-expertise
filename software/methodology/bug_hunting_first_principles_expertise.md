# Bug-Hunting First Principles — Operational Doctrine

This doc is the prioritization doctrine that runs across all four canonical VR methods (code review, variant analysis, fuzzing, patch diffing — see [[reference-vr-methodology]]). When approaching a target, follow this doctrine to produce a ranked bug-hypothesis list before opening an editor.

Audience: Claude when bug-hunting on a target. Register: directive and operational. Anchor: Kurt Boberg's first-principles north star (§1, verbatim).

---

## 1. The doctrine statement

> First principles is always how you look for bugs. Figure out what the system does — what does it have that's valuable? It's always looking around for injection issues — compute is always useful. From there, first use the language features: what is potentially dangerous or interesting? How does a program in that language interact with file systems? Access control lists? Network requests? Command shells? Complex serialization? This produces a list of "hotspots" in conjunction with "what information does this system have access to" to make a priority list of bugs. E.g. a SPA with a NoSQL db and a PHP frontend talking to an ORM is worth checking for: classical webshell pvp eval bugs, NoSQL injection, DOM-based XSS, broken or missing authentication, broken or missing authorization, and PHP serialization bugs. Generally we assume denial of service is a universal condition to watch for: this is as much a reliability concern as a security concern. We only care if the approach is highly asymmetric in nature: a small number of inputs or requests must cause the outage condition. Zero-click vulnerabilities are always more interesting than N-click vulnerabilities (from a human user). N-clicks that are entirely agentic *may* be considered 0-click *if* there is a plausible explanation for missing HITL.

— Kurt Boberg

This is the prioritization doctrine that runs *across* the four canonical VR methods catalogued in [[reference-vr-methodology]] (code review, variant analysis, fuzzing, patch diffing). The VR-methodology doc tells you *how* to look; this doc tells you *what* to look at and *in what order*. Read both. The two compose: first-principles produces the bug-hypothesis list, the VR method produces the evidence.

Use this doc as a checklist when approaching a new target. Do §2 before §3 before §4 before §5 — the order is load-bearing, not stylistic. Skipping ahead means prioritizing without knowing what's valuable, which means optimizing the search loop for the wrong objective.

---

## 2. First principles — what does the system do and what's valuable?

Before you read a line of code, answer three questions about the target. You cannot prioritize what you have not characterized.

### (a) What does the system *compute*?

Compute is the universal target. Every program that takes input and produces output is, at some layer, an interpreter. The interpreter may be obvious (a SQL engine, a template renderer, a YAML parser, a shell, an LLM) or hidden (a routing table that interprets headers, a permission system that interprets identity tokens, a config file that interprets environment variables). Enumerate the interpreters before anything else. Every interpreter is a candidate point for injection per §3.

Specifically, ask:
- What inputs does the system accept, and where do they come from?
- What language-like operations does the system perform on those inputs — concatenation, evaluation, parsing, deserialization, template-substitution, command-construction, query-building, path-resolution?
- Where do user-controlled values reach an interpreter without intermediate structural typing?

### (b) What does the system *have*?

The asset inventory. List, by name, what the target has access to that an attacker would want:
- **Data assets:** customer DB rows, source code, model weights, training data, telemetry, logs, scan findings.
- **Credentials:** AWS/GCP/Azure keys, SSH keys, OAuth tokens, signing keys (cosign / Apple / Authenticode), GitHub PATs / App private keys, internal service tokens, session secrets.
- **Authority over other systems:** ability to push to a registry, merge a PR, deploy a release, post to a queue, write to a shared bucket, call an internal API with elevated identity, sign a release artifact.
- **Compute capacity:** GPU minutes, CI runner hours, paid-API quotas (LLM tokens, payment-processor capacity).

Assets you cannot name, you cannot prioritize against. Spend disproportionate effort on this step.

### (c) What does the system *trust*?

Map the trust boundaries. For each input source, write down whether the target treats it as authoritative:
- User input via the public HTTP API — typically untrusted, but check.
- Webhooks from third parties — partial trust; signature-verified or not?
- Internal-RPC inputs — frequently mistreated as trusted; this is the perimeter / east-west asymmetry.
- Filesystem inputs from disk — trusted unless the disk is a shared mount or the file was placed there by an untrusted process.
- Environment variables — trusted by default, often mistaken.
- Compiler / build inputs — trusted by default, the supply-chain class.
- Outputs of other services in the same deployment — implicitly trusted; usually wrong (see Comment-and-Control class in §9).

The output of §2 is a one-page mental inventory: *the interpreters, the assets, the trust map*. Without it you cannot run §5.

---

## 3. Compute as the universal target — injection is always the first lens

Aphorism: every program is an interpreter; every interpreter has a syntax; every syntax has a way to break out of data into code.

When a system has compute and an attacker can inject into that compute, the attacker wins. Everything else is downstream. Therefore: enumerate every place an external input is consumed by an interpreter, and treat each as a candidate point until eliminated.

Injection, broadly defined, is any input that crosses a trust boundary and is interpreted as one of:

- **Code** — `eval` / `exec` / `Function()` / `new Function` / Python `compile`, scriptable engines (SpEL, OGNL, MVEL, JEXL), template-engines that allow code (Jinja2 `{% %}`, Velocity, Freemarker, ERB). See [[reference-template-code-injection]] for the engine-by-engine reach map.
- **Query** — SQL, NoSQL (Mongo `$where`, `$regex`), GraphQL, LDAP, XPath, Cypher, SPARQL. Per-dialect quirks live in `software/language-footguns/sql_dialect_footguns_expertise.md` (Postgres `COPY FROM PROGRAM`, MSSQL `xp_cmdshell`, etc.).
- **Command** — shell argv (CWE-78 metachar / CWE-88 argv-injection / CWE-150 terminal-escape). The three-class split matters: `escapeshellcmd`-strength sanitizers stop CWE-78 but pass CWE-88. See [[reference-shell-injection]].
- **Format string** — `printf`-family in C, `%n` write primitive, `String.format` indirect leaks, log injection. See `software/language-footguns/c_cpp_footguns_expertise.md`.
- **Deserialized object** — pickle / Marshal / Java Serialization / Jackson polymorphic / PHP `unserialize` / .NET `BinaryFormatter` / Ruby `Marshal.load` / YAML constructors / JSON with prototype-keys. See `software/vuln-classes/deserialization_expertise.md` and [[reference-prototype-pollution]] for the `__proto__` class.
- **Path** — directory traversal, `path/filepath.Join` quirks, Zip Slip, tarfile filter, archive-extraction-into-arbitrary-location.
- **Parser-differential** — XML / SAML / HTML / JSON / YAML / URL / HTTP-header. See [[reference-xml-parser-differential]] for XXE + SAML XSW; [[reference-ssrf-url-parsing]] for URL parser differentials (Orange Tsai taxonomy).
- **Prompt** — direct + indirect prompt injection into LLM contexts; tool-use surface in MCP / agentic loops. See [[reference-llm-agent-security]].

Operational rule: when you find a place where any of the above categories applies, write the bug hypothesis down before you go looking for the next one. The hypothesis is concrete and falsifiable: "input X at line Y, interpreted as Z, can be made to escape its data context by W." Then run the §5 priority calc against it.

---

## 4. Language-feature dangerous-primitive enumeration

The five primitive categories Kurt names in the doctrine. For each, ask: how does *this* language's idiomatic API for this primitive behave by default, and where does the default leak attacker-controllable state into a privileged operation?

### (a) Filesystem operations

What to enumerate: open / read / write / unlink / glob / rename / `os.path.join` family / archive-extraction / symlink-following / temp-file creation / `chmod` and `chown` with attacker-influenced paths.

Per-language footgun docs (read before authoring a hypothesis on a file in that language):
- Python — `software/language-footguns/python_footguns_expertise.md` (tarfile filter, `pathlib` path traversal, `shutil.copytree`, `tempfile.mktemp` race).
- Java — `software/language-footguns/java_footguns_expertise.md` (Zip Slip, `Files.copy` follow-symlinks default, `File.createTempFile` permissions).
- Ruby — `software/language-footguns/ruby_footguns_expertise.md` (`File.open` mode-string quirks, `Tempfile` permissions).
- Go — `software/language-footguns/go_footguns_expertise.md` (`path/filepath.Join` cleaning, `os.OpenFile` mode bits, `archive/tar` traversal).
- Node — `software/language-footguns/javascript_node_footguns_expertise.md` (`fs.realpath` symlink resolution, missing `O_NOFOLLOW`, `tar` package extraction).
- C/C++ — `software/language-footguns/c_cpp_footguns_expertise.md` (`open`/`openat` flag mistakes, `O_NOFOLLOW`, `RESOLVE_BENEATH`).
- Rust — `software/language-footguns/rust_footguns_expertise.md` (`std::fs::canonicalize` semantics, `tar` crate defaults).

The TOCTOU class lives here too: any pattern that `stat`s a path then operates on it has a race window. See [[reference-race-conditions-concurrency]] for the canonical primitives (openat2 `RESOLVE_BENEATH`, Kettle single-packet attack, filesystem-race exploitation).

### (b) Access control lists

Local file permissions, K8s RBAC, IAM policies, DB `GRANT`, `sudoers`, Linux capabilities, Windows ACLs, AWS resource policies + SCPs, Entra app-registrations + delegated/application permissions.

Cross-links:
- [[reference-distributed-authz]] for the anti-pattern catalog (CWE-287 / CWE-306 / CWE-308 / CWE-862 / CWE-863 mapping, Zanzibar model, missing-authz primitive).
- [[reference-cloud-iam]] for the AWS 5-policy-evaluation order, `iam:PassRole` privesc, Entra OAuth-consent abuse, GCP Workload Identity Federation.
- [[reference-container-k8s-security]] for pod-level RBAC, service-account-token mounting, NetworkPolicy gaps.

Operational rule: if the target enforces *any* authz check, ask "what is the precondition stack to reach the check, and does any unauthenticated path reach the data the check guards?" See `code_review_expertise.md` click-count severity for the operational form.

### (c) Network requests

Two sub-classes: outbound (the target makes a request the attacker influences) and inbound (the target accepts a request and routes it).

- **Outbound** — SSRF, blind SSRF, DNS rebinding, gopher pivot, cloud metadata service (IMDSv1 vs v2), in-cluster service mesh. See [[reference-ssrf-url-parsing]].
- **Inbound** — HTTP header smuggling, request smuggling (TE/CL ambiguity), HTTP/2 desync, CORS misconfiguration, CSRF + SameSite defaults, auth-bypass via path normalization. See [[reference-http-web-security]].

Don't forget: webhook signature verification (HMAC timing-safe-compare, replay protection, body-canonicalization mismatch).

### (d) Command shells

`system()` / `exec()` / `Runtime.exec` / backticks / `subprocess` / `child_process.spawn` / `os.system` / Powershell `Invoke-Expression` / Ruby `Kernel#system` / Perl backticks.

See [[reference-shell-injection]] for the three-class CWE-78/88/150 taxonomy. Critical distinction: argv-array invocation (CWE-88) is *not* equivalent to shell-string invocation (CWE-78). Sanitizers that protect against one frequently fail at the other. `escapeshellcmd` is a documented example of this weakness (per `feedback_escapeshellcmd_weak_sanitizer.md`).

Don't forget: argument-injection on binaries with `--option=value` or `--option value` forms (curl `-K @file`, `git --upload-pack`, ssh `-oProxyCommand`, find `-exec`). The per-binary dangerous-flag catalog is in [[reference-shell-injection]].

### (e) Complex serialization

The single most reliable RCE-primitive class in the post-Java-Serialization decade.

Per-format reach:
- Java — `ObjectInputStream.readObject` + ysoserial gadgets; Jackson polymorphic + `@JsonTypeInfo`; Fastjson `autoType`; XStream.
- Python — `pickle.loads` + `__reduce__` gadgets; `yaml.load` (not `yaml.safe_load`); `marshal.loads`.
- PHP — `unserialize` + magic methods (`__wakeup`, `__destruct`, `__toString`); Phar deserialization via filesystem operations (pre-PHP 8.0); `php://filter` chain RCE.
- .NET — `BinaryFormatter` (deprecated but present); `LosFormatter` ViewState; `SoapFormatter`; `Json.NET` with `TypeNameHandling != None`.
- Ruby — `Marshal.load`; `YAML.load` with object instantiation; `Oj.load` default mode (vakzz universal-gadget chain adapted to Oj by GitHub Security Lab).
- JS / Node — `JSON.parse` with `__proto__` ([[reference-prototype-pollution]]); `node-serialize` (eval-on-deserialize by design).

Cross-link: `software/vuln-classes/deserialization_expertise.md` is the canonical primary. The per-language footgun docs catalog the language-specific entry points. When you find a deserialization sink on attacker-controlled bytes, the hypothesis is automatic.

### (f) Per-language grep-first quick reference

The five axes above are organized by primitive class. When you arrive at a target written in a specific language, the more useful framing is "what is the grep list for this language." This section is the actionable bridge between the §3 / §4 primitive catalog and the per-language footgun docs in [[reference-language-footguns-class]]. Run the per-language grep pass before reading any code; the grep output is the candidate-point list for §5's matrix.

**Python.** Filesystem: `tarfile.extract*` without `filter=`, `os.path.join` with attacker input, `tempfile.mktemp`. Network: `urllib`/`requests` with `verify=False`. Command shells: `subprocess(shell=True)`, `os.system`, `os.popen`. Complex serialization: `pickle.loads`, `yaml.load` (not `safe_load`), `marshal.loads`, `jsonpickle.decode`. Compute: `eval`, `exec`, `__import__`, `compile`, Jinja2 sandbox-escape via `__subclasses__`. Grep first: `pickle\.loads|yaml\.load\b|subprocess.*shell=True|eval\(|exec\(|tarfile\.extract`.

**JavaScript / Node.** Filesystem: `fs.readFile` on attacker path, archive extractors without traversal validation. Network: `fetch`/`http.request` with redirect-follow leaking auth, `dns.lookup` rebinding. Command shells: `child_process.exec`, `child_process.spawn({shell: true})`, `execSync`. Complex serialization: `node-serialize`, `JSON.parse` with reviver injection. Compute: `eval`, `new Function()`, `vm.runInNewContext` (sandbox illusion — see [[reference-js-sandbox-escape]]), `require()` with computed string. Prototype-pollution surface: `_.merge`, `_.set`, `Object.assign` with attacker-keyed source — see [[reference-prototype-pollution]]. Grep first: `eval\(|new Function|child_process.*shell|vm\.runIn|require\(.*\$\{|_\.merge\(|Object\.assign\(.*req\.`.

**Java.** Filesystem: Zip Slip in `ZipEntry.getName()` consumers, `Files.copy` symlink-following. Network: `URL.openConnection` default redirect handling, custom trust-all `HostnameVerifier`. Command shells: `Runtime.exec(String)` (tokenizes on whitespace, not argv-safe), `ProcessBuilder` with string-joined args. Complex serialization: `ObjectInputStream.readObject` (ysoserial gadget universe), Jackson `@JsonTypeInfo`, Gson polymorphic, Fastjson `autoType`, XMLDecoder. JNDI / lookup: `InitialContext.lookup` with attacker URL (Log4Shell class). Compute: `Class.forName` + `newInstance`, `ScriptEngineManager`, SpEL `parser.parseExpression`, OGNL / MVEL / JEXL. XXE-by-default: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`. Grep first: `ObjectInputStream|readObject\(|@JsonTypeInfo|InitialContext\.lookup|Runtime\.exec|XMLDecoder|ScriptEngine|parser\.parseExpression`.

**PHP.** Filesystem: `include`/`require` with attacker variable (LFI/RFI), `file_get_contents` with `php://filter` chain (Synacktiv 2022 RCE via base64+convert.iconv chains). Command shells: `system`, `exec`, `shell_exec`, backticks, `passthru`, `popen`. `escapeshellcmd` is metachar-only, not argv-safe (per `feedback_escapeshellcmd_weak_sanitizer.md`). Complex serialization: `unserialize` (universal gadget surface via `__wakeup`/`__destruct`/`__toString`), Phar deserialization (pre-PHP 8.0, any filesystem op on a `phar://` URL triggers unserialize). Compute: `eval`, `assert` (string-eval pre-8.0), `preg_replace /e` (legacy), `create_function` (removed 8.0), variable variables `$$var`, `extract($_REQUEST)`. Type juggling: `==` magic-hash collisions (`0e...` strings), `in_array` without strict mode. Grep first: `unserialize\(|eval\(|assert\(.*\$|extract\(|preg_replace.*['\"][^'\"]*e['\"]|include.*\$|\$\$`.

**Ruby.** Filesystem: `File.open` traversal, `open-uri` accepting both `http`/`https` AND local-file paths (SSRF + LFI conflation). Command shells: `system`, backticks, `IO.popen`, `Kernel#exec`, `%x{}`, `open("|cmd")` — the pipe-to-open is the historic Rails footgun. Complex serialization: `Marshal.load` (universal Ruby gadget surface), `YAML.load` (Psych < 4.0 unsafe), `Oj.load` default mode (vakzz universal-gadget chain adapted to Oj — class reach via `^o` directive). Compute: `eval`, `instance_eval`, `class_eval`, `binding.eval`, `send`/`public_send` with attacker method name, `const_get` with attacker class name, ERB template injection. Rails specifics: `where(attacker_str)`, `order(attacker_str)`, mass assignment, `raw`/`html_safe` in views. Grep first: `Marshal\.load|YAML\.load[^_]|Oj\.load|eval\(|instance_eval|send\(.*params|raw\s+|html_safe|where\(.*\#\{`.

**Go.** Filesystem: `filepath.Join` (does NOT prevent traversal; `filepath.Clean` does not validate root). Network: `net/http.Client` with no `Timeout` (default is unbounded — the textbook Go footgun), `DefaultServeMux` registration collision. Command shells: `exec.Command(cmd, args...)` is argv-safe; `exec.Command("sh", "-c", attacker)` is not. The grep is for the second form. Complex serialization: `encoding/gob.Decoder` (type registration confusion), `encoding/json.Unmarshal` into `interface{}`, `encoding/asn1` parser surface. Compute: Go has no eval (which removes a class of bugs); the replacement surface is `text/template` and `html/template` with attacker-controlled template body (SSTI), and `cgo` boundaries with unsafe.Pointer. Grep first: `exec\.Command\("sh"|filepath\.Join.*request|http\.Client\{\}\s*$|gob\.Decoder|text/template.*Parse.*req`.

**C / C++.** Filesystem: `open` followed by `fstat` (TOCTOU is the dominant class — use `openat2` with `RESOLVE_BENEATH` on Linux), `tmpnam` / `mktemp` (deprecated). ACLs: `setuid` family ordering — `setreuid`/`setresuid` are the safe primitives; `setuid` alone is not. Network: `gethostbyname` (no IPv6, blocking, deprecated), `inet_aton` 0-padded octet quirks, raw `recv`/`recvfrom` without length validation. Command shells: `system()`, `popen()`. Both invoke `/bin/sh -c`. Always. Complex serialization: ASN.1 parsers (Heartbleed adjacent), `boost::archive::text_iarchive`. Compute / memory: the UB master class — signed overflow, strict aliasing, null deref, uninit memory; banned string primitives `strcpy`/`gets`/`sprintf`; format strings `%n`/`%s`; malloc/new lifecycle (UAF / double-free); iterator invalidation in C++. Modern mitigations: ASLR/CFI/PAC/MTE/CET/CHERI. Grep first: `strcpy\(|sprintf\(|gets\(|system\(|popen\(|memcpy\(.*sizeof|free\(.*\);.*free\(|setuid\(`.

**Rust.** Filesystem / ACLs / network: relatively few defaults-unsafe primitives; the language's safety story holds up here. The audit surface is the `unsafe` block. The block boundary is the soundness contract; bugs are almost always inside `unsafe` or at the boundary between `unsafe` and safe code. Complex serialization: `serde_json` is generally safe. Custom `Deserialize` impls that call `unsafe { transmute(...) }` are the bug shape. Compute: `mem::transmute` (type punning across non-matching layouts), `Box::leak` / `mem::forget` / `ManuallyDrop` lifetime escapes, `MaybeUninit` misuse, FFI boundary bugs. Grep first: `unsafe\s*\{|transmute|forget\(|Box::leak|extern\s+["']C["']`.

**PowerShell.** Compute: `Invoke-Expression` / `iex`, `ScriptBlock::Create`, `Add-Type` with attacker source, `[scriptblock]::Create`. Execution-policy bypass shape: `-EncodedCommand <base64>`. Complex serialization: CLIXML deserialization (`Import-Clixml`, PSRemoting serialized objects) — full .NET type instantiation surface. AMSI / Constrained Language Mode: bypasses exist; the bug-hunter's audit is for reflection-based unloads (`amsiInitFailed`-style patches). Network / filesystem: `Invoke-WebRequest` redirect-follow, `Out-File` UTF-16-BOM defaults causing escape-bypass on downstream parsers, `Set-Acl` race. Grep first: `Invoke-Expression|iex\s|Add-Type|ScriptBlock::Create|Import-Clixml|-EncodedCommand`.

**Shell (bash/zsh/sh).** IFS / word-splitting: unquoted variable expansion is the universal injection primitive. `cmd $var` is bug-shaped; `cmd "$var"` is not. Any `eval "$var"` with attacker influence on `$var` is RCE. Missing `set -euo pipefail` on most production scripts; `-u` catches half the injection bugs by accident. Shellshock-class: function-export envvar injection (CVE-2014-6271) still shows up in CGI-shaped contexts. Glob expansion: `rm $files` with attacker filename `-rf` becomes `rm -rf`. See `software/language-footguns/shell_footguns_expertise.md` for the broader catalog and the per-shell quirks (macOS bash-3.2 array semantics, zsh prompt-expansion CVE-2021-45444). Grep first: `eval\s+["'\$]|\$\w+[^"]|read\s+\w+(\s|$)|<\$\(|\| sh`.

The pattern: on a multi-language target, run the grep pass per language before reading any code. The output goes into §5's matrix as rows; the §2(b) inventory provides the columns.

---

## 5. The hotspot × information-access matrix

This is the doctrine's load-bearing operational tool. A 2-D matrix:

- **Rows** = hotspots from §4 instantiated against the target's actual language stack and framework choices.
- **Columns** = information-access / asset categories from §2(b).
- **Cells** = bug hypotheses with a priority score.

Cell priority is `hotspot_likelihood × asset_value_if_compromised`. Likelihood is a function of how idiomatic the unsafe primitive is in the target's framework and how strongly the framework discourages it. Asset value is the §2(b) inventory.

### Worked example — Kurt's SPA + NoSQL + PHP + ORM stack

Inventory output (§2):
- *Computes:* PHP request handling, ORM query construction, NoSQL document evaluation, SPA DOM rendering, session cookie verification.
- *Assets:* user PII in DB, application secrets in PHP `.env`, session tokens, possibly outbound API keys.
- *Trust:* HTTP request body / query / cookies = untrusted; ORM input = author treats as semi-trusted (frequently wrong); NoSQL `$where` = author treats as trusted (always wrong).

Hotspot list (§4):
- PHP `unserialize` on cookie / session / cache-fetched bytes.
- PHP `eval` / `assert(string)` / `create_function` / `preg_replace /e` (legacy).
- NoSQL operator injection (`$where`, `$regex`, `$function`).
- DOM-based XSS via SPA `innerHTML` / `dangerouslySetInnerHTML` / Vue `v-html`.
- Missing/broken authentication on PHP endpoints (`isset($_SESSION['user_id'])` only, no rotation, no MFA gate).
- Missing/broken authorization (BOLA on `/api/users/:id`).

Matrix top-5 hypotheses ranked:

| # | Hotspot | Asset | Priority |
|---|---------|-------|----------|
| 1 | PHP `unserialize` on session/cache | App-secrets + PII | CRITICAL (RCE → secrets) |
| 2 | Missing authz on `/api/users/:id` (BOLA) | PII | HIGH (direct PII exposure, unauthenticated/low-priv) |
| 3 | NoSQL `$where` injection on search endpoint | PII + auth-bypass | HIGH (auth-bypass or PII enum) |
| 4 | DOM XSS via SPA `v-html` on user-content | Session tokens | HIGH (session theft chain to ATO) |
| 5 | PHP `eval`-class legacy in admin tool | App-secrets | MEDIUM if admin-gated, HIGH if reachable pre-auth |

This is the artifact the doctrine produces. It is *not* a finding list — it is a hypothesis-ranking. Each row is now a falsification target for one of the four VR methods in [[reference-vr-methodology]]: code review for #1, #2, #5; manual fuzzing for #3; runtime testing for #4.

Re-rank when new context arrives. If §2(b) discovers the host has AWS credentials in the IMDS, every RCE hotspot's asset value jumps an order of magnitude. The matrix is rebuilt cheaply once the inventory is in your head.

---

## 6. Per-stack worked examples

The doctrine becomes concrete on real stacks. For each below: (a) inventory; (b) hotspots; (c) top-5 hypotheses.

### Go gRPC + Postgres

(a) Inventory:
- *Computes:* gRPC request unmarshalling (protobuf), Postgres query construction (`pgx` or `database/sql`), JSON column manipulation, internal RPC fan-out.
- *Assets:* DB rows, internal service tokens, possibly Postgres `pg_execute_server_program` via SUPERUSER if misconfigured.
- *Trust:* gRPC clients in production typically authenticated via mTLS, but internal-east-west often trusted blindly.

(b) Hotspots: SQL via `fmt.Sprintf` instead of parameterized queries; missing authn on internal gRPC endpoints; missing context.Context propagation enabling DoS via slow clients; `os/exec` with user-influenced args; goroutine leaks producing memory-exhaustion DoS; nil-interface-vs-nil-pointer panics on parsed protobuf.

(c) Top-5:
1. SQL injection via `fmt.Sprintf` in any non-parameterized query — CRITICAL if reaches a Postgres SUPERUSER role.
2. Missing authn on internal gRPC service that routes user data — HIGH if reachable from any pod.
3. SSRF via outbound `http.Client` without timeouts/redirect-cap on attacker-influenced URLs — HIGH.
4. Asymmetric DoS via unbounded `make([]T, n)` where `n` is attacker-controlled (§7 gate) — MEDIUM unless input is from public path, then HIGH.
5. Argument injection on `exec.Command` if used with `bash -c` shell-string form — MEDIUM-HIGH depending on what the binary is.

### Node + React + MongoDB

(a) Inventory:
- *Computes:* Express/Fastify routing, MongoDB query building, React DOM rendering, JWT verification, third-party SDK calls.
- *Assets:* session secrets in `.env`, MongoDB connection string, payment-processor keys, customer data.
- *Trust:* `req.body` / `req.query` / `req.params` = untrusted; cookies = signed, verify before trust; environment = trusted.

(b) Hotspots: prototype pollution on Express middleware merging `req.body` into config; NoSQL injection on `find({ user: req.body.user })` where `req.body.user` is an object (`{$ne: null}` bypass); DOM XSS via `dangerouslySetInnerHTML`; SSRF via `axios.get(req.body.url)`; missing authz via direct ID lookups; JWT alg-confusion if verifier accepts `none` or `HS256` with public-key-as-secret.

(c) Top-5:
1. NoSQL injection via untyped `req.body` reaching `find` / `update` — CRITICAL when reaches auth path (login bypass via `{$ne: null}`).
2. Prototype pollution via deep-merge of `req.body` into config object — HIGH (RCE on common gadgets, see [[reference-prototype-pollution]]).
3. SSRF via `axios`/`fetch` on user-supplied URL → cloud metadata / internal services — HIGH.
4. Missing authz: BOLA on `/api/orders/:id` returning anyone's order — HIGH.
5. DOM XSS via React `dangerouslySetInnerHTML` on user content — MEDIUM-HIGH (session theft chain).

### Python ML pipeline + Pickle + S3

(a) Inventory:
- *Computes:* model loading (`pickle.loads` / `torch.load` / `joblib.load`), feature engineering, S3 fetch + upload, training-job orchestration.
- *Assets:* model weights, training data, S3 bucket (multi-tenant?), GPU-runner identity, possibly an IAM role with `s3:*` on a shared bucket.
- *Trust:* model artifacts on S3 = author treats as trusted (frequently wrong if multi-tenant or community-uploaded); user-supplied feature inputs = untrusted; SageMaker / Kubeflow control-plane = trusted.

(b) Hotspots: `pickle.loads` on any S3 object the attacker can influence (model-upload, dataset-upload, cache); `numpy.load(allow_pickle=True)`; `torch.load` legacy without `weights_only=True`; `joblib.load`; arbitrary-code execution via custom `__reduce__` gadgets; SSRF via training-job URL parameter; supply-chain via pip-install of attacker package.

(c) Top-5:
1. `pickle.loads` on model artifact attacker can influence — CRITICAL (RCE on GPU runner, IAM-role theft, lateral to other tenants).
2. `torch.load` without `weights_only=True` on Hugging Face download — CRITICAL (same shape, broader corpus of attacker uploads).
3. SSRF via training-job webhook → IMDSv1 on EC2 GPU instance → role theft — HIGH.
4. Pip-install of attacker package via typo / dependency-confusion in `requirements.txt` — HIGH (supply-chain to GPU runner).
5. Asymmetric DoS via unbounded `numpy.load` of a tiny ZIP-bomb pickle — MEDIUM unless reachable pre-auth.

### Java Spring + Kafka

(a) Inventory:
- *Computes:* Spring MVC routing, Spring Data JPA query construction, Jackson deserialization, Kafka consumer record handling, SpEL evaluation in `@Value` / `@PreAuthorize`, JNDI lookups via `InitialContext`.
- *Assets:* DB rows, Kafka topic contents, internal-service mTLS certs, possibly OIDC client-secrets for downstream service calls.
- *Trust:* HTTP request = untrusted; Kafka record = author frequently treats as trusted (wrong — anything producing to the topic).

(b) Hotspots: Spring4Shell DataBinder mass-assignment; Jackson polymorphic deserialization on `@JsonTypeInfo`; SpEL injection in `@PreAuthorize("hasPermission(#input)")`; Log4Shell-class JNDI on any log line that includes attacker-controlled string; Kafka record consumer that deserializes untrusted bytes; HTTP path traversal in static-resource handler.

(c) Top-5:
1. Jackson polymorphic deserialization with `@JsonTypeInfo(use=Id.CLASS)` on attacker-controlled JSON — CRITICAL (RCE).
2. SpEL injection in `@PreAuthorize` / `@PostAuthorize` annotations with user input — CRITICAL (RCE + authz bypass).
3. Spring4Shell mass-assignment on a controller that binds `Class` — HIGH-CRITICAL depending on Java/Tomcat version.
4. Kafka consumer of attacker-influenced topic with `ObjectInputStream.readObject` — HIGH.
5. JNDI lookup via Log4j2 in log line — HIGH if pre-mitigation version is reachable.

### CI-runner agent: GitHub Actions workflow + reusable composite action

(a) Inventory:
- *Computes:* shell evaluation of `${{ }}` template expressions, Docker container exec, registry token usage, Git checkout of PR head SHA.
- *Assets:* `GITHUB_TOKEN` (repo write or admin), org / OIDC sub-claim, secrets in workflow environment, release-signing keys if release workflow.
- *Trust:* `pull_request` event = untrusted (forked PR); `pull_request_target` = elevated context but still untrusted body; `issues` event = untrusted body; `schedule` = trusted; `workflow_run` = elevated but triggered by untrusted parent.

(b) Hotspots: `pull_request_target` checking out PR HEAD then running build (`pwn_request`); `${{ github.event.* }}` interpolation into `run:` (shell-injection in YAML); cache-poisoning across PR boundary; mutable tag references for third-party actions; AI-bot reading issue/PR body with tool-use authority (Clinejection class — see §9 + `software/supply-chain/cicd_supply_chain_expertise.md` §2.9).

(c) Top-5:
1. `pull_request_target` + checkout-PR-head + run-build → arbitrary code in privileged context — CRITICAL ([[reference-cicd-supply-chain]] §2.1).
2. Shell-injection via `${{ github.event.pull_request.title }}` in a `run:` block — HIGH.
3. AI-bot in `claude-code-action` / Cursor / Copilot Workspace reading attacker-controlled text with tool-use authority — HIGH (Clinejection, Comment-and-Control).
4. Cache poisoning via PR setting cache key that the protected branch reuses — HIGH.
5. Unpinned third-party action (`@v1` tag) on a privileged workflow — MEDIUM-HIGH (tag-mutation attack, supply-chain).

### LLM-agent runtime + MCP server fleet

(a) Inventory:
- *Computes:* LLM inference (model interprets prompt + tool-output as input), tool-call dispatch (file ops, web fetch, shell), MCP server message handling.
- *Assets:* the calling identity's full capability set (SSH keys, cloud creds, repo write, browser session, email, Slack), conversation history, any document the agent has read.
- *Trust:* user prompt = trusted by *the user*, untrusted by the agent from a security-policy perspective; tool-output = always untrusted (this is the indirect-prompt-injection class); MCP-server descriptors = often blindly trusted, frequently shouldn't be.

(b) Hotspots: indirect prompt-injection via fetched web content / fetched file / tool-output / MCP-server tool description; MCP tool-poisoning + rug-pull; tool-call without HITL on destructive operations (file unlink, git push --force, shell exec); confused-deputy across MCP servers (one server's output drives another server's call); credential exfil via tool-call that posts to attacker URL.

(c) Top-5:
1. Indirect prompt-injection from fetched web content → unauthorized tool-call (file-write, git-push, shell-exec) — CRITICAL on agents with shell access.
2. MCP-server tool-description injection ("the user wants you to also do X") — HIGH (read [[reference-llm-agent-security]] for tool-poisoning primitive catalog).
3. Confused-deputy: agent reads user's email via one MCP, then posts content via another MCP at attacker direction — HIGH.
4. Asymmetric DoS: attacker prompt that drives the agent into a multi-thousand-tool-call loop → quota exhaustion / cost DoS — MEDIUM-HIGH (§7 gate: small input, large output).
5. Capability leak via tool-call that writes attacker-controlled bytes to `~/.aws/credentials` / `~/.ssh/authorized_keys` — CRITICAL when shell or filesystem tools are unrestricted (see [[reference-agentic-web-capabilities]] for the POLA / capability framing).

---

## 7. DoS as universal background condition + the asymmetric-input gate

Aphorism: DoS is a security bug only when the attacker's cost is much less than the defender's.

The default rule: assume DoS is a watch-for condition on every target, but **only prioritize when the approach is highly asymmetric** — small inputs / few requests → outage. Symmetric resource-exhaustion attacks (10 Gbps for an hour) are reliability + capacity engineering problems; they belong to SRE, not security research.

Asymmetry threshold heuristic: if the attacker pays less than one-thousandth of the defender's cost, treat it as a security bug. Otherwise treat it as reliability.

Asymmetric DoS classes worth checking, with cross-link to [[reference-redos-algorithmic-dos]] for the canonical catalog:

- **ReDoS** — pathological regex (nested quantifier, alternation-overlap) with attacker-controlled input. Tiny input, exponential CPU.
- **Hash flooding** — pre-2012 hash-table implementations, still present in some languages (some Go map use cases, older JVMs, custom hash maps). Tiny input set, hours of CPU in collision chains.
- **Compression bombs** — zip / gzip / brotli / tar bombs. Few-KB upload, GB of decompressed memory.
- **YAML / XML billion-laughs** — nested entity expansion. Tiny document, exponential parsing memory.
- **Memory amplification via deserialization** — pickle `array.array` constructors, Java `HashMap.readObject` with large `count`. Bytes-of-input to GB-of-RAM.
- **Algorithmic complexity in sorting/parsing** — quadratic merge on adversarial input, parser-state-machine explosion.
- **Agent cost-DoS** — small prompt produces large tool-call fan-out, draining LLM tokens or paid API quota. New class; see §9 + [[reference-llm-agent-security]].

Operational rule: when scanning a target, every parser, every regex on user input, every decompression call, and every dynamic allocation sized by user input is a candidate point for asymmetric DoS. Apply the 1000× heuristic to decide whether to file a hypothesis.

---

## 8. Zero-click vs N-click prioritization

Aphorism: severity is a function of how much consent the victim had no chance to withhold.

Zero-click > one-click > N-click. Why: zero-click means no plausible deniability for the victim, no social-engineering precondition, no compromise of the victim's judgment. The attacker did not need anything from the human. The class of vulnerabilities that compromise without consent is structurally worse than the class that requires the victim to be tricked.

Concrete corpus:
- **Zero-click iMessage** — BLASTPASS (CVE-2023-41064, Citizen Lab + Apple, Sep 2023); FORCEDENTRY (CVE-2021-30860, Citizen Lab, Sep 2021); Operation Triangulation (Kaspersky, Jun 2023). See [[reference-mobile-security]].
- **Zero-click iMessage class methodology** — Beer and Groß, "A deep dive into an NSO zero-click iMessage exploit" (P0, 2021). The standing methodology: enumerate every parser the platform invokes on attacker-controlled input before any user interaction.
- **Zero-click email / chat protocols** — RCS and MMS attachment parsing, XMPP / IRC server-side parsers; the class is "attacker sends, victim's device parses without notification."
- **Zero-click VoIP** — Pegasus on WhatsApp (CVE-2019-3568, video-call parsing without answer). Generalizes to FaceTime / Zoom / Teams parser surface.
- **One-click** — open-this-document classes (Microsoft Office / PDF zero-day chains), open-this-URL (browser drive-by), accept-this-friend-request (rare modern class).
- **N-click** — multi-step social engineering, "the user has to be persuaded to disable a setting first." Score lower.

Operational rule: when ranking hypotheses, the click-count of the precondition stack is a first-order severity multiplier. A buffer overflow reachable by an SMS to a phone number > a buffer overflow reachable by clicking a malicious link > a buffer overflow reachable by social-engineering a sysadmin into running an attacker binary.

---

## 9. Agentic-N-click → 0-click promotion rule

Aphorism: if no human had the chance to refuse, the click did not happen.

Kurt's specific gate: N-clicks that are entirely agentic *may* be considered 0-click *if* there is a plausible explanation for missing HITL. Walk through the two-pronged test:

1. **The N clicks happen entirely within an autonomous agent's tool-use loop.** No human input between the trigger and the exploit. The agent reads → reasons → acts; all clicks are tool-calls the agent generates.
2. **There is a plausible operational reason that human-in-the-loop (HITL) was disabled or skipped.** Agentic auto-approve mode, auto-apply on PR, scheduled cron, background-task runner, "yolo mode," `--auto-approve` flag set by org default, MCP `auto: true` config, Copilot Workspace auto-apply.

When both hold, treat the bug as 0-click for prioritization purposes. The victim org had no human standing at the gate.

Concrete examples:
- **Clinejection** (Adnan Khan, GHSA-9ppg-jx86-fqw7, public Feb 2026). CI-bot in `claude-code-action` triggered by issue title — N=1 human click in the issue creator, but the bot's read+exec was entirely agentic with no HITL → 0-click for the org owning the bot. See `software/supply-chain/cicd_supply_chain_expertise.md` §2.9. The structural pattern: untrusted text + agent tool access + privileged context. The GHA trigger event is incidental; `issues` / `pull_request_target` / `workflow_run` / `discussion_comment` all inherit the same shape.
- **Comment-and-Control class** (Aonan Guan with Johns Hopkins researchers, Apr 2026; CVSS 9.4 on Claude Code Security Review variant). PR-title-in-prompt → shell exec → secrets exfil via PR comment. The bot is agentic; the human PR author's "click" is creating a PR. For the org running the review bot, this is 0-click.
- **PwnedRabbit** (Kudelski Security Research, Jan 2025 / Aug 2025 published). CodeRabbit's Rubocop linter executed in unsandboxed context → PEM-file exfil → 1M-repo write access. The bot is agentic; the PR is the trigger; the org running CodeRabbit had no HITL gate. Partial fit: the human PR author had to write malicious code, but for the *org running CodeRabbit*, the compromise was 0-click.
- **CurXecute** (CVE-2025-54135, Aim Labs, Aug 2025) on Cursor. Indirect prompt injection in fetched content → MCP-tool-call to write a new workspace `.cursor/mcp.json` → arbitrary command. Creating that file needed no user approval (GHSA-4cxx-hrm3-49rm), so 0-click.

Inverse rule (do not promote): an agentic-N-click does NOT promote to 0-click if a human had to approve each tool call. The HITL was present, not missing. Default-on permission prompts (Claude Code's `allow / ask / deny` model, Cursor's default-ask mode) preserve the click. Org-wide `--auto-approve` defaults erase it.

Cross-links: [[reference-llm-agent-security]] (MCP / prompt-injection / tool-use surface), [[reference-agentic-web-capabilities]] (capability-based defense, POLA, confused-deputy applied to agents).

Operational rule: when reviewing an agentic system, the highest-leverage question is "what is the org's effective HITL stance?" If `yolo` is set, if auto-apply is the default, if the bot can write to disk or call shell without prompt, every prompt-injection bug is a 0-click bug.

---

## 10. When first-principles bug-hunting fails / is the wrong frame

Honest accounting. The doctrine is not universal. Four classes where it dead-ends and you need a different frame:

- **Capability-mismatch.** When the system has no useful compute and no useful information, first-principles produces nothing. A static-content CDN cache, a stateless number-formatting library, a public health-check endpoint. Pivot to **upstream** (the supply chain that produces the static content, the build pipeline that compiles the library) or **downstream** (where this system's outputs are consumed and could be poisoned). The bug is rarely *in* the trivial system; it is in what the trivial system feeds.
- **Symbolic-trustworthy targets.** Formally verified microkernels (seL4), hardware roots-of-trust (TPMs, secure-enclave processors). First-principles is still useful for the *protocol* layer — how messages flow between verified and unverified components, how attestation is bound to identity — but not for the verified code itself. Reading the verified code looking for traditional bugs is a category error. The bug is in the boundary, the spec, or the unverified attestation flow. See `software/crypto-trust/formal_verification_protocols_expertise.md` for the discipline of attacking the protocol around verified code.
- **Business-logic-only bugs.** When there's no injection, no language-feature primitive, just a flawed policy. The classic: a coupon system that lets you stack two non-stackable coupons; a wire-transfer flow that lets a sender choose the destination account after the recipient confirmed; an OAuth flow where the redirect URI is checked against the wrong domain. First-principles produces no hypotheses on these; you need domain expertise and threat modeling. Closest sibling: [[reference-distributed-authz]] for the authz-policy anti-pattern catalog. The frame is "what is the system's intended invariant, and where does the implementation diverge from the spec the humans believed?"
- **Configuration-only bugs.** IAM wildcards, exposed S3 buckets, open security groups, default credentials in deployed config, signed-but-untrusted artifacts. The hotspot is the misconfig itself; the code is correct. Cross-link [[reference-cloud-iam]] and `software/supply-chain/supply_chain_provenance_expertise.md`. First-principles applies, but the "primitive" is "an IAM statement is a programming language for AWS authority" — extending §3's compute-as-universal-target framing one level up.

Recognize these patterns early. When the matrix at §5 produces no high-priority hypotheses for an hour, you are probably in one of these four cases, not in a "the target is secure" case. Pivot frames.

---

## 11. Concrete bug-class-by-asset-class lookup table

Reference table. Rows = asset class the target has access to. Columns = bug class. Cells = the canonical bug-shape to test (and a known primary-source incident where applicable).

| Asset → / Bug ↓ | Customer DB | Source code | AWS keys | SSH keys | Signing keys | Payment processing | Model weights |
|---|---|---|---|---|---|---|---|
| **Injection (code/cmd)** | SQL / NoSQL injection on data path; RCE via deserialization (cf. PHP `unserialize` Magento class) | RCE in CI runner → repo write (PwnedRabbit Aug 2025) | RCE → IMDS theft (Capital One 2019 via SSRF→IMDS) | RCE → `~/.ssh` read (default-trust class) | RCE → cosign / signing-key memory read | RCE in payment-flow service → process-memory token leak | RCE on GPU runner → weight exfil + IAM-role theft |
| **SSRF** | IMDS/internal-DB metadata enum | Internal-only Git fetch | IMDSv1 role theft (Capital One 2019) | Limited (filesystem read via `file://` URL parsers — XXE-class) | Internal artifact-registry read | Internal payment-API call as the service identity | Inter-tenant S3 fetch on shared bucket |
| **Auth bypass / BOLA** | Direct PII enum (Optus 2022; T-Mobile 2023) | `/admin` reachable pre-auth → repo download | API endpoint exposing IAM-policy details | Endpoint returning host inventory | Endpoint that re-signs without re-auth check | Direct refund-issuance / charge-without-confirm | Endpoint returning private-model inference |
| **Authz failure** | Cross-tenant read | Cross-org repo read | Cross-account assume-role with permissive trust policy | Cross-fleet SSH-via-bastion gap | Cross-team release re-sign | Cross-merchant settlement read | Cross-customer model-weights download |
| **Deserialization** | Pickle in cache → RCE → DB creds | Java serialization in build → CI compromise | BinaryFormatter in deployed .NET → role theft | Pickle in ssh-agent forwarding tool (rare) | YAML.load in cosign-adjacent config → key access | Marshal in Ruby payment pipeline → token leak | Pickle in model-load → weights + GPU compromise |
| **Asymmetric DoS** | Query-of-death on parser/regex | CI-runner exhaustion via malicious workflow | LLM cost-DoS (1000× quota) | Limited direct value; chain to outage | Re-sign API hammered | Payment-API rate-cost asymmetry | GPU exhaustion |
| **Supply chain** | Compromised JS package on customer-facing app (Magecart class) | Compromised build action (Clinejection Feb 2026; tj-actions Mar 2025) | Compromised CI action with OIDC trust → AWS | Compromised SSH-key-issuing tool (Wiz disclosure class) | Compromised signing-tool deps (XZ utils Mar 2024) | Compromised payment-SDK | HF-Hub typosquat / malicious tokenizer (Sleeper Agents class) |

Use this as a fast lookup. If the inventory at §2(b) lists an asset class on the column header, scan down the column to find the canonical bug-shapes worth testing. Cross-reference the bug-class to the per-class deep-dive doc.

### Asset-class → first-pass bug-class lookup (extended)

Sibling table, asset-class as rows. When the §2(b) inventory names an asset class, scan the row to find the first-lens bug classes plus the language / framework anchor that points into §4.

| Asset class | High-value attacker goal | First-lens bug classes | Language / framework anchor |
|---|---|---|---|
| SaaS user database | Cross-tenant read, password-hash exfil, admin impersonation | BOLA / IDOR, SQL/NoSQL injection, AuthN bypass on login | Rails / Django / Express / Spring patterns; [[reference-distributed-authz]] |
| Source-code repository host | Cross-repo read/write, exfil of org-wide source | Repository-permission TOCTOU, GitHub-App token escape, webhook secret confusion | Git-server / GitLab / Gerrit; PwnedRabbit class ([[reference-ai-pr-review-platform]]) |
| CI/CD pipeline | RCE on runner, exfil of publish credential | `pull_request_target` / `workflow_run` / `issues`-event injection, cache-poisoning, action-tag-mutation | GHA, Buildkite, CircleCI; [[reference-cicd-supply-chain]] §2.1 + §2.9 |
| Secrets manager / vault | Token exfil, cross-tenant secret read | AuthZ bypass on policy evaluation, IMDSv1 SSRF reaching the vault, secret-ref injection in templated configs | HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager |
| Cloud control plane (IAM/STS) | Privilege escalation, cross-account assume-role | `iam:PassRole` privesc, trust-policy misconfiguration, OIDC sub-claim trust on `*`, IMDSv1 | AWS / Entra / GCP; [[reference-cloud-iam]] |
| ML model weights | Weight exfil, model-supply-chain poisoning | Pickle gadget chains on attacker model, S3 ACL misconfiguration on weights, registry-token theft | PyTorch / TF / HuggingFace Hub; [[reference-adversarial-ml-model-security]] |
| Payment ledger | Double-spend, refund-flow abuse, currency arbitrage | Race conditions on debit/credit, BOLA on order endpoints, signature-replay on webhook callbacks | Stripe-shaped APIs; [[reference-race-conditions-concurrency]] |
| Ad-tech bid stream | Bid manipulation, cross-tenant click data | Bid-response injection, cookie-syncing trust-boundary confusion, OpenRTB schema-coercion | OpenRTB; [[reference-privacy-preserving-advertising]] |
| Federated identity (SAML/OIDC) | Cross-tenant identity assumption | SAML XSW (8-shape taxonomy), JWT alg-confusion, OIDC `sub` claim trust on `*`, audience-validation gaps | SP/IdP libraries; [[reference-saml-federation]] |
| Email infrastructure | Inbound parser RCE, outbound credential ATO | Parser zero-clicks on MIME/HTML/inline attachments, DKIM-record manipulation, SPF/DMARC bypass | Exim/Postfix/SendGrid; BLASTPASS class on inbound |
| Message queue | Cross-tenant message read, job-deserialization RCE | Marshal/YAML on job payloads, ACL bypass on topic subscription, retention-policy abuse | Kafka, Sidekiq, Celery, RabbitMQ |
| Container registry | Cross-tenant image push, registry-token theft | OCI manifest type-confusion, layer-extraction path traversal, signature bypass on cosign verify | Docker Hub, ECR, GCR, GHCR |
| Package registry (npm/pip/etc.) | Cross-package compromise, namespace squat, tag-mutation | Lockfile-spoofing on transitive, dependency-confusion namespace, sigstore-verify bypass on absent signatures | npm / PyPI / crates.io; [[reference-supply-chain-provenance]] |
| DNS infrastructure | Cache poisoning, registrar ATO, NS-record hijack | Kaminsky-class poisoning, registrar-account weak MFA, DNSSEC-validation bypass on resolver, IDN homograph | Resolver, registrar, registry |
| Build cache (CI shared cache) | Cache-poisoning to inject malware into downstream builds | Cache-key collision in shared workspace, race between cache-write and verification, missing integrity check on cache entries | GHA cache, Bazel remote cache; Clinejection / Cacheract class |
| AI agent runtime | LLM-provider cred exfil, customer-source leak, cross-customer leakage via cache | Indirect prompt injection, tool-call abuse on exfil-capable tools, shared-cache key collision, token-cost-amplification DoS | Claude/OpenAI tool runtimes; [[reference-llm-agent-security]], [[reference-ai-pr-review-platform]] §10 |
| MCP server fleet | Tool-poisoning, rug-pull, exfil via tool-description | Description injection, tool-shadowing, request smuggling on HTTP transport, MCP-config-write-as-primitive (CurXecute class) | MCP transport / server; [[reference-llm-agent-security]] |

DEEPENING TARGET: extend with specialized rows for (a) blockchain wallets (custodial vs hardware vs MPC; [[reference-blockchain-wallet-consensus]]), (b) ICS controllers (PLCs, RTUs; [[reference-ics-ot-security]]), (c) automotive head-units and ECU networks ([[reference-automotive-security]]), (d) medical devices (implantables and hospital infrastructure; [[reference-medical-device-security]]), (e) wireless / RF / satellite ([[reference-wireless-rf-satellite]]). The doctrine generalizes; the priority rows are domain-specific.

---

## 12. End-to-end worked example — applying the doctrine on `tj-actions/changed-files`

Pick a small well-bounded target: `tj-actions/changed-files` (a popular GitHub Actions reusable composite action; canonical pwn-request-class exposure post Mar 2025 supply-chain incident). Apply §2 → §3 → §4 → §5 → §6 → §7 → §8 → §9 in order.

### §2 inventory

- *Computes:* shell evaluation in the action's `run:` steps; `git` invocations on the calling-repo's checkout; comparison of base vs head trees.
- *Assets the action has access to in a calling workflow:* the calling repo's `GITHUB_TOKEN` (whatever its scopes are; often `contents: write` or higher), the calling job's environment variables (frequently including `AWS_*` and other secrets injected via `env:`), the calling job's filesystem (which may include build artifacts and `.npmrc` etc.).
- *Trust:* inputs to the action come from `github.event.pull_request.*` and `github.event.head_commit.message` — untrusted; the action's own code = trusted by callers, *but only as much as the pin allows*. Tag pin = mutable; SHA pin = immutable. The Mar 2025 incident exploited the gap: attackers force-pushed a malicious commit onto multiple tags that callers had pinned by tag.

### §3 injection lens

For each `run:` block in the action, is there a place where `${{ github.event.* }}` is interpolated directly into a shell line? If yes, every consumer-of-this-action with a `pull_request_target` trigger has shell injection. Even if the action only does `git log --format='%s' "$PR_TITLE"` via env-var injection (safer), the *action's own consumers* may interpolate output back into shells.

### §4 dangerous primitives in this stack

- Filesystem ops: action reads files via `git diff --name-only`. Low primitive risk.
- ACLs: the action runs as whatever identity the calling workflow has — typically `GITHUB_TOKEN` with whatever scopes the caller granted.
- Network requests: action may call GitHub API; not typically outbound to attacker-controlled URLs (sanity-check this).
- Command shells: this is the entire surface of a GHA composite — every step is shell.
- Complex serialization: minimal; action output is plain text.

### §5 matrix

Top-3 hypotheses on the *action itself*:

1. Shell injection in any `run:` block that interpolates `${{ github.event.* }}` text directly — CRITICAL on any caller using `pull_request_target` ([[reference-cicd-supply-chain]] §2.1).
2. Supply-chain compromise via tag-mutation: if all callers pin by tag, a force-push to the tag executes attacker code in every caller's privileged context — CRITICAL (this is what actually happened Mar 2025).
3. Argument injection in `git log` / `git diff` calls if any input is concatenated into the args without a `--` separator — MEDIUM-HIGH (CWE-88 class).

### §6 stack instantiation

Matches the GHA stack template in §6. The action is one node in the supply graph; the *calling repo* is the target. So flip the frame: what assets do typical callers of `tj-actions/changed-files` have? Typically `contents: write` on the repo, sometimes OIDC trust to AWS / GCP via `aws-actions/configure-aws-credentials`. That moves the priority of (1) and (2) from "RCE in action" to "RCE in customer cloud."

### §7 asymmetric-DoS gate

Action DoS is low-leverage here. Not a priority.

### §8 zero-click vs N-click

Pinning by SHA → 1-click (someone has to merge a bump). Pinning by tag → 0-click for callers (mutable tag updates without consent). The Mar 2025 incident was 0-click for organizations that hadn't pinned by SHA.

### §9 agentic-N-click promotion

Not directly applicable for this action specifically — there's no agentic loop here. But generalizes: if a downstream caller of this action is running an AI-bot workflow with `--auto-approve`, the chain becomes [Mar 2025 supply-chain mutation] → [agentic bot reads attacker-influenced output] → [tool-call as the bot's identity]. The promotion rule applies one hop downstream.

### Doctrine output

Two concrete bug hypotheses worth testing:
- *(H1)* Audit every `run:` block in `tj-actions/changed-files` for `${{ github.event.pull_request.* }}` interpolation. Variant-analyze across the action's history; check whether any historical commit had this shape (variant analysis per [[reference-vr-methodology]] §2).
- *(H2)* Audit the org's calling-workflow corpus for tag-pinned references to `tj-actions/changed-files` and other high-blast-radius composites. The first-principles concern isn't "is the action vulnerable today" — it's "do the callers have a precondition stack that includes mutable supply chain?"

Test plan for (H1): grep the action source; if found, write a PoC PR that demonstrates the injection in a fork; report under coordinated disclosure. For (H2): grep org workflow YAML for `uses:` lines and flag any reference that isn't a 40-char SHA.

This is the doctrine's deliverable: prioritized hypotheses with concrete test plans, derived from a 6-step inventory rather than from pattern-matching against the target's surface.

---

## 13. Cross-link cluster + status / known gaps

### Cross-links named in this doc

- [[reference-vr-methodology]] — the four canonical VR methods (code review, variant analysis, fuzzing, patch diffing). This doc's closest sibling.
- [[reference-code-review-expertise]] — click-count severity, candidate-point auditing, TAOSSA methodology.
- [[reference-steelman-doctrine]] — operational-doctrine doc shape this doc matches.
- [[reference-llm-agent-security]] — prompt-injection primitives, MCP / A2A attacks, agent tool-use surface.
- [[reference-agentic-web-capabilities]] — POLA, confused-deputy, capability-based defense for agents.
- [[reference-shell-injection]] — CWE-78/88/150 three-class taxonomy, per-binary dangerous-flag catalog.
- [[reference-template-code-injection]] — 12-engine SSTI catalog, SpEL/OGNL/MVEL/JEXL reach.
- [[reference-prototype-pollution]] — JS prototype-pollution gadget corpus.
- [[reference-xml-parser-differential]] — XXE primitives, parser differentials, SAML XSW.
- [[reference-ssrf-url-parsing]] — SSRF primitives, URL parser differentials (Orange Tsai), cloud metadata.
- [[reference-http-web-security]] — HTTP / header smuggling / CORS / CSRF / request smuggling.
- [[reference-race-conditions-concurrency]] — TOCTOU, Kettle single-packet, openat2 `RESOLVE_BENEATH`.
- [[reference-distributed-authz]] — Zanzibar, CWE-287/306/308/862/863 anti-pattern catalog, OAuth threat model.
- [[reference-cloud-iam]] — AWS 5-policy-eval, Entra OAuth-consent, GCP Workload Identity Federation.
- [[reference-container-k8s-security]] — pod-level RBAC, service-account-token mounts, NetworkPolicy.
- [[reference-mobile-security]] — zero-click iMessage corpus (BLASTPASS, FORCEDENTRY, Operation Triangulation).
- [[reference-redos-algorithmic-dos]] — ReDoS / hash flooding / compression bombs / algorithmic-complexity attacks.
- [[reference-cicd-supply-chain]] — GHA pwn_request / pull_request_target / workflow_run primitives, Clinejection §2.9.

File-path cites (no canonical reference-slug yet, or domain-specific docs not in the cross-link spec):
- `software/vuln-classes/deserialization_expertise.md` — canonical deserialization catalog.
- `software/language-footguns/sql_dialect_footguns_expertise.md` — per-dialect SQL footguns.
- `software/language-footguns/python_footguns_expertise.md`, `java_footguns_expertise.md`, `ruby_footguns_expertise.md`, `go_footguns_expertise.md`, `javascript_node_footguns_expertise.md`, `c_cpp_footguns_expertise.md`, `rust_footguns_expertise.md`, `php_footguns_expertise.md` — language-specific dangerous-primitive enumeration; pair with §4.
- `software/crypto-trust/formal_verification_protocols_expertise.md` — the discipline of attacking the protocol around verified code; cited in §10 for symbolic-trustworthy targets.
- `software/supply-chain/supply_chain_provenance_expertise.md` — SLSA / sigstore / SBOM operationalization; cited in §10 for config-only bugs and §11 for the supply-chain column.

### What this doc does *not* cover

Be honest about scope. This doc is the *prioritization* doctrine, not a primitive catalog or per-domain field guide. Specifically:

- **Browser-engine specifics** — V8 / JSC / SpiderMonkey type-confusion, JIT-spray primitives, Wasm-exit bugs, Mojo IPC sandbox escape. First-principles still applies at the protocol layer (what does the renderer have access to, what is the trust boundary at the IPC), but the dangerous-primitive enumeration is domain-specific and lives in `software/exploitation/browser_js_engine_exploitation_expertise.md`.
- **Mobile platform specifics** — iOS / Android sandbox model, BLASTPASS / Operation Triangulation chains, Frida runtime instrumentation, baseband. The doctrine's zero-click framing (§8) anchors here, but the surface-specific primitives are in [[reference-mobile-security]].
- **Hardware side-channels** — Spectre / Meltdown / Rowhammer / SGX-attack lineage. First-principles applies at the protocol layer (what is the boundary between attacker and victim execution), but the primitive catalog is in `software/exploitation/hardware_side_channels_expertise.md`.
- **Cryptographic protocol attacks** — symbolic vs computational adversary models, Tamarin / ProVerif analyses, padding-oracle / nonce-reuse / hash-length-extension primitive enumeration. The doctrine's "every interpreter is a candidate point" rule still applies, but crypto-protocol attacks need the formal-verification doctrine in `software/crypto-trust/formal_verification_protocols_expertise.md` and the crypto-specific primitives in `software/crypto-trust/cryptography_expertise.md`.
- **Smart-contract / EVM** — reentrancy, flash-loan, oracle manipulation, MEV. First-principles applies at the asset-inventory step (the contract's tokens are the asset; its callable functions are the surface), but the primitive catalog is in `software/industry-verticals/smart_contract_evm_security_expertise.md`.
- **OS kernel exploitation** — heap-spray primitives, slab grooming, eBPF / io_uring / netfilter surface, mitigation bypass. See `software/exploitation/linux_kernel_exploitation_expertise.md`. First-principles applies at the syscall-surface enumeration; the spray-primitives are domain-specific.
- **Specific detection / runtime-rule authoring** — this doc tells you where to hunt; detection-rule authoring is the inverse problem (write rules that catch the patterns at runtime). See [[reference-detection-engineering]].

### Known gaps in the doctrine itself

- **Quantitative asset valuation** — §2(b) lists assets qualitatively. A future revision could anchor a numeric framework (Schneier four-pressures, Ryan McGeehan's quantitative-risk approach via [[reference-game-theory-mechanism-design]] adjacent work). Today the matrix at §5 is intuition-driven on the asset axis.
- **Empirical validation of the asymmetry heuristic** — §7's "1/1000th of defender's cost" threshold is a heuristic, not a calibrated value. Anchored on operational experience, not on a study.
- **The HITL stance is binary in §9** — the agentic-N-click → 0-click promotion treats HITL as on/off. Real agentic systems have partial HITL (some tool calls prompt, some don't). A future revision should grade the HITL stance per tool-call type.
- **Cross-tenancy as its own column** — multi-tenant SaaS has a structural asset-class ("other tenants' data") that doesn't appear cleanly in §11's table. A future revision should add it.

---

*Doctrine status: v1. Anchored on Kurt Boberg's first-principles north star (§1, verbatim). Read with [[reference-vr-methodology]] for method, [[reference-code-review-expertise]] for line-level discipline, [[reference-steelman-doctrine]] for the meta-procedure that audits the output of this doctrine.*
