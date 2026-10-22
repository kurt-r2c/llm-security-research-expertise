# PHP Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Stefan Esser, Sam Thomas, Charles Fol, Johannes Dahse, Anthony Ferrara, Orange Tsai, Hanno Böck, and the SonarSource / Synacktiv / Quarkslab research corpora

> **Currency marker:** Last refreshed 2026-05-14. The 2024-2026 deepening pulls
> in CVE-2024-4577 (Orange Tsai / DEVCORE PHP-CGI argument injection via
> Windows Best-Fit Mapping), the Synacktiv `php_filter_chains_oracle_exploit`
> error-based file-read primitive, CVE-2024-28859 / CVE-2024-28861 (Symfony 1
> Swift_KeyCache and sfNamespacedParameterHolder chains, contributed to PHPGGC), CVE-2024-55555 (Invoice Ninja
> Laravel `decrypt()`-into-`unserialize()`), CVE-2025-1220 (null-byte
> hostname allowlist bypass in `fsockopen()`), and CVE-2025-54236
> ("SessionReaper" pre-auth Magento RCE chain disclosed by Blaklis).
>
> **Scope:** This is a **behavioral-footgun** doc. It catalogs PHP-internal
> primitives whose *default behavior* is unsafe — distinct from cross-language
> bug-class docs (`deserialization_expertise.md`, `shell_injection_expertise.md`)
> or framework-specific guidance. The unit of analysis is the language feature,
> not the vulnerability class.

> **Researchers:**
> - **Stefan Esser** (@i0n1c, formerly SektionEins GmbH) — Canonical PHP-internals
>   security. PHP core developer since 2002. Founded the Hardened-PHP Project
>   (2004), which evolved into the Suhosin PHP Security System (2006), the only
>   widely-deployed PHP runtime hardening layer. Published "Month of PHP Bugs"
>   (March 2007) and "Month of PHP Security" (May 2010). Disclosed dozens of
>   CVEs against the PHP core engine, Zend stream wrappers, and PHP extensions.
> - **Sam Thomas** (Secarma, then independent) — Author of "It's a PHP
>   unserialization vulnerability Jim, but not as we know it" (Black Hat USA
>   2018). Discovered that the `phar://` stream wrapper auto-triggers
>   `unserialize()` on Phar metadata when any file-operation function is
>   invoked with a `phar://` URI — converting every file-reading function in
>   PHP (`file_exists`, `getimagesize`, `file_get_contents`, `is_dir`, etc.)
>   into a deserialization sink. Reclassified PHP LFI / arbitrary-upload bugs
>   as pre-auth RCE in any application with a user-reachable Phar gadget.
> - **Charles Fol** (@cfreal_, also @cfreal on GitHub) — Security researcher at
>   LEXFO / Ambionics. Author of PHPGGC (https://github.com/ambionics/phpggc),
>   the canonical PHP-gadget-chain generator and library. Disclosed RCE chains against Drupal, Magento, Symfony, Laravel.
> - **Synacktiv research team** — Extended the filter-chain primitive
>   into the **error-based file-read oracle**
>   (https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle).
>   First surfaced as a DownUnderCTF 2022 challenge by @hash_kitten; Synacktiv
>   productized it into the `php_filter_chains_oracle_exploit` CLI, which
>   exfiltrates arbitrary file contents one character at a time through
>   memory-exhaustion error oracles, requiring only that the target perform any
>   file operation on a fully-attacker-controlled URI.
> - **Johannes Dahse** (RIPS Technologies co-founder, then SonarSource research)
>   — Authored RIPS, the first deep static analyzer for PHP (open-sourced May
>   2010, commercial rewrite 2016, acquired by SonarSource 2020). Won the
>   inaugural Facebook Internet Defense Prize (2014, with Thorsten Holz) for
>   static detection of second-order vulnerabilities in web applications. The
>   SonarSource PHP research corpus is the modern continuation: phpBB3 Phar
>   deserialization, Composer supply-chain disclosures, and CVE-class research
>   on PHP object injection and file-operation gadgets.
> - **Anthony Ferrara** (@ircmaxell) — PHP internals contributor; author of the
>   `password_hash` / `password_verify` RFC (PHP 5.5,
>   https://wiki.php.net/rfc/password_hash) and the `password_compat` userland
>   library. Long-running blog (https://blog.ircmaxell.com/) documenting PHP's
>   password storage history and timing-safe comparison rationale.
> - **Orange Tsai** (@orange_8361, DEVCORE) — Disclosed CVE-2024-4577
>   (https://blog.orange.tw/posts/2024-06-cve-2024-4577-yet-another-php-rce/),
>   a PHP-CGI argument injection RCE that abuses Windows "Best-Fit"
>   character-encoding mapping to smuggle dashes through the `php-cgi` argv
>   parser. CVSS 9.8; added to CISA KEV within days of disclosure. Sat dormant
>   for ~12 years between CVE-2012-1823 and the 2024 best-fit-bypass — a
>   textbook example of a patched bug-class returning via an unaudited
>   upstream behavior.
> - **Hanno Böck** (https://itsec.hboeck.de/) — Independent journalist and IT
>   security consultant. Created `snallygaster` (scanner for accidentally-public
>   secrets, .git directories, backup files) and `freewvs` (PHP webapp
>   version-vulnerability scanner). Long history of PHP / web-stack security
>   writeups for golem.de and his own blog; contributor to TLS robustness
>   research (ROBOT, AES-GCM analyses) adjacent to PHP deployments.
> - **Blaklis** — Magento / Adobe
>   Commerce specialist. Discovered CVE-2025-54236 ("SessionReaper"), a
>   pre-auth RCE chain in Magento 2 / Adobe Commerce.
>
> **Modern-era contributors (2022-2026):** Quarkslab research (Laravel
> deserialization gadget chain corpus); darkpills (Symfony 1 / Swift Mailer
> chain research; contributed to PHPGGC); watchTowr Labs (CVE-2024-4577 PoC and
> field exploitation telemetry); @hash_kitten / WhiteCat (DownUnderCTF 2022 PHP
> filter-chain oracle challenge); Hadrian.io (CVE-2025-1220 null-byte allowlist
> bypass in `fsockopen()`).
>
> Sources: SektionEins.de archive; suhosin.org; Black Hat USA 2018 paper
> archive; Synacktiv publications; Ambionics blog / PHPGGC GitHub; SonarSource
> blog; blog.orange.tw; itsec.hboeck.de; Quarkslab blog; Lexfo Security blog;
> PHP RFC wiki (wiki.php.net/rfc); php.net manual; portswigger.net Daily Swig;
> Doyensec blog; primary CVE numbering and NVD; OWASP PHP Security Cheat Sheet.
>
> **Cross-links to neighboring expertise docs:**
> - `deserialization_expertise.md` §3 — PHP `unserialize()` covered as one of
>   seven language-level deserialization vectors; this doc extends with the
>   Phar metadata auto-trigger primitive and the PHPGGC gadget catalog
> - `shell_injection_expertise.md` — `system()`, `popen()`, `passthru()`,
>   `shell_exec`, backticks, `proc_open` as PHP's standard CWE-78 sinks;
>   `escapeshellcmd` weak-sanitizer note in
>   `feedback_escapeshellcmd_weak_sanitizer.md`
> - `code_review_expertise.md` — click-count severity; heterogeneous-auth and
>   serialization-with-type-handling heuristics
> - [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) — patterns for detecting `unserialize($USER)`,
>   `eval`, `extract($_GET)`, `==`-in-security primitives
> - `template_code_injection_expertise.md` — Smarty / Twig / Blade sandbox
>   escape primitives
> - `redos_algorithmic_dos_expertise.md` — PCRE backtracking limits
> - `http_web_security.md` — PHP session handling, cookie defaults, header
>   injection
> - `cicd_supply_chain_expertise.md` §5 — Composer / Packagist supply chain

---

## 1. The behavioral-footgun framing

Most PHP security writeups frame the problem as "dangerous functions": `eval`,
`system`, `unserialize`, `include`, `extract`. This framing is useful for
grep-based rule authoring but misses the deeper class of issues: **PHP's
*default semantics* on otherwise-ordinary operations are unsafe.** The
vulnerability is not that `unserialize` exists; it is that when `unserialize`
is called, magic methods on attacker-determined classes execute side effects.
The vulnerability is not that `==` exists; it is that `==` performs lossy
type juggling. The vulnerability is not that `include` exists; it is that
`include` accepts stream-wrapper URIs that auto-deserialize Phar metadata or
chain encoding conversions into executable bytecode.

The behavioral-footgun framing makes this concrete. Each section below covers
a PHP-internal primitive whose **default behavior is unsafe** — where calling
the feature in its ordinary, documented, supported mode produces a security
exposure that the developer did not opt into. The defensive counter-pattern
is almost always "use a different, explicit, safer API the language provides"
— but the developer has to know it exists.

### PHP's permissive-by-design historical posture

PHP grew out of Rasmus Lerdorf's personal-homepage CGI scripts (1994). The
language was designed to be forgiving: implicit type conversions,
`register_globals` (auto-promoting GET / POST / cookies into top-level
variables), `magic_quotes_gpc` (auto-escaping all incoming strings), silent
error suppression with `@`, and a standard library that bundled network,
filesystem, database, regex, and XML parsing under context-sensitive defaults.
The forgiving semantics were the language's biggest commercial asset
(entry-level developers shipping running code) and its biggest security
liability.

The PHP team has spent the last fifteen years walking back the worst defaults:

| Era | Removed / restricted | Reference |
|-----|----------------------|-----------|
| PHP 5.3 (2009) | `register_globals` / `safe_mode` deprecation | https://www.php.net/manual/en/security.globals.php |
| PHP 5.4 (2012) | `register_globals`, `safe_mode`, `magic_quotes_gpc` removed | https://www.php.net/manual/en/migration54.deprecated.php |
| PHP 5.5 (2013) | `preg_replace` `/e` deprecated | https://wiki.php.net/rfc/remove_preg_replace_eval_modifier |
| PHP 7.0 (2015) | `preg_replace` `/e` removed | same |
| PHP 7.2 (2017) | `create_function`, `each()` deprecated; `assert()` string-eval deprecated | https://wiki.php.net/rfc/deprecations_php_7_2 |
| PHP 7.4 (2019) | `__serialize` / `__unserialize` added | https://wiki.php.net/rfc/custom_object_serialization |
| PHP 8.0 (2020) | Phar metadata auto-`unserialize` removed; "saner" type juggling | https://wiki.php.net/rfc/phar_stop_autoloading_metadata + https://wiki.php.net/rfc/string_to_number_comparison |
| PHP 8.1 (2021) | `htmlspecialchars` default `ENT_QUOTES \| ENT_SUBSTITUTE` | https://php.watch/versions/8.1/htmlspecialchars-default-flags |

What remains is a long tail of behavioral footguns where the default is still
unsafe, the unsafety is documented, and applications continue to ship the
unsafe pattern. The rest of this doc catalogs that long tail.

Each technique section follows the same shape: what the primitive is, the
default behavior, why it's a footgun, real-world examples (CVEs, public
writeups, gadget catalogs), defensive counter-patterns, and detection
patterns. The goal is to give a code reviewer (the Foil persona of
`steelman_doctrine_expertise.md`) a fast scan list.

---

## 2. Type juggling and loose comparison (`==` vs `===`)

PHP supports two comparison operators with related but distinct semantics:

- `==` (loose) — coerces operands to a common type before comparing. The rules
  live at https://www.php.net/manual/en/language.types.type-juggling.php and
  https://www.php.net/manual/en/types.comparisons.php.
- `===` (strict) — compares both value and type without coercion.

PHP also overloads `==` semantically into the standard library: `in_array()`
defaults to loose, `array_search()` defaults to loose, `switch ($x) { case "0":
... }` uses loose comparison internally.

### Default behavior — the type-juggling surface

Pre-PHP-8, the following all evaluated to `true` under `==`:

```
0 == "0"            // expected
0 == ""             // surprising — empty string equals zero
0 == "abc"          // shocking — any non-numeric string equals zero (pre-PHP-8)
0 == null           // expected
0 == false          // expected
"0" == false        // expected
"" == null          // expected
"0e123" == "0e456"  // magic-hash collision — both parsed as scientific zero
"1" == "01"         // numeric coercion
"10" == "1e1"       // numeric coercion
100 == "1e2"        // numeric coercion
```

The PHP "type comparison" table is a multi-page matrix that no human
memorizes; many developers assume "PHP behaves like JavaScript or Perl here"
and ship broken comparisons.

### Why it's a footgun — the magic-hash class

Hash functions that produce hex output (md5, sha1, sha256) occasionally emit
strings of the form `0e\d+` — a leading `0e` followed only by decimal digits.
PHP `==` parses such strings as scientific-notation floats: `"0e215962017"`
becomes `0e215962017 = 0.0`. Two distinct hex hashes that both happen to
match the regex `^0e\d+$` therefore compare equal under `==`.

A typical vulnerable pattern:

```php
$expected_hash = "0e462097431906509000000000000000";  // attacker-known hash
$user_input    = $_POST['token'];
if (md5($user_input) == $expected_hash) {             // <-- "==" not "==="
    grant_access();
}
```

If the attacker can find any input whose md5 begins with `0e` and contains
only digits afterward, the comparison succeeds. The brute-force cost is low:
roughly 1 in 10^N where N is the digit-count required after `0e`. Public
catalogs (https://github.com/spaze/hashes) document known magic-hash inputs
for md5, sha1, sha256, md4, ripemd128, ripemd160, crc32, fnv132,
fnv1a32, fnv164, fnv1a64, joaat, haval128, haval160, and Tiger, xxHash
and MurmurHash3 variants — letting an attacker pick the right input in O(1).

The OWASP "PHP Magic Tricks: Type Juggling" slide deck
(https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf) covers
the historical examples in Laravel CSRF-token and encryption-MAC checks
and WordPress auth-cookie verification.

### `in_array`, `array_search`, and `switch` are loose by default

```php
in_array("abc", [0, 1, 2])      // true pre-PHP-8 — "abc" coerces to 0
in_array("0", [false, true])    // true — "0" coerces to false
array_search(0, ["admin", "x"]) // 0 pre-PHP-8 — "admin" coerces to 0, matches at index 0
```

Both `in_array` and `array_search` accept a `$strict = true` parameter that
makes the comparison `===`. **The default is loose.** Every call in
security-sensitive code (allowlists, role checks, capability enumeration)
needs to be audited.

`switch` compares case labels to the switch expression under `==`. There is
no `strict switch`. Workaround: use `if/elseif` chains with `===` or the PHP
8.0 `match` expression (uses `===` semantics by default; also exhaustive).

### Real-world examples

- **WordPress auth-cookie forgery** (MWR, 2014) — core compared the
  cookie HMAC with `!=`; magic-hash forgery was demonstrated.

### Defensive counter-patterns

1. **Use `===` for all security-sensitive comparisons.** No exceptions.
2. **Use `hash_equals($known, $user_input)` for cryptographic comparisons**
   — type-strict and timing-safe (see §7).
3. **For `in_array` / `array_search`, always pass `$strict = true`.**
4. **For prefix / contains checks**, use PHP 8.0+ `str_contains`,
   `str_starts_with`, `str_ends_with` — strings only, no coercion.
5. **Use `match` instead of `switch`** in security paths.

### PHP 8 "Saner string to number comparisons" RFC

The RFC (https://wiki.php.net/rfc/string_to_number_comparison) shipped with
PHP 8.0 and tightened `==` when comparing a number to a non-numeric string.
Pre-8.0, `0 == "abc"` was `true` because PHP cast `"abc"` to 0. Post-8.0,
PHP first checks whether the string is numeric; if not, it casts the number
to a string and performs a string comparison. So `0 == "abc"` is now `false`.
The change did **not** eliminate the magic-hash class — two numeric strings
(both `0e\d+`) still compare equal because both are parsed as numbers — but
it eliminated the "any non-numeric string equals zero" surface that was a
common source of authentication bypasses.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: $X == md5(...)
    - pattern: md5(...) == $X
    - pattern: $X == hash(...)
    - pattern: hash(...) == $X
    - pattern: $X == hash_hmac(...)
    - pattern: in_array($X, $Y)        # check for $strict argument
    - pattern: array_search($X, $Y)    # same
```

Static analyzers `psalm` and `phpstan` at level 9 will flag `==` on
mixed-type operands.

---

## 3. Magic methods and object lifecycle

PHP classes can define **magic methods** — methods with reserved names that
are invoked automatically on specific events. The canonical list
(https://www.php.net/manual/en/language.oop5.magic.php):

| Magic method | Triggered by |
|--------------|--------------|
| `__construct` / `__destruct` | object creation / refcount-zero |
| `__call` / `__callStatic` | call to undefined method |
| `__get` / `__set` / `__isset` / `__unset` | undefined property access |
| `__sleep` / `__wakeup` | `serialize()` / `unserialize()` (legacy) |
| `__serialize` / `__unserialize` (PHP 7.4+) | `serialize()` / `unserialize()` (typed alternative) |
| `__toString` | object used in string context |
| `__invoke` | object called as function |
| `__set_state` | `var_export()` import |
| `__clone` | `clone $obj` |
| `__debugInfo` | `var_dump()` |

### Default behavior — implicit side effects

Every magic method is an implicit side-effect point. The developer defining
`__wakeup()` to "reconnect the database" or `__destruct()` to "clean up a
temp file" rarely considers that these methods will fire when an
*attacker-controlled* serialized object is unserialized on the same classpath.

### Why it's a footgun — the gadget primitive

Together, the magic methods form a Property-Oriented Programming (POP)
primitive set. The attacker does not inject code; they inject **serialized
object state** that, during deserialization, walks the magic-method graph to
reach a sink. Frohoff's POP framing (see `deserialization_expertise.md`)
applies directly:

- `__wakeup` / `__unserialize` — entry points; fire before any application
  logic touches the object.
- `__destruct` — exit point; fires after refcount hits zero, which happens at
  end of request or when the local variable goes out of scope.
- `__toString` — string-coercion trigger; any concatenation, `sprintf("%s",
  $obj)`, `strlen($obj)`, `echo $obj`, exception message construction, or
  PHP 7.x loose comparison with a string invokes it.
- `__call` / `__callStatic` — dispatch hijacking; if any code path calls an
  undefined method on the deserialized object, the attacker's `__call` body
  runs.
- `__get` / `__set` — property-access hijacking.
- `__invoke` — object-as-callable; `$obj(...)` and `call_user_func($obj)`
  invoke it.
- `__clone` — fires during clone; relevant in chains that pass objects
  through deep-copy caches.

A gadget chain is a sequence: attacker injects a serialized `OuterGadget`
whose `__destruct` calls a method on an inner `MiddleGadget` whose
`__toString` calls a method on a `SinkGadget` whose `__call` invokes
`system($cmd)`. The chain is composed entirely of legitimate classes from
the application's classpath.

### `__toString` is silently triggered everywhere

```php
echo $obj;
"$obj"
"prefix" . $obj
sprintf("%s", $obj)
strlen($obj)
htmlspecialchars($obj)
$obj === "some-string"           // PHP 7.x with == coerces; PHP 8+ === does not
file_put_contents($path, $obj)
trigger_error("$obj")
throw new Exception($obj)        // Exception::__construct takes a string
```

`__toString` invocation during exception construction is a particularly
common late-stage gadget primitive — attackers reach `__toString` via the
error-handler path even when the normal code path never touches the object.

### `__destruct` fires unconditionally at end-of-scope

The attacker does not need to find a code path that calls anything on the
deserialized object. Once `unserialize($USER_INPUT)` returns, the
reconstructed object lives in a local variable; at end of the request
handler (or sooner if `unset()` is called), `__destruct` fires automatically.
This is why even `unserialize($USER_INPUT)` with the result discarded is RCE
if any class on the classpath has a dangerous `__destruct`.

### PHP 7.4+ `__serialize` / `__unserialize`

The PHP 7.4 RFC (https://wiki.php.net/rfc/custom_object_serialization)
introduced `__serialize` (returns an array of state) and `__unserialize`
(receives the array and rebuilds state). These are **preferred** over
`__sleep` / `__wakeup` because they round-trip typed data more cleanly. For
security, `__unserialize` is **just as dangerous** as `__wakeup`: it fires
automatically and any side effect in its body is reachable.

### Defensive counter-patterns

1. **Treat every magic method as a deserialization entry point** when the
   class is in any application's classpath. Even if your code never calls
   `unserialize` on user input, a downstream consumer might.
2. **Avoid side effects in `__destruct`, `__wakeup`, `__unserialize`,
   `__toString`, `__call`.** If state changes are required, restrict to
   in-memory operations on `$this` — no I/O, no system calls, no SQL.
3. **Mark gadget-prone classes `final`** to prevent gadget-chain composition
   via subclassing.
4. **Use the `$options['allowed_classes']` parameter to `unserialize`** to
   restrict instantiable classes (PHP 7.0+).
5. **Cross-link to `deserialization_expertise.md`** for the full defense-in-
   depth catalog: JSON / msgpack alternatives, signed serialized blobs,
   `is_string`-checked HMAC verification.

---

## 4. `unserialize()` + Phar deserialization + autoloader gadgets

`unserialize(string $data, array $options = [])` reconstructs PHP objects,
arrays, scalars, and nulls from a string produced by `serialize()`. PHP's
serialization format encodes class names inline; deserialization auto-loads
the named class and invokes its magic methods.

### Default behavior — class name and method dispatch are attacker-controlled

The serialized format `O:N:"ClassName":K:{s:N:"prop";...}` includes the class
name as a string. `unserialize` looks the name up via the PSR-4 / autoload
mechanism, instantiates it, and dispatches the magic-method graph (§3). The
`allowed_classes` option (PHP 7.0+) accepts an allowlist, but **the default
is `true`** — all classes are allowed.

### Phar metadata auto-deserialization (Sam Thomas, Black Hat 2018)

The most consequential PHP-specific deserialization discovery of the last
decade. Sam Thomas's Black Hat USA 2018 paper
(https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
showed that the `phar://` stream wrapper, when used with any file-operation
function (not just `unserialize`), automatically deserializes the Phar
metadata block.

The Phar archive format includes a metadata field that is `serialize()`-d
PHP object state. Pre-PHP-8.0, this metadata was auto-`unserialize`-d when
the Phar was opened via the stream wrapper, regardless of why the file
operation occurred. Affected functions (non-exhaustively):

- `file_exists("phar://...")`
- `file_get_contents("phar://...")`, `file()`, `fopen()`
- `getimagesize("phar://...")` — the WordPress / image-CMS path
- `is_dir`, `is_file`, `is_readable`, `is_writable`, `filesize`, `stat`
- `md5_file`, `sha1_file`
- `copy("phar://...", $dst)`, `unlink("phar://...")`

The technique reclassified an enormous class of bugs:

- **File-upload bypasses** that previously only enabled file squatting now
  enabled RCE if any code path later called any file function on the upload.
- **Path-traversal LFI** that previously only enabled file read now enabled
  RCE.
- **WordPress author-account-to-RCE** (Thomas's demo on stage) — WP authors
  could point an attachment's thumbnail path
  (`wp_get_attachment_thumb_file`) at a previously uploaded Phar, triggering
  the unserialize.

Phar archives can be **disguised as other file types**. Data inserted into
the stub (or, in the tar format, the 100-byte filename field) can fake the
leading bytes of most formats such as JPEG; the attacker must control the
end of the file. The `phar://` stream wrapper does not check the file extension; it
parses the file format.

The "Don't automatically unserialize Phar metadata" RFC
(https://wiki.php.net/rfc/phar_stop_autoloading_metadata) shipped in PHP 8.0
(2020). After 8.0, only explicit calls to `Phar::getMetadata()` and
`PharFileInfo::getMetadata()` trigger the deserialization. Stream-wrapper
file operations no longer do.

This **does not** eliminate the gadget primitive: applications that call
`Phar::getMetadata()` are still vulnerable, and **PHP 7.x is still widely
deployed**. PHP 7.4 reached EOL November 2022, but the long tail of
un-upgraded shared hosting, managed Magento, managed WordPress, and
enterprise CMS deployments means Phar deserialization remains relevant for
assessment work.

The `phar.readonly` `php.ini` directive (default `1`) prevents the PHP
process from *creating* Phar archives; it does **not** prevent reading them.

### Gadget chains — the PHPGGC catalog

Charles Fol's PHPGGC (https://github.com/ambionics/phpggc) is the canonical
PHP gadget-chain library. It includes ready-made RCE chains for: CodeIgniter
(4.x), CakePHP, Doctrine (ORM + Common + Lexer), Drupal,
**Guzzle** (`FnStream`), Laravel (5.x through 11.x — multiple chains per major version),
Magento (1, 2), Monolog (`SyslogUdpHandler`),
Phalcon, Slim, SwiftMailer (CVE-2024-28859 Symfony 1 chain
via `Swift_KeyCache_DiskKeyCache::__destruct`), Symfony (1 through 5),
Twig, WordPress (`WP_Hook` and PHP-meta gadgets), Yii (1, 2), Zend Framework
(1, 2).

Chains can be composed: an outer Guzzle `FnStream` can wrap a Monolog inner
that wraps a Doctrine inner-inner.

### Real-world examples

- **WordPress < 5.0.1** (CVE-2018-20148) — author-to-RCE via Phar
  deserialization of attachment thumbnail paths (Thomas 2018).
- **TYPO3 < 9.5.8** (CVE-2019-12747) — authenticated backend
  deserialization in FormEngine / DataHandler.
- **phpBB 3.2.3** (Sonar disclosure,
  https://blog.sonarsource.com/phpbb3-phar-deserialization-to-remote-code-execution/)
  — admin-CP-to-RCE via `phar://` in an image-resize call.
- **SuiteCRM** (Snyk disclosure) — Phar deserialization via document upload.
- **CVE-2024-28859 / CVE-2024-28861** (darkpills) — Symfony 1
  Swift_KeyCache and `sfNamespacedParameterHolder` gadget chains; contributed to PHPGGC.
- **CVE-2024-55555** (Invoice Ninja) — Laravel `decrypt()` auto-`unserialize`-s
  decrypted data; an attacker who recovers `APP_KEY` can mint encrypted
  gadget payloads.
- **CVE-2025-54236** ("SessionReaper" Magento 2 / Adobe Commerce) — pre-auth
  improper input validation in the Web API `ServiceInputProcessor`, which
  deserializes nested input types.

### Defensive counter-patterns

1. **Never call `unserialize()` on untrusted input.** First-rank rule. JSON
   is the safe alternative; msgpack works too.
2. **If you must `unserialize`, pass `['allowed_classes' => false]`** — turns
   the result into `__PHP_Incomplete_Class` for any object, blocking
   magic-method dispatch. For specific classes:
   `['allowed_classes' => ['MyClass']]`.
3. **Sign serialized payloads.** HMAC-SHA256 over the blob with a server-only
   key; verify with `hash_equals()` (§7) before `unserialize`. Symfony's
   `Cookie` component and Laravel's encrypted cookies do this.
4. **Avoid `Phar::getMetadata()` on user-influenced Phar files.** If you
   must, extract metadata as JSON, not serialized PHP.
5. **Set `phar.readonly = 1`** and **forbid `.phar` uploads at the
   web-server level** — defense in depth against an attacker manufacturing
   Phar archives via a separate upload bug.
6. **Audit autoload entry points.** Every class in every Composer
   dependency is reachable from `unserialize`. Reducing dependency count
   reduces gadget surface.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: unserialize($USER_INPUT)
    - pattern: unserialize($USER_INPUT, ...)
  - metavariable-pattern:
      metavariable: $USER_INPUT
      patterns:
        - pattern-either:
            - pattern: $_GET[...]
            - pattern: $_POST[...]
            - pattern: $_REQUEST[...]
            - pattern: $_COOKIE[...]
            - pattern: file_get_contents(...)
```

Heuristic: any hardcoded `phar://` literal in production code is a
review-worthy signal. Psalm `TaintedUnserialize` rule catches direct cases.

---

## 5. PHP filter chains and stream wrappers

PHP's I/O subsystem (Streams API, https://www.php.net/manual/en/intro.stream.php)
abstracts over file URLs, network URLs, archive formats, and meta-wrappers
that perform in-stream transformations:

| Wrapper | Default | Purpose |
|---------|---------|---------|
| `file://` | on | Local filesystem |
| `http://` / `https://` | on if `allow_url_fopen` | Remote HTTP |
| `ftp://` / `ftps://` | on if `allow_url_fopen` | Remote FTP |
| `php://stdin`, `stdout`, `stderr`, `input`, `output`, `fd/N` | on | Process / FD |
| `php://memory`, `php://temp` | on | In-memory / temp-backed buffers |
| `php://filter/...` | on | The filter-chain meta-wrapper |
| `phar://` | on | Phar archive contents |
| `zip://` | on | Zip-archive contents |
| `compress.zlib://`, `compress.bzip2://` | on if extension | Compressed file |
| `data://` | configurable | Inline RFC2397 data URI |
| `glob://` | on | Glob iteration |
| `expect://` | requires PECL `expect` | Process spawning |

### Why it's a footgun — file functions become multi-modal attack surfaces

`file_get_contents`, `fopen`, `include`, `require`, `readfile`, `file`,
`copy`, `getimagesize`, and friends accept stream-wrapper URIs **by default**.
The same `include($path)` line is LFI, RFI, Phar deserialization, or
filter-chain RCE depending on whether `$path` is `/etc/passwd`,
`http://attacker/`, `phar://upload.jpg/`, or
`php://filter/.../resource=/etc/passwd`.

### `php://filter/...` — the filter-chain RCE primitive

The most consequential PHP-specific file-inclusion finding of the last five
years. The `php://filter/` wrapper applies a chain of encoding
transformations to a target resource as it is read. Each transformation is
a "filter": `convert.base64-encode`, `convert.base64-decode`,
`convert.iconv.SRC.DST`, `zlib.deflate`, `zlib.inflate`, `string.toupper`,
`string.tolower`, `string.rot13`, `dechunk`, and several dozen
`convert.iconv.*` charset converters.

Full URI grammar:
`php://filter/[read|write]=filter1|filter2|.../resource=...`

The technique (credited to a 2021 CTF write-up by loknop; walked through in
Wavestone's Barb'hack 2022 CTF write-up,
https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/)
shows that **`include()` on a fully-attacker-controlled `php://filter/` URI is
universal RCE** — independent of any application logic, file content on
disk, or existing gadget. The trick exploits a property of the
`convert.iconv.UTF8.CSISO2022KR` filter: it prepends the output with a
specific four-byte ANSI escape sequence (`\x1b$)C`). By chaining base64
decode/encode filters around the iconv, the attacker shifts the prepended
bytes through the base64 alphabet, producing arbitrary characters at the
start of the output. By chaining such filter sequences end-to-end, the attacker
synthesizes arbitrary PHP source code in the output stream — which
`include()` then parses and executes.

The technique requires (1) `include` / `require` / `include_once` whose path
argument is fully or prefix-controlled, (2) the `php://filter/...` wrapper
enabled (default-on), and (3) `convert.iconv.*` filters available (default-on
when iconv is enabled, the universal default).

No file on disk is needed; no upload bug is needed; no existing gadget is
needed. The technique works against any application with the file-inclusion
primitive. The Synacktiv `php_filter_chain_generator`
(https://github.com/synacktiv/php_filter_chain_generator) is the canonical
exploit-generator CLI.

### The Synacktiv error-based file-read oracle

A separate, equally consequential primitive: even **without** an `include`,
the filter wrapper enables arbitrary file read via an error-based oracle.
First surfaced by @hash_kitten at DownUnderCTF 2022; Synacktiv productized
it (https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle).

The trick: chained `convert.iconv.*` filters can exponentially expand the
target file's content (repeated `UCS-4`
conversions), triggering PHP's memory-limit exception. The first
character of the file determines whether the memory-blow happens — making
the memory error a 1-bit oracle on a chosen character position. By varying
the filter chain, the attacker reads the file one character at a time.

Applicability: any code path that performs **any** file operation on a
fully-attacker-controlled URI is a file-read sink. The Synacktiv CLI
(https://github.com/synacktiv/php_filter_chains_oracle_exploit) exfiltrates
entire files one character at a time (Synacktiv's demo leaked a
746-character file in around 14k requests).

### `data://`, `expect://`, `file://`

- **`data://text/plain;base64,...`** — inline payload. If `allow_url_include`
  is on (rare in production, default off), this is `include()` → RCE.
- **`expect://command`** — spawns a process. Only available if PECL `expect`
  is installed; rare in modern PHP.
- **`file:///etc/passwd`** — explicit file URI; useful when the application
  strips or interprets bare-path strings differently.

### Defensive counter-patterns

1. **Never pass user input as a stream-wrapper URI.** `include`, `require`,
   `file_get_contents`, `fopen`, `readfile`, `copy`, `getimagesize` arguments
   should be fully-validated application-internal paths. Stripping the
   user-input portion is **not** sufficient — the wrapper prefix can be
   smuggled via prefix-controlled paths
   (`php://filter/resource=user_path`).
2. **Allowlist file basenames** and canonicalize via `realpath()` with a
   prefix-check against permitted directories. Handle the `false` return
   from `realpath` explicitly.
3. **Set `allow_url_fopen = Off` and `allow_url_include = Off`** in
   production. This disables `http://` / `https://` / `ftp://` stream
   wrappers but does **not** disable `php://filter/...` or `phar://`. The
   filter-chain RCE works regardless of these directives.
4. PHP does not provide a built-in `php.ini` directive to disable
   `php://filter`. Suhosin or a custom stream-wrapper unregister can do it
   where you control runtime configuration.

### Real-world examples

- **MISP arbitrary file read** (Synacktiv advisory) — filter-chain oracle.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: include($USER)
    - pattern: include_once($USER)
    - pattern: require($USER)
    - pattern: require_once($USER)
    - pattern: file_get_contents($USER)
    - pattern: fopen($USER, ...)
    - pattern: readfile($USER)
    - pattern: copy($USER, ...)
```

---

## 6. Variable variables, `$$var`, `extract()`, reference assignment

PHP supports three forms of variable indirection that turn strings into
variable names:

1. **`$$name`** — variable variables. `$$name` where `$name = "foo"` reads
   `$foo`.
2. **`extract($array)`** — promotes every key in `$array` to a local variable.
   Default flags overwrite existing variables.
3. **`compact("var1", "var2")`** — the inverse: gathers named variables into
   an associative array.

### Default behavior — implicit variable creation

`$$name = $value` is a one-liner that, when `$name` is attacker-controlled,
creates an attacker-named variable. `extract($_GET)` imports all GET
parameters into local variables, overwriting any same-named locals.

### Why it's a footgun — turns local scope into attacker scope

```php
function authenticate($username, $password) {
    $admin = false;
    extract($_GET);                            // attacker passes ?admin=1
    if (check_password($username, $password)) {
        return true;
    }
    if ($admin) {                              // attacker overwrote $admin
        return true;
    }
    return false;
}
```

The `extract($_GET)` line silently overwrites the `$admin = false` local.
Attacker sends `?admin=1` and bypasses authentication.

Variants:

```php
foreach ($_POST as $key => $value) {
    $$key = $value;                            // manual register_globals
}
extract($_REQUEST, EXTR_OVERWRITE);            // explicit overwrite
parse_str($_SERVER['QUERY_STRING']);           // single-arg parse_str
                                               // (removed PHP 8.0)
```

The single-argument `parse_str($qs)` form (no destination array) was
deprecated in 7.2 and removed in 8.0. The two-argument form
`parse_str($qs, $result)` is safe.

### `register_globals` — historical context

PHP versions before 4.2.0 shipped with `register_globals = On`. The runtime auto-
imported `$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER`, `$_ENV` into the
top-level scope. A request to `page.php?admin=1` set `$admin = "1"`.
Disabled by default in 4.2 (2002), deprecated in 5.3 (2009), removed in
5.4 (2012). The *patterns* that register_globals enabled — relying on
top-level `$foo` having expected initialization — survived: the
`extract` / `$$` / `parse_str` forms are the descendant primitives.

### Reference-assignment quirks

```php
$a = 1; $b = $a; $b = 2;          // $a is still 1
$c = 1; $d = &$c; $d = 2;          // $c is now 2
```

`foreach ($array as &$value)` — the loop variable is a reference into the
array. Failing to `unset($value)` after the loop leaves a dangling
reference; if `$value` is reused later, mutations bleed back into the
array. Produces hard-to-diagnose authorization bugs in role-manipulation
code.

### Defensive counter-patterns

1. **Never call `extract($_GET)`, `extract($_POST)`, or `extract($_REQUEST)`.**
   No legitimate use in modern PHP. Name variables explicitly.
2. **If `extract` is unavoidable on a curated array, pass `EXTR_SKIP`** to
   prevent overwriting locals. Better: extract into a prefix with
   `EXTR_PREFIX_ALL`.
3. **Avoid `$$var` in security code.** Refactor to explicit `if`-chain or
   `match`.
4. **Use `parse_str($qs, $result)` with explicit destination array.**
5. **Initialize all variables before user-input handling.** `$is_admin = false`
   BEFORE any `extract` defends against attacker overwrite.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: extract($_GET)
    - pattern: extract($_POST)
    - pattern: extract($_REQUEST)
    - pattern: extract($_COOKIE)
    - pattern: extract($_SERVER)
    - pattern: parse_str($X)              # single-arg form
    - pattern: $$VAR = ...
```

---

## 7. Loose typing in security-critical contexts

### Numeric-string parsing primitives

#### `is_numeric()`

```php
is_numeric("0e123")     // true — scientific notation
is_numeric("0x1F")      // false in modern PHP — hex literal not numeric
is_numeric("  42")      // true — leading whitespace ignored
is_numeric("42  ")      // true — trailing whitespace ignored from PHP 8.0
is_numeric(".5")        // true
is_numeric("1e10")      // true — scientific
```

The "looks like a number" set is broad enough that `is_numeric` + `==`
reintroduces the magic-hash class: `is_numeric("0e123") && "0e123" == "0e456"`
is true.

#### `intval($string, $base = 10)`

```php
intval("42 abc")   // 42 — stops at first non-digit
intval("abc 42")   // 0 — no leading digits
intval("0x1A")     // 0 — without base 0, "0x" is not parsed as hex prefix
intval("0x1A", 0)  // 26 — base 0 auto-detects "0x" prefix
intval("0123", 0)  // 83 — base 0 auto-detects leading-zero octal
intval("1e10")     // 10000000000 — scientific notation parsed (PHP 7.1+)
intval(true)       // 1
intval([1, 2])     // 1 — non-empty array
```

Common confusion: `intval($s) > 0` passes for "42 abc" but fails for "abc 42"
— silently. `intval` returns 0 on parse failure, not `false`.

#### `floatval` and locale sensitivity

`floatval` does not recognise a locale's comma decimal separator, and
before PHP 8.0 float-to-string casts used the locale's separator, so a
float → string → `floatval` round trip under such a locale loses the fraction.

### `password_verify` vs `==`

```php
$stored_hash = "$2y$10$...";        // bcrypt hash from DB

// WRONG:  if ($user_input == hash_password($stored_hash))    // timing-vulnerable
// WRONG:  if (hash_password($user_input) === $stored_hash)   // bcrypt has random salt
// RIGHT:  if (password_verify($user_input, $stored_hash))
```

`password_verify` (PHP 5.5+) internally extracts salt and cost from the hash
blob, recomputes bcrypt, and performs constant-time byte comparison.
Anthony Ferrara's `password_hash` RFC
(https://wiki.php.net/rfc/password_hash) was the motivation: pre-5.5,
developers had to write the comparison manually and constantly got it wrong.

### `hash_equals` for HMAC and signature checks

```php
$expected = hash_hmac('sha256', $body, $secret);
$received = $_POST['signature'];

// WRONG:  if ($expected == $received)        // type-coerces; magic-hash class
// WRONG:  if ($expected === $received)       // type-strict but TIMING-VULNERABLE
//                                            // (byte-by-byte short-circuit on mismatch)
// RIGHT:  if (hash_equals($expected, $received))
```

`hash_equals` (PHP 5.6+) is constant-time. Both arguments must be strings;
the `$known_string` should be the first argument per the manual.

Rouven Weßling's timing-attack RFC (https://wiki.php.net/rfc/timing_attack)
and Anthony Ferrara's blog post "It's All About Time"
(https://blog.ircmaxell.com/2014/11/its-all-about-time.html) walk through
the primitive: with statistical sampling (about 49,000 samples to detect
~15 ns differences remotely), a secret can be recovered byte-by-byte.

### Defensive counter-patterns

1. **Use `filter_var` with explicit type and flags** for numeric parsing:
   ```php
   $id = filter_var($_GET['id'], FILTER_VALIDATE_INT,
       ['options' => ['min_range' => 1]]);
   if ($id === false) { reject(); }
   ```
   Returns `false` (not `0`) on parse failure.
2. **Always `password_verify` for plaintext-to-hash.**
3. **Always `hash_equals` for HMAC / token / signature.**
4. **Bias new code to `declare(strict_types=1);`** at the top of every file
   — surfaces implicit-coercion bugs at call time.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: $X == hash_hmac(...)
    - pattern: hash_hmac(...) == $X
    - pattern: $X === hash_hmac(...)     # type-safe but timing-vulnerable
    - pattern: hash_hmac(...) === $X
```

---

## 8. Function callables and `call_user_func`

PHP supports four callable forms
(https://www.php.net/manual/en/language.types.callable.php):

1. **String** — a function name, `"function_name"`.
2. **Array** — `[$object, "method"]` or `["ClassName", "method"]`.
3. **Static-string** — `"ClassName::method"`.
4. **Closure / arrow function** — anonymous forms.

Historical:
- `create_function` — produced a closure from a string body; removed in PHP
  8.0. Implemented internally as `eval`.
- Magic-method-based pseudo-callables via `__invoke`.

### Default behavior — callables resolve dynamically

`call_user_func`, `call_user_func_array`, `array_map`, `array_filter`,
`array_walk`, `usort`, `preg_replace_callback` — all resolve the callable
at call time. There is no static binding.

### Why it's a footgun — any attacker-controlled string is RCE

```php
$action = $_GET['action'];
call_user_func($action);          // attacker-supplied function name
```

If `$action` is `"system"` (or `"passthru"`, `"shell_exec"`, `"exec"`,
`"eval"`, `"assert"`, `"create_function"` pre-PHP-8, ...), the call becomes
RCE. Even non-shell functions are dangerous:

- `call_user_func("phpinfo")` — discloses configuration
- `call_user_func("file_get_contents", "/etc/passwd")` — file read
- `call_user_func("unserialize", $_POST['x'])` — pivot into deserialization
- `call_user_func("eval", $_POST['x'])` — direct RCE if no quoting

Variants:

```php
$cb = $_GET['cb'];
$result = $cb(...);                       // direct callable invocation
array_map($cb, $list);                    // dispatched into array_map
preg_replace_callback($re, $cb, $haystack);  // callback dispatch
usort($array, $cb);                       // comparison callback
```

The `preg_replace_callback($re, $cb, $haystack)` form is tempting because
it's the documented replacement for the removed `/e` modifier — but if `$cb`
is attacker-controlled, it's RCE.

### `eval` and `assert` — historical equivalence

`eval($code)` evaluates a string as PHP code. **No legitimate production
use case** on attacker-influenced input.

`assert($expression)` — pre-PHP-7.2, when passed a string argument,
evaluated the string as PHP code. This made `assert($_GET['x'])` an RCE
primitive. String-eval was deprecated in 7.2 and removed in 8.0; modern
`assert` takes a boolean. Pre-8.0 codebases retain the historical primitive.

`create_function($args, $code)` produced an anonymous function from two
string arguments. Internally `eval`. Removed in 8.0; deprecated in 7.2.
Legacy codebases still ship it; treat all extant calls as `eval`.

### Defensive counter-patterns

1. **Never accept a callable name from user input.** For fixed-set operations,
   use explicit `match`:
   ```php
   $sort_fn = match ($_GET['sort']) {
       'asc'  => fn($a, $b) => $a <=> $b,
       'desc' => fn($a, $b) => $b <=> $a,
       default => throw new InvalidArgumentException(),
   };
   ```
2. **Allowlist callable names** when dispatch is unavoidable.
3. **Avoid `eval`, `assert($string)`, `create_function`.** No exceptions.
4. **Prefer first-class callable syntax** (PHP 8.1+): `strlen(...)`,
   `Foo::bar(...)` — same semantics as `Closure::fromCallable()`.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: call_user_func($USER, ...)
    - pattern: call_user_func_array($USER, ...)
    - pattern: array_map($USER, ...)
    - pattern: usort(..., $USER)
    - pattern: preg_replace_callback($RE, $USER, ...)
    - pattern: eval($USER)
    - pattern: assert($USER)
    - pattern: create_function($A, $USER)
    - pattern: $USER(...)
```

---

## 9. Regex with `e` modifier (historical) + `preg_*` corpus

### The `/e` modifier (pre-PHP-7.0)

```php
preg_replace("/(\w+)/e", "strtoupper('$1')", $input);
```

The replacement string was **evaluated as PHP code**, with backreferences
substituted in. Direct user-controlled `eval` if any portion of the
replacement was attacker-influenced:

```php
preg_replace("/__(.+?)__/e", "strtoupper('$1')", $_GET['text']);
// Attacker: __'.eval($_GET['cmd']).'__
//          → strtoupper('') . eval($_GET['cmd']) . strtoupper('')
//          → RCE
```

`/e` was deprecated in PHP 5.5 (2013) and removed in PHP 7.0 (2015) —
https://wiki.php.net/rfc/remove_preg_replace_eval_modifier. Notable
real-world impacts: RoundCube webmail; many WordPress plugins for image-tag,
shortcode, and templating.

### Modern replacement: `preg_replace_callback`

```php
preg_replace_callback("/__(.+?)__/", function ($matches) {
    return strtoupper($matches[1]);
}, $_GET['text']);
```

Caveat: if the callback is *dynamically chosen*, the underlying
`call_user_func` primitive (§8) applies.

### PCRE backtracking and regex DoS

PHP's PCRE is recursive-backtracking and vulnerable to **catastrophic
backtracking** — exponential time growth. Full treatment in
`redos_algorithmic_dos_expertise.md`; PHP-specific:

- `pcre.backtrack_limit` defaults to **1,000,000** and `pcre.recursion_limit`
  to **100,000** — permissive enough that pathological patterns consume seconds per request.
- PCRE JIT (`pcre.jit = 1`, default-on since PHP 7.0) accelerates the *fast*
  path but does not change worst-case complexity.

Vulnerable patterns: `(a+)+`, `(a*)*`, `(\w+)*` on input `"aaaaa...!"` —
all exponential.

### `preg_match` return-value confusion

```php
$result = preg_match("/regex/", $input);
if ($result) { ... }                   // true if match; misses parse error
if ($result !== false) { ... }         // distinguishes 0 (no match) from false (parse error)
```

`preg_match` returns `1`, `0`, or `false`. Naïve `if ($result)` treats parse
errors as no-match, silently missing validation failures.

### Defensive counter-patterns

1. **Use `preg_replace_callback`** over `/e` (mostly historical now).
2. **Always check `preg_match` for `=== false`** before treating boolean.
3. **Audit user-supplied regex patterns.** `preg_match` accepts user-
   controlled pattern argument — DoS-prone and (in pre-PHP-7 code with `/e`)
   RCE-prone.
4. **Lower `pcre.backtrack_limit`** to 10,000–100,000 in security-critical
   deployments.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern-regex: 'preg_replace\([^,]*?/e[^,]*,'
    - pattern: preg_replace($PATTERN, $USER, ...)
    - pattern: preg_match($USER_RE, ...)
```

---

## 10. Output, escaping, and template-engine footguns

### `htmlspecialchars()` default-flag history

| PHP version | Default flags |
|-------------|---------------|
| < 5.4 | `ENT_COMPAT \| ENT_HTML401` (double quotes only) |
| 5.4 - 8.0 | `ENT_COMPAT \| ENT_HTML401` |
| 8.1+ | `ENT_QUOTES \| ENT_SUBSTITUTE \| ENT_HTML401` |

The pre-8.1 default did not encode single quotes, so output emitted into a
single-quoted attribute (`<input value='$x'>`) was XSS-vulnerable even with
`htmlspecialchars` applied. **Modern usage should always be explicit**:

```php
htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

`ENT_SUBSTITUTE` replaces invalid UTF-8 sequences with U+FFFD rather than
returning an empty string (the default before 8.1).
Without it, an attacker-supplied invalid UTF-8 sequence can produce empty
escape output, bypassing the encoder.

### `addslashes` is NOT SQL-safe

`addslashes($string)` prefixes `'`, `"`, `\`, NUL with backslash. It is
**not** a SQL escape function. It doesn't handle character-set–dependent
SQL-quote smuggling; doesn't escape `%` or `_` for LIKE; doesn't address
multi-byte SQL-injection via GBK/CP932/similar.

**Use prepared statements** (`PDO::prepare`, `mysqli::prepare`). If escaping
is unavoidable, use `mysqli_real_escape_string` (character-set-aware via
`mysqli_set_charset`).

### `urlencode` vs `rawurlencode`

```php
urlencode("hello world+&=")     // "hello+world%2B%26%3D"  (form-urlencoded)
rawurlencode("hello world+&=")  // "hello%20world%2B%26%3D" (URI path segment)
```

For URL path segments, use `rawurlencode`. For query-string values,
`http_build_query` is most idiomatic.

### Template-engine footguns

| Engine | Default auto-escape | Notes |
|--------|---------------------|-------|
| Twig | `html` | Symfony default; opt out via `\|raw` |
| Blade | `html` | Laravel default; `{!! $x !!}` for raw |
| Smarty 3+ | configurable | `$smarty->escape_html = true` |
| Smarty 2 | off | Legacy; needs explicit `\|escape` everywhere |

Cross-engine SSTI corpus in `template_code_injection_expertise.md`.
PHP-specific notes: `{!! $x !!}` in Blade and `{{ $x|raw }}` in Twig are
frequent XSS findings; Smarty `{php}...{/php}` (legacy) allows arbitrary
PHP code in templates; `Twig\Environment::createTemplate($source)` with
user-controlled `$source` is template-injection RCE.

### Defensive counter-patterns

1. **Use `htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`**
   explicitly in every output path. Don't rely on PHP-version defaults.
2. **Use prepared statements for SQL.** Treat `addslashes` and
   `mysqli_real_escape_string` as deprecated for SQL.
3. **Configure template engines for HTML auto-escape**; audit for `|raw` /
   `{!! !!}` markers.
4. **laminas-escaper** (rules follow OWASP recommendations) provides
   context-specific escapers:
   `escapeHtml`, `escapeHtmlAttr`, `escapeJs`, `escapeUrl`, `escapeCss`.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: echo $USER                        # unescaped echo
    - pattern: htmlspecialchars($X)              # missing ENT_QUOTES (legacy)
    - pattern: htmlspecialchars($X, ENT_COMPAT, ...)
    - pattern: addslashes($USER)                 # heuristic SQL context
```

---

## 11. Configuration footguns (`php.ini`)

| Directive | Default | Notes |
|-----------|---------|-------|
| `allow_url_include` | Off (since 5.2) | Never enable. Direct RFI when on. |
| `allow_url_fopen` | On | Enables `http://`/`https://`/`ftp://` for file functions. |
| `register_globals` | removed in 5.4 | Verify removal in PHP-5-era codebases. |
| `magic_quotes_gpc` | removed in 5.4 | Historical. |
| `safe_mode` | removed in 5.4 | Never worked as a sandbox. |
| `disable_functions` | (empty) | Defense in depth; many public bypasses. |
| `open_basedir` | (empty) | Defense in depth; PHP team says "not a security feature." |
| `expose_php` | On | Emits `X-Powered-By: PHP/8.x` header. Set Off. |
| `display_errors` | On | Must be Off in production. |
| `session.cookie_httponly` | Off | Set 1. |
| `session.cookie_secure` | Off | Set 1. |
| `session.cookie_samesite` | (empty) | Set `Lax` or `Strict`. |
| `session.use_strict_mode` | Off | Set 1 — rejects client-supplied session IDs. |
| `phar.readonly` | On (1) | Prevents Phar creation; does not prevent reads. |

`disable_functions` bypasses (https://www.tarlogic.com/blog/bypass-disable_functions-open_basedir/)
include: `mail()` with `LD_PRELOAD`, `imap_open()` with `-X command`
injection, putenv+dl in older PHP, PHP-FPM Unix-socket abuse. Treat as
defense in depth.

`open_basedir` bypasses (https://www.bencteux.fr/posts/open_basedir/) are
many; PHP's security classification does not treat open_basedir bypasses
as security issues (https://bugs.php.net/bug.php?id=81715). Useful for accident-avoidance,
not adversarial isolation.

Recommended production session config:

```ini
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Lax
session.use_strict_mode = 1
session.use_only_cookies = 1
expose_php = Off
display_errors = Off
log_errors = On
```

### Defensive counter-patterns

1. **Maintain a baseline production `php.ini`** with the directives above
   set. Version-control it.
2. **Run `php --ini`** in CI to verify settings against an expected manifest.
3. **Treat `disable_functions` and `open_basedir` as defense-in-depth**, not
   as security boundaries.

---

## 12. Filesystem operations

PHP's filesystem API
(https://www.php.net/manual/en/book.filesystem.php) is one of the broadest
in any language. All file-operating functions except `realpath` accept
stream-wrapper URIs (§5). `realpath` resolves through the local filesystem
only.

### `include` with a path is a code-execution sink

```php
include $path;   // executes PHP file at $path
```

If `$path` is user-controlled, this is: LFI (local-path execution of any
`.php` on disk, including uploaded files), RFI (if `allow_url_include` is
on), Phar deserialization (pre-PHP-8.0, even without `.phar` extension), or
filter-chain RCE (universal — §5).

### Null-byte truncation (PHP < 5.3.4)

```php
include "/var/www/uploads/" . $_GET['file'] . ".jpg";
// Attacker: ?file=../../../etc/passwd%00
// → pre-5.3.4 PHP truncated at null byte
// → include "/var/www/uploads/../../../etc/passwd"
```

Fixed in PHP 5.3.4 (2010); modern PHP throws a warning and refuses. However,
stream wrappers and some extensions still have null-byte issues — see
CVE-2025-1220 (Hadrian.io) for a 2025-disclosed `parse_url` null-byte
allowlist bypass.

### `realpath` quirks

- Returns `false` on non-existent paths.
- Resolves through symlinks (no flag to disable).
- Does not resolve stream-wrapper URIs — `realpath("phar://x.phar/y")`
  returns `false`.

The symlink-following default is the source of many filesystem-confusion
vulnerabilities. An attacker who can plant a symlink in a writable directory
can redirect a subsequent file operation to an arbitrary path.

### `move_uploaded_file` and validation gaps

```php
move_uploaded_file($_FILES['upload']['tmp_name'],
                   "/uploads/" . $_FILES['upload']['name']);
```

`$_FILES['upload']['name']` is **client-supplied**, not sanitized by PHP. An
attacker can supply `"../../config/shell.php"` as the filename. The PHP
manual notes this; the documentation example shows `basename(...)` on the
filename, which most developer-copied code omits.

Correct pattern:

```php
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, ['jpg', 'png', 'gif'], true)) { abort(); }
$safe_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['upload']['tmp_name'], "/uploads/" . $safe_name);
```

### Symlink-following and `tempnam`

`unlink`, `rename`, `copy`, `chown`, `chmod`, `stat` all follow symlinks by
default. Race conditions where a file is replaced with a symlink between
two operations are a canonical privilege-escalation pattern (cross-link to
`shell_injection_expertise.md` for the TOCTTOU framing).

`tempnam($dir, $prefix)` creates a temp file with a unique name built
from `$prefix`. `tmpfile()` (returns a file handle on a temp file with no path
exposed) is preferred for security-sensitive work.

### Defensive counter-patterns

1. **Never pass user-controlled paths to file operations directly.**
   Canonicalize via `realpath`, then prefix-match against an allowlist of
   permitted directories. Reject the `false` return from `realpath`.
2. **`basename($_FILES[...]['name'])`** before constructing upload paths.
3. **`random_bytes(16)`-derived filenames** for uploads; don't preserve the
   client basename.
4. **Allowlist extension checks**, not blocklist.
5. **`tmpfile()` instead of `tempnam()`** for security-sensitive temp files.
6. **Audit symlink behavior** in writable working directories — mitigate via
   tempdir + atomic `rename`.

### Detection

```yaml
patterns:
  - pattern-either:
    - pattern: include($_GET[...])
    - pattern: include($_POST[...])
    - pattern: include($_REQUEST[...])
    - pattern: file_get_contents($USER)
    - pattern: fopen($USER, ...)
    - pattern: readfile($USER)
    - pattern: move_uploaded_file($_FILES[...]['tmp_name'], $_FILES[...]['name'])
    - pattern: move_uploaded_file($_FILES[...]['tmp_name'], $DIR . $_FILES[...]['name'])
```

---

## 13. PHP-FPM, Zend Engine, and the Composer ecosystem

### PHP-FPM as production target

PHP-FPM is the production runtime for nearly all modern PHP — replacing
mod_php. Architecturally:

- Listens on Unix socket or TCP for FastCGI requests from nginx / Apache.
- Forks a pool of long-lived workers that handle many requests each.
- Workers share OPcache (bytecode cache); poisoned OPcache entries persist
  across requests within a worker pool.

PHP-FPM-specific surface:

- **Unix-socket-to-anyone**. If the FPM socket is reachable by any process
  other than the web server (typical in shared hosting or misconfigured
  containers), an attacker with code-exec in any language can spawn
  arbitrary PHP via FastCGI directly to the socket — bypassing every
  web-server-layer control.
- **`ALL_HEADERS` to PHP**. PHP-FPM forwards all HTTP headers as CGI
  environment variables prefixed `HTTP_`. `X-Forwarded-For` becomes
  `$_SERVER['HTTP_X_FORWARDED_FOR']`. Custom headers are auto-imported;
  nothing filters them.
- **`PHP_ADMIN_VALUE` / `PHP_VALUE` FastCGI parameters**. Override `php.ini`
  per-request. CVE-2019-11043 (PHP-FPM `env_path_info` underflow under an
  nginx `fastcgi_split_path_info` config)
  showed an attacker could smuggle FastCGI parameters via nginx
  misconfiguration.

### OPcache

OPcache is the PHP bytecode cache; default-on. Cached bytecode is keyed by
file path and mtime. Security-relevant:

- **OPcache poisoning via timestamps**. If an attacker can write to a `.php`
  file and set its mtime to match the cached version, OPcache may serve
  stale bytecode that doesn't match the on-disk source. Useful for backdoor
  persistence after RCE.
- **`opcache.file_cache` mode** writes bytecode to disk. If the cache
  directory is attacker-writable, cached `.bin` files can be replaced — and
  on next load, PHP executes attacker bytecode.

### Composer + autoload + supply chain

Composer is the PHP package manager; `composer.json` declares deps,
`composer.lock` pins versions, `vendor/autoload.php` provides PSR-4 / PSR-0
autoload.

Supply-chain concerns specific to PHP (cross-link
`cicd_supply_chain_expertise.md` §5):

- **Packagist** (https://packagist.org/) — primary Composer registry. No
  package signing. Manifest-only layer over GitHub / GitLab / Bitbucket.
- **Typosquatting**. Documented incidents
  (https://www.mend.io/blog/typosquatting-malware-found-in-composer-repository/).
- **Abandoned-package takeovers**. Multiple 2022-2025 incidents.
- **`vendor/` directory committed to source**. Backdoor-injection PR
  becomes a 200-file diff nobody reads.
- **Post-install scripts**. `composer.json` `scripts` keys declare hooks
  that run arbitrary PHP, but only the root package's scripts execute —
  unlike npm `postinstall`, a dependency's `scripts` do not run on install.
  Dependency code-exec during installs and CI comes through Composer
  plugins (hence `allow-plugins` below).
- **Toran Proxy / Private Packagist**. Org-internal mirror — single
  compromise point.

Sonar's two PHP supply-chain advisories
(https://www.sonarsource.com/blog/php-supply-chain-attack-on-composer,
https://www.sonarsource.com/blog/securing-developer-tools-a-new-supply-chain-attack-on-php/)
document Packagist-specific issues. Socket PHP-package launch
(https://socket.dev/blog/introducing-php-and-composer-support) brings real-
time package-content scanning to Composer.

Recommended Composer discipline:

- **Commit `composer.lock`** in application repos.
- **Run `composer audit`** (Composer 2.4+) in CI.
- **Set `allow-plugins`** to an explicit allowlist (Composer 2.2+ refuses
  unallowlisted plugins).
- **Pin major versions**: `"vendor/pkg": "^2.5"`, not `"*"` or
  `"dev-master"`.

### Alternative PHP runtimes

- **Swoole** (https://www.swoole.com/) — coroutine async PHP runtime.
- **RoadRunner** (https://roadrunner.dev/) — Go-based PHP app server.
- **Hyperf** (https://hyperf.io/) — coroutine framework on Swoole.
- **ReactPHP** / **Amp** — event-loop frameworks.

Each adds its own attack surface:

- **Coroutine-shared state**. Coroutines on Swoole / Hyperf share the
  worker's heap; static class state, container singletons, and connection
  pools must be coroutine-safe. Failing to clear request-scoped state
  between coroutines is a session-bleed primitive.
- **Long-lived workers**. Memory leaks, connection-pool exhaustion, and
  stale autoloader-cached state don't exist in PHP-FPM.

---

## 14. Detection patterns (Semgrep + static analysis)

### Semgrep rule catalog

The patterns below capture high-priority sinks. Each should be paired with
metavariable-pattern constraints for user-controlled input.

#### Unserialize with user input

```yaml
- id: php-unserialize-user-input
  pattern: unserialize($X)
  metavariable-pattern:
    metavariable: $X
    patterns:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
          - pattern: $_COOKIE[...]
          - pattern: base64_decode(...)
          - pattern: file_get_contents(...)
```

#### Eval / assert / create_function

```yaml
- id: php-eval-and-friends
  pattern-either:
    - pattern: eval($X)
    - pattern: assert($X)               # string-eval form, pre-PHP-8
    - pattern: create_function(...)     # removed PHP 8.0
```

#### preg_replace with /e

```yaml
- id: php-preg-replace-eval-modifier
  pattern-regex: |
    preg_replace\s*\(\s*['"][^'"]*?/[a-z]*e[a-z]*['"]
```

#### extract / parse_str on user input

```yaml
- id: php-extract-user-input
  pattern-either:
    - pattern: extract($_GET, ...)
    - pattern: extract($_POST, ...)
    - pattern: extract($_REQUEST, ...)
    - pattern: extract($_COOKIE, ...)
    - pattern: parse_str($X)            # single-arg form (removed PHP 8.0)
```

#### Dynamic callable with user input

```yaml
- id: php-call-user-func-user-controlled
  pattern-either:
    - pattern: call_user_func($X, ...)
    - pattern: call_user_func_array($X, ...)
  metavariable-pattern:
    metavariable: $X
    patterns:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
```

#### Loose comparison on hash

```yaml
- id: php-loose-equals-on-hash
  pattern-either:
    - pattern: $X == md5(...)
    - pattern: md5(...) == $X
    - pattern: $X == hash(...)
    - pattern: hash(...) == $X
    - pattern: $X == hash_hmac(...)
    - pattern: hash_hmac(...) == $X
```

#### include / require with user input

```yaml
- id: php-include-user-input
  pattern-either:
    - pattern: include($X)
    - pattern: require($X)
    - pattern: include_once($X)
    - pattern: require_once($X)
  metavariable-pattern:
    metavariable: $X
    patterns:
      - pattern-either:
          - pattern: $_GET[...]
          - pattern: $_POST[...]
          - pattern: $_REQUEST[...]
          - pattern: $_COOKIE[...]
```

### Static-analysis tools

- **PHPStan** (https://phpstan.org/) at level 9; `phpstan-strict-rules` bans
  loose comparisons.
- **Psalm** (https://psalm.dev/) — `@psalm-taint-sink` /
  `@psalm-taint-source` docblock taint tracking; enabled via
  `--taint-analysis` or `runTaintAnalysis="true"`.
- **Rector** (https://getrector.com/) — refactoring tool.
- **SonarPHP / SonarQube** — `php:S2068` credentials in source,
  `php:S5547` weak cryptography, etc.

The pattern-construction discipline is covered in
the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview). Avoid duplicating the methodology here; treat
the above as PHP-specific extensions.

---

## 15. Defensive patterns and code-review checklist

When reviewing PHP code, walk this 15-item list. Order is roughly
"most-impactful first" — matching the click-count discipline of
`code_review_expertise.md`.

#### 1. Grep for `unserialize(`

Any call on user-influenced input is RCE pending gadget. Ask: "Does the
application's classpath include Symfony, Laravel, Monolog, Guzzle, or
Doctrine?" If yes, assume an exploitable gadget exists (PHPGGC will produce
it).

#### 2. Grep for `eval(`, `assert(` with string arg, `create_function`

Direct code-execution primitives. Any one on user-influenced input is RCE.

#### 3. Grep for `extract(`, `parse_str(` (single-arg)

Canonical authorization-bypass primitive. Variants on `$_GET`, `$_POST`,
`$_REQUEST`, `$_COOKIE`. Single-arg `parse_str($qs)` was removed in PHP 8.0
but extant in legacy.

#### 4. Grep for `$$`, `$_GET[$key]`, `$_POST[$key]`, `$_REQUEST[$key]`

Variable-variable indirection. Any `$$key` with attacker-controlled `$key`
is a variable-assignment primitive — §6.

#### 5. Grep for `==` in comparisons adjacent to `hash`, `hmac`, `md5`, `sha`, `password`, `token`, `nonce`

Loose comparison on cryptographic output is the magic-hash class. Replace
with `hash_equals()` (HMAC) or `password_verify` (passwords). §2, §7.

#### 6. Grep for `include(`, `include_once(`, `require(`, `require_once(`

Any user-influenced argument is LFI / RFI / Phar / filter-chain RCE. §4, §5.

#### 7. Grep for `phar://` literals

Hardcoded `phar://` in production code is review-worthy. Most legitimate use
is CLI tools; production web code rarely needs them.

#### 8. Grep for `php://filter/`, `php://input`, `data://`, `expect://`

Stream-wrapper URIs. Investigate origin and use case.

#### 9. Grep for `system(`, `passthru(`, `shell_exec(`, `exec(`, `popen(`, `proc_open(`, backticks

Shell-execution sinks. Cross-link `shell_injection_expertise.md` for the
metacharacter / argv / terminal-escape framing. `escapeshellcmd` is **weak**
(argument-injection bypasses) — `feedback_escapeshellcmd_weak_sanitizer.md`.

#### 10. Grep for `addslashes(` adjacent to SQL

Not a SQL escape function. Replace with prepared statements.

#### 11. Grep for `htmlspecialchars(` without `ENT_QUOTES`

Pre-8.1 default (`ENT_COMPAT`) didn't encode single quotes or include
`ENT_SUBSTITUTE`. Always:
`htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`.

#### 12. Grep for `move_uploaded_file(` with `$_FILES[...]['name']` in destination

Client-supplied filenames are unsafe destinations. Use server-generated
random names.

#### 13. Grep for `mt_rand`, `rand` in security-sensitive contexts

`rand`/`mt_rand` are NOT cryptographically secure. Use `random_bytes(N)`
(PHP 7.0+) or `random_int($min, $max)`. Cross-link
`cryptography_expertise.md`.

#### 14. Grep for `session_start(` and surrounding session config

Check `session.cookie_httponly`, `session.cookie_secure`,
`session.cookie_samesite`, `session.use_strict_mode`. §11.

#### 15. Audit production `php.ini`

`disable_functions` / `open_basedir` are defense-in-depth, not security
boundaries — but their absence reveals a hardening gap.

### Architectural patterns to encourage

- **`declare(strict_types=1);`** at the top of every file. Forces typed
  function signatures to reject coerced arguments at call time.
- **Single, central input-validation layer** (Symfony Validator, Laravel
  FormRequest, Respect/Validation) — never read `$_GET` / `$_POST` directly
  elsewhere.
- **Auto-escape templates**; audit every `|raw` / `{!! !!}` annotation.
- **Allowlist-based dispatch via `match`** — type-safe, exhaustive, no
  dynamic-callable RCE surface.
- **Hardened session config** (set the five session directives explicitly).
- **`composer audit` in CI** — every PR; gate merge.

### Cross-link to `code_review_expertise.md`

The PHP-specific checklist above operationalizes the methodology in
`code_review_expertise.md`:

- "Heterogeneous auth in single control abstraction" — PHP's `$_SESSION` +
  `$_COOKIE` + custom-header auth mix on a single endpoint.
- "Absolute path handling is always suspicious" — `realpath` + allowlist
  prefix check, §12.
- "Serialization with type handling is suspicious" — the `unserialize` +
  `__wakeup` + Phar + PHPGGC corpus, §3, §4.

---

## 16. Variant analysis — under-explored

### PHP 8 attribute syntax

PHP 8.0 introduced **attributes**
(https://www.php.net/manual/en/language.attributes.php):

```php
#[Route('/admin', methods: ['GET', 'POST'])]
#[IsGranted('ROLE_ADMIN')]
public function admin() { ... }
```

Attributes are inert metadata until reflected. Symfony / Doctrine / Laravel
have adopted attributes for HTTP routes, authz gates, argument resolution,
ORM mapping, validation, caching.

Attribute-driven security concerns:

- **Missing `#[IsGranted]` on new methods.** Attribute-driven authz
  requires the developer to remember the attribute. Easy to miss. Compare
  to method-decorator patterns in Python (Flask / Django) — same audit
  pattern as automated parent-chain detection in AI-assisted authz review.
- **Attribute-target mismatch.** Class-level vs method-level. Some authz
  frameworks read both; inheritance handling varies.
- **Inheritance discovery.** Reflection may or may not walk the chain.
  Child overrides parent method, loses parent's attribute — endpoint
  becomes unauthenticated.

### WeakReference and WeakMap (PHP 7.4+ / 8.0+)

Allow holding references without preventing GC. Security relevance:
minimal in most code, but in long-running processes (Swoole, RoadRunner)
they enable per-request state to be reclaimed without leaking across
coroutines. Edge case: `WeakMap` keyed by request object is clean for
per-request caches; be careful that the key object's lifetime matches the
cache lifetime — premature collection silently invalidates the cache.

### Enums (PHP 8.1+)

```php
enum Role: string {
    case Admin = 'admin';
    case User = 'user';
    case Guest = 'guest';
}
```

Backed enums provide type-safe serialization. `Role::from($string)` throws
on unknown; `Role::tryFrom` returns null on unknown. `match` on enum is
exhaustive — replaces string-comparison authorization.

`__unserialize` is **not** valid on enums (PHP rejects at parse time),
which narrows the gadget surface. But enum-typed properties on serializable
classes can still pivot through their containing class's magic methods.

### Fibers (PHP 8.1+)

Cooperative-scheduling green threads with explicit `Fiber::suspend()` /
`Fiber::resume()`. Security relevance:

- **Fiber state retention across requests** in long-running workers — a
  bug where a fiber's state leaks into a subsequent request is a session-
  bleed primitive.
- **Exception propagation across fiber boundaries.** Uncaught exceptions
  propagate to the resumer.

### Asynchronous PHP — Amp and ReactPHP

Event-loop frameworks layered over Fibers (Amp 3+) or hand-rolled callback
dispatch. One process handles many concurrent connections; per-request
state must be in closures or fiber-local context, not module-level
globals. Standard `set_error_handler` / `set_exception_handler` apply
per-process, not per-connection.

### JIT (PHP 8.0+)

PHP 8.0 added an opcode JIT. Security-relevant only at extreme cases:
JIT-specific bugs, performance side
channels for hot paths in cryptographic code (where you'd use a non-PHP
language anyway).

### Readonly classes (PHP 8.2+)

`readonly class Foo` makes all properties write-once. Reduces gadget
surface — readonly properties can be initialized only once, from the declaring class's scope.
Caveat: `__unserialize` runs in the declaring class's scope and can
initialize readonly properties during unserialization. For security-critical immutability, combine `readonly` with
a custom `__unserialize` that validates allowed state.

### Asymmetric visibility (PHP 8.4+)

PHP 8.4 (November 2024) added asymmetric visibility:
`public private(set) string $name;`. Allows finer-grained property
visibility — an immutability / auditability primitive that lets the
developer prove which code paths can write a sensitive property.

---

## 17. References

### Primary research and writeups (chronological)

- Stefan Esser — Hardened-PHP / Suhosin (https://suhosin.org/,
  https://github.com/sektioneins/suhosin).
- "Month of PHP Bugs" (Stefan Esser, March 2007).
- "Month of PHP Security" (Stefan Esser, May 2010) — included Johannes
  Dahse's RIPS launch.
- Johannes Dahse — "RIPS — A static source code analyser for vulnerabilities
  in PHP scripts" (2010, https://rips-scanner.sourceforge.net/).
- Johannes Dahse — "Simulation of Built-in PHP Features for Precise Static
  Code Analysis" (2014).
- Anthony Ferrara — "It's All About Time"
  (https://blog.ircmaxell.com/2014/11/its-all-about-time.html).
- Anthony Ferrara — `password_hash` RFC
  (https://wiki.php.net/rfc/password_hash).
- Rouven Weßling — `hash_equals` /
  timing-attack-safe comparison (https://wiki.php.net/rfc/timing_attack).
- Sam Thomas — "It's a PHP Unserialization Vulnerability Jim, but not as we
  know it" (Black Hat USA 2018,
  https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf).
- Jean Marsault (Wavestone) — "Barb'hack 2022: Leveraging PHP Local File
  Inclusion to achieve universal RCE"
  (https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/).
- Synacktiv — "PHP filter chains: What is it and how to use it"
  (https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it).
- Synacktiv — "PHP filter chains: file read from error-based oracle"
  (https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle).
- Quarkslab — "PHP deserialization attacks and a new gadget chain in
  Laravel" (https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html).
- Sonar — "PHP Object Injection"
  (https://www.sonarsource.com/blog/php-object-injection); "phpBB 3.2.3
  Phar Deserialization to RCE"
  (https://blog.sonarsource.com/phpbb3-phar-deserialization-to-remote-code-execution/);
  "PHP Supply Chain Attack on Composer"
  (https://www.sonarsource.com/blog/php-supply-chain-attack-on-composer);
  "Securing Developer Tools: A New Supply Chain Attack on PHP"
  (https://www.sonarsource.com/blog/securing-developer-tools-a-new-supply-chain-attack-on-php/).
- Orange Tsai (DEVCORE) — "CVE-2024-4577: Yet Another PHP RCE"
  (https://blog.orange.tw/posts/2024-06-cve-2024-4577-yet-another-php-rce/).
- darkpills — "Hunting for gadget chains in Symfony 1 (CVE-2024-28859,
  CVE-2024-28861)"
  (https://darkpills.com/hunting-for-gadget-chains-in-symfony-1-cve-2024-28859-cve-2024-28861/).
- Daniel "Blaklis" Le Gall + Pentest-Tools — "SessionReaper, CVE-2025-54236
  in Magento 2 & Adobe Commerce"
  (https://pentest-tools.com/blog/sessionreaper-cve-2025-54236-exploit).
- Hadrian.io — "CVE-2025-1220: Null byte trickery bypasses hostname
  allowlists in PHP"
  (https://hadrian.io/blog/cve-2025-1220-null-byte-trickery-bypasses-hostname-allowlists-in-php).

### Tools and gadget libraries

- PHPGGC: https://github.com/ambionics/phpggc
- Synacktiv `php_filter_chain_generator`:
  https://github.com/synacktiv/php_filter_chain_generator
- Synacktiv `php_filter_chains_oracle_exploit`:
  https://github.com/synacktiv/php_filter_chains_oracle_exploit
- Suhosin: https://github.com/sektioneins/suhosin
- RIPS (historical): https://rips-scanner.sourceforge.net/
- PHPStan: https://phpstan.org/
- Psalm: https://psalm.dev/
- SonarPHP: https://github.com/SonarSource/sonar-php
- Rector: https://getrector.com/
- Socket PHP (Composer / Packagist): https://socket.dev/

### PHP RFCs (security-relevant)

- "Saner string to number comparisons":
  https://wiki.php.net/rfc/string_to_number_comparison
- "Don't automatically unserialize Phar metadata":
  https://wiki.php.net/rfc/phar_stop_autoloading_metadata
- "Remove the /e modifier on preg_replace":
  https://wiki.php.net/rfc/remove_preg_replace_eval_modifier
- "Custom object serialization":
  https://wiki.php.net/rfc/custom_object_serialization
- "Timing attack safe string comparison":
  https://wiki.php.net/rfc/timing_attack
- "Password hashing API":
  https://wiki.php.net/rfc/password_hash
- "Explicit octal integer literal notation":
  https://wiki.php.net/rfc/explicit_octal_notation

### Documentation pages cited

- Magic Methods: https://www.php.net/manual/en/language.oop5.magic.php
- Type Juggling:
  https://www.php.net/manual/en/language.types.type-juggling.php
- Type Comparison Tables:
  https://www.php.net/manual/en/types.comparisons.php
- Stream Wrappers: https://www.php.net/manual/en/wrappers.php
- `unserialize`: https://www.php.net/manual/en/function.unserialize.php
- `hash_equals`: https://www.php.net/manual/en/function.hash-equals.php
- `password_verify`:
  https://www.php.net/manual/en/function.password-verify.php
- `htmlspecialchars`:
  https://www.php.net/manual/en/function.htmlspecialchars.php
- `call_user_func`:
  https://www.php.net/manual/en/function.call-user-func.php
- Filesystem: https://www.php.net/manual/en/book.filesystem.php
- Fibers: https://www.php.net/manual/en/language.fibers.php
- Enumerations:
  https://www.php.net/manual/en/language.types.enumerations.php
- Attributes:
  https://www.php.net/manual/en/language.attributes.php

### OWASP and reference catalogs

- "PHP Magic Tricks: Type Juggling"
  (https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf).
- "Function Injection"
  (https://owasp.org/www-community/attacks/Function_Injection).
- PayloadsAllTheThings:
  https://github.com/swisskyrepo/PayloadsAllTheThings (Type Juggling,
  Insecure Deserialization PHP, File Inclusion sections).
- HackTricks "LFI2RCE via PHP Filters":
  https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters
- The Hacker Recipes "PHP wrappers and streams":
  https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/php-wrappers-and-streams
- Spaze's magic-hash catalog: https://github.com/spaze/hashes

### Conference talks

- Sam Thomas — Black Hat USA 2018 ("It's a PHP Unserialization Vulnerability
  Jim").
- Charles Fol — OffensiveCon 2024
  (https://www.offensivecon.org/speakers/2024/charles-fol.html).
- Orange Tsai — DEVCORE blog (CVE-2024-4577); HITBSecConf; Black Hat USA.
- Stefan Esser — HITB 2011, 2016, 2019; Black Hat USA 2012.
- Anthony Ferrara — PHP Benelux 2013 ("Password Storage").

### CVE catalog (cited inline)

- CVE-2012-1823 (PHP-CGI argument injection, original)
- CVE-2018-* (Phar deserialization CVEs post-Thomas disclosure)
- CVE-2019-12747 (TYPO3 Phar)
- CVE-2019-11043 (PHP-FPM nginx env_path_info)
- CVE-2021-21703 (PHP-FPM local privilege escalation)
- CVE-2022-24828 (Composer command injection)
- CVE-2023-3824 (PHP Phar buffer overflow)
- CVE-2024-4577 (PHP-CGI argument injection, Best-Fit bypass)
- CVE-2024-28859, CVE-2024-28861 (Symfony 1 / Swift_KeyCache)
- CVE-2024-32651 (changedetection.io Jinja2 SSTI RCE)
- CVE-2024-55555 (Invoice Ninja Laravel deserialization)
- CVE-2025-1220 (PHP null-byte hostname bypass in fsockopen)
- CVE-2025-54236 (Magento SessionReaper)

---

## Appendix A: PHP-specific severity rubric

When triaging PHP findings, apply the click-count framing of
`code_review_expertise.md` and the blast-radius rubric of
`SEVERITY_DEFINITION.md`:

| Primitive | Default click-count | Severity ceiling |
|-----------|---------------------|------------------|
| `unserialize($USER)` with PHPGGC-eligible classpath | 0 | CRITICAL |
| `eval($USER)` / `assert($USER_STR)` | 0 | CRITICAL |
| `include($USER)` with `php://filter/` reachability | 0 | CRITICAL |
| `phar://` deserialization (pre-PHP-8.0) via any file operation | 0 | CRITICAL |
| `extract($_GET)` overwriting authz local | 0 | HIGH |
| `call_user_func($USER, ...)` | 0 | CRITICAL |
| `preg_replace` `/e` with group-controlled replacement | 0 | CRITICAL |
| `system($USER)` / `shell_exec` metachar passthrough | 0 | CRITICAL |
| `==` on `hash_hmac` output (magic-hash class) | 0-1 (brute) | HIGH |
| `move_uploaded_file` with client-name destination | 0 | HIGH |
| `htmlspecialchars($X)` no ENT_QUOTES, attribute context | 0 | HIGH |
| `htmlspecialchars($X)` element context (PHP 5.4+ default) | 0 | MEDIUM |
| `mt_rand` for session-ID generation | 0 | MEDIUM |
| `addslashes($USER)` adjacent to SQL | 0 | HIGH |
| `disable_functions` empty in production | n/a (config) | LOW |
| `display_errors = On` in production | 0 | LOW (info disclosure) |

"0-click" — reachable via a single unauthenticated HTTP request, no prior
auth, no separate vulnerability chained. "0-1" — requires brute force or
session/auth pivot.

---

## Appendix B: PHP gadget-chain availability matrix

Drawn from PHPGGC as of 2026-05-14. Yes = at least one chain exists
in PHPGGC for at least one version.

| Library / Framework | Public chain | Recent CVE |
|---------------------|:------------:|------------|
| CakePHP | Yes | — |
| CodeIgniter 4 | Yes | — |
| Doctrine | Yes (essential gadget) | — |
| Drupal 7, 8 | Yes | SA-CORE-2018-002 et al. |
| Guzzle (`FnStream` chain — most reused) | Yes | — |
| Laravel (5.x → 11.x) | Yes (multiple) | CVE-2024-55555 |
| Magento 1, 2 | Yes | CVE-2025-54236 |
| Monolog (`SyslogUdpHandler`) | Yes | — |
| Phalcon | Yes | — |
| Slim | Yes | — |
| SwiftMailer | Yes | CVE-2024-28859, CVE-2024-28861 |
| Symfony 1, 2, 3, 4, 5 | Yes (many) | — |
| WordPress | Yes (`WP_Hook` + meta) | — |
| Yii 1, 2 | Yes | — |
| Zend Framework 1, 2 | Yes | — |

If your application's `composer.json` includes any of the above
(transitively), assume an exploitable `unserialize($USER_INPUT)` sink is
RCE pending five minutes of PHPGGC.

---

*This document is a living reference. The PHP behavioral-footgun surface
continues to evolve: PHP 8.4 readonly + asymmetric visibility narrowed some
gadget surface; the Phar deserialization class is largely closed on modern
PHP but extant on EOL versions; the filter-chain RCE primitive remains
universal pending a language-level fix. Update on substantive new technique
disclosures, RFC removals of unsafe defaults, or major CVE disclosures in
the PHP-Composer ecosystem.*
