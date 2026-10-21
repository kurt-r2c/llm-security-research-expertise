AUDIT CHECKLIST. Grep for the cue, then run its probes on every hit. Trace untrusted input (request, file, queue, user-written DB field) to the sink; name attacker and precondition.

A. ROUTE/HANDLER CUES (decorators, router calls, controllers, resolvers)
1. List each route's auth guard. Which routes have none (admin, internal, export, webhook, batch)?
2. Object loaded by request id: is owner/tenant compared to the caller? Check nested ids too (does item belong to project?).
3. Is the check on the same object that is used? Look for check on parent but act on child, id from URL vs body, first list element vs all.
4. Is the guard result enforced? Look for ignored return value, `if` with no return/throw, async check not awaited (Promise is truthy), catch that logs and continues, middleware skipped by path variants (trailing slash, case, `//`, `..;/`, method override).
5. Mass assignment (`update(**body)`, `Object.assign`, `fill`, `permit!`, struct binding): can role, is_admin, owner_id, tenant_id, price be set?
6. Role compares: flag `includes`/`in`, loose `==`, case folding, string-vs-array coercion.
7. Multi-step flows (reset, invite, payment, MFA, OAuth callback): does each step re-verify the previous? Can the last step be called directly? Is state bound to the session?
8. GraphQL/batch: per-field and per-item authz, not just top level.

B. SINK CUES (check each argument's origin)
9. SQL/NoSQL: concatenation, f-strings, `.format`, template literals in query/raw/where/order. ORDER BY, column, table names cannot be parameterized: need an allowlist. Mongo: can request objects reach the filter (`$ne`, `$where`)?
10. Command: `system`, `exec`, `popen`, `shell=True`, `Runtime.exec(String)`, `sh -c`, backticks. Argument injection counts: user value starting with `-` into git/curl/tar. `escapeshellcmd` does not stop it.
11. Path: `open`, `readFile`, `send_file`, `include`, `join`, archive extraction. An absolute joined segment replaces the base. Prefix check without trailing separator, or before symlink resolution, fails. Check upload filenames.
12. Template/eval: `render_template_string`, `eval`, `new Function`, `vm.run*`, SpEL/OGNL, ERB, `text/template`. Is the template body user data, or only the context?
13. Deserialization: `pickle`, `yaml.load`, `marshal`, `ObjectInputStream`, Jackson default typing, `unserialize`/`phar://`, `Marshal.load`, `node-serialize`. Is the source authenticated or signed?
14. HTML: `innerHTML`, `dangerouslySetInnerHTML`, `|safe`, `raw`, `html_safe`, `v-html`; user values in href/src (`javascript:`).
15. Prototype pollution: recursive merge or path-set with request-keyed input and no `__proto__`/`constructor` filter.
16. Regex built from user input, or nested quantifiers on request-sized strings.

C. OUTBOUND URL CUES (`fetch`, `requests`, `http.Get`, `openConnection`, webhook/import/preview/renderer)
17. Check: scheme allowlist; resolved IP pinned (rebinding); private/loopback/link-local/metadata blocked after redirects; redirects not followed blindly; auth headers not forwarded cross-origin.
18. Do validator and fetcher use the same parser? Flag `startswith`/`endswith`/`contains` host checks (`good.com.evil.com`, `evil.com#@good.com`, userinfo `@`) and checks on the string, not the parsed host.
19. Redirect targets (`next`, `returnUrl`, `redirect_uri`, `RelayState`): need exact-match allowlist. `startswith("/")` admits `//evil.com` and `/\evil.com`.

D. TOKEN/CRYPTO/SESSION CUES
20. `jwt.decode`/`verify`: algorithm pinned (not from header; `none`, HS/RS confusion); signature verification not disabled; `exp`, `aud`, `iss` checked; `kid`/`jku`/`x5u` not used as path, query, or URL. Is unverified decode used for decisions?
21. Secret compares (token, HMAC, key) with `==`: timing leak. Hunt hardcoded or default secrets (`SECRET || "changeme"`) and tokens from `rand`/`Math.random`/time.
22. Reset/invite/magic-link tokens: single-use, expiring, bound to user, not leaked in response or logs.
23. ECB, static IV/nonce, MD5/SHA1 for auth, TLS verification off, signature check skipped when the signature is absent.
24. Sessions: regenerated on login, invalidated on logout, CSRF on cookie-auth writes, CORS reflecting Origin with credentials.

E. PARSER/SANITIZER CUES
25. For each sanitizer (strip, replace, blocklist, escape), ask what survives. Check single-pass replace (`....//`), decode or normalize after the check (URL, unicode, double encoding), null byte, case. Validate-then-decode-then-use is the bug.
26. Two parsers on one input: proxy vs app, duplicate keys/params (first vs last wins), JSON vs form, content-type confusion.
27. XML: external entities/DTDs disabled? Does the signature cover the element actually consumed?

F. NUMBERS/STATE/LOGIC
28. Request-supplied quantity, price, amount: negative, zero, huge, float, string. Totals recomputed server-side? Coupons repeatable or stackable?
29. Check-then-act without lock/transaction (balance, coupon, invite, limit): race. Look for read-modify-write without atomic update.
30. Integer width/sign on lengths and indexes (Java int, JS Number precision, Go casts); off-by-one bounds.
31. State machine skips/replays; soft-deleted, expired, or disabled objects excluded on every query path.

G. RESOURCE/LIMITS
32. Uploads, bodies, pagination, batch/GraphQL depth: size/count limits? Decompression bombs, unbounded `limit`, HTTP clients without timeout (Go default has none).
33. Rate limits on login/reset/OTP: is the key spoofable (`X-Forwarded-For`)?

DO NOT REPORT
- Sinks fed only by constants, config, or developer values; parameterized queries; argv-array exec with no shell.
- Needs admin or equivalent privilege, unless it grants more than that role holds.
- Missing headers, generic "no rate limit", verbose errors, unreachable dependency versions, test/fixture/example code.
- Hardening-only: md5 cache keys, non-security `random`.
- Anything not traced to a reachable entry point. If middleware or framework may sanitize upstream, read it first.

Per finding: file:line, entry point, attacker, input path, why guards fail, impact.
