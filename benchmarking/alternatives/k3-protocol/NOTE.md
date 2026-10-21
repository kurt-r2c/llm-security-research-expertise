SYSTEMATIC SEARCH PROTOCOL (read before auditing)

Premise: audits miss bugs mainly by stopping early (satisficing), anchoring on the first plausible finding, and skipping trust boundaries nobody enumerated. Your job is to enumerate the search space first, keep a written ledger of what you ruled out, and report only after the ledger is closed. You have only Read/Grep/Glob, so every claim must cite file:line you have actually read.

STEP 0. Orient (cheap). Glob manifests and top-level dirs to learn languages, frameworks, and where routes, jobs, CLI, and plugins live. Skip vendored, generated, and test-only code, and note that you skipped it.

STEP 1. Enumerate every ENTRY (where outside data or an outside actor enters). Write a numbered list E1..En. Include non-obvious ones:
- HTTP routes, GraphQL resolvers, RPC/gRPC methods, WebSocket handlers, webhooks
- CLI args, env vars, config and manifest files, archives and uploads (zip/tar/XML/YAML/images)
- Queue/cron/job consumers, DB or cache rows written by other tenants or users
- Outbound-response data (fetched URLs, API replies), file names and paths from disk, plugin/extension loaders, template and email bodies, headers (Host, X-Forwarded-*, Origin), cookies, JWT claims
Also enumerate ACTORS: unauthenticated, low-privilege user, other tenant, admin-who-should-not-reach-the-OS. Every route is an entry; check auth is applied per route, not per app (grep the route table, then diff the list of protected vs unprotected handlers).

STEP 2. Enumerate every SINK / protected operation with Grep. Write S1..Sm. Seed greps (then widen with repo-specific wrappers; grep the helper names you discover):
- Python: sources `request\.(args|form|json|files|headers|GET|POST)|sys\.argv|os\.environ`; sinks `subprocess|os\.(system|popen)|shell=True|eval\(|exec\(|pickle\.loads?|yaml\.load\b|marshal|tarfile\.extract|zipfile|open\(|os\.path\.join|send_file|render_template_string|requests\.|urlopen|\.execute\(.*(%|format|f")|jwt\.decode|verify=False|tempfile\.mktemp|__import__|getattr\(`
- JS/TS/Node: sources `req\.(body|query|params|headers|cookies)|process\.(argv|env)|location\.|postMessage|searchParams`; sinks `child_process|exec(Sync)?\(|spawn\(.*shell|eval\(|new Function|vm\.|require\(.*[$+]|fs\.(read|write|create|unlink)|path\.(join|resolve)|res\.(sendFile|download|redirect)|fetch\(|axios|http\.request|innerHTML|dangerouslySetInnerHTML|\.query\(.*(\$\{|\+)|\$where|_\.(merge|set|defaultsDeep)|Object\.assign|jwt\.(verify|decode)|JSON\.parse`
- Go: sources `r\.(URL|Form|Header|Body)|FormValue|mux\.Vars|chi\.URLParam|os\.Args|Getenv`; sinks `exec\.Command|"sh", "-c"|filepath\.Join|http\.(Get|NewRequest)|http\.Client\{|Sprintf\(.*(SELECT|WHERE)|text/template|template\.HTML|gob\.|json\.Unmarshal|InsecureSkipVerify|math/rand|archive/(zip|tar)|os\.(Open|Create|Remove)`
- Java: sources `@(Request|Path|Query)(Param|Variable|Body)|getParameter|getHeader|MultipartFile|HttpServletRequest`; sinks `Runtime\.exec|ProcessBuilder|ObjectInputStream|readObject|XMLDecoder|XStream|enableDefaultTyping|@JsonTypeInfo|InitialContext\.lookup|parseExpression|ScriptEngine|DocumentBuilderFactory|SAXParser|XMLInputFactory|TransformerFactory|ZipEntry|getName\(\)|new File\(|Paths\.get|createQuery\(.*\+|Statement|openConnection|new Yaml\(|HostnameVerifier|@PreAuthorize|permitAll`
- PHP: sources `\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|php://input`; sinks (also backtick shell) `unserialize|eval\(|assert\(|include|require|extract\(|\$\$|system\(|exec\(|shell_exec|passthru|popen|proc_open|move_uploaded_file|file_get_contents|fopen|curl_exec|preg_replace.*/e|in_array\(|==\s*['"]0e|->query\(.*\$|DB::raw|whereRaw|mysqli_query|header\(.*Location|phar://`
- Ruby/Rails: sources `params\[|request\.(headers|env)|ARGV|ENV\[`; sinks `Marshal\.load|YAML\.load[^_]|Oj\.load|eval|instance_eval|class_eval|send\(|public_send|constantize|const_get|system|%x|IO\.popen|open\(|File\.(open|read)|where\(.*#\{|order\(|find_by_sql|html_safe|raw\b|render inline|permit!|redirect_to params|Net::HTTP|open-uri`
- Authz, all languages: handlers taking an id (`:id|<id>|{id}|PathVariable`) then loading by id; role/permission decorators and middleware; JWT/session code; multi-tenant filters; admin routes; file-serving routes; password reset/token/invite flows.

STEP 3. Build pairs. For each sink, find its callers (Grep the function name) and walk back to an entry. List pairs (Ei -> Sj) with the path file:line. Include second-order paths (data stored then used later by another request, job, or tenant) and config-as-input. Sinks with no entry path get disposition "unreachable: <why>".

STEP 4. Per-pair control audit. For EACH pair list every control on the path (validation, sanitizer, allowlist, auth check, ownership check, canonicalization, size/limit, safe-API flag) and test whether it is actually enforced:
- Is the return value used? (a check or sanitizer whose result is discarded does nothing)
- Awaited / error-checked? (un-awaited async guard, ignored `err`, exception swallowed, `if (!ok) log()` without return/abort)
- Applies to the same object that reaches the sink? (checked `a`, used `b`; checked the parent, used the child; the check covers GET but the sink is on PUT/DELETE or a sibling route)
- Runs after decoding and normalization? (URL/percent/Unicode decode, `..` collapse, symlink resolve, case-fold, host parse all happen BEFORE the check; resolve THEN verify, never prefix-check an unresolved path)
- Authentication is not authorization: logged-in or signed is not "this user may touch THIS resource"; scoping must be in the query or an enforced check.
- Does the check cover every branch, method, content-type, and default (missing key = allow? empty list = allow all? flag defaults off?)
- Blocklist vs allowlist; regex anchors and multiline; `startsWith` vs equality; `==` vs strict compare; escaping for the wrong context (shell-escape is not argv-safe; HTML-escape is not attribute/JS/URL-safe; SQL quoting is not LIKE/ORDER BY-safe); TOCTOU between check and use; redirects followed after validating the first URL; DNS resolved twice.
- Compare siblings: when 9 of 10 handlers perform a check, the tenth lacking it is the bug. Read the 10th.
Disposition per pair: VULNERABLE (cite the missing/broken control), SAFE (name the enforced control and where), or UNCERTAIN (state what you could not read; then read it).

STEP 5. Pre-mortem, then report. Assume your report missed a serious bug: which entry, actor, or sink class did you not enumerate? Check at least: authz on every route, unauthenticated entries, file/path handling, outbound requests, deserialization/templates/eval, SQL/NoSQL/command construction, secrets/crypto/tokens, parsers on uploaded or fetched data. Grep once more for those, then report.

STOP RULES
- Do not finish while any enumerated pair lacks a disposition. Keep the ledger (E list, S list, pair dispositions) in your working notes and show it compactly at the end.
- After the first finding in a file, keep scanning the rest of that file; bugs cluster.
- A finding does not end the search of its neighbors: check sibling handlers, copies of the same helper, and other callers of the broken control.
- Report each distinct root cause once, listing all affected sites under it. Do not split one missing check into many reports, and do not merge different missing checks.
- Budget: breadth before depth. Finish enumeration (Steps 1-2) before deep-diving any single path; revisit the budget if the repo is large by sampling every module rather than reading one fully.

DO NOT REPORT
- Sinks fed only by constants, build-time config, or trusted operator-controlled values with no outside influence.
- Findings needing the attacker to already hold equal or greater privilege than the impact grants (admin editing own config, local shell access).
- Test, example, fixture, docs, vendored, or dead code, unless it ships to production.
- Hardening advice, missing headers, theoretical gadgets, style, or version-based CVE guesses without a reachable path you traced.
- Anything where you found an enforced control on the path (state it as SAFE in your ledger instead).
- Any claim you have not verified by reading the cited lines.

For each reported finding give: class, file:line of entry and sink, the broken or missing control, attacker, and impact in one or two sentences.
