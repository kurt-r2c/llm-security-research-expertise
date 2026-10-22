# Injection Security Audit

Audit the codebase for 5 injection vulnerability classes: SQL injection, LDAP/XPath
injection, command injection, server-side template injection (SSTI), and cross-site
scripting (XSS).

---

## Quick Scope

- Database access layers: files matching `*repository*`, `*dao*`, `*store*`, `*db*`, `*query*`
- Shell invocation sites: files containing `subprocess`, `exec`, `popen`, `system`, `shell`
- LDAP clients: files containing `ldap`, `ldap3`, `go-ldap`, `ldapjs`, `JNDI`
- Template rendering: files containing `jinja2`, `Template`, `Handlebars`, `nunjucks`, `ejs`,
  `pug`, `ERB`, `Twig`, `Velocity`, `text/template`, `html/template`
- ORM raw-query escape hatches: `raw()`, `execute()`, `text()`, `Arel.sql()`
- Run Semgrep rules from `security-research/rules/sql_injection/`,
  `security-research/rules/command_injection/`,
  `security-research/rules/ldap_xpath_injection/`, and
  `security-research/rules/template_injection/` as a first pass, then do a
  second LLM-native pass to catch patterns the rules miss.

---

## Check 1: SQL Injection — string concatenation into query sinks

**Find:** Calls to query-execution sinks where the argument is assembled by string
concatenation, interpolation, or formatting with a non-literal value.

Sinks by language:
- Python: `cursor.execute(f"...")`, `cursor.execute("..." % var)`, `cursor.execute("..." + var)`
- Java: `stmt.executeQuery("..." + var)`, `stmt.execute(String.format(...))`,
  `stmt.executeUpdate("..." + var)`
- Go: `db.Query("..." + var)`, `db.Query(fmt.Sprintf(...))`, `db.Exec(...)`, `db.QueryRow(...)`
- JS/TS: `conn.query("..." + var)`, `conn.query(\`...\`)`, `conn.execute(\`...\`)`
- Ruby: `connection.execute("...#{...}...")`, `Model.find_by_sql("..." + var)`,
  `Model.where(Arel.sql("...#{...}..."))`
- PHP: `mysqli_query($conn, "..." . $var)`, `$conn->query("...$var...")`
- C#: `cmd.CommandText = "..." + var`, `new SqlCommand("..." + var)`

Also audit ORM escape hatches: any call to `.raw()`, `.execute()`, `.text()`,
`Arel.sql()` where the argument is not a string literal.

**Evaluate:** Trace the concatenated or interpolated value back to its origin. Flag if
any segment originates from request parameters, headers, path variables, form fields,
cookies, or any external data store written by users. Safe if all non-literal fragments
are bound through `?` / `$1` / `:name` placeholders via a `PreparedStatement`,
`cursor.execute(sql, params)`, or equivalent parameterized API — not merely
cast or sanitized before concatenation.

**Severity:** HIGH if the sink is reachable without authentication or the query can
return, modify, or delete arbitrary rows; MEDIUM if authentication is required to reach
the sink or the query is read-only and output is not reflected to the caller; LOW if
input passes through a strict allowlist (e.g., column name limited to a fixed enum).

**Common false positives:** Query strings assembled entirely from compile-time constants
with no runtime variable fragments; ORM escape hatches called with a string literal
argument (e.g., `Model.where(Arel.sql("status = 'active'"))`).
**Safe ORM APIs (do not flag):** Django ORM `.filter()`, `.get()`, `.exclude()` are
parameterized by design; only `.raw()`, `.extra()`, and `connection.execute(str)` are
sinks. SQLAlchemy `.query().filter()` and `.filter_by()` are safe; only `text()`
with a concatenated string is a sink.

**NoSQL Injection — MongoDB and Elasticsearch:**

Also audit NoSQL query construction:
- MongoDB `$where` operator with user input: `db.collection.find({$where: "this.field == " + userVar})`
- `find()`/`findOne()` with a user-controlled JSON structure passed directly without
  an explicit field allowlist: `Model.find(req.body)` (Mongoose mass-assignment to
  query object)
- Operators injected via query parameters: `?password[$ne]=x` reaching
  `Model.findOne({password: req.query.password})` without `typeof` or schema validation
- Elasticsearch query DSL with user-controlled `query_string.query`:
  `client.search({body: {query: {query_string: {query: userVar}}}})`

**Evaluate:** Confirm user input reaches the query without passing through a
strict field-name allowlist or a schema-validation step that rejects operator keys
(`$where`, `$ne`, `$gt`, `$regex`). Mongoose `strict` mode drops unknown
document fields, and `strictQuery` (default `false` in Mongoose 7+) governs unknown filter paths; neither
blocks operator injection — `sanitizeFilter` wraps object values in `$eq`.

**Severity:** HIGH if operator injection enables authentication bypass
(`{password: {$gt: ""}}` bypasses equality check) or cross-user data access;
MEDIUM if the injection enables cross-user read without privilege escalation;
LOW if the endpoint is authenticated and returns only the attacker's own data.

---

## Check 2: LDAP/XPath Injection — unescaped input in filter strings

**Find:** LDAP filter construction and XPath expression construction where a
non-literal value is interpolated or concatenated directly into the filter/query string.

LDAP sinks by language:
- Python: `conn.search_s(dn, scope, f"...")`, `conn.search(dn, f"...")`,
  `conn.search_s(dn, scope, "..." % var)`; absent `ldap.filter.escape_filter_chars()`
  or `ldap.filter.filter_format()` wrapping the user value
- Java: `ctx.search(dn, "..." + var, ...)`, `ctx.search(dn, String.format(...), ...)`
- Go: `l.Search(&ldap.SearchRequest{Filter: "..." + var})`,
  `l.Search(&ldap.SearchRequest{Filter: fmt.Sprintf(...)})`; absent `ldap.EscapeFilter()`
- JS/TS: `client.search(base, {filter: "..." + var})`,
  `client.search(base, {filter: \`...\`})`
- PHP: `ldap_search($conn, $base, "..." . $var)`, `ldap_search($conn, $base, "...$var...")`
- Ruby: `Net::LDAP#search(filter: Net::LDAP::Filter.construct("...#{var}..."))` or
  raw filter strings with interpolation
- C#: `searcher.Filter = "..." + var`

XPath sinks: `xpath.evaluate(expr + var)`, `document.selectNodes("..." + var)`,
`XPathExpression.compile("..." + var)`, `XPath.compile(String.format(...))` in any
language; absent XPath variable binding via `XPathVariableResolver`.

**Evaluate:** Determine whether the user-supplied value is passed through a dedicated
escaping function (`ldap.filter.escape_filter_chars()`, `ldap.EscapeFilter()`,
`ldap_escape($v, "", LDAP_ESCAPE_FILTER)`, RFC 4515 encoding) before being placed in
the filter string, or whether LDAP filter objects (`EqualityFilter`, `AndFilter`, etc.)
are used instead of raw strings. For XPath, check whether the user value flows into
variable binding (`setXPathVariableResolver`) rather than string concatenation. Flag
any site that uses neither.

**Severity:** HIGH if the LDAP filter controls authentication (e.g., `(&(uid=%s)(pass=%s)`)
or the XPath query gates authorization; HIGH for blind injection enabling full directory
enumeration; MEDIUM if the injection only affects search results visible to the
authenticated caller; LOW if input is constrained to a known-safe character set by
prior validation.

**Common false positives:** Filter strings assembled entirely from compile-time constants;
LDAP filter objects (not strings) passed to the search API; XPath expressions with no
dynamic component.

---

## Check 3: Command Injection — shell-interpreted execution with user-controlled input

**Find:** Shell invocation sites where shell-interpretation mode is enabled and
user-controlled input can reach the command string.

Sinks and shell-mode indicators by language:
- Python: `subprocess.run(..., shell=True)`, `subprocess.call(..., shell=True)`,
  `subprocess.Popen(..., shell=True)`, `os.system(...)`, `os.popen(...)`
- Java: `Runtime.getRuntime().exec("..." + var)`, `Runtime.getRuntime().exec(var)`,
  `new ProcessBuilder("sh", "-c", var)`, `new ProcessBuilder("bash", "-c", "..." + var)`
- Go: `exec.Command("sh", "-c", var)`, `exec.Command("bash", "-c", var)`,
  `exec.Command(var)` (user-controlled command name)
- JS/TS: `exec(var)`, `exec("..." + var)`, `exec(\`...\`)`, `execSync("..." + var)`,
  `execSync(\`...\`)` (all via `child_process`; `exec`/`execSync` always invoke a shell)
- Ruby: `system("...#{var}...")`, `system("..." + var)`, `IO.popen("...#{var}...")`,
  backtick interpolation `` `...#{var}...` ``
- PHP: `exec("..." . $var)`, `shell_exec("...$var...")`, `system("..." . $var)`,
  `passthru("..." . $var)`, `popen("...$var...", ...)` without `escapeshellarg()`
- C#: `Process.Start("cmd.exe", "/c " + var)`, `Process.Start(new ProcessStartInfo { ... UseShellExecute = true })`
- Rust: `Command::new("sh").arg("-c").arg(var)`

**Evaluate:** Confirm two conditions: (1) the execution mode invokes a shell (not a
direct `execve`-style list call), and (2) user-controlled input reaches the command
string without strict allowlist filtering. A list-style invocation (`subprocess.run(["cmd", arg])`,
`exec.Command("git", "clone", userUrl)`) is safe for condition 1. An allowlist that
maps user choices to fixed command tokens (not arbitrary strings) satisfies condition 2.
`escapeshellarg()` / `shellescape()` mitigates but does not eliminate risk if the
command name itself is user-controlled.

Also confirm the site is reachable from an active request handler, background job, or
scheduled task. If the function containing the sink is never called with user-controlled
input — dead code, test-only helper, or a utility invoked exclusively with literals —
report the finding at LOW rather than discarding it. Document the unreachability reason
and flag it as a latent risk for future code paths.

**Severity:** HIGH if the injection runs as the web/app process user and the process has
filesystem write access or network egress; HIGH if the attacker controls the command
name (not just arguments); MEDIUM if `escapeshellarg()` is applied to all user values
but the command structure is still user-influenced; LOW if input is restricted to an
enum of known-safe values enforced before the call site.

**Common false positives:** `subprocess.run([...], shell=False)` with a list argument
and no user-controlled elements; `exec.Command("git", "clone", hardcodedUrl)`;
`os.system("make test")` with a fully static string; test/CI harness code that runs
fixed commands.

---

## Check 4: Template Injection (SSTI) — user input as template source

**Find:** Template compilation or rendering calls where the template source argument is
a variable, not a string literal or a call to a trusted file-loading function.

Sinks by language:
- Python: `jinja2.Template(var)`, `Template(var)` where the template source is not a
  literal; check also `Environment(undefined=...).from_string(var)`; verify
  `SandboxedEnvironment` is used when user content is rendered as data
- Java: `new Template(name, new StringReader(var), cfg)` (FreeMarker),
  `Velocity.evaluate(ctx, writer, log, var)`, `new ST(var)` (StringTemplate),
  `engine.process(var, ctx)` (Thymeleaf with user-supplied template name)
- Go: `t.Parse(var)` where `var` is not a constant; affects both `text/template`
  and `html/template`
- JS/TS: `Handlebars.compile(var)`, `Handlebars.precompile(var)`,
  `nunjucks.renderString(var, data)`, `ejs.render(var, data)`,
  `pug.render(var, opts)`, `pug.compile(var, opts)`
- Ruby: `ERB.new(var)`, `Liquid::Template.parse(var)`
- PHP: `$twig->createTemplate(var)`
- C#: `Engine.Razor.RunCompile(var, ...)`, `Template.Parse(var)` (Scriban/Fluid)
- Rust: `TinyTemplate::add_template(name, var)`, `Tera::render_str(var, ctx)`

Also check: template engine sandbox configuration. Flag `jinja2.Environment` without
`SandboxedEnvironment`; Twig `\Twig\Extension\SandboxExtension` absent; FreeMarker
`new DefaultObjectWrapperBuilder(VERSION)` with `setExposureLevel(BeansWrapper.EXPOSE_ALL)`.

**Evaluate:** Trace the template source variable back to its origin. Flag if it
derives from request parameters, database rows written by users, configuration editable
at runtime by users, or any other attacker-reachable data path. Safe only if the
template source is a compile-time constant, a file loaded from a path that cannot be
influenced by user input, or a value fetched exclusively from a trusted internal store
with no user-write path. Sandbox verification is a separate, secondary check: flag
disabled/missing sandboxing even if the template source appears trusted.

Also confirm the template rendering call is reachable from an active request handler or
scheduled job with user-controlled input. Dead code or test-only rendering sites should
be reported at LOW with the unreachability reason documented.

**Severity:** HIGH if the template source is directly user-supplied and the engine can
execute arbitrary code or OS commands (Jinja2, ERB, FreeMarker, Velocity, Go
`text/template`); HIGH if sandbox is explicitly disabled on an engine that defaults to
sandboxing; MEDIUM if the user controls only render-context data (not the template
source) but the engine auto-evaluates expression syntax (e.g., `{{7*7}}` in input
fields reflected into a page); MEDIUM if the template source comes from a
partially-trusted store (e.g., admin-editable config); LOW if only a sandboxed engine
(Liquid) is used with user-supplied template source and no
sandbox-escape gadget is present.

For stored SSTI where the template source is fetched from a database row writable by
users: apply the Detonation Control check from `../triage/SKILL.md` (Check 6). If
detonation is routine (e.g., an admin dashboard renders stored templates on each page
view, or a scheduled report processes them automatically), retain at HIGH. If detonation
requires an independent privileged trigger that is not part of any regular workflow,
downgrade to MEDIUM.

**Common false positives:** `jinja2.Template("Hello {{ name }}")` — literal source;
`nunjucks.render("emails/welcome.html", data)` — file-based loading, data only in
context; `ejs.renderFile(path, data)` — file-based.
**Auto-escaping frameworks (do not flag for data-in-context rendering):**
Django templates auto-escape all context variables by default; only `|safe`,
`mark_safe()`, and `{% autoescape off %}` bypass escaping and are sinks. React JSX `{variable}`
auto-escapes; only `dangerouslySetInnerHTML` is a sink.
`pug.renderFile(path, opts)` —
file-based; any call where the first argument is demonstrably a string literal.

---

## Check 5: Cross-Site Scripting (XSS) — Unencoded user input in HTML context

**Find:** Sites where user-controlled values are written into an HTTP response body
without context-appropriate encoding. Cover all four XSS surfaces:

**Reflected/Stored XSS — server-side rendering sinks:**
- Python: `render_template_string(f"...<b>{var}</b>...")` or direct response with
  `return f"<html>...{var}..."` without escaping; `|safe` or `Markup(var)` in Jinja2;
  Django `mark_safe(var)` or `format_html(...)` with `%s`-style substitution instead
  of `{}` named args
- Java: `response.getWriter().write("..." + var)`, `out.println("..." + var)`,
  `model.addAttribute("html", rawVar)` used with `th:utext` (Thymeleaf unescaped);
  JSP `<%= var %>` without `<c:out value="${var}"/>`
- Go: `fmt.Fprintf(w, "...%s...", var)` in an HTTP handler; `text/template` used
  where `html/template` is required
- JS/TS (server-side): `res.send("..." + var)`, `res.write("..." + var)` in Express;
  template literals in `res.send(\`...<b>${var}</b>...\`)`
- Ruby: `raw(var)`, `html_safe` on user input, `<%= raw var %>` in ERB
- PHP: `echo $var`, `print $var`, `echo "<b>" . $var . "</b>"` without
  `htmlspecialchars($var, ENT_QUOTES)` or `htmlentities()`
- C#: `Response.Write(var)`, `Html.Raw(var)` in Razor, `@Html.Raw(var)` in views

**DOM-based XSS — client-side sinks:**
- `document.write(location.hash)`, `element.innerHTML = userVar`,
  `element.outerHTML = userVar`, `$(element).html(userVar)`
- `eval(location.search)`, `eval(document.URL)`, `setTimeout(userVar, 0)`,
  `setInterval(userVar, 0)`
- `window.location.href = userVar` where `userVar` can be a `javascript:` URI

**Framework escape hatches to flag unconditionally:**
- React: `dangerouslySetInnerHTML={{ __html: userVar }}`
- Vue: `v-html="userVar"`
- Angular: `[innerHTML]` bound to `bypassSecurityTrustHtml(userVar)`
- Svelte: `{@html userVar}`

**Evaluate:**

1. Confirm the value originates from user-controlled input: request parameters,
   headers, path variables, cookies, database rows writable by users, or uploaded
   file content.
2. For server-side rendering: verify the value is not passed through a context-aware
   auto-escaping mechanism before insertion. React JSX `{variable}` and Django
   template `{{ variable }}` auto-escape — these are NOT findings unless an explicit
   bypass (listed above) is present.
3. For DOM-based XSS: confirm the source (`location.hash`, `document.URL`,
   `window.name`, `postMessage` data) flows to the sink without sanitization by
   DOMPurify, `textContent` assignment, or equivalent.
4. For stored XSS: apply the Detonation Control check from `../triage/SKILL.md`
   (Check 6). If the stored value is rendered in a multi-user context (shared page,
   admin panel, feed), detonation is routine → retain at HIGH.

**Severity:**
- **CRITICAL**: reflected XSS in an unauthenticated endpoint where the page loads
  sensitive data or session tokens accessible to the injected script.
- **HIGH**: stored XSS rendered in a multi-user context or to other authenticated
  users; reflected XSS with authenticated context that grants access to sensitive
  data.
- **MEDIUM**: DOM-based XSS requiring user interaction (victim must click a crafted
  link); reflected XSS with no sensitive data in scope.
- **LOW**: self-XSS (fires only in the attacker's own browser with no path to other
  users); apply triage/SKILL.md Check 10.

**Common false positives:** React `{variable}` JSX interpolation (auto-escaped);
Django `{{ variable }}` in templates without `|safe` (auto-escaped); server-side
HTML content loaded from a trusted static file with no user-controlled segment;
`textContent` assignment (not innerHTML).

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading an injection finding
without completing the full evidence chain:

- **"The pattern looks dangerous"** is not sufficient — confirm the tainted value
  actually reaches the execution sink without passing through parameterization,
  escaping, or an allowlist before flagging.
- **"Upstream parameterization may cover the sink"** — trace the full call chain.
  A prepared statement in a calling function does not protect a raw concatenation
  sink in a helper that bypasses it.
- **"A similar pattern is flagged elsewhere"** does not confirm this instance —
  each call site requires its own data-flow trace from source to sink.
- **"Sanitized before passing"** must be evaluated for sufficiency in context:
  HTML-entity encoding does not prevent SQL injection; `escapeshellarg` does not
  protect a user-controlled command name; stripping quotes does not prevent
  LDAP injection via parentheses.

## Output Format

For each confirmed finding:
- **[INJ-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted code snippet showing the sink and how attacker input reaches it
- **Trace:** `source:line` → `intermediate:line` (transform note, if any) → `sink:line`
  (Required for HIGH and CRITICAL findings. Omit for MEDIUM and LOW.)
- **Impact:** what the attacker gains (data exfiltration, RCE, authentication bypass, etc.)
- **Fix:** specific remediation (parameterized queries / subprocess list args /
  `ldap.EscapeFilter()` / sandboxed template environment / etc.)

Number findings sequentially across all five check types: INJ-1, INJ-2, ...

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "INJ",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For injection findings the most dispositive checks are:
implication/plausibility (can attacker-controlled input actually reach this sink?),
network reachability (is the endpoint exposed?), and authenticated-admin
equivalent-access (does the finding require admin credentials that already grant
equivalent capability?).
