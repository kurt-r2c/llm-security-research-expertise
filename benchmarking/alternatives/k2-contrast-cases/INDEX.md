Grep the code under audit for the cues below, open the matching case, and compare its structure to the code in front of you.
The pairs are minimal teaching examples of a shape, not a list of known bugs; judge the real code on its own data flow.

| Cue (what the code looks like) | Cases |
|---|---|
| result of a permission check is not used | [01-perm-result-ignored](cases/01-perm-result-ignored.md) |
| async check not awaited | [02-async-check-not-awaited](cases/02-async-check-not-awaited.md) |
| path joined from user input then opened | [03-path-join-open](cases/03-path-join-open.md), [20-zip-slip](cases/20-zip-slip.md), [26-decoy-realpath-prefix](cases/26-decoy-realpath-prefix.md) |
| URL validated then re-parsed differently | [04-url-validate-reparse](cases/04-url-validate-reparse.md), [12-ssrf-resolve-then-fetch](cases/12-ssrf-resolve-then-fetch.md), [21-open-redirect-prefix](cases/21-open-redirect-prefix.md) |
| check applied to object A, action to object B | [05-check-A-act-B](cases/05-check-A-act-B.md), [23-tenant-filter-missing](cases/23-tenant-filter-missing.md) |
| signature/algorithm taken from the token itself | [06-token-alg-from-header](cases/06-token-alg-from-header.md), [07-token-kid-lookup](cases/07-token-kid-lookup.md) |
| sanitizer run before decoding | [08-sanitize-before-decode](cases/08-sanitize-before-decode.md) |
| object fetched by id with no owner scope | [09-idor-find-by-id](cases/09-idor-find-by-id.md), [27-decoy-scoped-by-session](cases/27-decoy-scoped-by-session.md) |
| string built from input then executed by an interpreter | [10-sql-concat](cases/10-sql-concat.md), [22-ssti-template-string](cases/22-ssti-template-string.md), [25-decoy-identifier-allowlist](cases/25-decoy-identifier-allowlist.md) |
| user value passed as argv element | [11-argv-option-injection](cases/11-argv-option-injection.md), [28-decoy-shell-constant](cases/28-decoy-shell-constant.md) |
| client object merged into a server object | [13-mass-assignment](cases/13-mass-assignment.md) |
| recursive merge or path-set from parsed input | [14-proto-pollution-merge](cases/14-proto-pollution-merge.md) |
| check and use are separate steps on shared state | [15-check-then-act-balance](cases/15-check-then-act-balance.md) |
| client number used in arithmetic that moves value | [16-negative-quantity](cases/16-negative-quantity.md) |
| size checked in a different type than it is used | [17-int-truncation-size-check](cases/17-int-truncation-size-check.md) |
| untrusted bytes to an object-instantiating parser | [18-unsafe-yaml-load](cases/18-unsafe-yaml-load.md) |
| secret compared with ordinary equality | [19-secret-compare-timing](cases/19-secret-compare-timing.md) |
| validation regex without anchors | [24-regex-unanchored](cases/24-regex-unanchored.md) |

## Grep starters

- unused guard: `check|can|authorize|allowed|verify` as a bare statement; `if (!asyncFn(` without await
- paths: `join(|Join(|resolve(` near `open|send_file|ServeFile|readFile|getNextEntry`
- URLs: `startswith|includes|indexOf` on url/next/redirect; `urlparse|new URL` followed by a different client
- tokens: `alg|kid|jku|x5u` read from a decoded header; `==` on mac/sig/token
- injection: string-building near `execute|query|raw|subprocess|exec|render_template_string|yaml.load|unserialize`
- ownership: `find(params|findById(req|where: { id` without owner/tenant in the same expression
- state: `SELECT` followed by `UPDATE` on the same row; arithmetic on request numbers

## By class

- authz: cases 01, 02, 13
- parser/path: cases 03, 20, 26
- SSRF: cases 04, 12
- ownership/IDOR: cases 05, 09, 23, 27
- crypto/token: cases 06, 07, 19
- parser/sanitizer: cases 08, 14, 21, 24
- injection: cases 10, 11, 18, 22, 25, 28
- business logic: cases 15, 16
- numeric: cases 17

## Decoys (read before reporting)

Cases marked DECOY look vulnerable but are safe, with the reason given. Before reporting a finding, check whether the code matches a decoy's safety reason.
