# Worked example: the Brotli decoder bug, October 2026

How the four passes apply to a real case. Advisory details below come from
vendor and press write-ups published in the week of disclosure and were not
checked against NVD or the upstream advisory, which were not yet indexed when
this was written. They are marked `[unverified]`. Reach and default-config
findings come from a first-party source and runtime survey dated 2026-10-23.

## The public record ran this method in slow motion

The bug was first reported as a Node.js issue and branded accordingly. Over
the next days it was renamed as the consumer list grew: "Node2Shell", then
"HTTP2Shell" once Python and other HTTP stacks were found affected, then
"Brotli2Shell" once bundled copies outside HTTP turned up `[unverified]`. Each
rename is a fan-out pass someone did after the fact. Starting from bedrock gets
there on day one.

## Pass 1: bedrock

- Component: Google's Brotli decoder (`google/brotli`, C), the reference
  implementation of RFC 7932.
- Defect: an out-of-bounds write in the decoder; the CVE record pairs CWE-252
  (unchecked return value) with CWE-787 (out-of-bounds write). Affected
  1.0.3 through 1.2.0; fixed in 1.2.1, with 1.1.1 and 1.0.10 on older
  branches `[unverified]`.
- Amplifiers belong to each consumer: whether it decodes attacker bytes by
  default, and what it does when the decoder fails.

Check the advisory identity. In the same week, "PHP2Shell"
(CVE-2026-109618 and CVE-2026-109619, PHP core memory-safety bugs) was
reported and some retellings merged it with the Brotli bug `[unverified]`.
PHP core does not bundle Brotli; PHP reaches it only through the separate
PECL `brotli` extension, which bundles its own copy and shipped its own fix
release `[unverified]`. Attributing the Brotli fix to a PHP core upgrade would
leave the extension unpatched.

## Pass 2: consumers, by mechanism

- **System library**: distro `libbrotli` packages; fixed by OS update for
  everything that links them dynamically.
- **Embedded in a runtime**: Node.js and .NET ship their own Brotli. A
  precedent: the 2020 Brotli overflow (CVE-2020-8927, fixed in 1.0.8) was
  tracked separately against .NET runtime packages.
- **Binding packages that bundle a copy**: Python `Brotli` (official C
  extension) and `brotlicffi` (same C library through CFFI), Java `brotli4j`
  (JNI with native jars), Rust `brotli-sys`, the PHP PECL extension, Perl
  `IO::Compress::Brotli`. Precedent: for CVE-2020-8927 the Perl module needed
  its own CVE (CVE-2020-36846) because it bundled a pre-1.0.8 copy, and
  `brotli-sys` lagged upstream.
- **Vendored source**: find by code-searching for the decoder's file names
  (`decode.c`, `state.c` under a `brotli/` or `dec/` directory) and its error
  strings, not by package manifests.

## Pass 3: other implementations

The C library is the reference, so ports are the first candidates:

- Go `andybalholm/brotli`, machine-translated from the C reference.
- Rust `brotli` / `brotli-decompressor` (Dropbox), a port of the C decoder.
- The pure-Java decoder in `google/brotli/java/org/brotli/dec`.

Each needs its own answer: does the same unchecked path exist, and what does
the trigger input do there (panic, exception, truncated output)? A
memory-safe port that panics on the input is still a DoS in any server that
does not recover from panics.

## Pass 4: reach and side effects

The assumption "Brotli is HTTP content coding, so every web server decodes
it" is mostly wrong in the request direction and right in the response
direction:

- Decoding a `Content-Encoding: br` **request** body by default was found in
  three server lineages: Express 5 / body-parser 2, Go Fiber from v2.14.0,
  and actix-web 4 with default features. Most others (WSGI servers and
  frameworks, Rack and Rails, PHP SAPIs, Tomcat and Jetty, Go `net/http`,
  ASP.NET Core without its request-decompression middleware) pass the
  compressed bytes through or reject them.
- Latent defaults exist: a JVM server whose request decompression is on by
  default but whose Brotli support activates only when `brotli4j` lands on
  the runtime classpath, for an unrelated reason.
- Decoding Brotli **responses** is default in mainstream HTTP clients
  (urllib3 and requests with a Brotli backend installed, httpx, aiohttp,
  crawlers such as Scrapy). The attacker there is any server the client
  fetches from: SSRF targets, crawled sites, upstreams behind a proxy.

Side effects beyond the headline write, all from the same class of input:

- Decompression bombs: Brotli exceeded 600,000:1 in testing (421 bytes to
  256 MiB). Size limits checked after decoding bound the response, not peak
  memory.
- Error handling diverges by consumer: the Python bindings raise a catchable
  exception; some native-addon paths surface the error asynchronously, where
  a missing handler ends the process.
- A related bug one layer up turned up during the survey: a Netty release
  line did not enforce its decompression size cap for Brotli and some other
  codecs (CVE-2026-42587) `[unverified]`, which matters to every JVM server
  that enables `brotli4j`.

## Sources

- Vendor and press write-ups of CVE-2026-111497 (Phoenix Security, JFrog,
  Aikido, broccoli2shell.com), October 2026 `[unverified]`.
- CVE-2020-8927 (GHSA-5v8v-66v8-mwm7) and CVE-2020-36846, for the bundled-copy
  precedent.
- First-party source and runtime survey of Brotli request decoding across
  twelve languages, 2026-10-23.
