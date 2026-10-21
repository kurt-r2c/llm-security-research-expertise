# Race Conditions and Concurrency Security — Primitives, Tools, and Defenses
## Synthesized from James Kettle, Matt Bishop, Crispin Cowan, Madanlal Musuvathi, Cormac Flanagan & Stephen Freund, Konstantin Serebryany, Drew Dean & Alan Hu, Kyle Kingsbury, and Martin Kleppmann

> **Researchers:**
> - **James Kettle** (@albinowax) — Director of Research, PortSwigger. Author of the **single-packet attack** and "Smashing the State Machine" (Black Hat USA 2023 / DEF CON 31); Turbo Intruder; long portfolio of HTTP desync and request-smuggling research.
> - **Matt Bishop** (UC Davis) — UC Davis Tech Report CSE-95-9 "Race Conditions, Files, and Security Flaws; or the Tortoise and the Hare Redux" (1995) and CSE-95-10 "Checking for Race Conditions in File Accesses" (with M. Dilger). The canonical academic treatment of filesystem TOCTOU.
> - **Crispin Cowan** — RaceGuard (USENIX Security 2001, with Beattie/Wright/Kroah-Hartman); kernel-level protection against temp-file race vulnerabilities. Also StackGuard and a long body of OS-security defensive work.
> - **Madanlal Musuvathi** (Microsoft Research) — Co-author of **CHESS** ("Finding and Reproducing Heisenbugs in Concurrent Programs", OSDI 2008, with Qadeer, Ball, Basler, Nainar, Neamtiu). Applied context bounding, introduced by Qadeer & Rehof (TACAS 2005).
> - **Cormac Flanagan** (UC Santa Cruz) and **Stephen Freund** (Williams) — **FastTrack** (PLDI 2009 / CACM 2010) and the **RoadRunner** dynamic-analysis framework. Adaptive epoch vector clocks; the algorithm underlying modern TSan.
> - **Konstantin Serebryany** (Google) — **ThreadSanitizer** (WBIA 2009; LLVM reimplementation 2011). Same author thread that produced ASan, MSan, and libFuzzer.
> - **Drew Dean** (SRI) and **Alan J. Hu** (UBC) — "Fixing Races for Fun and Profit: How to use access(2)" (USENIX Security 2004). Proved no portable deterministic UNIX TOCTOU solution exists without syscall-interface changes; proposed probabilistic hardness-amplification (later defeated by Borisov's "filesystem maze").
> - **Kyle Kingsbury** (@aphyr, Jepsen) — Jepsen.io founder; Knossos and Elle linearizability checkers. The dominant practitioner of empirical distributed-systems consistency testing.
> - **Martin Kleppmann** (Cambridge) — "Designing Data-Intensive Applications" (O'Reilly 2017) and "How to do distributed locking" (2016), which formalized the **fencing-token** argument against Redis Redlock.
>
> **Cited inline:** Wang et al. (USENIX 2017, double-fetch); Xu et al. (S&P 2020, KRACE); Engler & Ashcraft (SOSP 2003, RacerX); Lamport (CACM 1978, happens-before); Cahill, Röhm, Fekete (SIGMOD 2008, SSI).
>
> Sources: portswigger.net/research; nob.cs.ucdavis.edu/bishop; USENIX Security 2001/2004/2017; Microsoft Research; CACM; Jepsen.io; martin.kleppmann.com; LLVM/Clang TSan documentation; SOSP 2003; IEEE S&P 2020.

---

## 1. The Primitive — Concurrency as Attack Surface

### The check-then-use boundary

The defining pattern across every race-condition vulnerability is a **non-atomic compound operation** whose component steps span a window during which the world can change. The textbook form is `check(x); use(x);` — the property the check verifies is invalidated between the check and the use. Filesystem TOCTOU calls this *time-of-check to time-of-use*; the web form calls it *state-machine* or *limit-overrun*; the kernel form calls it *double-fetch*; the distributed form calls it *non-linearizable*. Different vocabulary, identical pathology.

The boundary is non-atomic with respect to some interleaving observer:

| Domain | Observer that interleaves |
|---|---|
| Filesystem | Concurrent process via fs syscalls |
| Web app | Concurrent HTTP request via same backend |
| Database | Concurrent transaction in the same isolation level |
| Kernel | Another CPU, interrupt handler, or userspace racing kernel |
| Distributed system | Replica that hasn't yet observed the operation |
| Memory (UAF) | Concurrent thread sharing the address space |
| AI agent | Parallel tool invocation in the same agent step |

The attacker's job is to time the interleaving so that the check sees one world and the use sees a different one.

### Why concurrency bugs are uniquely hard

Three properties distinguish race conditions:

1. **Non-determinism.** Two identical runs can produce different observable behaviors. A vulnerable race may execute correctly 9,999 times in testing and only manifest in production once attackers start probing. Standard unit tests exercise the sequential happy path, not interleavings.
2. **Heisenbug behavior.** Instrumentation (printf, breakpoints, tracing) perturbs timing enough that the race stops reproducing. The term predates CHESS; Jim Gray used it in a 1985 Tandem report for a bug that appears to alter or disappear when one attempts to study it.
3. **Asymmetric exploitation.** The attacker runs thousands of probes cheaply; defender baseline is one or zero observed occurrences. In Dean & Hu's framing: the attacker can lose almost every race, as long as they win at least one.

These properties explain why race conditions are systematically under-found by traditional QA — they live in the gap between "does the code work?" (which testing answers) and "what happens under an adversarial scheduler?" (which it doesn't).

### Concurrency bugs vs logic bugs vs memory-safety bugs

- **Pure logic bug:** Wrong outcome regardless of scheduling. Reproducible single-threaded.
- **Pure memory-safety bug:** Spatial or temporal memory violation independent of scheduling. Reproducible single-threaded.
- **Pure concurrency bug:** Correct under all single-threaded interleavings; wrong under some multi-threaded interleaving. Not reproducible single-threaded.

Real-world bugs cross boundaries. Concurrent use-after-free is both memory-safety and concurrency. Double-fetch (Wang et al., USENIX 2017) is both input-validation and concurrency — the validated value differs from the used value because the kernel reads userspace memory twice. The same defensive primitive (read-once-into-kernel, validate, then use) closes the entire double-fetch class. The same offensive primitive (single-packet attack) crosses from "web race" into atomicity of any backend operation the HTTP layer composes.

### Happens-before as the theoretical underpinning

Lamport's 1978 paper introduced the **happens-before** partial order: A happens-before B if A is on the same process and earlier in program order, OR A is the send of a message B receives, OR transitively. Two events not related by happens-before are **concurrent**. A data race is formally two memory accesses to the same location by different threads, at least one a write, concurrent under happens-before. TSan, FastTrack, and Helgrind all compute approximations of this at runtime.

Locks work by manufacturing happens-before edges: acquiring a lock another thread previously released creates an ordering edge that transitively orders all events on each side.

### Real-world impact

Race conditions have produced:

- **LPE** — Dirty COW / CVE-2016-5195 (Linux mm/gup.c race in copy-on-write, present since 2007, exploited in the wild).
- **Auth bypass** — Kettle's GitLab case studies (invitation and email-change races) via single-packet race.
- **Double-spend** — banking duplicate-credit races.
- **Filesystem permission bypass** — decades of OpenSSH, sudo, setuid TOCTOU CVEs.
- **Distributed data loss** — MongoDB w=majority writes lost under partition; Redis Sentinel split-brain; Cassandra/etcd linearizability violations across the Jepsen corpus.
- **Container/VM escape** — runc CVE-2019-5736 had a TOCTOU component; CRIU/namespace races.
- **Web logic violation** — vote-counting, voucher redemption, MFA-bypass via parallel-codepath enrollment.

Blast radius is bounded by the operation made non-atomic — and the operations composed via shared state are often the most security-sensitive: authorization, financial transactions, identity proofs, capability checks.

---

## 2. Filesystem TOCTOU — The Classical Instance

### The canonical pattern: `access()` then `open()`

The defining filesystem race is the setuid-binary check:

```c
// VULNERABLE
if (access("/tmp/foo", W_OK) == 0) {       // 1. check (uses real UID)
    int fd = open("/tmp/foo", O_WRONLY);   // 2. use (uses effective UID)
    write(fd, attacker_data, len);
}
```

`access(2)` checks against the real UID, not the effective UID, so a setuid program can verify "the calling user has permission to write this file" before doing the write. Between line 1 and line 2, the attacker swaps `/tmp/foo` for a symlink to `/etc/passwd`. The check sees the original file (user has permission); the open follows the symlink and writes to a root-owned target.

Bishop & Dilger's 1995 UC Davis tech reports laid out the full taxonomy of this pattern. Bishop's "Race Conditions, Files, and Security Flaws; or the Tortoise and the Hare Redux" (CSE-95-9) framed the abstract problem; the companion CSE-95-10 (with Dilger) presented a static analyzer that detected `stat()/access()/lstat()` followed by `open()/creat()/exec()` patterns.

### Symlink swap and /tmp races

Any syscall taking a pathname follows the symlink at resolution time. If the attacker controls a directory along the path, they can rename or symlink entries between sequential pathname-based syscalls.

`/tmp` is world-writable, so any setuid binary creating files there with predictable names invites the **tempfile race**: pre-create `/tmp/myprog.XXXX` as a symlink to `/etc/passwd`; the setuid binary's `open(path, O_WRONLY|O_CREAT)` follows the symlink. Defenses: `mkstemp(3)`, `tmpfile(3)`, or — modern recommendation — `O_TMPFILE` (Linux 3.11+) which creates an unlinked inode that has no path at all.

### Mitigations: the file-descriptor discipline

The single most important defensive primitive against filesystem TOCTOU is **operate on file descriptors, not pathnames**. Once you have an open file descriptor, the kernel's path-resolution layer can no longer be raced — the FD points at a specific inode, not a name that can be swapped.

| Bad (pathname-based) | Good (fd-based) |
|---|---|
| `stat(path)` | `fstat(fd)` |
| `chmod(path, mode)` | `fchmod(fd, mode)` |
| `chown(path, uid, gid)` | `fchown(fd, uid, gid)` |
| `open(path)` after check | `openat(dirfd, name, O_NOFOLLOW)` once |
| `unlink(path)` | `unlinkat(dirfd, name, ...)` |

`openat(2)` (Linux 2.6.16+) lets the caller bind the resolution to a specific directory fd, eliminating the race in which the parent directory is swapped between the dirname-lookup and the basename-open.

### `openat2()` and `RESOLVE_BENEATH` (Linux 5.6+)

Linux 5.6 added `openat2(2)` with explicit resolution-restriction flags: `RESOLVE_BENEATH` (refuse to resolve outside the starting dirfd — no `..`, no absolute paths, no out-of-tree symlinks), `RESOLVE_NO_SYMLINKS` (refuse all symlinks), `RESOLVE_NO_MAGICLINKS` (refuse `/proc/PID/fd/N`), `RESOLVE_NO_XDEV` (refuse FS boundary crossing), `RESOLVE_IN_ROOT` (treat dirfd as `/`). Modeled after FreeBSD's `O_BENEATH` but corrected its bug; FreeBSD 13+ renamed to `O_RESOLVE_BENEATH` and aligned semantics with Linux. These flags are the modern primitive for safe pathname operations in security-sensitive code.

### Subterfugue: ptrace-based TOCTOU exploitation

Subterfugue (Michael Karl Coleman, 2000) was a ptrace-based syscall-interposition framework that intercepted `access(2)` returns and paused the target until the attacker's swap completed, turning TOCTOU races into reliable single-shot exploits. The tool is unmaintained; the concept (ptrace-based scheduling control) survives in Mozilla's `rr` for deterministic replay of concurrency bugs.

### Cross-link to firmware/embedded

See `firmware_embedded_security.md` for the setuid corpus and the cross-references between filesystem TOCTOU and embedded-Linux privilege boundaries. The mitigations there (capabilities, fully unprivileged daemons, file-descriptor passing over UNIX sockets) are the deployment-side complement to the syscall-level defenses listed here.

---

## 3. Kettle's Single-Packet Attack — The Web Revolution

### "Smashing the State Machine" (Black Hat USA 2023)

James Kettle's 2023 Black Hat talk and accompanying PortSwigger research paper ("Smashing the State Machine: The True Potential of Web Race Conditions") is the canonical modern web race-condition reference. Three contributions:

1. **The single-packet attack** — a new technique that defeats network jitter and enables effectively-simultaneous arrival of 20–30 requests at any server reachable over HTTP/2.
2. **The state-machine framing** — extends the analysis beyond "limit overrun" (the prior dominant frame) to cover any application state-machine where transitions are non-atomic.
3. **Tooling** — a `single_packet_attack` engine in Turbo Intruder (PortSwigger's Burp Suite extension), the first widely-available tooling to make these attacks routine.

### Why prior race attempts were weak

Before single-packet, the dominant technique was bursting HTTP requests as fast as possible. Two problems: TCP serialization on a single connection (pipelined requests get processed serially by the HTTP parser), and network jitter across multiple connections (TCP/TLS handshake variance, OS scheduling) that exceeded the race window for most application-layer races. Races that should have been exploitable often weren't, because attackers couldn't deliver requests with low enough inter-arrival variance.

### The technique: last-byte synchronization on HTTP/2

HTTP/2 multiplexes multiple streams over a single TCP connection. Kettle's procedure:

1. Open a single HTTP/2 connection.
2. For each race candidate, send all of the request EXCEPT the final byte of the body.
3. Wait for all "almost-complete" requests to stage on the server.
4. Send the final bytes of all requests in a **single TCP packet**.

The server can't act on any request until each is complete; completion comes from one packet arriving in one network event. Server-side processing then proceeds in parallel with inter-request variance bounded by internal scheduling, not by network jitter. Kettle measures sub-1ms execution windows for 20–30 requests sent from Melbourne to Dublin — tighter than the timer-resolution of most rate-limit checks.

### Real-world targets

Validated by Kettle and subsequent disclosures:

- **Voucher / promo redemption** — redeem the same code N times before any worker observes the "used" flag.
- **Multi-step financial flows** — drain an account through N parallel transfers, each individually passing the balance check.
- **MFA bypass** — complete a sensitive action before MFA-enrollment is observed by the auth path.
- **Vote counting / poll-stuffing** — cast multiple votes before the "has this user voted?" flag propagates.
- **Token / invitation acceptance** — accept the same invite into multiple accounts.
- **Email verification token reuse** — validate-then-invalidate is not atomic.

### A 5-step methodology

1. **Identify the limit or guarded action** — anywhere the app says "X only once" or "X requires precondition Y." Universe of candidate races.
2. **Find the security implication** — financial transactions, authorization grants, identity proofs, capability redemption. Not every limit is a security boundary.
3. **Establish prerequisites** — unused token, account with balance, invite waiting.
4. **Probe with single-packet** — 5–30 parallel requests. Look for: multiple HTTP 200s where you expected 1 success + N failures, multiple distinct success bodies, observable state changes >1.
5. **Refine** — if the window is too narrow, widen it: debug parameters that slow the backend, expensive operations on the same codepath, slow third-party calls.

### Turbo Intruder + single_packet_attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

The `gate=` parameter stages requests; `openGate` releases them in the single-packet pattern. A successful race shows N successful responses where the state machine should have allowed only 1.

Subsequent research: Flatt Security's 2024 "Beyond the Limit" extends Kettle's technique past the single-packet attack's ~1,500-byte limit via IP fragmentation and first-sequence sync. HTTP/3 (QUIC) primitives are being re-derived now.

### Cross-link to HTTP/Web security

See `http_web_security.md` for related primitives: HTTP request smuggling, HTTP/2 desync, CRLF injection. Single-packet race is the **concurrency analog** of the request-smuggling family: both exploit gaps between layers of the HTTP stack to make backend state inconsistent with what the parser believes happened.

---

## 4. Database-Layer Race Conditions

### Row-level locking and the lost-update anomaly

The canonical database race is **lost update**:

```sql
-- Transaction A and B both run concurrently:
BEGIN;
SELECT balance FROM accounts WHERE id = 1;  -- A and B both read 100
-- application computes balance - 10 (= 90)
UPDATE accounts SET balance = 90 WHERE id = 1;
COMMIT;
```

Both transactions read 100; both write 90. One $10 debit is lost. Under READ COMMITTED isolation (default in many systems), there is no detection of this conflict. In PostgreSQL the conflict surfaces under REPEATABLE READ or SERIALIZABLE (or via explicit `SELECT ... FOR UPDATE`).

### Locking and concurrency control

`SELECT ... FOR UPDATE` acquires a row-level write lock during the SELECT, serializing the critical section at the cost of blocking. Common misuse: it only locks rows the SELECT returns. `SELECT ... WHERE foo = 'bar' FOR UPDATE` does not prevent INSERT of a new row with `foo = 'bar'` (the **phantom read** problem). Defense: SERIALIZABLE isolation or explicit range locks.

**Pessimistic** (locks): hold until commit. Correct but blocks. **Optimistic** (version numbers / OCC): write conditional on version-number still matching; retries on conflict. Optimistic works well when conflicts are rare; pathological under high contention. PostgreSQL's SERIALIZABLE uses Serializable Snapshot Isolation (Cahill et al., SIGMOD 2008) — snapshot-read tracking rw-antidependency edges, aborting transactions that form a dangerous structure of two adjacent edges.

### The double-spend pattern

Financial/inventory lost-update: `get_balance(X) → check balance ≥ amount → debit(X, amount) → credit(Y, amount)`. Two parallel calls both read balance=1000 and both pass the check; both debits land; account overdraws.

Defense: collapse check and debit into one atomic database operation:

```sql
UPDATE accounts SET balance = balance - 1000 WHERE id = X AND balance >= 1000;
-- Check rowcount; if 0, abort.
```

The `WHERE balance >= 1000` clause makes the check-and-debit atomic at the database layer. This is the database analog of compare-and-swap.

### PostgreSQL SERIALIZABLE pitfalls

SSI provides true serializability under MVCC. Cost: occasional `40001 serialization_failure` at commit; transactions must retry. Common pitfalls: application code that catches `serialization_failure` and ignores it (silently commits inconsistent state — must retry the whole transaction logic); long-running transactions that accumulate predicate locks until memory pressure forces escalation; READ ONLY transactions held open forcing writer aborts (use `READ ONLY DEFERRABLE`).

### MongoDB find-and-modify

MongoDB's `find()` followed by `update()` is not atomic — another writer can modify between. The fix is `findAndModify`/`findOneAndUpdate`. Applications predating this API often have races that survive migration if the developer doesn't realize the find-update pair was supposed to become one operation. Jepsen's MongoDB analyses repeatedly found that even `w=majority` writes could be lost during partition recovery — driving MongoDB's adoption of Raft-based replication.

### 2-phase commit pitfalls

2PC's race is **prepare-then-crash**: coordinator says "prepare," participants reply "prepared," coordinator commits its decision then crashes before notifying. Participants block (can't abort — others may have committed; can't commit — haven't received the message), holding locks until coordinator recovers. This is why 2PC is called the "blocking protocol." Modern systems prefer single Raft/Paxos groups over cross-group 2PC.

### Cross-link to GraphQL/API security

See `graphql_api_security_expertise.md` §2 for BOLA + race interactions. The common pattern: a GraphQL mutation that performs an authorization check, then performs a database operation that's separately fetched. Two such mutations in parallel can confuse the authorization layer about which object was actually accessed.

---

## 5. TOCTOU in Authorization

### The "auth check on validate, action on different value" pattern

This CWE-863 (Incorrect Authorization) pattern: an entry-decorator checks authorization on parameter X, but the body of the handler operates on parameter Y. The check authorizes X; the action happens on Y. If the attacker can vary the relationship between X and Y, the authorization is bypassed.

Example (Python/Django-style):

```python
@require_object_permission('document', 'document_id', 'read')
def get_document(request, document_id):
    target_id = request.GET.get('target_id', document_id)  # ← Y diverges from X
    document = Document.objects.get(id=target_id)
    return JsonResponse(document.to_dict())
```

The decorator checked permission on `document_id`. The body operated on `target_id`. The attacker passes a `document_id` they have permission on, but a `target_id` they don't — and the check passes while the action goes through.

This is technically not a race condition in the sense of *concurrent threads* — both the check and the action happen on the same request, in sequence. But it's an atomicity violation in the sense that *the property the check verifies* (authz on X) is not the property the action requires (authz on Y). It's a *value-domain* race rather than a *time-domain* race.

### Time-domain authz races

Classical time-domain authorization races:

- **Permission revocation** — user U has permission P at t1; revoked at t2; request started at t1 < t2 completes at t3 > t2. Most systems miss the revocation: check happened at start, action completes later.
- **Group-membership race** — U briefly added to admin group, performs action, removed. Action proceeds. Defense: re-verify at moment of action, not request entry.
- **Token revocation race** — JWT checked at request entry; revocation between entry and action is missed unless application explicitly checks revocation list.

### React Server Components / Next.js Server Actions

Naive Next.js pattern: `getCurrentUser()` then `if (!user.canDelete(postId)) throw` then `db.posts.delete(postId)`. If `getCurrentUser` reads from a session store that can be modified concurrently, check and action might use different identities. More commonly: Server Actions invoke side effects not transactional with the auth check, so an admin-role revocation between can leave the delete proceeding under stale role.

### Defense: transaction-scoped auth checks

The structural fix makes auth check and action atomic with respect to the source of authorization truth:

```python
with db.transaction():
    user = db.users.get_for_update(user_id)
    if not user.has_permission('delete_post', post_id):
        raise PermissionDenied()
    db.posts.delete(post_id)
```

The lock on `user` serializes concurrent permission revocation; the commit creates the happens-before edge ordering check before action.

### Cross-link to distributed authorization

See `distributed_authz_expertise.md` §7 for the broader TOCTOU-on-authorization treatment — including the distributed-systems failure mode where the auth check happens against one replica and the action against another, and the replicas haven't yet synchronized a revocation.

---

## 6. Memory-Safety Race Conditions (UAF, Double-Free)

### Concurrent use-after-free

The canonical race:

```c
// Thread A: free(obj);
// Thread B: obj->method();   // ← UAF if scheduled after A's free
```

Without explicit synchronization, the C/C++ memory model permits arbitrary interleavings. Common in real-world C++: refcount races (drop last reference + use stale pointer), callback-after-shutdown (unregister + dispatch race), async-completion races (free `this` while I/O completion thread calls into it).

### TOCTOU in reference counting

The classic refcount race: `if (atomic_load(&refcount) == 1) { free(obj); } else { atomic_dec(&refcount); }`. Between the load and the decision, two threads both load 1 → double-free, or one thread frees while another increments → UAF. Fix: `atomic_dec_and_test()` (or `__atomic_sub_fetch` returning the new value) atomically decrements and tests, eliminating the window. Linux's `kref` and `refcount_t` encapsulate this; misuse of plain `atomic_t` for refcounts has produced dozens of CVEs.

### iOS XNU and Linux kernel concurrency

Post-2018 iOS sandbox escapes have relied heavily on XNU races: find an IPC/syscall handler operating on a shared object, invoke from two threads with carefully timed arguments, cause state transitions between consistency checks, exploit the resulting UAF/type-confusion/OOB. Examples include IOSurface (cross-process shared memory), various IOKit drivers, AppleAVD, Mach voucher reference counting.

Linux user namespaces (CLONE_NEWUSER) introduced a major attack surface: CVE-2021-3493 (Ubuntu OverlayFS did not validate file-capability setting with respect to user namespaces), CVE-2022-0185 (heap overflow in legacy_parse_param, reachable with namespaced CAP_SYS_ADMIN), CVE-2023-32233 (nf_tables use-after-free from mishandled anonymous sets in batch requests). Prolific enough that distributions have considered disabling unprivileged user namespaces by default (Ubuntu 23.10+ uses AppArmor restrictions).

The "use-after-symlink" cousin: an operation captures a directory fd, the attacker swaps the directory's contents or replaces it with a symlink, the operation proceeds on what it believes is the original. Defense: `openat2()` with `RESOLVE_NO_SYMLINKS` + `RESOLVE_BENEATH`; for capability handoff, prefer fd-passing over UNIX sockets to passing pathnames.

### ThreadSanitizer + AddressSanitizer

TSan (Serebryany 2009/2011) catches the concurrency aspect via happens-before; ASan catches the memory-safety aspect via shadow memory and red zones. Each catches a different facet of concurrent UAF — TSan flags missing happens-before; ASan flags the actual use-after-free if it manifests. Combining both in CI on a multithreaded fuzz harness finds far more bugs than either alone. Overhead (TSan ~5–15x, ASan ~2x) makes them CI-only, not production-deployed.

### Cross-link to macOS memory-corruption investigation

See `macos_memory_corruption_investigation.md` for the heap-spray and nano-zone-internals discipline. The intersection with this section: many race-condition exploits *use* memory corruption as the payload, but the *primitive* is the race. Treat them as separate layers: the race makes the corruption possible; the heap-layout work makes it useful.

---

## 7. Distributed-Systems Race Conditions

### Linearizability and the consistency hierarchy

**Linearizability** (Herlihy & Wing 1990): each operation appears to take effect atomically at some point between invocation and response, consistent with the object's sequential specification. Informally, the system looks like a single shared atomic copy. Weaker models in order: linearizability > sequential consistency (program order without real-time constraint) > causal consistency (happens-before order, concurrent ops free) > eventual consistency (converge after quiescence).

The Jepsen consistency map is the canonical visualization. Critical insight: many systems claim "strong consistency" while offering only partial guarantees (linearizable reads but not writes; linearizable on leader but not followers). Jepsen's value is empirically testing the claim against the implementation.

### CAP and Jepsen

Brewer's CAP theorem (Gilbert & Lynch 2002): under partition, choose Consistency or Availability. Practical choice is AP (eventually consistent, available) vs CP (linearizable, refuses during partition); CA is single-machine. Security implication of AP: the same authorization decision can produce conflicting answers on different replicas during partition — both replicas accepting "transfer $1000" splits-brains the model. CP means partition attacks deny service.

Jepsen's methodology: cluster of N nodes, stream of client operations, fault injection (iptables partitions, crashes, clock skew, filesystem corruption), record history, run a checker (Knossos linearizability, Elle transactional isolation). Public findings include:

- **MongoDB** — lost committed writes under partition pre-Raft.
- **Redis** — Sentinel split-brain under partition lost 56% of acknowledged writes.
- **Cassandra** — lightweight transactions not linearizable, losing acknowledged writes even without a partition; stale reads under default consistency.
- **CockroachDB / FaunaDB / TiDB / YugabyteDB** — extensive Jepsen iteration to reach SERIALIZABLE.
- **PostgreSQL** — single-node SERIALIZABLE exhibited G2-item anomalies in 12.3 (bug present since 9.1); multi-node logical replication does not provide linearizability.

The security takeaway: never trust consistency claims without empirical validation. Jepsen-style stress testing belongs in any security review of systems that depend on distributed consistency for authorization, financial transactions, or audit-trail integrity.

### Cross-link to vulnerability-research methodology

See `vulnerability_research_methodology_expertise.md` §4 for the application of fuzzing-as-discipline to distributed-system correctness. The same epistemics — adversarial scheduler, oracle for correct behavior, large-scale automated runs — apply to both fuzzing and Jepsen-style testing. See also `fuzzing_discipline_expertise.md` for the related concurrency-fuzzing tools.

### AWS S3 strong-read-after-write

S3 offered only eventual consistency for object writes for 15 years — new objects could 404 after PUT if the key had been requested before it existed; overwrites could read stale data. Constant source of races in customer code assuming read-your-writes. AWS shipped strong consistency for all S3 operations in December 2020. The migration was multi-year top-level engineering work — retrofitting linearizability onto a system originally designed AP is hard at hyperscaler scale.

### Distributed-lock anti-patterns + Kleppmann's fencing tokens

The naive SETNX pattern: `redis.set(key, "owner", nx=True, ex=30)`, hold lock, release. Vulnerable when the critical section runs longer than TTL:

1. Client A acquires lock TTL=30s.
2. A pauses (GC, scheduling) for 35s.
3. Lock expires. Client B acquires.
4. A resumes, still believes it holds the lock, performs the critical operation.
5. B also performs the critical operation. Race with no detection.

Kleppmann's 2016 "How to do distributed locking" formalized why **fencing tokens** are the only correct solution: monotonically-increasing IDs issued at acquisition, validated at the storage layer. Even if A and B both believe they hold the lock, storage accepts only the operation with the higher token.

```python
token = acquire_lock_returning_token("important-job")
storage.write(data, fencing_token=token)
# storage rejects writes with token < last-seen token
```

Redis Redlock generates random nonces, not monotonic IDs, so it cannot be made safe for correctness boundaries. Use ZooKeeper, etcd, or Consul (consensus-based, monotonic IDs). Sanfilippo defended Redlock in "Is Redlock safe?" — the debate continues; the security takeaway is that any lock scheme without a fencing token is advisory only.

### Multi-region replication

Cross-region replication adds latency to the race window: DynamoDB Global Tables use last-writer-wins by timestamp (older write silently lost); Aurora Global Database is eventually consistent (cross-region lag typically under 1s); Spanner/Cosmos offer linearizability at latency cost. Security review of multi-region apps: what consistency does the application *assume* and what does the store *provide*? Mismatches are races waiting to happen.

---

## 8. AI Agent Concurrency

### Parallel tool execution: the "two tools see the same world" assumption

Modern LLM agent frameworks (Anthropic's Claude tool-use, OpenAI function calling, LangGraph, ReAct-style agents) increasingly support **parallel tool calls** — the model emits multiple tool invocations in one turn, and the framework executes them concurrently. This is a significant performance win over sequential execution but introduces race conditions that the LLM is not equipped to reason about.

The "two tools see the same world" assumption: the model writes its tool calls as if they execute sequentially with no interleaving, and reads tool results as if each reflects state caused only by the model's prior turns. Parallel execution breaks this.

### Three canonical patterns

1. **Shared-state mutation** — parallel `increment_counter(key, +10)` and `increment_counter(key, +20)` against a read-compute-write implementation produces lost-update. Initial 100 + parallel +10/+20 should yield 130; classic race yields 110 or 120.
2. **Read-then-act dependencies** — model sees A and B both return `in_stock: 1`, emits parallel `reserve_item(sku=X)` from C and D, both succeed, over-sold. Fix at the tool layer: `reserve_item` must atomically check-and-reserve, not trust the model's prior knowledge.
3. **Budget / quota checks** — budget-check tool returns "remaining: $50", model emits multiple $30 calls, all pass individual budget-check, total exceeds $50. Fix: enforcement at the tool gateway, not in model reasoning. Each call atomically decrements; insufficient = fail.

### Idempotency tokens

The same defense that secures payment APIs against client retries secures agent tool calls against parallel-execution races: **idempotency keys**. The agent framework attaches a unique idempotency key to each tool call (typically derived from a hash of the call arguments + a random nonce). The tool implementation deduplicates against this key — a second invocation with the same key returns the cached result rather than re-executing.

For destructive operations (`delete_record`, `send_email`, `charge_card`), idempotency is the only way to make parallel agent execution safe without manual reasoning about which tools can be parallelized.

### Race between LLM context update and tool execution

A subtler race: the LLM is invoked again before all parallel tool calls complete. The model may receive partial results (some tools' outputs available, others still running) and emit follow-up tool calls based on the partial view. If the framework doesn't strictly wait for all tools to complete before re-invoking the LLM, the agent can produce contradictory action sequences. This is implementation-dependent; the safe default is to wait for all parallel tool calls before re-invoking the model.

### Multi-agent race conditions

Multi-agent orchestration (LangGraph supervisors, AutoGen group chats, ChatDev) adds a higher-order concurrency surface: two agents acting on the same shared resource (workspace, ticket queue, database). The "two AI agents acting on the same user account" surface is emerging; the defenses are the same as for any concurrent system (locks, optimistic concurrency, idempotency), but they have to be designed in — the agent framework does not provide them by default.

### Cross-link to LLM agent security

See `llm_agent_security_expertise.md` §1 for trust-boundary analysis of agent tool calls. See `agentic_web_capabilities_expertise.md` for capability-based defenses; capability revocation under concurrency is a known hard problem — the capability may be revoked while the agent's parallel tool call is in flight.

---

## 9. Detection — Static + Dynamic

### Static analysis patterns

Cross-reference the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview). The high-value static patterns:

- **TOCTOU candidate** — `if ($CHECK($X)) { ... $ACT($X) ... }` where `$CHECK` is `access|stat|lstat|exists|is_authorized|has_permission` and `$ACT` is `open|fopen|write|delete|grant|execute`. Low precision (single-threaded code is fine), useful for triage.
- **Pathname-based syscall in security-critical path** — `open`/`chmod`/`chown`/`unlink`/`rename` taking strings in setuid binaries; recommend `*at` variant.
- **Non-atomic refcount** — `if (--refcount == 0) free(...)`. Recommend `atomic_dec_and_test` / `refcount_dec_and_test`.
- **Unsynchronized shared-state in goroutines / async** — Go: shared writes inside `go func() {}()` without `sync.Mutex`. Python asyncio: shared mutations across `await` without `asyncio.Lock`. Rust: borrow-checker handles `&mut T` but not external resources.
- **Missing condition in atomicity-critical UPDATE** — `UPDATE accounts SET balance = balance - $X WHERE id = $ID` without `AND balance >= $X`. High-FP unless scoped to specific tables; useful as code-review hint.
- **BYPASS / disabled-check in concurrent path** — permission/lock-bypass flags in fork/spawn paths. Detection corpora for CWE-863 commonly include variants against decorator-based authz.

### Dynamic detection: the sanitizers

- **ThreadSanitizer (TSan)** — happens-before race detection via shadow memory and per-thread vector clocks. Overhead 5–15x. Reports only races that actually occur during test runs (floor, not ceiling). Some races are technically true under the C++ memory model but benign (e.g., double-checked locking with atomics) and need annotation.
- **Helgrind / DRD** — older Valgrind-based race detectors. Useful when TSan unavailable.
- **Go race detector** (`go build -race`) — same TSan algorithm, idiomatic in Go CI. Mandatory in concurrent Go code.
- **Rust** — borrow checker eliminates most data races at compile time. `Send`/`Sync` traits encode thread-safety. Remaining surface (`unsafe`, FFI, OS resources) exercised with `loom` (model checker) or `miri` (interpreter with UB detection).
- **libFuzzer + TSan/ASan combo** — multithreaded fuzz harnesses under multiple sanitizers. Kernel equivalent: syzkaller + KASAN/KCSAN.

### Concurrency-specific testing tools

- **CHESS** (Musuvathi et al., Microsoft Research, OSDI 2008) — context-bounded model checking. Most concurrency bugs manifest within 2–3 preemptions, so bounding context switches makes exploration polynomial. Found 27 bugs, 25 previously unknown, in Microsoft code bases.
- **RoadRunner** (Flanagan & Freund) — framework containing FastTrack. Pluggable dynamic-analysis tools for Java (race detection, atomicity violations, lock-order checking).
- **KRACE** (Xu et al., S&P 2020) — concurrency-aware kernel-filesystem fuzzer. Tracks alias coverage (which interleavings were exercised). Found 23 races in ext4/btrfs/VFS, 9 confirmed harmful.

### The production-vs-test reality

Race conditions show up in production, not in tests. Three reasons: tests are mostly single-threaded; production hardware differs (NUMA, core count, cache topology); production has adversaries actively probing. Assume the test suite has not exercised concurrent codepaths. Reason about concurrency from the code, not from test confidence. Use sanitizers and static analysis to extract candidate races; review each for atomicity.

### Cross-link to detection engineering

See `detection_engineering_expertise.md` for SIEM-side detection of race-exploitation behaviors: rapid bursts of HTTP requests to the same endpoint, repeated `access(2)` calls from setuid binaries, multiple successful "first-time" actions on the same token. These are observable indicators of an active race-exploitation campaign.

---

## 10. Defensive Patterns

### Atomicity primitives

The fundamental defense is atomicity at the right boundary. Three building blocks:

1. **Compare-and-swap** — hardware-atomic (`cmpxchg`, `LL/SC`). Basis of lock-free data structures. `compare_exchange` in C++/Rust, `AtomicReference.compareAndSet` in Java, `sync/atomic.CompareAndSwap` in Go.
2. **Locks** — pthread mutexes, Java `synchronized`, Go `sync.Mutex`, Python `threading.Lock`. Simple but heavy; correct if lock ordering is consistent (no deadlock).
3. **Atomic database operations** — `UPDATE ... WHERE condition`, `INSERT ... ON CONFLICT`. Push atomicity to the database layer.

**The general rule: the check and the act must be inside the same atomic boundary as the source of authorization truth.** If the check looks at the database but the act happens in application memory, the boundary is wrong.

### Lock-ordering discipline

Locks prevent races but introduce deadlocks if multiple locks are acquired in inconsistent orders. Discipline: define a global lock order; use try-lock + back off when the order can't be statically guaranteed; annotate lock-required functions (Java `@GuardedBy`, Clang Thread Safety Annotations); use lockdep (kernel) or Coverity (commercial) for static lock-order analysis.

### Idempotency

Design operations so retries are safe. Attach a unique idempotency key to each operation; the server deduplicates against the key and returns the cached result on second invocation. Cost: storage to remember keys, plus transactional consistency between dedup state and the operation's effects. The same defense that secures payment APIs against client retries secures any parallel duplicate invocation.

### Fencing tokens

For distributed-lock correctness, fencing tokens (monotonic IDs issued at acquisition, validated at the operation target) are the only structural defense against lock-expiry races. Use ZooKeeper, etcd, or Consul for issuance; reject operations with stale tokens at the storage layer.

### Optimistic concurrency with version numbers

Application-layer CAS:

```python
rows = db.execute(
    "UPDATE t SET data = $1, version = version + 1 WHERE id = $2 AND version = $3",
    new_data, row_id, expected_version)
if rows == 0:
    raise OptimisticConcurrencyError()
```

Two clients reading version=5 both try to update; one succeeds, the loser sees `rows == 0` and rereads. Cleaner than locking; no deadlocks; works across distributed clients.

### Transaction-scope auth checks

For authorization races, do the check inside the same transaction as the action with the user/policy row locked:

```python
with db.transaction():
    user = db.users.get_for_update(user_id)
    if not user.has_permission('action', target_id):
        raise PermissionDenied
    db.targets.update(target_id, ...)
```

The lock on `user` serializes concurrent permission revocation against this transaction; the commit creates the happens-before edge between check and action.

### Avoid pathname-based security checks

Operate on file descriptors. `fstat(fd)`, not `stat(path)` then `open(path)`. `openat(dirfd, name, O_NOFOLLOW)` for safe parent-anchored opens. Eliminates a whole class of TOCTOU.

### HTTP rate limiting is necessary but not sufficient

Per-user-per-endpoint rate limiting bounds the frequency of race attempts but not the parallelism of a single burst — single-packet lands 20–30 requests with a ~1ms median spread, below the resolution of most rate limiters. Rate limiting raises cost; it does not close the race. The structural defense is application-layer atomicity: check-and-act as one database operation with idempotency or fencing tokens.

### Code review checklist

For any code operating on shared state:

1. **What's the atomic boundary?** If you can't name it, there isn't one.
2. **Are check and act inside the same boundary?** If they cross, there's a race.
3. **What happens-before edges enforce ordering?** Locks, transaction commits, atomic operations.
4. **What's the worst interleaving?** Adversarial scheduler — what order could two threads execute these in?
5. **Where is irreversible state change?** That's where the race matters most.
6. **Failure mode if race wins?** Silent state corruption vs. observable error.
7. **Idempotency key for external side effects?** HTTP call, email send, payment — should have one.
8. **Pathname-based syscall with an `*at` variant available?** Prefer FD-based.
9. **Refcounts: atomic decrement-and-test?** Use `dec_and_test` primitives.
10. **Distributed locks: fencing token?** Without one, advisory only.
11. **TSan / `-race` clean?** Floor on confidence; fix any reports before review proceeds.
12. **Production load shape?** What would 1000 parallel requests do?

### Cross-link to code review

See `code_review_expertise.md` for the click-count severity model and the heterogeneous-auth-pattern heuristic. Race-condition severity follows the click-count model: a zero-click race (anonymous, unauthenticated, no preconditions) is HIGH/CRITICAL; a multi-click race requiring privileged access is LOW/MEDIUM. The auth-homogeneity heuristic catches the auth-races: when the same logical operation is checked differently in different code paths, the inconsistency is a race waiting to happen.

---

## 11. Variant Analysis — Under-Explored

### Browser-extension content-script ↔ background-script handoff

Extensions split execution between content scripts (page context, limited privileges) and background scripts (extension context, full capabilities). Communication is asynchronous message-passing. Between send and receive: the content script's page may have navigated; a different content script may have sent its own message; the tab may have been switched/suspended; the background script may have been discarded (Manifest V3 service workers). Validation must verify origin matches the sending tab's *current* URL, not the URL at message-send time. Most extensions get this wrong.

### WebAssembly threading

`SharedArrayBuffer` and atomics expose the same race conditions as native C/C++ in a sandboxed context. Browser defenses (cross-origin isolation, Spectre mitigations) limit some attacks; application-level races (UAF in wasm heap, refcount races) remain. Wasm fuzzing is an active research area (Wasmtime continuous fuzzing, Mozilla Wasm-sandbox audits).

### iOS / Android intent-handling

Mobile IPC is concurrent by construction. Intent-redirect TOCTOU: validate sender package, perform action; sender package could be replaced during update windows. Universal-link race: between OS's "which app claims this URL?" check and dispatch, transient windows exist during install/uninstall.

### Cloud-IAM policy evaluation races

IAM policies evaluate per-request. AWS has eventual consistency for policy changes — new policies take seconds to propagate. In-flight requests may use the old policy. Between "policy updated to deny" and "all requests denied" is a window of seconds to minutes. For critical revocation, supplement policy changes with credential rotation.

### CI/CD: PR-merge race conditions

GitHub branch protection checks the branch state at merge time. Between "checks passed" and the merge, a new commit could have landed on `main` from another PR. CI ran against the old base; the merged state was never validated. Two security PRs each passing CI can land a combined state that no reviewer saw. Defense: require branch-up-to-date; use merge queues (gh merge-queue, Bors).

### Two AI agents acting on the same user account

The emerging variant. Users delegate to multiple agents (coding, research, assistant), each with API tokens to the same accounts. Agents execute concurrently without coordination — two simultaneously processing the same email queue, Notion workspace, or calendar interact in races neither agent's prompt anticipated. Defense: capabilities (agent-A's token allows X not Y; agent-B's allows Y not X), idempotency at the API tier, explicit serialization tokens. Current state of practice is poor; open security-engineering problem.

### Feature-flag and webhook races

Feature flags evaluated per-request: flag flipped mid-flow produces inconsistent behavior (flow starts with feature=off, submit handler hits a code path that wasn't exercised at start). For security flags, snapshot at flow start; do not re-evaluate mid-flow. Async webhooks: parallel deliveries of related events interleave incorrectly unless consumers are idempotent on event ID. Stripe/GitHub/Shopify webhook docs all emphasize this; still a common implementation gap.

---

## 12. References

### Foundational academic papers

- Lamport, L. ["Time, Clocks, and the Ordering of Events in a Distributed System"](https://lamport.azurewebsites.net/pubs/time-clocks.pdf). CACM 21(7), 1978.
- Bishop, M. ["Race Conditions, Files, and Security Flaws; or the Tortoise and the Hare Redux"](https://seclab.cs.ucdavis.edu/projects/vulnerabilities/scriv/ucd-ecs-95-08.pdf). UC Davis CSE-95-9, 1995.
- Bishop, M. and Dilger, M. "Checking for Race Conditions in File Accesses". UC Davis CSE-95-10, 1995.
- Dean, D. and Hu, A. J. ["Fixing Races for Fun and Profit: How to use access(2)"](https://static.usenix.org/events/sec04/tech/full_papers/dean/dean_html/accessopen.html). USENIX Security 2004.
- Cowan, C. et al. "RaceGuard: Kernel Protection from Temporary File Race Vulnerabilities". USENIX Security 2001.
- Herlihy, M. P. and Wing, J. M. "Linearizability: A Correctness Condition for Concurrent Objects". TOPLAS 12(3), 1990.

### Race detection

- Serebryany, K. and Iskhodzhanov, T. ["ThreadSanitizer – data race detection in practice"](https://research.google.com/pubs/archive/35604.pdf). WBIA 2009.
- Flanagan, C. and Freund, S. N. ["FastTrack: Efficient and Precise Dynamic Race Detection"](https://www.cs.williams.edu/~freund/papers/10-cacm.pdf). PLDI 2009 / CACM 2010.
- Engler, D. R. and Ashcraft, K. ["RacerX"](https://web.stanford.edu/~engler/racerx-sosp03.pdf). SOSP 2003.
- Musuvathi, M. et al. ["Finding and Reproducing Heisenbugs in Concurrent Programs"](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/musuvathi/musuvathi.pdf). OSDI 2008 (CHESS).
- Xu, M. et al. ["KRACE: Data Race Fuzzing for Kernel File Systems"](https://taesoo.kim/pubs/2020/xu:krace.pdf). IEEE S&P 2020.
- Wang, P. et al. ["How Double-Fetch Situations turn into Double-Fetch Vulnerabilities"](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-wang.pdf). USENIX Security 2017.

### Web race conditions

- Kettle, J. ["Smashing the State Machine: The True Potential of Web Race Conditions"](https://portswigger.net/research/smashing-the-state-machine). PortSwigger / Black Hat USA 2023 / DEF CON 31.
- Kettle, J. ["New techniques and tools for web race conditions"](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions).
- PortSwigger Web Security Academy. ["Race conditions"](https://portswigger.net/web-security/race-conditions).
- GMO Flatt Security. ["Beyond the Limit"](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/). 2024.

### Distributed systems

- Kleppmann, M. ["How to do distributed locking"](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html). 2016.
- Sanfilippo, S. ["Is Redlock safe?"](https://antirez.com/news/101).
- Kleppmann, M. *Designing Data-Intensive Applications*. O'Reilly 2017. Chapter 9.
- Jepsen.io — [Distributed Systems Safety Research](https://jepsen.io/).
- Cahill, M. J., Röhm, U., Fekete, A. D. "Serializable Isolation for Snapshot Databases". SIGMOD 2008.
- Ports, D. R. K. and Grittner, K. ["Serializable Snapshot Isolation in PostgreSQL"](https://www.drkp.net/papers/ssi-vldb12.pdf). VLDB 2012.
- PostgreSQL wiki. ["Serializable"](https://wiki.postgresql.org/wiki/Serializable).
- AWS. ["Strong read-after-write consistency for S3"](https://aws.amazon.com/about-aws/whats-new/2020/12/amazon-s3-now-delivers-strong-read-after-write-consistency-automatically-for-all-applications/). 2020.

### Linux kernel / filesystem

- [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html), [LWN — Fixing the symlink race problem](https://lwn.net/Articles/472071/), [Wikipedia — Symlink race](https://en.wikipedia.org/wiki/Symlink_race), [Wikipedia — Dirty COW](https://en.wikipedia.org/wiki/Dirty_COW), [dirtycow.ninja](https://dirtycow.ninja/), [CWE-367 TOCTOU](https://cwe.mitre.org/data/definitions/367.html), [Subterfugue archive](https://github.com/michaelkarlcoleman/subterfugue).

### AI agent concurrency

- Tian Pan. ["Parallel Tool Calls in LLM Agents"](https://tianpan.co/blog/2026-04-10-parallel-tool-calls-hidden-coupling). 2026.
- MachineLearningMastery. ["Handling Race Conditions in Multi-Agent Orchestration"](https://machinelearningmastery.com/handling-race-conditions-in-multi-agent-orchestration/).
- Fast.io. ["AI Agent Idempotent Operations"](https://fast.io/resources/ai-agent-idempotent-operations/).
- LangChain forum. ["Race Condition with Parallel Tool Calls"](https://forum.langchain.com/t/race-condition-with-parallel-tool-calls-tool-responses-out-of-order/1112).

### Tooling

- [LLVM ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html), [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), [Go race detector](https://go.dev/blog/race-detector), [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder), [Mozilla rr](https://rr-project.org/), [Jepsen Knossos](https://github.com/jepsen-io/knossos), [Jepsen Elle](https://github.com/jepsen-io/elle).

### Cross-references within this corpus

- [http_web_security.md](http_web_security.md) — single-packet attack, HTTP/2 streams, request smuggling.
- [distributed_authz_expertise.md](distributed_authz_expertise.md) — §7 TOCTOU on authorization; multi-replica auth races.
- [macos_memory_corruption_investigation.md](macos_memory_corruption_investigation.md) — heap-layout discipline for concurrent UAF.
- [firmware_embedded_security.md](firmware_embedded_security.md) — setuid corpus, kernel-namespace races, capabilities.
- [llm_agent_security_expertise.md](llm_agent_security_expertise.md) — agent trust boundaries; parallel-tool-call surface.
- [agentic_web_capabilities_expertise.md](agentic_web_capabilities_expertise.md) — capability revocation under concurrency.
- [vulnerability_research_methodology_expertise.md](vulnerability_research_methodology_expertise.md) — adversarial-scheduler discipline.
- [fuzzing_discipline_expertise.md](fuzzing_discipline_expertise.md) — KRACE, syzkaller, libFuzzer + TSan.
- [detection_engineering_expertise.md](detection_engineering_expertise.md) — SIEM detection of race-exploitation.
- [code_review_expertise.md](code_review_expertise.md) — click-count severity and heterogeneous-auth heuristic.
- [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) — static patterns for TOCTOU/refcount races.
