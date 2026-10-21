# C# and .NET Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Microsoft .NET team engineers, Project Zero / NCC / GitHub Security Lab researchers, and the institutional advisories that catalog .NET-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is the first in a new class of
> expertise reference — **language-specific behavioral footguns** — that catalogs primitives
> whose *default behavior* in a particular language ecosystem is unsafe, distinct from
> cross-language bug-class docs (which cover SQL injection, deserialization, shell injection,
> path traversal, etc. by attack class rather than language surface). The .NET 9 deprecation
> of BinaryFormatter (now throws `PlatformNotSupportedException` at runtime), the 2025 wave
> of SharePoint ViewState advisories (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770,
> CVE-2025-53771), and the continued churn around Native AOT trimming + DI registration are
> the load-bearing 2024-2026 updates.
>
> **Researchers:**
> - **Soroush Dalili** (@irsdl) — formerly NCC Group; ysoserial.net co-maintainer and
>   `ysonet` author; ASP.NET `.resx` resource-file deserialization research (reported
>   2018-01); the canonical "Exploiting Deserialisation in ASP.NET via ViewState" writeup
>   documenting the `ObjectStateFormatter` + `MachineKey` attack chain
> - **Alvaro Muñoz** (@pwntester) — Principal Security Researcher, GitHub Security Lab;
>   original `ysoserial.net` author; co-author with Oleksandr Mirosh of "Friday the 13th:
>   JSON Attacks" (Black Hat USA 2017 / DEF CON 25) cataloguing `BinaryFormatter`,
>   `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `SoapFormatter`,
>   and JSON-deserializer gadget chains in .NET
> - **James Forshaw** (@tiraniddo) — Google Project Zero; the 2017 "Exploiting .NET
>   Managed DCOM" post plus Black Hat USA debut paper on .NET deserialization that
>   pre-dates the Frohoff Java work; deep COM/OXIDE/SCM research
> - **Stephen Toub** — Partner Software Engineer, Microsoft .NET team; author of the
>   canonical `ConfigureAwait` FAQ and "How Async/Await Really Works in C#" deep-dive;
>   primary source for
>   `async void`, `ValueTask`, `TaskCompletionSource`, and `AsyncLocal<T>` discipline
> - **David Fowler** (@davidfowl) — Partner Software Architect, ASP.NET Core team; author
>   of `AspNetCoreDiagnosticScenarios` (`AsyncGuidance.md` + `AspNetCoreGuidance.md`)
>   that formalized the "`async void` in ASP.NET Core is always bad" rule
> - **Levi Broderick** (@grabyourpitchforks) — ASP.NET team; "Cryptographic Improvements
>   in ASP.NET 4.5" series introducing purpose-bound `MachineKey.Protect`
> - **Krzysztof Cwalina** — Principal Architect, Microsoft; founding member of the .NET
>   Framework team; co-author of "Framework Design Guidelines" (Addison-Wesley) — the
>   primary source for the IDisposable / finalizer / Dispose-pattern discipline
> - **Joseph Albahari** — Author of "C# in a Nutshell" (O'Reilly, currently C# 12 edition);
>   inventor of LINQPad; C# MVP since 2008; reference for `Span<T>` / `Memory<T>` /
>   `ref struct` lifetime semantics
> - **Scott Hanselman** — VP, Microsoft; "ASP.NET — Overposting/Mass Assignment
>   Model Binding Security" walkthrough
> - **Zero Day Initiative (Trend Micro)** — Pwn2Own SharePoint chain (Viettel Cyber
>   Security, May 2025): CVE-2025-49706 + CVE-2025-49704 for unauthenticated RCE;
>   CVE-2025-53770 / CVE-2025-53771 "ToolShell" evolutions
>
> **Institutional contributors:** MITRE CWE (CWE-502, CWE-22, CWE-330, CWE-327); Microsoft
> MSRC + dotnet/docs (BinaryFormatter migration guide, CA2300-CA2330 analyzer rules);
> OWASP (Deserialization Cheat Sheet, ASP.NET security guidance).
>
> **What this doc is NOT:** not a C# language tutorial, not a replacement for cross-language
> bug-class guidance, not a substitute for static analysis. It is the .NET-specific layer
> beneath cross-language audit heuristics.

Cross-links: see `deserialization_expertise.md` for the cross-language
bug-class treatment; `code_review_expertise.md` for the click-count
severity heuristic + auth-homogeneity audit pattern; `cryptography_expertise.md`
for cross-language crypto-primitive discipline; `ssrf_url_parsing_expertise.md`
for `Uri` / `WebRequest` parsing surface; `http_web_security.md` for the
generic web-security cross-cuts; `vulnerability_research_methodology_expertise.md`
for variant analysis and corpus-mining; the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for
detection-rule authoring guidance.

---

## 1. The behavioral-footgun framing

### 1.1 Why this class of doc exists

The existing corpus in this repo has two adjacent
shapes: **cross-language bug-class** (deserialization, cryptography,
SSRF, HTTP) and **methodology** (code review, steelman doctrine,
vulnerability research). Neither captures *behavioral footguns* —
primitives whose default behavior in a specific language ecosystem
is unsafe, where the unsafety is not visible to the compiler or the
type system.

A *bug class* answers "what is this kind of vulnerability." A
*behavioral footgun* answers "what does this language primitive *do*,
such that ordinary use produces a bug class without the developer
noticing." `BinaryFormatter.Deserialize(stream)` is not a bug
class — it is a primitive whose default behavior is a deserialization
vulnerability. `async void Method()` is not a bug class — it is a
primitive whose default behavior makes exceptions unobservable and
crashes the host process in ASP.NET Core. `Path.Combine(a, b)` is
not a bug class — it is a primitive whose default behavior discards
the first argument when the second is absolute, producing path
traversal without any user-controlled `../` substring.

This is the first doc in a new behavioral-footgun class. Companion
docs (Java, Python, Go, Rust, JavaScript, Ruby) are planned.

### 1.2 The compiler-will-let-you axiom

Every footgun in this document satisfies: **the compiler accepts the
code without warning, the default static analyzer does not flag it,
and the runtime executes it without complaint**. The primitive is
legitimate language; the default behavior is just unsafe in
security-relevant contexts.

This distinguishes a behavioral footgun from a straightforward
"unsafe API." An unsafe API has a name that signals danger
(`Process.Start`, `eval`, `system(3)`). A behavioral footgun has a
name that signals normal operation — `Path.Combine`, `String.Equals`,
`JsonConvert.DeserializeObject`, `new Random()`, `async void` — and
only the .NET-specific runtime semantics produce the security
problem.

### 1.3 The audit-cost asymmetry

The developer writes `Path.Combine(uploadDir, userFilename)` once.
The auditor reads it many times. The developer either knows the
second-argument-absolute-path discard rule or writes the bug. The
auditor has to know the rule, recognize the call site, *and* trace
the source of `userFilename` to taint — for every call site.

The footgun is primarily a review problem, not a write problem.
Detection tooling (Roslyn analyzers, Semgrep, CodeQL) is the
scalable answer.

### 1.4 Cross-link discipline

The behavioral footgun describes *what the primitive does in .NET*;
the cross-language doc describes *what the bug class looks like in
general*. For SQL injection, the .NET behavioral footgun is
"`SqlCommand.CommandText = $\"SELECT * FROM Users WHERE id =
{userId}\"` compiles and executes with no warning" — the
cross-language doc explains why that matters.

---

## 2. The `unsafe` keyword and pointer manipulation

### 2.1 `unsafe` opts out of memory safety

The `unsafe` keyword disables verified-memory-safety guarantees of
the CLR for the enclosing block, method, or class. Inside `unsafe`,
the developer can declare and dereference raw pointer types
(`int*`, `byte*`, `char*`); use `fixed` to pin managed heap memory
and obtain a raw pointer (defeating GC movement); use `stackalloc`
for variable-sized stack buffers; cast pointers freely between
unrelated types; read/write memory at computed addresses with no
bounds check.

`unsafe` exists for performance-critical interop and high-throughput
buffer manipulation. It is rarely required in ordinary code. Every
`unsafe` block is a candidate audit point.

### 2.2 The `fixed` statement and the GC pinning lifecycle

`fixed (byte* p = &buffer[0]) { ... }` pins the managed object for
the duration of the enclosing block. The footgun is that `fixed` is
*scope-bound*: once the block exits, the GC may move the object at
any subsequent collection, and any captured pointer becomes
dangling. Code that captures a pinned pointer into a field, a
delegate closure, or a longer-lived `Span<T>` produces a
use-after-free when the GC next runs.

A second `fixed` footgun: pinning `buffer[0]` does *not* pin the
array's element range from an external caller's perspective; only
the address of the captured element is guaranteed stable. Treating
`fixed` as "the whole array is safe for this scope" is wrong when
the array is also reachable from another thread.

### 2.3 `stackalloc` and the buffer-overflow surface

`stackalloc` allocates a contiguous buffer on the current method's
stack frame. The buffer's lifetime is the enclosing method, not the
enclosing block. The size argument is a runtime integer.

Two footguns dominate. First, the runtime does no bounds check on
writes through a pointer derived from `stackalloc`. Writing past the
requested length corrupts the stack frame — return address, frame
pointer, locals — in the exact pattern of a 1990s-era C buffer
overflow. The CLR's stack-cookie protection catches *some* overflows
but is not a security boundary.

Second, `stackalloc` inside a loop accumulates allocations across
iterations because stack memory is not released until method return.
Microsoft's CA2014 analyzer flags this.

Since C# 7.2, Microsoft recommends `stackalloc Span<byte>` over raw
pointer `stackalloc` for bounds-checked access. But the underlying
allocation is the same; an attacker-controlled length still reaches
`StackOverflowException`, which is *not catchable* — it terminates
the process.

### 2.4 `Marshal.PtrToStructure` and type confusion

`Marshal.PtrToStructure<T>(IntPtr)` reads raw bytes from an arbitrary
address and reinterprets them as `T`. The CLR performs no validation
of the pointer or the source memory shape. The footgun chain:
untrusted input → derived `IntPtr` → `PtrToStructure<SomeStruct>` →
typed access to attacker-shaped memory. If `SomeStruct` contains a
delegate field or an object reference, arbitrary reference injection
becomes a direct path to type confusion and RCE.

`[StructLayout(LayoutKind.Explicit)]` with overlapping `IntPtr` and
`object` fields at the same offset provides a direct reinterpret-cast
primitive between native and managed pointers. Forshaw's Project
Zero research catalogs several such primitives in .NET's COM interop
surface.

### 2.5 You opted out of memory safety

The summary rule: **every `unsafe` block must have an explicit
security-reviewed justification, or be rewritten using `Span<T>` /
`Memory<T>` / safe APIs**. Detection patterns: any `unsafe` block
without an audit-comment annotation; `stackalloc` inside any loop;
`Marshal.PtrToStructure` with a non-constant size argument;
`[StructLayout(LayoutKind.Explicit)]` with overlapping reference and
value-type fields.

See `code_review_expertise.md` §"Format strings almost always have a
better approach" — the same logic applies to `unsafe`: the
almost-always-better alternative is `Span<T>` or `MemoryMarshal.Cast`.

---

## 3. IDisposable, using statements, and finalizer ordering

### 3.1 The GC, the finalizer thread, and `Dispose`

The GC reclaims managed memory automatically but does *not* manage
non-memory resources — file handles, DB connections, sockets,
mutexes, OS allocations. `IDisposable.Dispose()` is the contract for
releasing these. The parallel CLR mechanism is the *finalizer*
(`~ClassName()` in C#): when a finalizable object becomes
unreachable, the GC enqueues it; a dedicated finalizer thread runs
`Finalize` and the object is reclaimed at the next collection.

Four footguns: (1) finalizer invocation is **not deterministic** —
may be seconds, may be never if the process exits first. Resources
held only by finalizer are held for unbounded duration. (2) The
finalizer thread is **single** for the whole process — a slow or
hung finalizer blocks every other; a finalizer that takes a lock
held by an ordinary thread can deadlock the queue. (3) Finalizer
**order is undefined** — A's finalizer must not assume held B is
still alive. (4) An exception thrown from a finalizer **terminates the
process** unless the host overrides the default policy;
finalizers must not throw.

### 3.2 The canonical Dispose pattern

The pattern Cwalina & Abrams document in "Framework Design Guidelines"
is:

```csharp
public class MyResource : IDisposable
{
    private bool disposed;
    private IntPtr nativeHandle;
    private SomeManagedThing managedResource;

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposed) return;
        if (disposing)
        {
            managedResource?.Dispose();
        }
        if (nativeHandle != IntPtr.Zero)
        {
            NativeMethods.Release(nativeHandle);
            nativeHandle = IntPtr.Zero;
        }
        disposed = true;
    }

    ~MyResource() => Dispose(disposing: false);
}
```

Four invariants: `Dispose()` is idempotent; suppresses the finalizer
to avoid double-release; the protected virtual `Dispose(bool)` uses
the `disposing` flag to distinguish managed-and-native vs.
native-only cleanup; the finalizer routes to `Dispose(false)` for
native-only cleanup.

Footguns inside the pattern: forgetting `GC.SuppressFinalize`
(double-release); forgetting the `disposed` flag (double-release on
explicit double-dispose); accessing `managedResource` inside the
`disposing: false` branch (use-after-finalize); inheriting from a
class with a non-virtual `Dispose()` (subclass cleanup never runs).

### 3.3 `using` block scoping edge cases

`using` guarantees `Dispose()` is called on block exit, even on
exception. The C# 8 *using declaration* (`using var x = new R();`)
scopes disposal to the enclosing block. Footguns:

- A `catch` clause referencing the `using`-scoped variable sees a
  *live* resource because the implicit `Dispose()` runs *after* the
  catch. Double-dispose results if the catch path disposes
  explicitly.
- `using` declarations dispose in reverse declaration order at every
  return site. Order-dependent disposal (transaction commits before
  connection close) is wrong with this pattern.
- `using (var x = new Resource())` where `Resource()` itself throws
  *after acquiring a native handle but before returning* leaks the
  handle. The Dispose pattern requires constructors to release on
  the throw path; many `IDisposable` implementations get this wrong.

### 3.4 `IAsyncDisposable` and `await using`

`IAsyncDisposable.DisposeAsync()` (.NET Core 3.0+) returns a
`ValueTask`, allowing disposal to perform I/O without blocking. The
footgun is mixing interfaces. A class implementing both `IDisposable`
and `IAsyncDisposable` may run different cleanup depending on which
method the caller invokes. A `using` statement on an
`IAsyncDisposable`-only class does not compile (CS1674), and an
`await using` on an `IDisposable`-only class does not compile
(CS8410).

Microsoft guidance: prefer `await using` for I/O-disposing classes;
also implement `IDisposable` for sync consumers; route `Dispose()`
to a blocking
`DisposeAsync().AsTask().GetAwaiter().GetResult()` only as a last
resort — that pattern reintroduces the §4 sync-over-async deadlock
surface.

### 3.5 The leaked-resource pattern

The most common shape is:

```csharp
var connection = new SqlConnection(connectionString);
connection.Open();
// ... use command ...
return result;  // never disposed
```

Variants: `HttpClient` instances created and disposed per request
(TCP source port exhaustion — fix: `HttpClientFactory`);
`Task.Run(async () => { /* IDisposable */ })` whose exception path
is unobservable (§4).

Auditor heuristic: **for every `new` of an `IDisposable`, trace
disposal explicitly**. A `using` declaration on the same line is the
safe pattern. Detection: `new SqlConnection`, `new HttpClient`,
`new StreamReader`, `new FileStream`, `File.OpenRead`, etc., without
a surrounding `using` declaration; classes implementing `IDisposable`
without `GC.SuppressFinalize` in `Dispose()`.

---

## 4. `async void` and the async lifecycle

### 4.1 `async void` versus `async Task`

A C# `async` method may return `void`, `Task`, `Task<T>`, `ValueTask`,
or `ValueTask<T>`. `async void` is *fire-and-forget*: no return
value, no awaitable handle, no way for the caller to observe
exceptions.

Exceptions thrown inside `async void` propagate to the
`SynchronizationContext` captured at method entry. In ASP.NET Core,
*there is no `SynchronizationContext`*. In console apps or
libraries, the captured context is null. The exception escapes to
the `ThreadPool` unobserved, and the ThreadPool's default behavior
is to crash the process.

David Fowler's `AspNetCoreDiagnosticScenarios` states it plainly:
"The use of async void in ASP.NET Core applications is always bad."
The only legitimate use is event handlers — and even there, the body
must wrap all work in `try`/`catch (Exception)`. Outside event
handlers, `async void` is always a bug.

### 4.2 The unobservable-exception trap

```csharp
[HttpPost]
public async void DoWork()  // Bug: should be async Task
{
    await _service.DoSomethingAsync();
}
```

The ASP.NET Core action invoker gets a synchronous void return,
considers the action complete, and starts writing the response. If
`DoSomethingAsync()` throws, the exception crashes the worker process.

Same shape appears in: WPF/WinForms event handlers performing real I/O;
`Timer.Elapsed += async (s, e) => ...`.

### 4.3 `ConfigureAwait(false)` and deadlock surface

`ConfigureAwait(false)` releases the captured `SynchronizationContext`,
running continuations on the ThreadPool. Library code that omits it
and is called synchronously from UI / legacy ASP.NET deadlocks:

```csharp
public string GetData() => GetDataAsync().Result;
public async Task<string> GetDataAsync() =>
    await _http.GetStringAsync(url);  // Captures context
```

`.Result` blocks the caller's thread. The continuation tries to
resume on the captured context — the same thread the caller blocked.
Permanent deadlock.

Stephen Toub's `ConfigureAwait` FAQ rule: library code without
context requirements should use `ConfigureAwait(false)` on every
await. Application code does not need it. ASP.NET Core has no
context (so it's a no-op there), but Microsoft's internal .NET
libraries use it ubiquitously because they're consumed by both.

The deeper footgun: `.Result`, `.Wait()`, `.GetAwaiter().GetResult()`
are all sync-over-async — block the calling thread on async, defeat
the pattern, reintroduce deadlock surface. Rule: **never block on
async code from a context that may have captured itself**.

### 4.4 `Task` vs `ValueTask` and `IValueTaskSource` hazards

`ValueTask<T>` avoids allocation in the synchronous-completion case
but has consumption restrictions `Task<T>` does not: may be awaited
**at most once**; may be converted to `Task<T>` via `.AsTask()`; may
be inspected via `.IsCompleted` before being awaited.

Awaiting twice, calling `.Result` after awaiting, or using
`.AsTask()` and then awaiting the original is undefined behavior;
the CLR does not check in Release builds.

`IValueTaskSource<T>` (the backing interface for custom producers)
compounds the problem. A pooled source may be reused after the
consumer reads its result; a stale read returns *the next
operation's data* — a correctness footgun with security implications
when the data is authentication state.

### 4.5 `TaskCompletionSource` footguns

Three footguns:

1. **Forgetting to complete.** A TCS that's never `SetResult`-ed
   blocks awaiters forever — no exception, no timeout. Common when a
   registered event handler should complete the TCS but the event
   never fires.
2. **Synchronous continuation on the producer's thread.** Without
   `TaskCreationOptions.RunContinuationsAsynchronously`, the
   awaiting code resumes synchronously on the producer's thread —
   often a critical thread (timer callback, network read pump). The
   producer blocks while the awaiter runs arbitrary code. Always
   pass `RunContinuationsAsynchronously`.
3. **Double-completion.** `SetResult` twice throws
   `InvalidOperationException`; the defensive `TrySetResult` exists
   but is easy to forget.

### 4.6 `AsyncLocal<T>` and `ExecutionContext` flow

`AsyncLocal<T>` flows across `await` boundaries: values written
before an `await` flow forward; values written *after* an await flow
forward in the current branch only and do *not* propagate back to
the caller. Using `AsyncLocal<T>` for security-sensitive ambient
state (user identity, tenant context, permission set) is wrong when
"writes flow back" is assumed. Code pushing a "deny" state inside an
awaited method does not restrict the caller after the await.

### 4.7 `Task.Run` and the wrong synchronization context

`Task.Run(action)` schedules on the ThreadPool. Footguns: UI-thread
caller's inner work calls back into the UI via the captured
context; ASP.NET request caller's inner work needs request-scoped
DI; wrapping already-async methods in `Task.Run` adds a pointless
ThreadPool hop. Rule: `Task.Run` is for offloading CPU-bound work,
not for "making things async."

### 4.8 Detection patterns

`async void` not subscribed to an event (`+= async (s, e) =>`);
library code without `ConfigureAwait(false)` on awaits; any
`.Result` / `.Wait()` / `.GetAwaiter().GetResult()` on a Task;
`TaskCompletionSource<T>` without
`TaskCreationOptions.RunContinuationsAsynchronously`;
`Task.Run(async () => ...)` whose body has no CPU-bound work.

---

## 5. `dynamic`, reflection, and runtime-typed code

### 5.1 The `dynamic` keyword

`dynamic` defers type resolution to runtime; the DLR resolves member
accesses against the actual object's type. Every static-analysis
benefit — type safety, null safety, async-flow analysis, taint
propagation in CodeQL / Semgrep — is opted out of. A `dynamic`
value crossing an API boundary erases all type information from that
point forward. For security review, `dynamic` is a taint sink and a
type-confusion primitive: if untrusted input controls the member
name (JSON dispatch table, RPC method selector), the attacker can
invoke arbitrary methods on arbitrary reachable objects.

### 5.2 `MethodInfo.Invoke` and `Activator.CreateInstance`

`MethodInfo.Invoke(target, args)` calls a reflected method without
checking the caller's authorization to invoke it.
`Activator.CreateInstance(Type, args)` instantiates any constructable
type. With `Type.GetType(typeName)` reading attacker input, both
become RCE sinks. The deserialization surface (§6) is the dominant
abuse path — a deserializer reading a type name and calling
`Activator.CreateInstance` is a POP gadget chain entry point.

### 5.3 `ExpandoObject` and dynamic dispatch

`ExpandoObject` as a deserialization target for JSON/YAML with
attacker-controlled keys: no key allowlist. Downstream code reading
`e.SomeProperty` behaves differently for absent (binding error),
present-but-null, and present-with-wrong-type — distinctions rarely
handled correctly.

### 5.4 `Reflection.Emit`

`DynamicMethod` / `AssemblyBuilder.DefineDynamicAssembly` /
`ILGenerator.Emit` constructed from data are direct RCE sinks.

### 5.5 Roslyn scripting and `CSharpScript`

`CSharpScript.EvaluateAsync(code)` / `RunAsync(code)` compile and
execute arbitrary C# in the host process with host permissions. The
.NET equivalent of `eval` / `exec`. `ScriptOptions` restrictions are
advisory — `System.Reflection` bypasses most. Rule: **never feed
untrusted input to `CSharpScript`**. For customer-supplied logic,
sandbox in a separate process or use a constrained DSL.

Detection: `CSharpScript.*` calls; `Microsoft.CSharp.RuntimeBinder.*`
outside tests; `Type.GetType(stringExpr)` non-literal;
`Activator.CreateInstance(typeExpr, ...)` non-literal.

Cross-link: `code_review_expertise.md` §"Serialization with type
handling is suspicious."

---

## 6. `BinaryFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`

### 6.1 The full list of dangerous deserializers

Multiple .NET deserializers are *polymorphic* — they read type names
from the payload and instantiate arbitrary types. Every one is an RCE
sink on untrusted input:

- `BinaryFormatter` (canonical .NET binary; removed .NET 9, throws
  `PlatformNotSupportedException`)
- `NetDataContractSerializer` (WCF DataContract)
- `LosFormatter` (WebForms ViewState)
- `ObjectStateFormatter` (WebForms ViewState + Session state)
- `SoapFormatter` (legacy SOAP)
- `JavaScriptSerializer` with `SimpleTypeResolver`

Muñoz & Mirosh's "Friday the 13th: JSON Attacks" (Black Hat USA 2017
/ DEF CON 25) documented the gadget chains. Dalili's "Exploiting
Deserialisation in ASP.NET via ViewState" gives the canonical
`ObjectStateFormatter` attack chain. Rule: **never call `Deserialize`
on input crossing a trust boundary, regardless of formatter**.

### 6.2 The .NET 9 BinaryFormatter removal

Microsoft's guidance: "BinaryFormatter is insecure and can't be made
secure." Timeline: .NET 5 marked `[Obsolete]` SYSLIB0011; .NET 6
banned new uses in `dotnet/*` repos; .NET 8 disabled it by default
across all project types; .NET 9 removed the runtime implementation
(unsupported opt-in NuGet package
`System.Runtime.Serialization.Formatters` for legacy), so every
call throws `PlatformNotSupportedException`. Migration: `System.Text.Json`,
`MessagePack`, or `protobuf-net`. ASP.NET WebForms ViewState requires
either upgrade to ASP.NET Core or a custom safe formatter — neither
trivial.

### 6.3 ViewState and the 2025 SharePoint chain

ASP.NET WebForms serializes per-request control state to the
`__VIEWSTATE` hidden field via `ObjectStateFormatter`. The
`MachineKey` (in `web.config` or generated by IIS) signs and
optionally encrypts the ViewState; signature validation is the only
barrier between attacker input and arbitrary deserialization.

The 2025 SharePoint "ToolShell" chain (Viettel Cyber Security,
Pwn2Own Berlin 2025; CVE-2025-49706 + CVE-2025-49704, then
CVE-2025-53770 / CVE-2025-53771):

1. Auth bypass (CVE-2025-49706) on `/_layouts/15/ToolPane.aspx`.
2. Upload of `spinstall0.aspx` to extract `MachineKey` material.
3. Forge a valid `__VIEWSTATE` with a `ysoserial.net` payload
   targeting `ObjectStateFormatter`.
4. RCE.

MachineKey extraction is load-bearing. Once `ValidationKey` and
`DecryptionKey` are known, any ViewState is forgeable. Mitigations:
rotate keys on suspected compromise; configure auto-generate-and-rotate
rather than hard-coding in `web.config`; move off WebForms.

### 6.4 Newtonsoft.Json with `TypeNameHandling`

The default `JsonConvert.DeserializeObject<T>` is safe — only `T`
and its declared property types are instantiated. The footgun is
`JsonSerializerSettings.TypeNameHandling` set to anything other than
`None`: Newtonsoft honors a `$type` discriminator naming the target
type and calls `Type.GetType` + `Activator.CreateInstance` +
reflection-based property setters.

```json
{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
    "MethodName": "Start",
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System",
        "StartInfo": { "FileName": "calc.exe" }
    }
}
```

With `TypeNameHandling.All`, the above results in
`Process.Start("calc.exe")` — direct command execution.

Microsoft `CA2326` flags any `TypeNameHandling` != `None`; `CA2327`
flags missing `SerializationBinder` when `TypeNameHandling` is
non-`None`. Rule: **`TypeNameHandling` must be `None` or have an
allowlist `ISerializationBinder`**.

### 6.5 `System.Text.Json` and safer defaults

`System.Text.Json` (.NET Core 3.0+) has no equivalent to
`TypeNameHandling.All` by default. Polymorphic deserialization
requires explicit `JsonDerivedType` attribute allowlists. Custom
`JsonConverter<T>` implementations can still introduce RCE if they
call `Type.GetType` on payload-derived strings. Audit `JsonConverter<T>`
subclasses for reflection or type construction inside `Read`.

### 6.6 Detection patterns

- Any usage of `BinaryFormatter`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter`, `SoapFormatter`,
  `JavaScriptSerializer` with `SimpleTypeResolver`.
- `JsonSerializerSettings { TypeNameHandling = ... }` where the value
  is not `None`.
- `JsonSerializerSettings { SerializationBinder = ... }` without
  evidence of allowlist enforcement.
- ASP.NET WebForms applications with hard-coded `MachineKey` in
  `web.config`.
- `Type.GetType(string)` where the argument is not a literal.

Cross-link: `deserialization_expertise.md` for the full cross-language
gadget-chain treatment; the .NET-specific gadget catalog is in
`ysoserial.net` and `ysonet`.

---

## 7. Strings, encoding, and string-comparison footguns

### 7.1 `String.Compare` and culture-aware comparison

The default `String.Compare(a, b)` is *culture-aware, case-sensitive*
comparison using the thread's current culture. US-English and Turkish
locales produce different results for the same input (Turkish treats
`i`/`İ` and `I`/`ı` as separate case pairs).

```csharp
if (String.Compare(role, "admin", true) == 0)  // Bug
    GrantAdminAccess();
```

On Turkish locale, `"admin".ToUpper()` is `"ADMİN"`, not `"ADMIN"`.
Use `StringComparison.OrdinalIgnoreCase` for non-display comparisons.
Audit: every `String.Compare`, `String.Equals` without
`StringComparison`, and `ToUpper()` / `ToLower()` (current culture
versions).

### 7.2 `Path.Combine` and the absolute-path discard rule

`Path.Combine(a, b)` — **if `b` is absolute, `a` is discarded**.
Microsoft's documentation: "if path2 or path3 is also an absolute
path, the combine operation discards all previously combined paths."

```csharp
var fullPath = Path.Combine(safeDirectory, userSuppliedFilename);
File.ReadAllText(fullPath);
```

If `userSuppliedFilename` is `/etc/passwd` or `C:\Windows\...\hosts`,
`safeDirectory` is discarded — path traversal without a single `../`,
defeating sanitizers that look for traversal sequences.

`Path.Join` (.NET Core 3.0+ for `string` arguments; `ReadOnlySpan<char>` overloads since .NET Core 2.1) does *not* discard on absolute input
but does not validate the result is under the intended root. The
canonical safe pattern:

```csharp
var combined = Path.Join(safeDirectory, userSuppliedFilename);
var resolved = Path.GetFullPath(combined);
var safeRoot = Path.GetFullPath(safeDirectory);
if (!resolved.StartsWith(safeRoot + Path.DirectorySeparatorChar))
    throw new SecurityException("Path traversal");
```

Praetorian's writeup is the canonical reproducible example.

### 7.3 `Uri` parsing inconsistencies

`Uri.IsWellFormedUriString` returns RFC compliance; "well-formed" is
not "safe" (many SSRF-bypass URIs are well-formed). `new Uri(s)`
applies percent-decoding, IDN-to-ASCII host normalization, and scheme
lowercasing — re-serialization may produce a different string.
.NET-specific surface: `Uri.Authority` vs `Uri.Host` vs `Uri.IdnHost`
disagreeing on IDN inputs; `Uri.LocalPath` decoding percent-escapes
that `Uri.AbsolutePath` does not; `WebRequest.Create(string)`
accepting `file://` URIs by default.

Cross-link: `ssrf_url_parsing_expertise.md` for the cross-language
treatment.

### 7.4 Timing-safe comparison

`String.Equals` short-circuits on the first differing character. For
token equality, HMAC verification, or password hash comparison this
is a timing oracle. Use `CryptographicOperations.FixedTimeEquals`
(.NET Core 2.1+) on byte arrays. Watch for prefix-revealing
short-circuits in conversion paths (hex/base64 decode) before the
fixed-time call.

### 7.5 Detection patterns

`String.Compare` / `String.Equals` without `StringComparison`;
`ToUpper()` / `ToLower()` (prefer Invariant); `Path.Combine` with
non-literal second arg; `==` on tokens / HMACs / password hashes.

---

## 8. `Span<T>` and `Memory<T>` lifetime

### 8.1 `Span<T>` is a `ref struct`

`Span<T>` is a value-type window over contiguous memory (arrays,
stack allocations, native memory, string slices) marked as a **ref
struct**. Ref struct restrictions: cannot be boxed; cannot be
assigned to `object` / `dynamic` / interfaces; cannot be a field of
a reference type; cannot cross `await` or `yield`; cannot be
captured by lambdas; cannot be an async method parameter or return.

These exist because `Span<T>` may reference stack memory or pinned
heap memory the GC cannot track — escape would be use-after-free.
The footgun: restrictions look arbitrary to developers who haven't
internalized the lifetime model, so they reach for `Memory<T>`
workarounds with subtly different semantics.

### 8.2 `Memory<T>` and the lifetime contract

`Memory<T>` is heap-storable. The lifetime contract: the referenced
memory must remain valid as long as the `Memory<T>` is reachable. If
the memory is stack-allocated or `fixed`-pinned, the `Memory<T>` may
outlive the storage and produce undefined behavior. Microsoft
guidance: use `Memory<T>` only over GC-managed arrays
(`new T[N]`, `ArrayPool<T>.Rent`) or memory with an explicit owner
(`MemoryManager<T>`).

### 8.3 `MemoryMarshal.Cast` and reinterpret semantics

`MemoryMarshal.Cast<TFrom, TTo>(Span<TFrom>)` reinterprets bytes
between primitive-type spans. The runtime allows only casts between
types without references and does *not* verify the source bytes
hold a valid `TTo`. For structs with explicit field layouts or
function-pointer fields, the cast is a type-confusion primitive
equivalent to memcpy + reinterpret_cast in C.

### 8.4 Range / Index slicing surprises

`x[1..^1]` compiles to method calls with type-dependent semantics:
on arrays, slicing **copies**; on `Span<T>`, slicing creates a
**view**. Modifications to a span slice affect the underlying span;
modifications to an array slice do not. For security review, the
aliasing distinction matters when one slice is exposed to untrusted
code and the other is expected to remain unchanged.

### 8.5 Stack overflow on stack-frame return

`stackalloc Span<byte>(N)` returns a span referencing the current
method's stack frame. Returning is a compile-time error per
ref-struct lifetime checks. Storing the span in a longer-lived ref
struct field and returning that field is a subtler escape; custom
ref-struct types with misannotated members may permit it.

### 8.6 Detection patterns

`MemoryMarshal.Cast` between unrelated types; `Memory<T>`
constructed from a stack-referencing `Span<T>`; custom `ref struct`
types with reference-typed fields and `[UnscopedRef]`-annotated
members; `Span<T>` returned from methods containing `stackalloc`.

---

## 9. ASP.NET-specific behavioral footguns

### 9.1 ViewState revisited (WebForms)

Two additional ViewState footguns beyond §6.3:
**`EnableViewStateMac="false"`** disables signature validation —
attacker-supplied ViewState deserialized directly. Ignored starting
in .NET 4.5.2; a September 2014 update extended this to all ASP.NET
versions 1.1-4.5.2.
**`EnableEventValidation="false"`** disables event-source validation
— attacker postbacks invoke arbitrary server-side actions.

### 9.2 Anti-forgery token defaults

`[ValidateAntiForgeryToken]` (MVC) and `@Html.AntiForgeryToken()`
emit per-form tokens signed with the application key. Footguns: the
attribute is **opt-in** (controllers without it or
`AutoValidateAntiforgeryTokenAttribute` accept any POST); API
controllers that disable anti-forgery for programmatic clients are
exploitable when cookie-authenticated; ASP.NET Core's generic
cookie APIs default `SameSite` to `Unspecified` (no attribute sent),
while the cookie-authentication cookie defaults to `Lax` and the
antiforgery cookie to `Strict`.

### 9.3 Model binding and over-posting

ASP.NET auto-binds form fields / query strings / JSON bodies. Default
is **implicit allowlist by parameter type** — every public settable
property is a candidate target. Exposing entity models is the
canonical bug:

```csharp
public class User { public int Id; public string Name; public bool IsAdmin; }
[HttpPost] public IActionResult Update(User user) { _users.Save(user); ... }
```

Attacker submits `IsAdmin=true`; binder sets it; save persists the
privilege escalation. Fix: dedicated **input model** containing only
user-settable properties; map explicitly to entity. Andrew Lock's
"Preventing mass assignment" gives the canonical patterns. `[Bind]`
provides allowlist for legacy MVC; `[BindNever]` denylists individual
properties.

### 9.4 File upload and path canonicalization

`IFormFile.FileName` is **client-supplied**. `Path.Combine(uploadDir,
file.FileName)` compounds the §7.2 footgun with trust-the-filename.
File size limits exist at IIS / Kestrel / middleware / form-binding —
missing any layer leaves DoS. `ContentType` is client-controlled. No
default AV scanning. Audit posture: server-derived filenames (UUID,
content hash, counter); validate file size at every layer; validate
content by sniffing, not `ContentType`.

### 9.5 Static-file middleware

`UseStaticFiles()` serves `wwwroot/` files without authentication.
Path traversal is caught by the middleware; the footgun is enabling
`ServeUnknownFileTypes = true` or `UseDirectoryBrowser()` in
production — both expose the filesystem.

### 9.6 Razor `@Html.Raw` and bypass-by-default

Razor default behavior is HTML-encoding-on-output (`@user.Name`).
`@Html.Raw(user.Name)` emits verbatim — XSS by construction. Adjacent
bypass surface: `@Html.DisplayFor` via a custom template that uses
`Html.Raw` internally; `IHtmlString` / `HtmlString` return values
bypass encoding; `MvcHtmlString.Create(s)` explicitly wraps for
bypass.

### 9.7 Detection patterns

`EnableViewStateMac="false"` / `EnableEventValidation="false"` in
`web.config`; POST actions without `[ValidateAntiForgeryToken]`
(absent global filter); action methods binding entity models;
`Path.Combine(*, file.FileName)` for `IFormFile`; `@Html.Raw(...)`
calls; `ServeUnknownFileTypes = true`.

Cross-link: `http_web_security.md` for cross-language web security;
`code_review_expertise.md` §"User-input paths must be resolved AND
verified."

---

## 10. Cryptographic API footguns

### 10.1 `Random` is not cryptographic

`System.Random` is a deterministic PRNG (clock-based default seed on
.NET Framework; default seed from a thread-static pseudo-random
generator on .NET Core). Microsoft's docs direct cryptographically
secure use to `RandomNumberGenerator` (static
`GetBytes`, `GetInt32`, `GetString` over the OS RNG).

```csharp
public string GenerateResetToken()
{
    var random = new Random();
    var bytes = new byte[32];
    random.NextBytes(bytes);  // Bug
    return Convert.ToBase64String(bytes);
}
```

Tokens generated by `System.Random` are predictable to an attacker
who can observe a few outputs and recover the seed. Use
`RandomNumberGenerator.GetBytes(32)`.

### 10.2 Symmetric encryption defaults

`Aes.Create()` defaults: mode CBC, padding PKCS7, key size 256
bits. Reasonable but CBC without explicit IV management and without
authenticated encryption is malleable. Historical footguns:
`RijndaelManaged` (deprecated; default mode CBC);
three legacy AES implementations (`AesManaged`, `AesCng`,
`AesCryptoServiceProvider`) had subtly different defaults — use
`Aes.Create()`; `MachineKey.Encode/Decode` legacy modes (DES, 3DES
in old installations).

Modern API is `AesGcm` (.NET Core 3.0+) — authenticated encryption.
Footgun: nonce reuse catastrophically breaks confidentiality.
Per-message random nonce or strict counter; never fixed.

### 10.3 Password hashing

`PasswordDeriveBytes` is PBKDF1 — cryptographically obsolete.
Replacement `Rfc2898DeriveBytes` (PBKDF2) footguns: default
constructor uses 1000 iterations (OWASP guidance is 600,000+ for
PBKDF2-SHA256); default hash algorithm in older constructors is
SHA-1. Verify salt is ≥16 bytes
and unique per password. For new code, prefer
`Microsoft.AspNetCore.Identity` or Argon2 NuGet packages.

### 10.4 RSA padding defaults

`RSA.Encrypt(byte[], RSAEncryptionPadding)` requires explicit
padding. The footgun is the older `RSACryptoServiceProvider.Encrypt(byte[],
bool fOAEP)` whose `fOAEP = false` uses PKCS#1 v1.5 — vulnerable to
Bleichenbacher padding-oracle attacks if the decrypter exposes
timing. Rule: RSA encryption uses OAEP
(`RSAEncryptionPadding.OaepSHA256` or stronger); PKCS#1 v1.5 for
**signing** is acceptable.

### 10.5 ASP.NET MachineKey-based protection

`MachineKey.Protect` (System.Web) and `IDataProtector.Protect`
(ASP.NET Core) provide authenticated symmetric encryption tied to
application identity. Legacy MachineKey footguns: hard-coded
`web.config` keys enable cross-application ViewState forgery
(SharePoint ToolShell chain); legacy API does not enforce the
`purpose` parameter, producing cross-purpose token confusion.
`IDataProtector` enforces purpose binding by construction. Levi
Broderick's "Cryptographic Improvements in ASP.NET 4.5" series
introduced the purpose-bound API specifically for this.

### 10.6 Detection patterns

`new Random()` followed by `NextBytes` or use in security context;
`Rfc2898DeriveBytes` constructor without iteration argument;
`RSACryptoServiceProvider.Encrypt(_, false)`; hard-coded keys in
`web.config` `machineKey`; `Aes.Create()` with `Mode = ECB`;
`AesGcm` with a fixed-byte-array nonce.

Cross-link: `cryptography_expertise.md` for cross-language crypto.

---

## 11. Exception handling, finalization, and process exit

### 11.1 Catch-all `catch (Exception)` swallows everything

`catch (Exception)` catches every CLR exception except corrupted-state
exceptions (`AccessViolationException`, `StackOverflowException`,
sometimes `OutOfMemoryException`). Intentional swallowing —
`catch (Exception) { /* ignore */ }` — is a footgun: the swallowed
exception may be a `SecurityException` the developer thought
recoverable, a `CryptographicException` indicating tampered
ciphertext (not bad format), or a `SqlException` for a constraint
violation. Defensive pattern: catch specific types; let unknown
exceptions propagate.

### 11.2 `AppDomain.UnhandledException` and `TaskScheduler.UnobservedTaskException`

Two last-line handlers: `AppDomain.CurrentDomain.UnhandledException`
(any thread, before termination); `TaskScheduler.UnobservedTaskException`
(never-awaited Task with `.Exception`-never-observed). Defaults
changed: .NET 4.0 terminated on unobserved task; .NET 4.5+ swallowed;
.NET Core / 5+ swallowed but configurable. `async void` exceptions
(§4.1) bypass Task observation and hit `UnhandledException`
directly — ASP.NET Core's default is crash-the-process.

### 11.3 `Thread.Abort` and the non-recoverable state

`Thread.Abort()` injected `ThreadAbortException` at the next
safepoint, with auto-rethrow at end of catch. Deprecated in
.NET Core / 5+ (throws `PlatformNotSupportedException`). Legacy code
relying on Abort for cancellation must migrate to
`CancellationToken`. Locks held by an aborted thread release but
mutable state under them may be torn — subsequent reads observe
inconsistency.

### 11.4 Async exception flow

Exception **after** the first `await` is captured by the state
machine and placed on the returned Task. In an `async` method, an exception
**before** the first await (argument validation) is also stored in
the returned Task, not thrown synchronously. A non-`async`
Task-returning method can instead throw eagerly (e.g. on a null
argument) rather than fault the returned task.

### 11.5 `Environment.Exit` vs `Process.Kill`

`Environment.Exit(code)` skips pending `finally` blocks; finalizers
run at termination on .NET Framework but not on .NET Core / .NET 5+. `Process.GetCurrentProcess().Kill()`
terminates immediately — no flush. Using `Environment.Exit` from a
security-critical tamper-detection path gives the attacker a
finalization window; use kill, after explicitly flushing only
safety-critical state.

### 11.6 Detection patterns

`catch (Exception)` without log/rethrow; `async void` (§4.1);
`Thread.Abort` (legacy); `Environment.Exit` in a `try` block.

---

## 12. P/Invoke and native interop

### 12.1 Marshaling semantics

`[DllImport]` calls native functions; the CLR marshaler converts
between managed and native ABI types. Defaults: `string` → `LPSTR`
(ANSI); `bool` → 4-byte `BOOL`; arrays → pointer-to-first-element
(length not passed); structs → field-by-field with default packing.
A wrong `MarshalAs` produces silent data corruption — wrong offsets,
wrong encoding, wrong integer widths. The CLR does not detect the
mismatch; the native function sees garbage. For security-sensitive
interop (crypto functions, OS permission checks), marshaling errors
can produce silent fallback to weaker behavior or false-positive
permission grants.

### 12.2 DllImport and calling conventions

`CallingConvention.Winapi` resolves to StdCall on Windows, Cdecl on
Linux. A native function compiled with a different convention does
not crash on call — it returns with an unbalanced stack, and
subsequent calls observe wrong-data bugs that look like memory
corruption. Wrong conventions are *possibly-corrupting* but rarely
crash in short test runs; they surface under specific load patterns.

### 12.3 DEP, CFG, and Control Flow Guard

Windows exploit mitigations apply to P/Invoke: DEP prevents
execution from non-executable pages; CFG validates indirect-call
targets; CET / Shadow Stack validates return addresses. Native
function pointers obtained dynamically must respect these mitigations.

### 12.4 COM interop and threading

`[STAThread]` / `[MTAThread]` control the COM apartment. Calling
COM objects from a different apartment triggers cross-apartment
marshaling that **re-enters the message pump**. A COM call from a
background thread to an STA-requiring object may run UI message
handlers in the middle of the call — classic reentrancy where shared
state is observed mid-mutation.

### 12.5 `HandleRef` vs `SafeHandle`

`HandleRef` keeps the managed wrapper alive for a P/Invoke call but
does *not* close the handle. `SafeHandle` (derived types:
`SafeFileHandle`, `SafeWaitHandle`, etc.) wraps native handles with
proper lifetime management — finalizer (or `Dispose`) releases the
handle, and the finalizer is finalization-critical (runs even at
process termination). Use `SafeHandle`-derived types for any handle
requiring cleanup; `IntPtr` / `HandleRef` are for short-lived
references only.

### 12.6 Detection patterns

`[DllImport]` with implicit `CallingConvention`; `IntPtr` as a
long-lived handle (should be `SafeHandle`); `[MarshalAs]` on strings
without verifying ANSI/Unicode against native signature;
`Marshal.GetDelegateForFunctionPointer` on attacker-controlled
pointers.

---

## 13. Detection patterns

This section consolidates Semgrep / Roslyn / SonarSource patterns
referenced throughout. Most patterns are syntactic; a few require
taint mode.

### 13.1 Semgrep rule sketches

**`async void` outside event handlers** — pattern `async void $METHOD(...)`
with `pattern-not-inside` of `$TYPE.$EVENT += $METHOD;`. Severity ERROR.

**`BinaryFormatter` usage** — `new BinaryFormatter(...)` or
`$BF.Deserialize(...)` on any expression typed as `BinaryFormatter`.
Severity ERROR (removed in .NET 9).

**`TypeNameHandling` not None** — `new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All, ... }`
(or `Auto` or `Objects`). Severity ERROR.

**`Random` for security tokens** — `new Random().NextBytes($BYTES)` or
the multi-line equivalent. Severity WARNING (replace with
`RandomNumberGenerator.GetBytes`).

**`Path.Combine` tainted** — taint-mode rule with sources of
`$REQUEST.Form[...]`, `$REQUEST.Query[...]`, `$REQUEST.Body` and sink
`Path.Combine($BASE, $TAINTED)`. Severity ERROR.

**`@Html.Raw` with non-literal argument** — `@Html.Raw($X)` with
`pattern-not: '@Html.Raw("...")'`. Severity WARNING.

**`stackalloc` in loop** — `stackalloc` inside `for` or `while` body.
Severity ERROR (mirrors Roslyn CA2014).

### 13.2 Roslyn analyzers (built-in Microsoft rules)

The Microsoft `dotnet/roslyn-analyzers` repository ships
production-ready analyzers for many of the patterns in this document:

- **CA2300, CA2301, CA2302** — BinaryFormatter usage.
- **CA2305** — LosFormatter.
- **CA2310, CA2311, CA2312** — NetDataContractSerializer.
- **CA2315** — ObjectStateFormatter.
- **CA2321, CA2322** — JavaScriptSerializer with SimpleTypeResolver.
- **CA2326, CA2327, CA2328, CA2329, CA2330** — Newtonsoft.Json
  TypeNameHandling and JsonSerializerSettings.
- **CA2350-CA2354** — `DataTable` / `DataSet` deserialization
  (`ReadXml` on untrusted input; unsafe `DataSet` / `DataTable` in
  serializable types or deserialized object graphs).
- **CA2014** — stackalloc in loops.
- **CA5350, CA5351** — broken cryptographic algorithms (DES, MD5,
  SHA1 for signing).
- **CA5379** — weak key derivation algorithms.
- **CA5394** — non-cryptographic random for security context (in
  more recent analyzer releases).

These rules ship in `Microsoft.CodeAnalysis.NetAnalyzers` (the
default in modern .NET SDK projects). Enabling
`<AnalysisMode>All</AnalysisMode>` activates them by default; many
require explicit suppressions for legacy code.

### 13.3 Third-party analyzers

- **SecurityCodeScan** (security-code-scan.github.io) — Roslyn-based
  vulnerability pattern detector for C# and VB.NET. Covers SQLi,
  XSS, CSRF, XXE, weak crypto, and deserialization.
- **SonarAnalyzer.CSharp** — broader code-quality analyzer with a
  large security ruleset.
- **Puma Scan** — focused on web application security.

### 13.4 Tooling for ViewState analysis

- **Blacklist3r** (NotSoSecure) — identifies use of known/leaked
  MachineKeys for ViewState forgery.
- **ysoserial.net** — gadget chain generator for .NET formatters
  (BinaryFormatter, ObjectStateFormatter, LosFormatter,
  NetDataContractSerializer, SoapFormatter, JsonNet, and others).
- **ysonet** — Soroush Dalili's continuation of ysoserial.net with
  additional gadget chains.

Cross-link: the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the rule-authoring
discipline (precision threshold, corpus mining, severity assignment).

---

## 14. Defensive patterns and code-review checklist

### 14.1 The 15-item .NET review checklist

1. **`unsafe`** — every block has explicit justification or a
   rewrite plan.
2. **`dynamic`** — trace every value to source; crossing a trust
   boundary is a taint sink.
3. **`BinaryFormatter`** — any usage on .NET 8 or earlier is RCE;
   .NET 9+ throws.
4. **`JsonSerializerSettings`** — `TypeNameHandling = None` or
   allowlist `ISerializationBinder`.
5. **`async void`** — only event handlers; body must
   `try`/`catch (Exception)`.
6. **`.Result` / `.Wait()` / `.GetAwaiter().GetResult()`** —
   sync-over-async deadlock candidate.
7. **`Path.Combine` / `Path.Join`** — non-literal second arg
   resolved + allowlist-root-validated.
8. **`Html.Raw` / `IHtmlString` / `HtmlString`** — source trust
   verified.
9. **`new Random()`** — replace with `RandomNumberGenerator.GetBytes`
   if security-relevant.
10. **`Rfc2898DeriveBytes` without iteration argument** — require
    explicit value at OWASP guidance.
11. **`Type.GetType(stringExpr)` / `Activator.CreateInstance`**
    non-literal — RCE sinks.
12. **`CSharpScript` / `Reflection.Emit` / `Microsoft.CSharp.RuntimeBinder`**
    on untrusted input — RCE.
13. **Entity models as action parameters** — replace with input
    models.
14. **`String.Equals` / `String.Compare` without `StringComparison`**
    — explicit `Ordinal` / `OrdinalIgnoreCase`.
15. **`catch (Exception)` empty or log-only** — review what's
    swallowed.

### 14.2 The audit-priority axis

Sort findings by: (1) **reachability** from a trust boundary
(`BinaryFormatter` on `[HttpPost]` outranks the same inside a CLI
tool); (2) **click-count severity** per `code_review_expertise.md`
(zero-click RCE outranks one-click footgun); (3) **blast radius**
(shared-library code affects every consumer).

### 14.3 Dispose audit checklist

`Dispose()` calls `GC.SuppressFinalize`? Idempotent? Finalizer
routes to `Dispose(false)` without managed-state access? All
`IDisposable` fields disposed in `Dispose(true)`? Constructors
defensive against throw-after-acquire?

### 14.4 Async audit checklist

Return type is `Task` / `Task<T>` / `ValueTask` (not `void`, except
event handlers)? Library awaits use `ConfigureAwait(false)`? No
sync-over-async (`.Result` / `.Wait()` / `.GetAwaiter().GetResult()`)?
`TaskCompletionSource<T>` uses `RunContinuationsAsynchronously`?

### 14.5 Deserialization audit checklist

Which formatter? Is input trusted (internal source, schema-validated,
signed)? Newtonsoft.Json: `TypeNameHandling = None` or allowlist
binder? `System.Text.Json`: custom `JsonConverter<T>` doing
reflection? `XmlSerializer` / `DataContractSerializer`: `KnownTypes`
allowlist?

Cross-link: `deserialization_expertise.md` for gadget chain
analysis; `code_review_expertise.md` for general posture.

---

## 15. Variant analysis: under-explored .NET surfaces

### 15.1 ASP.NET Core minimal APIs

Minimal APIs (introduced .NET 6) bypass the controller / action model
with a lightweight `app.MapPost("/route", handler)` syntax. The
behavioral footguns: model binding semantics differ from MVC (the
`[FromBody]` / `[FromQuery]` defaults are inferred from parameter
type, producing runtime-not-compile-time binding ambiguity errors);
anti-forgery is validated only for endpoints whose metadata requires
it (in .NET 8, endpoints binding `IFormFile` / `IFormFileCollection`;
`DisableAntiforgery()` opts out); authentication is
per-endpoint and missing-attribute silently exposes the endpoint.

### 15.2 Blazor (Server and WebAssembly)

Blazor Server runs every component method on the server in the user's
SignalR connection — state leakage between users via static fields is
the canonical bug, partially mitigated by the default `Scoped`
per-circuit DI lifetime. Blazor WebAssembly runs the entire .NET
runtime in the browser; secrets in the assembly are exposed because
the assembly is downloaded to the client. Both modes: `@onclick` /
`@onchange` event handlers may bind to `async void` if the developer
mistypes the return type, reintroducing the §4 unobservable-exception
surface.

### 15.3 .NET MAUI

.NET MAUI inherits behavioral footguns from each platform SDK (iOS,
Android, Windows, macOS).

### 15.4 Native AOT and reflection stripping

Native AOT (introduced .NET 7) produces self-contained native
executables with no JIT. Unused code is trimmed; the trimmer cannot
see through reflection. Reflection-based serializers (Newtonsoft.Json
by default, XmlSerializer, BinaryFormatter, AutoMapper) may fail at
runtime because the types they expect were trimmed. DI that uses
`Type.GetType(typeName)` fails for trimmed types. `Assembly.LoadFile`
and `Reflection.Emit` are disallowed. The
`[DynamicallyAccessedMembers]` attribute is the primary mechanism for
telling the trimmer which members to preserve.

### 15.5 Source generators as security surface

Source generators (introduced .NET 5) run during compilation with
*full access* to the compilation environment — they can read any
file, make any network call, emit any code. A compromised NuGet
package containing a malicious source generator runs at every build
on every machine that consumes the package. Source generators can
emit code that calls reflection / `dynamic` / `Reflection.Emit`,
bypassing AOT or trimming protections. The mitigation is the same as
for any build-time dependency: pin versions, verify package
authenticity, audit generator source, run builds in sandboxed
environments.

### 15.6 SignalR and real-time bidirectional channels

SignalR's Hub class exposes every public method to any connected
client by default. `[Authorize]` is opt-in. JSON deserialization of
method arguments uses the configured Hub protocol with polymorphic
deserialization risks. Long-lived connections hold per-connection
state in memory; static-field leakage between users is the canonical
shared-context bug.

Cross-link: `vulnerability_research_methodology_expertise.md` for
variant-analysis; `code_review_expertise.md` §"Heterogeneous auth in
single control abstraction is suspicious."

---

## 16. References

### Primary documentation (Microsoft Learn)

- "Deserialization risks in use of BinaryFormatter and related types,"
  https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
- "BinaryFormatter migration guide,"
  https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/
- "Common async/await bugs,"
  https://learn.microsoft.com/en-us/dotnet/standard/asynchronous-programming-patterns/common-async-bugs
- "Native interoperability best practices,"
  https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices
- "Implement a Dispose method,"
  https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose
- "Memory<T> and Span<T> usage guidelines,"
  https://learn.microsoft.com/en-us/dotnet/standard/memory-and-spans/memory-t-usage-guidelines
- "RandomNumberGenerator Class,"
  https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator
- "Path.Combine Method,"
  https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine
- "ASP.NET Core support for Native AOT,"
  https://learn.microsoft.com/en-us/aspnet/core/fundamentals/native-aot
- "Code analysis in .NET,"
  https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview
- "CA2014," "CA2326," and the broader CA2300-CA2330 analyzer rules

### .NET team blog and devblogs

- Stephen Toub, "ConfigureAwait FAQ,"
  https://devblogs.microsoft.com/dotnet/configureawait-faq/
- Stephen Toub, "How Async/Await Really Works in C#,"
  https://devblogs.microsoft.com/dotnet/how-async-await-really-works/
- Stephen Cleary, "Async/Await Best Practices," MSDN Magazine 2013,
  https://learn.microsoft.com/en-us/archive/msdn-magazine/2013/march/async-await-best-practices-in-asynchronous-programming
- Levi Broderick, "Cryptographic Improvements in ASP.NET 4.5,"
  https://devblogs.microsoft.com/dotnet/cryptographic-improvements-in-asp-net-4-5-pt-1/
- ".NET 9 BinaryFormatter Removal,"
  https://devblogs.microsoft.com/dotnet/binaryformatter-removed-from-dotnet-9/
- David Fowler, AspNetCoreDiagnosticScenarios,
  https://github.com/davidfowl/AspNetCoreDiagnosticScenarios

### Security research

- Muñoz & Mirosh, "Friday the 13th: JSON Attacks," Black Hat USA /
  DEF CON 25 2017,
  https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Alvaro-Munoz-JSON-attacks-WP-UPDATED.pdf
- Soroush Dalili, "Exploiting Deserialisation in ASP.NET via
  ViewState,"
  https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- James Forshaw, "Exploiting .NET Managed DCOM," Project Zero 2017,
  https://googleprojectzero.blogspot.com/2017/04/exploiting-net-managed-dcom.html
- pwntester/ysoserial.net, https://github.com/pwntester/ysoserial.net
- irsdl/ysonet, https://github.com/irsdl/ysonet
- NCC Group / Freddy, https://github.com/nccgroup/freddy
- Praetorian, "Path.Combine Security Issues in ASP.NET Applications,"
  https://www.praetorian.com/blog/pathcombine-security-issues-in-aspnet-applications/
- Trend Micro, "Proactive Security Insights for SharePoint Attacks
  (CVE-2025-53770 and CVE-2025-53771),"
  https://www.trendmicro.com/en_us/research/25/g/cve-2025-53770-and-cve-2025-53771-sharepoint-attacks.html
- Andrew Lock, "Preventing mass assignment or over-posting in
  ASP.NET Core,"
  https://andrewlock.net/preventing-mass-assignment-or-over-posting-in-asp-net-core/
- Scott Hanselman, "ASP.NET — Overposting/Mass Assignment Model
  Binding Security,"
  https://www.hanselman.com/blog/aspnet-overpostingmass-assignment-model-binding-security

### Books

- Cwalina, K., Barton, J., Abrams, B., "Framework Design Guidelines,"
  3rd ed., Addison-Wesley, 2020.
- Albahari, J., "C# 12 in a Nutshell," O'Reilly, 2024.

### Standards

- MITRE CWE-502 (deserialization), CWE-22 (path traversal),
  CWE-330 / CWE-338 (random), CWE-327 (broken crypto).
- OWASP Deserialization Cheat Sheet; OWASP Password Storage Cheat
  Sheet.

### Tooling

- dotnet/roslyn-analyzers, https://github.com/dotnet/roslyn-analyzers
- SecurityCodeScan, https://security-code-scan.github.io/
- Blacklist3r (ViewState MachineKey audit)

### Academic

- Firouzi et al., "On the use of C# Unsafe Code Context," ESEM 2020,
  https://dl.acm.org/doi/abs/10.1145/3382494.3422165

---

## Coda — the next behavioral-footgun docs

This doc is the first in the language-specific-behavioral-footguns
class. Candidate companion docs (priority order): Java (`Object.equals`
vs `==`, `Comparable` contract, `Thread.stop` legacy, JCE provider
chain, `Class.forName`, `URLClassLoader`); Python (mutable default
arguments, late closure binding, `pickle`, `os.system` vs
`subprocess`, `eval` / `exec`, `__del__` resurrection,
`__init_subclass__`); JavaScript / TypeScript (`==` vs `===`,
`__proto__` pollution, `Object.assign` prototype-chain copying,
`async` / `await` in `forEach`, stringy `setTimeout`, `new Function`);
Go (silent type-assertion failures, `nil` interface vs nil-typed
interface, slice aliasing, goroutine leaks, context cancellation,
`os/exec` shell semantics, `encoding/gob` register-by-name); Rust
(`unsafe` interior contracts, `Pin` lifetime requirements,
`Send`/`Sync` auto-trait inference, `mem::transmute`, `Drop` panic
surface, async cancellation safety); Ruby (`Marshal.load`, `eval` /
`instance_eval` / `class_eval`, open-class meta-pattern, `send` vs
`public_send`).

Each follows this doc's shape: bio block of 7-10 named researchers,
14-16 numbered technique sections, tooling and defensive-checklist
sections, references with primary-source URLs. The cross-link
discipline holds: bug-class docs explain *what the vulnerability is*;
behavioral-footgun docs explain *what the language primitive does,
such that the bug class emerges from ordinary use*.
