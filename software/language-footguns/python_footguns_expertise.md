# Python Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from CPython core developers, PyPA / packaging maintainers, Twisted and modern-async authors, and the institutional research that catalogs Python-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — cataloguing primitives whose
> *default behavior* in a specific language ecosystem is unsafe, distinct from
> cross-language bug-class docs (SQL injection, deserialization, shell injection,
> path traversal) that cover attack surface by class rather than by language.
> The 2024-2026 load-bearing updates: PEP 703 free-threaded Python (3.13t and
> 3.14+) collapses GIL-based atomicity assumptions in third-party C extensions;
> the `tarfile.extractall(filter='data')` default in Python 3.14 closes the
> long-standing CVE-2007-4559 Tar Slip class; PyTorch 2.6 flipped `torch.load`
> default to `weights_only=True`; PyYAML 6.0 made `Loader=` a required argument;
> the 2025 ReversingLabs **nullifAI** disclosure (broken-pickle deserialization
> bypassing `picklescan`) and HiddenLayer **Silent Sabotage** (Hugging Face
> safetensors-conversion bot pull-request flow) re-opened the ML supply-chain
> surface; the `setup.py`-runs-at-install attack class continues to drive PyPI
> typosquatting and dependency-confusion incidents.
>
> **Researchers:**
> - **Moshe Zadka** — Python contributor since 1998, founding member of the
>   Twisted project, author of *DevOps in Python* (Apress) and co-author of
>   *Expert Twisted*; long-running corpus of Real Python / Red Hat /
>   Opensource.com writeups on Python infrastructure and security discipline
> - **Glyph Lefkowitz** — creator of the Twisted asynchronous-networking
>   framework; PSF Community Service Award 2017 for the asynchronous-programming
>   design influence that shaped JavaScript Promises and Python `asyncio`;
>   long-form writing on event-loop, TLS, and library-design security
> - **Łukasz Langa** — CPython core developer, first PSF "Developer in
>   Residence," release manager for Python 3.8 and 3.9, creator of the Black
>   formatter; co-author or author of multiple PEPs covering type-hint and
>   modernization mechanics
> - **Brett Cannon** — CPython core developer since 2003,
>   Principal Software Developer at Microsoft on the Python
>   tooling team; led the CPython GitHub migration, authored `importlib`, and
>   served on the inaugural CPython Steering Council
> - **Steve Dower** — CPython core contributor and the Windows build manager;
>   Microsoft Python engineer; CVE coordination for Windows-specific
>   bugs.python.org issues (CVE-2022-26488 escalation-of-privilege via the
>   Windows installer)
> - **Pradyun Gedam** — pip maintainer, PyPA member, PSF Fellow, CPython core
>   developer; co-author of multiple packaging PEPs including the PyPA
>   governance model; Python Infrastructure team at Bloomberg
> - **Alyssa Coghlan** (formerly Nick) — CPython core developer, PSF Fellow,
>   long-running author of *Curious Efficiency / Python Notes* covering import
>   system, packaging history, and language-evolution rationale; deep
>   experience documenting Python's design surface for security review
> - **Hynek Schlawack** — PSF Fellow, creator of `attrs` (the progenitor of
>   Python `dataclasses`); maintainer of `structlog` and `svcs`; CPython and
>   Twisted contributor; ongoing essay corpus at hynek.me on production-grade
>   Python discipline, particularly logging and service-layer security
> - **Sebastián Ramírez** (tiangolo) — creator of FastAPI, Typer, SQLModel,
>   Asyncer; one of the most influential authors driving Python-type-hint
>   adoption in web framework design; the FastAPI / Pydantic boundary is a
>   primary 2020s security surface in Python web applications
> - **Trail of Bits** (institutional) — security research firm; PyPI
>   first-formal-audit (2023, 29 advisories); authors of `fickling` (the
>   pickle decompiler / static analyzer / bytecode rewriter referenced by
>   nearly every modern Python deserialization writeup); `abi3audit` for
>   Python C-extension ABI auditing; `modern-python` Claude Skill plugin
>   for modern Python tooling (uv, ruff)
> - **ReversingLabs / JFrog / HiddenLayer / Snyk** (institutional) — the
>   2024-2025 ML-supply-chain CVE corpus (`nullifAI` Hugging Face
>   pickle-bypass, three zero-day `picklescan` CVEs, Silent Sabotage
>   safetensors-conversion bot, fake-Alibaba-SDK poisoned-model campaigns)
>
> **Institutional contributors:** Python Software Foundation (PEPs 458 /
> 480 / 517 / 518 / 668 / 703); PyPA (`pip` Secure Installs guide,
> `setuptools` build-system isolation); MITRE CWE (CWE-502, CWE-22,
> CWE-78, CWE-94, CWE-611, CWE-918, CWE-79, CWE-89, CWE-330, CWE-362);
> OWASP (Python Security Cheat Sheet, Deserialization Cheat Sheet,
> Django Security Cheat Sheet); PyCQA (`bandit` Python security linter,
> 47-check core ruleset); Astral (`ruff` security rules); the academic
> `safetensors` design papers from Hugging Face / ML supply-chain
> literature.
>
> **What this doc is NOT:** not a Python language tutorial, not a
> replacement for cross-language bug-class guidance, not a substitute
> for static analysis or `bandit`. It is the Python-specific layer
> beneath cross-language audit heuristics. Read this before reviewing
> any non-trivial Python codebase; read `code_review_expertise.md`
> for the click-count severity heuristic that lifts each footgun into
> a triage decision.

Cross-links: `deserialization_expertise.md` for the cross-language
deserialization bug class (pickle is the canonical example, but the
gadget-chain methodology generalizes); `code_review_expertise.md` for
the candidate-point auditing methodology and click-count severity
heuristic; the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for detection-rule authoring
guidance; `shell_injection_expertise.md` for the cross-language
shell-injection surface (`subprocess(..., shell=True)` is the Python
incarnation); `template_code_injection_expertise.md` for the SSTI
class (Jinja2 / `render_template_string` are the Python incarnations);
`xml_parser_differential_expertise.md` for XXE / Billion-Laughs /
DTD-recursion differentials (`lxml`, `xml.etree`, `defusedxml`);
`race_conditions_concurrency_expertise.md` for the GIL / `asyncio` /
`multiprocessing` surface; `cicd_supply_chain_expertise.md` for the
PyPI / pip / `setup.py` install-time RCE class; `adversarial_ml_model_security_expertise.md`
for the PyTorch / safetensors / pickle-in-ML-models surface;
`js_sandbox_escape_expertise.md` for the cross-language "you cannot
sandbox a fast language" axiom that applies in full force to Python.

---

## 1. The behavioral-footgun framing

### 1.1 Why Python footguns differ from compiled-language footguns

Python is a dynamically-typed, dynamically-dispatched language with
runtime-mutable class hierarchies, runtime-mutable attribute
namespaces, and a long-standing "consenting adults" posture. In a
statically-typed compiled language, the common failure modes are
either a primitive whose default behavior silently degrades to
insecure (`BinaryFormatter.Deserialize`, `Path.Combine`
second-arg-absolute discard) or a contract the compiler cannot
enforce (`equals` / `hashCode` consistency). The compiler accepts
the unsafe call; the runtime executes it; the type system never
gets a chance to warn.

In Python, the compiler is minimal and performs no security
verification. There is no default static analyzer. Every footgun
in this document satisfies: **the interpreter accepts the code
without warning, no default tool flags it, the runtime executes
it producing the unsafe behavior** — and there was never a
compiler to push back. The audit burden falls entirely on review
and opt-in static analysis (`bandit`, `ruff`, `semgrep`).

### 1.2 The dynamic-by-default reality

Three Python design choices amplify the footgun surface:

1. **Attribute access is a hook.** `obj.x` invokes `__getattribute__`
   then optionally `__getattr__`. Any object can intercept, forward,
   or fabricate any attribute. Code that *reads* like a simple field
   access can execute arbitrary code.
2. **Class hierarchies are mutable at runtime.** `instance.__class__`
   is reassignable. `cls.__bases__` is reassignable. `cls.__mro__`
   is walkable. `cls.__subclasses__()` enumerates every loaded
   subclass of `cls`. The Jinja2 SSTI escape
   `{{ ''.__class__.__mro__[1].__subclasses__() }}` weaponizes this
   to reach `subprocess.Popen` from a string literal.
3. **Imports execute code.** `import X` evaluates module `X` at top
   level — including any side-effectful `subprocess.run`, network
   connect, or file write at module scope. `pip install` extends
   this to package installation: `setup.py` is package-controlled
   code that runs with the installer's privileges. Both are
   ordinary, documented Python behavior; both are the primary
   primitives in PyPI supply-chain attacks.

### 1.3 Audit-cost asymmetry and cross-link discipline

The developer writes `yaml.load(user_input)` once; the auditor reads
it many times and must remember `yaml.load` is the unsafe variant.
Detection tooling — `bandit`, `semgrep`, `ruff`, CodeQL — is the
only scalable answer; read this document as *what to teach the
tool to find*, not as a list of one-at-a-time mistakes.

This doc explains *what each Python primitive does, such that the
bug class emerges from ordinary use*. The bug-class docs (linked
above) explain *what the bug class is in general*. For
deserialization, the Python footgun is "`pickle.loads(x)` on
untrusted `x` is unconditional RCE because the format specifies
arbitrary callable invocation via `__reduce__`"; the cross-language
doc explains why deserialization-with-callable-references is a
fundamental design flaw across languages, not just Python.

---

## 2. `eval`, `exec`, `compile`, and dynamic code primitives

### 2.1 `eval(USER_INPUT)` — direct RCE

`eval(expr_string)` parses `expr_string` as a Python expression and
evaluates it in the current scope. If `expr_string` is attacker-
controlled, this is unconditional remote code execution. There is
no sandboxing, no token whitelisting, no expression-only restriction
that prevents reaching `__import__('os').system('id')` via attribute
access:

```python
eval(user_input)  # user_input = "__import__('os').system('id')"
```

The Python documentation warns explicitly: "Overriding
`__builtins__` can be used to restrict or change the available
names, but this is **not** a security mechanism: the executed code
can still access all builtins." Restricting `eval` via `eval(s, {'__builtins__': {}})`
is **not safe** — the AST escape via `().__class__.__bases__[0].__subclasses__()`
reaches arbitrary classes in the running process without touching
`__builtins__`. Every published "safe eval" sandbox in Python has
been broken by class-hierarchy escape, and there is no general
defense at the eval-API layer.

### 2.2 `exec(USER_INPUT)` — same, but statement-form

`exec` is the statement-form analog of `eval`: it accepts arbitrary
Python statements (assignments, imports, function definitions,
class definitions) and executes them. Same RCE primitive, broader
syntactic reach. Same "you cannot restrict it" reality.

```python
exec(user_input)  # user_input = "import os; os.system('id')"
```

The documentation note: "be aware that the `nonlocal`, `yield`, and
`return` statements may not be used outside of function definitions even
within the context of code passed to the `exec()` function" is the
*only* restriction — and it is irrelevant to security.

### 2.3 `compile(USER_INPUT, '<string>', 'exec')` — code-object generation

`compile` parses a source string into a Python code object suitable
for later `exec` or `eval` invocation. The compilation step does
not execute the code, but the resulting code object is a fully-
empowered Python primitive: passing it to `exec` is equivalent to
the direct-`exec` case. Treating `compile` as "safer than `exec`"
because it doesn't execute immediately is wrong — it just moves the
execution to a later call site.

The legitimate use case (caching parsed code across invocations
where the source is fully trusted, e.g., a template engine
compiling templates from disk at startup) is narrow. Any pattern
where the input to `compile` is user-controlled is RCE.

### 2.4 `__import__(USER_INPUT)` — import-name injection

`__import__('os')` is the function form of the `import` statement.
If the module-name string is user-controlled, the attacker can
import any module installed on the system — including modules whose
top-level code has side effects. Combined with attribute access,
this reaches arbitrary callables:

```python
mod = __import__(user_module)  # user_module = "os"
mod.system(user_cmd)
```

`importlib.import_module(name)` is the documented modern variant
with identical security properties. The PEP 451 spec describes the
import machinery in detail; the security note is that *any* user-
controlled import name is sufficient for the attacker to escalate
to RCE if any module on the system has useful side effects (which
every Python install does — `os`, `subprocess`, `pickle`, etc.).

### 2.5 `globals()` / `locals()` mutation and the sandbox-escape primitive

Given any function `f` reachable from a restricted namespace,
`f.__globals__` returns the globals of `f`'s defining module
regardless of where `f` was passed. Any function from `os`,
`subprocess`, or any unrestricted module hands the attacker
unrestricted execution via `f.__globals__['os'].system(...)`.
The "safe eval namespace" defense ignores this.

### 2.6 The eval-with-safe-namespace anti-pattern

```python
result = eval(expr, {'__builtins__': {}}, {'sqrt': math.sqrt})
```

is **not safe**. Escape chains: `().__class__.__bases__[0].__subclasses__()`
reaches every loaded class; any callable in the namespace whose
`__globals__` includes dangerous builtins is a pivot. This is the Python instance of the universal
axiom **you cannot sandbox a fast reflective language at the
language level** (cross-link `js_sandbox_escape_expertise.md`).
Defenses: (a) don't evaluate untrusted strings at all; (b) use
a separate process / VM / container as the isolation boundary;
(c) AST-walk with a strict allowlist (§ 2.7).

### 2.7 AST-walking alternatives

`ast.parse(s, mode='eval')` + `ast.NodeVisitor` raising on any node
not in a strict allowlist (typically `Expression`, `BinOp`,
`UnaryOp`, `Constant`, `Compare`, `BoolOp`, allowlisted `Name`).
Interpret the AST directly or `compile` the validated AST in an
empty namespace. `simpleeval` (PyPI) implements this and has
shipped a sandbox-escape CVE (CVE-2026-32640) for allowlist gaps. If the
alternative is "build a real DSL with a real parser," that is
almost always the right answer.

### 2.8 Real-world CVE corpus

`eval` / `exec` RCEs appear routinely in: Jupyter notebooks
exposed to network input; framework debug consoles (Werkzeug,
Django); ML model-loading code that `exec`s embedded Python; ETL
tools supporting "Python expressions in config" (Airflow's
history is instructive); CLI tools that `eval` shell-style
expressions. Dozens per year across Python via Snyk / NIST NVD /
GitHub Security Advisories.

---

## 3. `pickle` and the ecosystem of insecure deserializers

### 3.1 `pickle.loads(USER_INPUT)` — canonical RCE

`pickle` is Python's binary serialization format. The Python
documentation states explicitly at the top of the module:

> Warning: The `pickle` module is not secure. Only unpickle data
> you trust. It is possible to construct malicious pickle data
> which will execute arbitrary code during unpickling. Never
> unpickle data that could have come from an untrusted source,
> or that could have been tampered with.

The mechanism is documented and intentional: pickle data is a
small stack-based program. The `REDUCE` opcode takes a callable
and an argument tuple from the stack and invokes the callable
with the arguments. Any pickle stream can encode "invoke
`os.system` with argument `('id',)`" — and the unpickler will
execute it.

```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(Exploit())
pickle.loads(payload)  # executes `id`
```

This is the canonical Python deserialization RCE. Treat any
`pickle.loads`, `pickle.load`, `pickle.Unpickler.load` on
attacker-controlled bytes as unconditional RCE. There is no
"safe pickle subset" at the format level.

### 3.2 The `__reduce__` magic method — gadget chain primitive

`__reduce__` is the user-extensible hook by which an object tells
the pickler "to reconstruct me, call this callable with these
arguments." The pickler emits the `REDUCE` opcode that the
unpickler then executes. The contract is: return a 2-tuple
`(callable, args)`; the callable is invoked with `args` at
unpickle time.

Any callable importable in the unpickling process is a valid
gadget. The exploitation methodology (cross-link
`deserialization_expertise.md`) treats this as a gadget-chain
search problem: enumerate callables reachable from
`sys.modules`, filter for callables whose side effects are
useful (RCE, file write, network connect), construct a payload.
The trail-of-bits `fickling` tool automates much of this.

`__reduce_ex__(protocol)` is the protocol-aware variant, and
`__setstate__` / `__getstate__` are the lower-level hooks. All
of these are part of the same primitive surface.

### 3.3 `cPickle` (Python 2 legacy)

`cPickle` was the C-implemented pickle module in Python 2. In
Python 3, the C implementation is merged into `pickle` itself
(transparent acceleration). Any code still importing `cPickle`
is Python 2 code; its security properties are identical (worse,
because Python 2 is end-of-life and unmaintained).

### 3.4 `pickle.HIGHEST_PROTOCOL` and protocol negotiation

Pickle has multiple wire-format versions (protocols 0-5 in
CPython 3.13). The protocol affects compatibility, performance,
and binary size — but **not** security. Every protocol supports
the `REDUCE` opcode and arbitrary-callable invocation. Code that
treats "we use protocol 5" as a security boundary is wrong.

### 3.5 `marshal.loads()` — internal Python serialization

`marshal` is the format CPython uses for `.pyc` files. It is
documented as not safe against arbitrary input and explicitly
not intended for cross-version interchange. The
`marshal.loads(bytes)` primitive can produce a code object that
`exec` can run. While the surface is narrower than pickle's
(no `__reduce__`-style hook for ordinary objects), code objects
themselves are sufficient for RCE. Treat `marshal.loads` on
untrusted input as RCE.

### 3.6 `shelve` — wraps pickle

`shelve` is a key-value-store-on-disk that uses `pickle` to
serialize values. Reading a `shelve` file written by an attacker
is `pickle.loads` with extra steps. Same threat model.

### 3.7 `dill` / `cloudpickle` — extended pickle with more gadgets

`dill` extends pickle to serialize objects pickle cannot
(lambdas, nested functions, closures). It does this by
registering additional `__reduce__`-style hooks. The attack
surface is *larger* than vanilla pickle — every additional
type `dill` knows how to pickle is an additional gadget surface
under unpickle.

`cloudpickle` (originally from PiCloud, later PySpark) is
similar — extends pickle to handle distributed-computing payloads
including dynamic functions. Same warning.

Both are commonly used in distributed-ML and data-science
pipelines. Treat any `dill.loads` / `cloudpickle.loads` on
untrusted bytes as RCE.

### 3.8 `joblib.load` — wraps pickle (sklearn / scientific Python)

`joblib.load` is the standard sklearn / scientific-Python
serialization API for saved models. Under the hood it uses
pickle (or `cloudpickle` for some objects). `sklearn.externals.joblib`
is the same. Loading a `.joblib` / `.pkl` model file is
unpickling untrusted bytes.

This is the dominant ML supply-chain risk in the scikit-learn
ecosystem. The Bandit B301 / B614 rules flag `pickle.load` and
`torch.load`, respectively; `joblib.load` is under the same
threat model.

### 3.9 `torch.load` (PyTorch) — default `weights_only=False` pre-2.6

`torch.load(path)` historically used pickle by default. Pre-PyTorch
2.6 (2025), the default was `weights_only=False` — equivalent to
`pickle.load`. Any attacker-published PyTorch model file (`.pt`,
`.pth`, `.bin`) loaded with defaults executed arbitrary code at
load time.

PyTorch 2.6 flipped the default to `weights_only=True`, using a
restricted unpickler that allows only tensors and a small type
whitelist. This closes the basic RCE primitive but does not
eliminate RCE — CVE-2025-32434 was RCE through
`weights_only=True` via the legacy `.tar` load path (PyTorch
≤ 2.5.1, fixed in 2.6.0). **Treat any `torch.load` on untrusted bytes as
RCE-adjacent** even with `weights_only=True`; the long-run correct
primitive is `safetensors`. Cross-link: `deserialization_expertise.md`
§ ML serialization; `adversarial_ml_model_security_expertise.md`.

### 3.10 The `safetensors` defensive alternative

`safetensors` (Hugging Face, 2022+) stores raw tensor data plus a
JSON header — no pickle, no callables, no `__reduce__`. The format
is deserialization-safe by design. Trade-off: it stores only
tensors and metadata; non-tensor model state serializes separately.

HiddenLayer's **Silent Sabotage** (2024) showed the
Hugging Face `SFconvertbot` pickle-to-safetensors conversion
pipeline was subvertible (attacker substitutes model in PR flow).
Format-safe; pipeline was not. Standard "trust the format, verify
the supply chain" reminder.

### 3.11 The 2024-2025 ML supply-chain corpus

- **nullifAI** (ReversingLabs, Feb 2025): malicious Hugging Face
  models in 7z archives bypass `picklescan` (which expects ZIP).
  Pickle inside is still deserialized at load. Truncated /
  "broken" pickles execute attacker code before raising, because
  pickle's stack machine commits side effects opcode-by-opcode.
- **Three zero-day `picklescan` CVEs** (JFrog 2025): scanner-bypass
  techniques exploiting scanner-vs-runtime opcode-dispatch
  differential.
- **Silent Sabotage** (HiddenLayer 2024): see § 3.10.
- **Fake Alibaba SDK models** (CSOonline 2025): typosquatted
  ML-package distribution shipping pickle payloads.

Collective message: pickle is the dominant Python ML serialization
surface, every defensive scanner is incomplete, the only
structurally-safe answer is `safetensors` (or HMAC / signed-blob
discipline).

---

## 4. Magic methods and dunders

- **`__init_subclass__` runs at class-definition (import) time.**
  Side effects (global registration, network calls) execute on
  every import path reaching the subclass. Attacker-controlled
  module imports trigger these.
- **`__getattr__` / `__getattribute__` — attribute-access
  interception.** Forwarding attributes to a remote service or
  user-controlled mapping turns every attribute access into an
  arbitrary-data fetch. A `__getattr__` that fabricates any
  attribute name is the Python analog of JS prototype pollution
  — `obj.is_admin` can be lied to. Raising `__getattribute__`
  breaks `hasattr` semantics. Audit heuristic: any class with
  one of these overrides deserves a longer look.
- **`__call__` makes any instance callable.** Breaks the
  `callable(x)` type-check pattern; `x` might be an arbitrary
  instance whose `__call__` does anything. Decorator chains,
  DI patterns, configured-handler dispatch all surface here.
- **`__class__` mutation.** CPython permits
  `instance.__class__ = OtherClass` under compatible memory
  layout — rebinds the instance type. Sandbox-escape primitive
  if attacker can write to `__class__` on a reachable object.
- **`__bases__` mutation.** `Cls.__bases__ = (NewBase,)` rebinds
  inheritance and re-runs MRO. Same threat model at class level.
- **`__subclasses__()` — the canonical Jinja2 SSTI primitive.**
  Returns every class inheriting from the target. From any
  string literal: `().__class__.__bases__[0].__subclasses__()`
  reaches every loaded class — `subprocess.Popen`,
  `os._wrap_close`, etc. Modern Jinja2 SandboxedEnvironment
  blocks `__class__`, `__mro__`, `__subclasses__`, `__globals__`,
  but the cat-and-mouse continues. Universal axiom: **you cannot
  sandbox a fast reflective language at the language level**.
- **`type.__mro__` walking** for class-hierarchy access.
  Variants: `type.__bases__`, `__class__.__base__`,
  `__class__.__bases__[-1].__subclasses__()`.
- **Full Jinja2 SSTI chain** (cross-link
  `template_code_injection_expertise.md`): attacker controls
  template expression → `''.__class__.__mro__[1].__subclasses__()`
  → index `subprocess.Popen` → construct + invoke → RCE.
  Structural defense: never call `render_template_string` on
  user input; use `render_template` with a fixed file and pass
  user data as context variables (auto-escaped in HTML mode).

---

## 5. Mutable default arguments

### 5.1 `def f(x=[]):` — the canonical "mutable default arg" trap

```python
def append_item(item, target=[]):
    target.append(item)
    return target
```

The default argument `[]` is evaluated **once**, at function
definition time, and the resulting list object is stored on
the function. Every call that omits `target` receives *the same
list object*. State leaks across invocations:

```python
>>> append_item(1)
[1]
>>> append_item(2)
[1, 2]
>>> append_item(3)
[1, 2, 3]
```

This is documented behavior (the function-object stores
`__defaults__` once), but it surprises everyone the first time.

### 5.2 Real-world bug patterns

The most common production manifestations:

- **Test isolation failure** — a test fixture function with a
  mutable default accumulates state across tests, producing
  order-dependent test failures.
- **Request-handler state leak** — a Flask or Django view with
  `def view(request, cache={})` leaks one request's cache to
  the next, including sensitive data.
- **Builder-pattern accumulation** — a `def build_query(parts=[])`
  function whose returned query accumulates clauses from prior
  calls.

The security relevance: in web handlers, the leaked state often
includes auth tokens, user IDs, or PII from the prior request.
This is "session bleed" at the language level.

### 5.3 The correction pattern

```python
def append_item(item, target=None):
    if target is None:
        target = []
    target.append(item)
    return target
```

`None` is immutable; the `is None` check creates a new list per
call. This is idiomatic Python; `ruff` rule B006 / `pylint`
W0102 / `flake8-bugbear` B006 all flag the mutable-
default pattern.

### 5.4 The `frozenset` / `()` / `MappingProxyType` exception

Immutable defaults are fine: `def f(x=())`, `def f(x=frozenset())`,
`def f(x=MappingProxyType({}))` cannot be mutated in-place, so
the shared-default-object problem doesn't apply. This is the
"if you really want a default container, use an immutable one"
discipline.

---

## 6. Late binding in closures + class scope

### 6.1 `[lambda: i for i in range(5)]` — all closures bind to final `i`

```python
fns = [lambda: i for i in range(5)]
[f() for f in fns]  # [4, 4, 4, 4, 4]
```

The lambdas all close over `i`. Closures in Python are
"late-binding" — they look up the name in the enclosing scope at
call time, not at definition time. By call time, `i` is 4 (the
final loop value).

This is documented in the Python FAQ ("Why do lambdas defined
in a loop with different values all return the same result?")
and is the subject of many writeups (e.g. the CodeQL `py/loop-variable-capture` query). The CodeQL rule
detects the pattern automatically.

### 6.2 The `lambda i=i: ...` default-arg trick

```python
fns = [lambda i=i: i for i in range(5)]
[f() for f in fns]  # [0, 1, 2, 3, 4]
```

The default-argument `i=i` captures `i`'s value at lambda
definition time (per § 5.1's "defaults evaluated once"
mechanism). This is the idiomatic Python fix for early-binding
intent.

Alternative: `functools.partial(lambda i: i, i)` — explicit
partial application. Or use a `def` inside the loop that
references `i` as a parameter, not as a closure.

### 6.3 Class-scope name resolution surprises

Python's LEGB rule (Local, Enclosing, Global, Built-in) does
**not** include the enclosing class scope for nested function
definitions. A method body cannot see names defined at the
class body level except via `self.` or `ClassName.`:

```python
class Foo:
    SHARED = []
    def method(self):
        return SHARED  # NameError: name 'SHARED' is not defined
```

This is correct Python (class body is not a normal enclosing
scope) but routinely surprises developers. The fix is `self.SHARED`
or `Foo.SHARED`.

### 6.4 The `nonlocal` keyword (Python 3) + its limits

`nonlocal` binds a name in the nearest enclosing function scope
(not class scope, not global). It is the Python-3 fix for
"rebind a closure variable":

```python
def make_counter():
    count = 0
    def increment():
        nonlocal count
        count += 1
        return count
    return increment
```

Without `nonlocal`, the `count += 1` would create a local `count`
and raise `UnboundLocalError`. `nonlocal` is class-scope-blind
in the same way function scoping is — you cannot `nonlocal` into
the class body.

### 6.5 Comprehension scoping (Python 3 leak-free vs Python 2 leaking)

In Python 2, `[x for x in range(5)]` *leaked* `x` into the
enclosing scope after the comprehension finished. In Python 3,
comprehensions have their own scope; `x` is local to the
comprehension and does not leak. Code ported from Python 2 to
Python 3 can break if it relied on the leak.

Generator expressions `(x for x in range(5))` have always had
their own scope, as did dict and set comprehensions (added in
Python 2.7). List comprehensions joined this behavior in Python 3.

---

## 7. `subprocess`, `os.system`, `shell=True`

- **`subprocess.run([...], shell=False)` is safe.** Default;
  passes argv directly to `execve(2)`. No shell expansion.
  `subprocess.run(f'ls {user}', shell=True)` invokes
  `/bin/sh -c` — every metachar (`;`, `|`, `&`, `$()`,
  backticks, `>`) is an injection point. Unconditional RCE
  when input is user-controlled. Cross-link
  `shell_injection_expertise.md`.
- **`os.system(USER_STRING)` / `os.popen(USER_STRING)`** invoke
  `/bin/sh -c`. Same injection surface as `shell=True`. Plus
  `os.system` discards stdout/stderr — usually a code-smell
  indicator.
- **`commands.getoutput(s)` (Py2 legacy)** — identical surface.
  Imports of `commands` signal unmaintained Python 2.
- **Argv injection — even with `shell=False`.** User-controlled
  arguments to commands with dangerous flags pivot to RCE:
  - `subprocess.run(['git', 'log', user_branch])` — if
    `user_branch` is `--output=/path/file`, git overwrites an
    arbitrary file.
  - `subprocess.run(['find', '.', user_pattern])` — `-exec sh
    -c 'id' \;` executes inside find.
  - `subprocess.run(['curl', user_url])` — `-K/--config @file`
    or `-o /etc/passwd` is destructive.
  Defense: per-command flag-surface awareness, input validation
  to expected shape, `--` end-of-options sentinel where
  supported (`['git', 'log', '--', user_branch]`). Cross-link
  `shell_injection_expertise.md` § argv-injection.
- **`shlex.split` / `shlex.quote`.** `shlex.split(s)` parses
  shell-style argv (argv-injection surface if `s` is user-
  controlled). `shlex.quote(arg)` shell-quotes a single arg
  for the rare cases `shell=True` is genuinely required (PHP
  `escapeshellarg` analog). No Python equivalent to PHP's
  `escapeshellcmd` — that primitive is structurally broken;
  Python's API forces you toward `shell=False` instead.

---

## 8. Path-traversal and filesystem operations

### 8.1 `open("/tmp/" + user_input)` — naive traversal

The canonical path-traversal pattern: concatenate a base
directory with a user-controlled filename. If `user_input` is
`../../etc/passwd`, the resulting path is
`/tmp/../../etc/passwd` which resolves to `/etc/passwd`. The
operating system handles `..` traversal in the kernel; the
application never sees the traversal as a special character.

### 8.2 `os.path.join("/base", user_input)` — does NOT prevent traversal

A trap that catches even experienced Python developers:

```python
os.path.join("/base", user_input)
```

If `user_input` is `../etc/passwd`, the result is
`/base/../etc/passwd` — still traversal-vulnerable. **But more
importantly**, if `user_input` is `/etc/passwd` (absolute),
`os.path.join` discards `/base` entirely and returns
`/etc/passwd`. This is documented behavior: "If a component is
an absolute path, all previous components are thrown away."

This is the Python analog of the .NET `Path.Combine` second-
arg-absolute-discard footgun (cross-link
`csharp_dotnet_footguns_expertise.md` § Path.Combine).

### 8.3 `pathlib.Path("/base") / user_input` — same trap

`pathlib.Path("/base") / "etc/passwd"` → `/base/etc/passwd` (ok).
`pathlib.Path("/base") / "/etc/passwd"` → `/etc/passwd` (discards
`/base`). Same semantics as `os.path.join`. The Pythonic-looking
`/` operator does not save you from the absolute-path trap.

### 8.4 Symlink-following defaults and TOCTOU

`os.open`, `open`, `os.stat`, `pathlib.Path.read_text` follow
symlinks by default. Classic TOCTOU: `if os.path.exists(path)
and not os.path.islink(path): open(path)` — attacker swaps a
file for a symlink to `/etc/shadow` between check and open.
Fix: `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)`. Cross-link
`race_conditions_concurrency_expertise.md` § TOCTOU.

### 8.5 `tempfile.mktemp()` (deprecated) vs `tempfile.mkstemp()`

`tempfile.mktemp()` returns a path that does not yet exist —
classic TOCTOU symlink race before the subsequent `open()`.
Deprecated since Python 2.3. Use `tempfile.mkstemp()` (atomic
`O_CREAT | O_EXCL`), `NamedTemporaryFile()`, or
`TemporaryDirectory()`. Modern code calling `mktemp()` is
ancient or deliberately race-vulnerable.

### 8.6 `tarfile.extractall()` — Zip Slip / Tar Slip (CVE-2007-4559)

`tarfile.extractall(path)` historically honored `..` components
in archive member names — write-anywhere primitive. CVE-2007-4559
was open from 2007 until Python 3.12 (2023) introduced
extraction filters (PEP 706); Python 3.14 made `filter='data'`
the default, which rejects symlinks outside destination, absolute paths, and
`..` traversal.

For Python ≤ 3.13 without an explicit `filter=` (and any backporting code), the safe pattern
canonicalizes per-member and prefix-checks:

```python
for member in tar.getmembers():
    target = os.path.realpath(os.path.join(path, member.name))
    if not target.startswith(os.path.realpath(path) + os.sep):
        raise Exception(f"Path traversal: {member.name}")
tar.extractall(path)
```

### 8.7 `zipfile.extractall()` — same Zip Slip class

Same vulnerability history, similar fix path. `ZipFile.extract()` /
`extractall()` strip absolute-path prefixes and remove `..`
components from member names; `extractall()` has no `filter=`
parameter.

### 8.8 `os.path.realpath` + canonical-prefix-check discipline

```python
base = os.path.realpath(BASE)
target = os.path.realpath(os.path.join(base, user_input))
if not (target == base or target.startswith(base + os.sep)):
    raise PermissionError()
```

`realpath` resolves symlinks and `..`. The `os.sep` separator
guard prevents the `/base2` vs `/base` prefix-aliasing trap.
Cross-link `code_review_expertise.md` § path-handling.

---

## 9. SSL / requests / urllib defaults

- **`urllib.request.urlopen()` verifies TLS by default (Python 3).**
  Since Python 2.7.9 / 3.4.3 via PEP 476. Python 2 `urllib2.urlopen`
  did NOT — legacy Python 2 code may have years of TLS-broken
  behavior baked in.
- **`requests.get(url, verify=False)` disables TLS validation.**
  Default is `verify=True`. The library prints a stderr warning
  that operators routinely silence with
  `requests.packages.urllib3.disable_warnings()`. Bandit / Ruff
  flag universally.
- **`ssl.create_default_context()` vs `ssl.SSLContext()`.**
  `create_default_context()` is default-secure: TLS 1.2+ minimum
  (since Python 3.10), strong ciphers, hostname verification
  ON, certificate validation ON. `ssl.SSLContext(protocol=...)`
  constructed directly with `PROTOCOL_TLS` / `PROTOCOL_TLS_SERVER`
  is default-INSECURE: hostname verification OFF, `CERT_NONE`;
  `PROTOCOL_TLS_CLIENT` enables both by default. Docs explicitly recommend
  `create_default_context()`.
- **`httpx` defaults to `verify=True`.** Same `verify=False`
  footgun pattern as `requests`.
- **The disable-warnings anti-pattern:**
  ```python
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
  ```
  Usually accompanies `verify=False` elsewhere. Smoking-gun grep
  target during review.
- **Custom `SSLContext` with deprecated TLS versions.** TLS 1.0 /
  1.1 are deprecated (RFC 8996). Python 3.10 disabled them in
  the default context; explicit selection still works but should
  be flagged. Cross-link `cryptography_expertise.md` §
  TLS deprecation.

---

## 10. SQL — DB-API parameter binding

- **`cursor.execute("SELECT ... WHERE id = %s" % user_input)` —
  SQLi.** String-formatting (`%`, `.format`, f-strings, `+`)
  bypasses driver parameter binding. The `%s` here is the
  Python format placeholder, not the DB-API one.
- **`cursor.execute("SELECT ... WHERE id = %s", (user_input,))` —
  safe.** PEP 249 specifies `execute(query, params)`; the driver
  handles binding (psycopg2 converts each value to a quoted SQL
  literal client-side).
  Placeholder styles per `paramstyle`: `qmark` (`?` — sqlite3),
  `numeric` (`:1`), `named` (`:name`), `format` (`%s` —
  mysqlclient/psycopg2), `pyformat` (`%(name)s` — psycopg2).
- **`f"SELECT * FROM {table_name}"` — the identifier trap.** SQL
  identifiers (tables, columns) cannot be parameterized; only
  values can. Dynamic identifier selection requires allowlist:
  ```python
  ALLOWED = {'users', 'orders', 'products'}
  if table not in ALLOWED: raise ValueError()
  cursor.execute(f"SELECT * FROM {table} WHERE id = %s", (user_id,))
  ```
  Same for `ORDER BY <column>` patterns.
- **SQLAlchemy `text()`.** `text("... :id").bindparams(id=x)` is
  safe (named binding). `text(f"... {user_input}")` is SQLi —
  `text()` does not auto-parameterize interpolated strings.
- **Django ORM raw escape hatches.** `Model.objects.filter(id=x)`
  is parameterized. `Model.objects.raw(query, params)` is safe
  with the params tuple, SQLi without. `Model.objects.extra(
  where=[USER_INPUT])` is a documented last-resort API Django aims to
  deprecate, and SQLi when
  user input flows in. `Model.objects.raw(f"... {user}")` is
  SQLi. Cross-link `code_review_expertise.md`: any Django ORM
  call with `raw`, `extra`, or `RawSQL` deserves a long look.
- **Dynamic `ORDER BY <column>` is almost always SQLi.** The
  fix is column-name allowlist. `1 ; DROP TABLE users --` in
  MySQL multi-statement mode or second-order subselects are
  payloads in the wild.
- **NoSQL injection.** `pymongo`'s `db.users.find({"name":
  user_input})` is safe if `user_input` is a string. If JSON
  body parsing returned `{"$ne": null}` and the dict reaches
  `find()`, the dict becomes a Mongo operator and bypasses
  authentication. Defense: enforce string type at API boundary.
  Cross-link `graphql_api_security_expertise.md` § deserialized-
  JSON-as-control-flow.

---

## 11. Web framework specifics (Django / Flask / FastAPI)

### 11.1 Django

- **`Model.objects.extra(where=[USER_INPUT])` — SQLi** (§ 10.5).
  `extra()` is the documented raw-SQL escape hatch; SQLi when args
  include user input.
- **`mark_safe()` / `|safe` template filter — XSS bypass.** Django
  auto-escapes by default; `mark_safe(user_html)` opts out. Bandit
  B703 / Ruff S308 flag the pattern.
- **CSRF discipline.** `CsrfViewMiddleware` must come after
  `SessionMiddleware` if you're using `CSRF_USE_SESSIONS`. `@csrf_exempt` is often abused on webhook
  receivers. `CSRF_TRUSTED_ORIGINS` (entries need a scheme since Django 4.0) needs explicit
  config for legitimate cross-origin POSTs.
- **`SECRET_KEY` exposure.** Signs sessions, password reset tokens,
  all `signing.dumps`/`loads`. Leaked SECRET_KEY =
  forgeable everything. Common leak channels: git commits, logs,
  `DEBUG=True` error pages.
- **`DEBUG=True` in production** exposes stack traces with locals,
  settings module contents (settings named with API, KEY, PASS, SECRET, SIGNATURE or
  TOKEN are hidden),
  installed apps, request headers / cookies. `ALLOWED_HOSTS` is
  one of the few protections still effective; otherwise total
  information disclosure. `python manage.py check --deploy` flags.
- **`SECURE_SSL_REDIRECT` / `SECURE_HSTS_SECONDS` / `SESSION_COOKIE_SECURE`
  / `CSRF_COOKIE_SECURE` are all OFF by default.** Production
  needs every one set; the deploy checklist flags each.

### 11.2 Flask

- **`request.form` / `request.args` / `request.get_json()` /
  `request.values`.** Parsing depends on `Content-Type`.
  `request.values` merges form + URL params into one namespace —
  CSRF protection for one doesn't imply CSRF protection for the
  other; consider it suspicious.
- **`flask.render_template_string(USER_INPUT)` — SSTI direct.**
  Canonical Flask SSTI primitive (§ 4.6 / § 4.8). Fix:
  `render_template('file.html', user_data=user_input)`.
- **`app.config['SECRET_KEY']` signs but does NOT encrypt
  sessions.** Flask sessions are signed cookies; contents are
  base64-readable. Anything sensitive in `session` is leaked.
  Leaked SECRET_KEY = forgeable sessions.
- **`@app.before_request` ordering** is registration-order;
  refactors that reorder break authorization. Audit accordingly.

### 11.3 FastAPI

- **Pydantic validation reach.** Validation surface is
  type-annotated parameters of the path-operation function.
  Untyped or `dict`-typed parameters bypass validation. Pydantic
  v1 silently drops extra fields by default; v2 same unless
  `model_config = {'extra': 'forbid'}`. Mass-assignment /
  overposting analog (cross-link
  `csharp_dotnet_footguns_expertise.md` § overposting).
- **`HTMLResponse(content=USER_INPUT)`** sends content verbatim —
  XSS if user-controlled. Use `Jinja2Templates` for HTML.
- **Path-parameter validation gaps.** `user_id: int` is
  auto-validated; `user_id: str` permits `..` traversal. Fix
  with strict typing (UUID, int) or explicit regex.
- **Dependency-injection ordering for auth.** Routes that forget
  to declare an auth `Depends` run with no auth unless it is applied app-wide via
  `FastAPI(dependencies=[...])`. Every route declares `Depends` or is
  explicitly public.

---

## 12. `json.loads` + custom parsers

### 12.1 `json.loads` is safe by default

`json.loads(s)` parses JSON per RFC 7159 with no `eval`, no
`__reduce__`, no callable invocation. One of the few
"deserialize untrusted bytes" APIs in Python that is safe by
default. The footgun is the layer *above*:
`obj = json.loads(s); SomeClass(**obj)` parses safely but then
constructs `SomeClass` from attacker-controlled kwargs. Pydantic /
dataclasses / `attrs` provide schema-validated alternatives.

### 12.2 `yaml.load(USER_INPUT)` is NOT safe

PyYAML's `yaml.load` historically defaulted to the unsafe loader,
which honors the `!!python/object/apply:os.system` tag — same RCE
primitive as pickle. PyYAML 6.0 (2021) made `Loader=` a required
argument; calling without a loader is now `TypeError`. But the
fix only forces a choice; `Loader=yaml.UnsafeLoader` or
`yaml.Loader` is still RCE.

Safe: `yaml.safe_load(s)`, `yaml.load(s, Loader=yaml.SafeLoader)`,
`yaml.load(s, Loader=yaml.BaseLoader)` (everything-as-string).
Avoid: `yaml.unsafe_load(s)`, `yaml.load(s, Loader=yaml.Loader)`,
`Loader=yaml.UnsafeLoader`, `Loader=yaml.FullLoader` (FullLoader
blocks the most-direct primitives but still constructs arbitrary
Python classes).

### 12.3 `yaml.unsafe_load` canonical RCE payload

```yaml
!!python/object/apply:os.system ["id"]
```

Single-line RCE under pre-5.1 `yaml.load` or any unsafe loader.

### 12.4 `xml.etree.ElementTree` — XXE not fully closed

Python 3's `xml.etree` mitigated some XML attacks (entity-expansion
limits, no external DTD in recent versions) but the full XXE /
Billion Laughs surface is not closed at the parser level. Python
docs point to their XML security section for untrusted input. Cross-link `xml_parser_differential_expertise.md`.

### 12.5 `lxml.etree` — defaults unsafe

`lxml.etree` wraps `libxml2`. Before lxml 5.0 the default
`resolve_entities=True` expanded external entities; 5.0 changed
it to `resolve_entities='internal'`. `no_network` defaults to True. lxml
maintainers recommend `resolve_entities=False, no_network=True,
load_dtd=False` for untrusted input, or `defusedxml`'s lxml wrapper.

### 12.6 `defusedxml` as defensive XML parser

`defusedxml` (tiran/defusedxml) wraps stdlib parsers with safe
defaults: DTDs allowed unless `forbid_dtd=True` (`DTDForbidden`), entity declarations
disabled (`EntitiesForbidden`), external references disabled
(`ExternalReferenceForbidden`), network disabled, Billion-Laughs
limits enforced. Any
production code parsing external XML without `defusedxml` (or
equivalent hardening) deserves review. Cross-link
`xml_parser_differential_expertise.md`.

---

## 13. Threading, asyncio, and the GIL

- **GIL serializes bytecode, not statements.** CPython's GIL
  serializes bytecode-instruction execution; `counter += 1` is
  four bytecode instructions (LOAD, LOAD, ADD, STORE), interleavable
  across threads — classic lost-update race. Code that assumes
  "the GIL makes this atomic" is wrong about which operations
  are atomic. Cross-link `race_conditions_concurrency_expertise.md`
  § GIL semantics.
- **`threading` is for I/O, not CPU** under the GIL. I/O syscalls
  release the GIL; pure-Python CPU work does not parallelize.
- **`multiprocessing` uses pickle for IPC.** Worker processes
  accepting pickled messages from a network source = unpickling
  untrusted bytes = RCE.
- **`asyncio.run(USER_COROUTINE)` has no built-in resource limits.**
  No timeout, memory limit, or concurrency cap; code accepting
  user-controlled work must enforce (`asyncio.wait_for`,
  `asyncio.Semaphore`).
- **`asyncio.gather(..., return_exceptions=True)` swallows
  exceptions** into the result list. Code that doesn't check
  `isinstance(r, Exception)` treats exceptions as successes —
  auth checks gathered as "all-or-nothing" silently degrade to
  "any-succeeds" with sloppy handling.
- **`ThreadPoolExecutor.submit(lambda: f(url))` over a loop**
  closes over `url` with late binding (§ 6.1) — all submissions
  fetch the FINAL URL. Fix: `submit(f, url)` or
  `submit(lambda u=url: f(u))`.
- **Race condition catalog.** TOCTOU on filesystem (§ 8.4),
  lost-update on counter (fix with `threading.Lock`), iterating
  over dict/list mutated concurrently (snapshot via
  `list(d.items())`), `asyncio` task scheduled between auth
  check and resource use (async-form TOCTOU). Cross-link
  `race_conditions_concurrency_expertise.md`.
- **PEP 703 free-threaded Python (3.13t+).** Removes the GIL.
  Invalidates atomicity assumptions in C extensions written
  pre-2024 (silent wrong answers, crashes, exploitable memory
  corruption) and pure-Python code that relied on incidental
  GIL serialization. ~5-6% single-thread overhead per PEP 703
  benchmarks. Treat as new concurrency surface needing full
  audit even if "thread-safe under the GIL" before.

---

## 14. PyPI supply chain

- **`pip install <package>` runs `setup.py`** (pre-PEP-517 build
  systems). Package-controlled arbitrary Python code runs at
  install time with the installer's privileges. Dominant primitive
  in PyPI supply-chain attacks: typosquatting, dependency
  confusion, maintainer-account hijack. `0wned`
  (github.com/mschwager/0wned) demonstrates explicitly.
- **PEP 517 + wheels are safer.** `pip install --only-binary=:all:`
  installs from pre-built wheels with no package-controlled
  install-time execution. Defense-in-depth: pin to wheels,
  `pip install --require-hashes`, `uv` or `pip-tools` lockfiles,
  Sigstore verification when available.
- **PyPI typosquatting corpus** (JFrog / Snyk / Phylum /
  ReversingLabs / Checkmarx / Socket) catalogs thousands of
  malicious packages per year. Pattern: name mimics popular
  package (`reqests` vs `requests`, `crytography` vs
  `cryptography`); `setup.py` exfiltrates env vars / SSH keys /
  AWS creds; occasional post-install backdoor. Defense: lockfiles,
  exact-name pinning, `--only-binary` for sensitive environments.
- **Dependency confusion via `--extra-index-url`.** Internal
  package names not registered on public PyPI are vulnerable —
  attacker registers the name publicly; developer's install
  resolves to malicious public version. Defense: stub-register
  internal names on public PyPI, use `--index-url` (private only,
  no fallback), org-specific name prefixes. Cross-link
  `cicd_supply_chain_expertise.md` § dependency confusion.
- **`pip install --break-system-packages` (PEP 668)** overrides
  the distribution's `EXTERNALLY-MANAGED` marker. Scripts /
  Dockerfiles using it are overriding a safety boundary; review
  for intent.
- **`uv` + lockfiles.** Astral's `uv` is the modern installer /
  resolver with native lockfile support (`uv.lock` pins exact
  versions + hashes). `tool.uv.exclude-newer = "1 week"` honors a
  cooldown — the org-wide 7-day-minimum policy in
  `~/.claude/CLAUDE.md` guards against typosquats the registry
  has not yet caught.
- **PEP 458 — TUF-signed PyPI metadata.** Cross-link
  `cicd_supply_chain_expertise.md` § signing.

---

## 15. Detection patterns (Semgrep)

The following are the highest-value Semgrep patterns for the
Python footguns covered here. Cross-link
the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for authoring discipline.

### 15.1 `pickle.loads(USER)`

```yaml
- pattern: pickle.loads($X)
- pattern-not: pickle.loads("...")
```

Plus taint mode: source = HTTP request body / file content from
user-controlled paths; sink = `pickle.loads` first arg.

### 15.2 `eval(USER)` / `exec(USER)`

```yaml
- pattern-either:
    - pattern: eval($X)
    - pattern: exec($X)
- pattern-not: eval("...")
- pattern-not: exec("...")
```

Combined with taint to user input.

### 15.3 `subprocess.run(..., shell=True)` with user input

```yaml
- pattern-either:
    - pattern: subprocess.run($X, ..., shell=True, ...)
    - pattern: subprocess.Popen($X, ..., shell=True, ...)
    - pattern: subprocess.call($X, ..., shell=True, ...)
    - pattern: os.system($X)
    - pattern: os.popen($X)
- pattern-not: subprocess.run("...", ..., shell=True, ...)
```

### 15.4 `yaml.load` without SafeLoader

```yaml
- pattern-either:
    - pattern: yaml.load($X)
    - pattern: yaml.load($X, Loader=yaml.Loader)
    - pattern: yaml.load($X, Loader=yaml.UnsafeLoader)
    - pattern: yaml.load($X, Loader=yaml.FullLoader)
    - pattern: yaml.unsafe_load($X)
```

### 15.5 `requests.get(verify=False)` and analogs

```yaml
- pattern-either:
    - pattern: requests.$METHOD(..., verify=False, ...)
    - pattern: requests.Session(...).$METHOD(..., verify=False, ...)
    - pattern: httpx.$METHOD(..., verify=False, ...)
    - pattern: urllib3.disable_warnings(...)
```

### 15.6 `mark_safe(USER)` Django XSS

```yaml
- pattern: mark_safe($X)
- pattern-not: mark_safe("...")
```

Plus the `|safe` filter in Django templates (separate template-
language rule).

### 15.7 `render_template_string(USER)` Flask SSTI

```yaml
- pattern: flask.render_template_string($X)
- pattern-not: flask.render_template_string("...")
```

### 15.8 `Model.objects.raw(USER)` / `extra(where=USER)`

```yaml
- pattern-either:
    - pattern: $MODEL.objects.raw($X)
    - pattern: $MODEL.objects.extra(where=$X)
    - pattern: $MODEL.objects.extra(...)
```

### 15.9 `os.path.join(BASE, USER)` traversal-prone

This one is hard to detect cleanly without taint mode — the
mere call site is not unsafe, but the data flow into the second
arg from user-controlled input is. Use Semgrep taint mode with
source = HTTP request params; sink = `os.path.join` second arg
used in subsequent `open` / `os.stat` / `shutil.copy`.

### 15.10 Mutable default arguments

`ruff` rule B006 handles this; Semgrep equivalent:

```yaml
- pattern-either:
    - pattern: def $F(..., $A=[], ...): ...
    - pattern: def $F(..., $A={}, ...): ...
    - pattern: def $F(..., $A=set(), ...): ...
```

### 15.11 `tarfile.extractall` / `zipfile.ZipFile.extractall` without filter

```yaml
- pattern-either:
    - pattern: $T.extractall()
    - pattern: $T.extractall($P)
- pattern-not: $T.extractall(..., filter="data")
- pattern-not: $T.extractall(..., filter=...)
```

Pre-3.14 the tarfile default is equivalent to `fully_trusted`;
3.14+ defaults to `data`. Explicit `filter=` makes the intent
legible.

### 15.12 Bandit (Python security linter) coverage

Bandit ships built-in checks covering most of the above:
B301 (pickle), B102 (exec_used), B307 (eval), B602
(subprocess_popen_with_shell_equals_true), B608 (hardcoded SQL
in string format), B501 (request_with_no_cert_validation), B506
(yaml_load), B703 (django_mark_safe), B701
(jinja2_autoescape_false), B614 (pytorch_load). Configure via
`.bandit` / `pyproject.toml`.

### 15.13 Ruff / pylint security rules

`ruff` ships a growing security ruleset (`S` prefix, derived
from Bandit). Faster than Bandit on large codebases. Configure
in `pyproject.toml`:

```toml
[tool.ruff.lint]
select = ["S"]
```

`pylint` ships its own checks; less comprehensive than Bandit
for security-specific patterns but useful in combination.

---

## 16. Defensive patterns + code review checklist

### 16.1 Grep targets (first-pass audit)

1. `pickle.loads` / `pickle.load` / `dill.loads` /
   `cloudpickle.loads` / `joblib.load` / `torch.load` —
   deserialization RCE (§ 3)
2. `eval(` / `exec(` / `compile(` / `__import__` —
   dynamic-code RCE (§ 2)
3. `subprocess.*shell=True` / `os.system(` / `os.popen(` —
   shell injection (§ 7)
4. `yaml.load(` (without `Loader=` or with unsafe) /
   `yaml.unsafe_load(` — YAML RCE (§ 12)
5. `mark_safe(` / `|safe ` in templates /
   `render_template_string(` — XSS / SSTI (§ 11)
6. `Model.objects.raw(` / `.extra(` / `cursor.execute(...%` /
   `cursor.execute(f"` — SQLi (§ 10)
7. `verify=False` / `disable_warnings(` /
   `ssl.SSLContext(ssl.PROTOCOL_TLSv1` — TLS broken (§ 9)
8. `os.path.join(` / `Path(...) /` with user input — path
   traversal (§ 8)
9. `tarfile.extractall(` / `zipfile.ZipFile.extractall(` —
   Tar/Zip Slip (§ 8)
10. `tempfile.mktemp(` — TOCTOU race (§ 8.5)
11. `xml.etree` / `lxml` without `defusedxml` — XXE (§ 12)
12. `DEBUG = True` in non-development settings — Django info
    disclosure (§ 11)
13. `def f(.., x=[]):` / `x={}` / `x=set()` — mutable defaults (§ 5)
14. `[lambda` / `[lambda ... for` — late-binding closures (§ 6)
15. `setup.py` side effects in org-owned packages —
    supply-chain hygiene (§ 14)

### 16.2 Tooling

- **Bandit** in CI; treat `B301` / `B307` / `B602` / `B506` /
  `B703` / `B701` as blocking failures.
- **Ruff** `select = ["S"]` in `pyproject.toml`; S301/S307/
  S506/S605/S608 cover the priority checks.
- **Semgrep** custom ruleset (cross-link
  the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview)).
- **CodeQL** GitHub Code Scanning Python rules.
- **`pip-audit`** / **`safety`** for known-CVE scanning of
  installed versions.

### 16.3 Pin, lock, boundary, async hygiene

- Lockfiles (`uv.lock` or `pip-tools`) with `--require-hashes`.
- `--only-binary=:all:` to avoid `setup.py` install-time exec.
- `tool.uv.exclude-newer` cooldown (org-wide 7-day per
  `~/.claude/CLAUDE.md`).
- Validate at the boundary: Pydantic / dataclasses / `attrs`
  for HTTP body; explicit type-check / cast for shell args,
  file paths, URLs. Allowlist for SQL identifiers (tables,
  sort columns).
- `defusedxml` for external XML. `safetensors` over pickle for
  ML model artifacts. Argv lists over `shell=True`.
- `asyncio.gather` with `return_exceptions=True` requires
  `isinstance(r, Exception)` check per result.
- `ThreadPoolExecutor.submit` over a loop variable: pass arg
  explicitly, not via closure (`submit(f, x)`, not
  `submit(lambda: f(x))`).
- Free-threaded Python 3.13t+: audit shared state as
  concurrency-unsafe by default.

### 16.4 Auth / session / TLS

- Django: `python manage.py check --deploy` and fix every
  warning.
- Flask: `SECRET_KEY` from secret manager;
  `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`.
- FastAPI: every route declares auth `Depends` or is
  explicitly public.
- HTTPS clients: never `verify=False` in prod;
  `ssl.create_default_context()` for custom contexts.

---

## 17. Variant analysis — under-explored areas

- **Type-checker gaps.** `Any` is a TOP type that silently flows
  through every constraint. `def handle(x: Any)` then
  `x.dangerous_op()` type-checks and executes arbitrary attribute
  access at runtime. Grep `: Any` in security-relevant signatures;
  replace with concrete types. Each `# type: ignore` deserves a
  justification.
- **Pydantic v1 vs v2 defaults.** v1 silently drops extra fields
  with loose coercion (`"1"` → `int`); v2 same unless
  `model_config = {'extra': 'forbid'}`. Set `extra='forbid'` on
  models that back ORM updates (overposting defense).
- **Async + cancellation.** `CancelledError` inside `__aexit__`
  is suppressed in some Python versions, propagated in others.
  PEP 654 `ExceptionGroup` (3.11+) changes exception shape.
  Resource-held-in-`async with` semantics may not match
  developer expectation.
- **`match` / `case` exhaustiveness.** Python 3.10+ pattern
  matching has no compile-time exhaustiveness check. Cases for
  `Admin` / `User` and no `case _` silently does nothing for
  `Guest` — if missing case is "deny by default," control is
  broken. Add explicit `case _: raise` to security-relevant
  match.
- **Free-threading (PEP 703, 3.13t+).** See § 13.7. Invalidates
  "GIL atomicity" assumptions in C extensions written before
  2024, pure-Python code that relied on incidental GIL
  serialization, and smaller ML libraries. Audit shared-state
  access as if writing concurrent C.
- **`inspect` module.** `inspect.getsource`, `getmembers`,
  `getclosurevars`, `getmro` is a large introspection surface
  frequently exposed by debug/admin endpoints — information-
  disclosure surface when fed user-influenced input.
- **`ctypes` / `cffi`.** Python's FFI escape hatches.
  `ctypes.CDLL("libc.so").system(b"id")` is RCE. Code calling
  attacker-controlled function names via `ctypes` is RCE.
- **`pickle5`** is pickle's out-of-band buffer protocol;
  security identical to pickle.
- **Logging format-string injection.** `logger.info(user_msg)`
  where `user_msg` is controlled — `%(name)s` references resolve
  against the LogRecord; raises at best, leaks at worst in
  custom factories. Cross-link `code_review_expertise.md` §
  format-string heuristic.
- **`urllib.parse.urlparse` differential / SSRF.** Application
  trusts urlparse's result; the *fetcher* uses a different
  parser. `http://expected.com#@attacker.com/` — urlparse sees
  `expected.com`, fetcher sees `attacker.com`. Cross-link
  `ssrf_url_parsing_expertise.md`.
- **`__del__` resurrection / shutdown order.** Finalizer that
  creates a new reference to `self` resurrects the object.
  Shutdown ordering is unspecified — `os` may be `None` when
  `__del__` runs. Use context managers, not `__del__`, for
  resource lifecycles.
- **`decimal` for money.** `float` is IEEE 754, not exact;
  financial code that uses `float` is integrity-broken
  (rounding, accumulation errors). Use `decimal.Decimal`.

---

## 18. References

### Python documentation (primary sources)

- `pickle` module (security warning):
  https://docs.python.org/3/library/pickle.html
- `eval` / `exec`:
  https://docs.python.org/3/library/functions.html#eval
- `subprocess` (security considerations):
  https://docs.python.org/3/library/subprocess.html#security-considerations
- `tarfile` extraction filters (PEP 706):
  https://docs.python.org/3/library/tarfile.html#extraction-filters
- `xml` (XML security):
  https://docs.python.org/3/library/xml.html
- `tempfile` (mktemp deprecation):
  https://docs.python.org/3/library/tempfile.html
- `asyncio`: https://docs.python.org/3/library/asyncio.html
- `ssl.create_default_context`:
  https://docs.python.org/3/library/ssl.html#ssl.create_default_context
- Free-threading guide:
  https://docs.python.org/3/howto/free-threading-python.html
- DB-API 2.0 (PEP 249): https://peps.python.org/pep-0249/

### Python Enhancement Proposals

- PEP 458 — Secure PyPI downloads with signed repository
  metadata: https://peps.python.org/pep-0458/
- PEP 480 — Surviving a Compromise of PyPI (maximum security):
  https://peps.python.org/pep-0480/
- PEP 517 — A build-system independent format for source
  trees: https://peps.python.org/pep-0517/
- PEP 668 — Marking Python base environments as
  "externally managed": https://peps.python.org/pep-0668/
- PEP 703 — Making the Global Interpreter Lock Optional in
  CPython: https://peps.python.org/pep-0703/
- PEP 706 — Filter for tarfile.extractall:
  https://peps.python.org/pep-0706/
- PEP 779 — Criteria for supported status for free-threaded
  Python: https://peps.python.org/pep-0779/

### Vulnerability disclosures and writeups

- CVE-2007-4559 (tarfile directory traversal):
  https://nvd.nist.gov/vuln/detail/CVE-2007-4559
- CVE-2007-4559 fix discussion (Python core):
  https://discuss.python.org/t/policies-for-tarfile-extractall-a-k-a-fixing-cve-2007-4559/23149
- CVE-2022-26488 (Python Windows installer EoP, Steve Dower
  coordination): https://bugs.python.org/issue46948
- ReversingLabs, "Malicious ML models discovered on Hugging
  Face platform" (nullifAI): https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face
- JFrog, "PyTorch Users at Risk: Unveiling 3 Zero-Day PickleScan
  Vulnerabilities":
  https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/
- HiddenLayer, "Silent Sabotage: Hijacking Safetensors
  Conversion on Hugging Face":
  https://www.hiddenlayer.com/research/silent-sabotage
- ArXiv 2025, "The Art of Hide and Seek: Making Pickle-Based
  Model Supply Chain Poisoning Stealthy Again":
  https://arxiv.org/html/2508.19774
- "Hacking with Pickle: Python Deserialization Attacks
  Explained": https://dev.to/leapcell/hacking-with-pickle-python-deserialization-attacks-explained-2gkl

### Researcher writing

- Łukasz Langa, personal site:
  https://lukasz.langa.pl/
- Brett Cannon, Microsoft Python blog:
  https://devblogs.microsoft.com/python/author/brettcannon78/
- Steve Dower, personal site:
  https://stevedower.id.au/
- Pradyun Gedam, "Thoughts on the Python packaging ecosystem":
  https://pradyunsg.me/blog/2023/01/21/thoughts-on-python-packaging/
- Hynek Schlawack, "import attrs":
  https://hynek.me/articles/import-attrs/
- Alyssa Coghlan, Python Notes:
  https://python-notes.curiousefficiency.org/en/latest/
- Glyph Lefkowitz on the Python Software Foundation:
  https://pyfound.blogspot.com/2017/08/the-ethical-maintainer-community.html
- Moshe Zadka, Real Python author profile:
  https://realpython.com/team/mzadka/
- Sebastián Ramírez, Real Python interview:
  https://realpython.com/interview-sebastian-ramirez/

### Tooling

- Bandit (PyCQA): https://bandit.readthedocs.io/
- Bandit GitHub: https://github.com/PyCQA/bandit
- Ruff security rules:
  https://docs.astral.sh/ruff/rules/#flake8-bandit-s
- Trail of Bits, `fickling` pickle decompiler/analyzer:
  https://github.com/trailofbits/fickling
- Trail of Bits, `abi3audit`:
  https://github.com/trailofbits/abi3audit
- Trail of Bits modern-python skill plugin:
  https://github.com/trailofbits/skills/tree/main/plugins/modern-python
- `defusedxml` (tiran):
  https://github.com/tiran/defusedxml
- `safetensors` (Hugging Face):
  https://github.com/huggingface/safetensors
- `pip-audit`: https://github.com/pypa/pip-audit
- `uv` (Astral): https://github.com/astral-sh/uv
- `pip` Secure Installs:
  https://pip.pypa.io/en/stable/topics/secure-installs/

### Standards and references

- MITRE CWE-502 (Deserialization),
  CWE-22 (Path Traversal), CWE-78 (OS Command Injection),
  CWE-79 (XSS), CWE-89 (SQL Injection), CWE-94 (Code
  Injection), CWE-611 (XXE), CWE-918 (SSRF), CWE-362 (Race
  Condition), CWE-330 (Insufficient Randomness),
  CWE-134 (Format String).
- OWASP Python Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html
- OWASP Django Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- OWASP Deserialization Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- PyPI Advisory Database:
  https://github.com/pypa/advisory-database

### Books

- Zadka, M., "DevOps in Python: Infrastructure as Python,"
  Apress, 2nd ed., 2022.
- Zadka, M. and others, "Expert Twisted," Apress, 2019.

### Institutional security research

- Trail of Bits, PyPI security audit (2023):
  https://blog.pypi.org/posts/2023-11-14-1-pypi-completes-first-security-audit/
- Trail of Bits audits index:
  https://blog.trailofbits.com/categories/audits/
- ReversingLabs ML supply-chain research index:
  https://www.reversinglabs.com/blog
- Snyk Python vulnerability database:
  https://security.snyk.io/vuln/pip
- Snyk advisor: https://snyk.io/advisor/python/

### CodeQL queries (security-relevant Python)

- Loop variable capture:
  https://codeql.github.com/codeql-query-help/python/py-loop-variable-capture/
- Insecure deserialization:
  https://codeql.github.com/codeql-query-help/python/py-unsafe-deserialization/
- Jinja2 templating with autoescape=False:
  https://codeql.github.com/codeql-query-help/python/py-jinja2-autoescape-false/

---

## Coda — Python's specific contribution to the behavioral-footgun class

The Python doc's specific contribution is the emphasis on the
**dynamic-by-default** axis: more than any other language in the
corpus, Python's runtime gives the attacker primitives that are not
visible at the function-name or call-site level. `getattr(x,
user_attr)` is a typed-looking call that reaches arbitrary state;
`pickle.loads(user_bytes)` is a documented serialization API that is
unconditional RCE; `render_template_string(user_template)` is a
templating convenience that escapes the Jinja2 sandbox via
class-MRO walking. The audit burden is correspondingly higher and
the tooling discipline (bandit, ruff, semgrep, codeQL) is
correspondingly more important to enforce.
