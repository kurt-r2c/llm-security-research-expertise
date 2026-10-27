---
title: AI Orchestration and Harnessing for Software Engineering and Security Research
last_updated: 2026-05-20
status: v1 (opened 2026-05-20) — design-and-operation framing for agent systems applied to programming-language, software-architecture, and static-analysis domains. Complements the threat-surface docs (`ai_assisted_coding_tool_security_expertise.md`, `ai_pr_review_platform_expertise.md`) which look at these systems from the outside; this doc looks at how to build and run them.
cross_links:
  - ai_assisted_coding_tool_security_expertise.md
  - ai_pr_review_platform_expertise.md
  - ai_pr_review_iac_security_expertise.md
  - ai_red_team_operator_playbook_expertise.md
  - ai_incident_response_playbook_expertise.md
  - llm_agent_security_expertise.md
  - adversarial_ml_model_security_expertise.md
  - agentic_web_capabilities_expertise.md
  - bug_hunting_first_principles_expertise.md
  - vulnerability_research_methodology_expertise.md
  - code_review_expertise.md
  - detection_engineering_expertise.md
  - race_conditions_concurrency_expertise.md
  - reverse_engineering_binary_analysis_expertise.md
---

# AI Orchestration and Harnessing for Software Engineering and Security Research

## 1. What "AI orchestration and harnessing" means in 2026

**Orchestration** is the coordination layer that decides which LLM call, which sub-agent, which tool, in what order, with what context, to achieve a goal. **Harnessing** is the runtime substrate around the agent: tool allowlists, permission gating, audit logging, sandbox boundaries, output validation, cost and latency budgets. Orchestration is the choreography; harnessing is the stage and the rigging. Distinct from the LLM itself (the model), the application (the user-facing product wrapping the agent), and the data layer (the codebase, ticket system, log store the agent reads and writes). In 2026 the orchestration-plus-harness combination IS the surface that determines whether an AI deployment is useful, safe, and economical. The model gets the headlines; the harness pays the bills.

## 2. Why this matters for software engineering and security research

Two reasons, with a focused third.

**Software engineering.** Between 2022 and 2026 the shape of "AI in the IDE" mutated three times. Copilot 2022 was type-ahead autocomplete: the model produces the next token, the human accepts or rejects. Cursor 2023 was ask-the-model-a-question: the human poses a question over a context window, the model answers, the human edits. Claude Code, Aider, Devin, GitHub Copilot Workspace, Replit Agent — 2024 through 2026 — are delegate-a-multi-step-task: the human states an objective, the agent reads, plans, edits, runs commands, and reports back. The third shape is the one that breaks without a harness. Without orchestration discipline an agent loses context after fifteen tool calls, calls the wrong tool with the right arguments, races itself on parallel writes, hallucinates a file path the codebase doesn't have, and burns compute trying to recover. With it, the agent ships PRs.

**Security research.** The same orchestration substrate underpins AI-PR-review (CodeRabbit, Greptile, Cursor BugBot, Semgrep Assistant), AI-fuzzing (OSS-Fuzz Gen, Fuzz4All), AI red-teaming (PyRIT, garak, promptmap), and AI SOC analysts (Dropzone, Prophet, Radiant, Charlotte). Whether AI-assisted security research produces durable findings or hallucinated noise is a harness question, not a model question. Two researchers running the same model against the same codebase will get different outcomes because their harnesses differ — one validates tool output against a schema, the other treats LLM prose as ground truth.

**Kurt's focus**: programming languages, software architecture, static analysis. These are the three sub-domains where AI orchestration meets security research depth, and where the harness has the most leverage. Sections 7 through 9 cover them in order.

## 3. Orchestration frameworks in 2026

Per-framework subsection covering maintainer, license, primary abstraction, strengths, weaknesses, and when to reach for it. Framework version numbers move; do not anchor strategy on a version pin without confirming current state. Where this section makes specific feature claims that have not been re-verified for this writeup, the claim is marked `[unverified specific advisory]`.

### 3.1 LangGraph (LangChain Inc.)

Graph-based agent construction. Primary abstraction: nodes (functions or LLM calls) connected by edges, with a typed shared state object. Strength: explicit state-machine semantics, which makes plan-execute and human-in-the-loop flows reviewable. Edges can be conditional and the framework supports persistence so an interrupted run can resume. Weakness: the LangChain ecosystem has gone through multiple incompatible reshapings (`langchain` core split, `langchain-community`, the v0.1 / v0.2 / v0.3 churn) and migration cost is non-trivial. Reach for it when your agent has clearly distinct stages and you want to be able to draw a diagram of the flow.

### 3.2 AutoGen (Microsoft Research)

Conversational multi-agent. Primary abstraction: an `Agent` with a system prompt and tool set, composed into a `GroupChat` with turn-taking rules. The original AutoGen (v0.2) was research-grade and saw broad adoption for academic experimentation. AutoGen v0.4 (rewritten on an actor-based async runtime, 2024-2025) was the official Microsoft track; a community fork named **AG2** continued the v0.2 lineage when v0.4's API broke compatibility. Strength: flexible multi-agent composition and a culture of publishing patterns. Weakness: production-readiness gap — the framework is research-shaped and the failure modes of multi-agent chat (round-robin loops, agents talking past each other) are not always visible from the API. `[unverified specific advisory]` on current state of v0.4 production-readiness; check upstream.

### 3.3 CrewAI

Role-based multi-agent, developed by CrewAI Inc. and open-source contributors. Primary abstraction: `Crew` containing `Agent`s, each with a `role`, `goal`, and `backstory`, executing `Task`s. Strength: opinionated and fast to onboard — the role/goal/task vocabulary maps cleanly to how non-engineers describe what they want. Weakness: the opinion may not fit your problem. If your task isn't naturally decomposed into roles, CrewAI's abstractions add friction without paying for themselves.

### 3.4 OpenAI Swarm and OpenAI Agents SDK

Swarm was published as an educational reference implementation of the OpenAI Cookbook's Orchestrating Agents patterns — minimalist multi-agent with handoffs. OpenAI's later first-party agent SDK (Agents SDK) supersedes Swarm for production use. Strength: simple enough to read in one sitting. Weakness: Swarm is explicitly marked educational by OpenAI; treating it as production substrate ignores OpenAI's own framing. Reach for Swarm when you want to understand the pattern; reach for the Agents SDK when you want to ship.

### 3.5 Microsoft Magentic-One

Microsoft Research's orchestrator that supervises specialist agents — typically FileSurfer, WebSurfer, Coder, and ComputerTerminal — coordinated by an Orchestrator agent that maintains a task ledger and a plan. Strength: empirical results on agent benchmarks have been strong relative to single-agent baselines `[unverified specific advisory]` on current benchmark deltas. Weakness: research-grade, with the operational shape of an experiment harness rather than a production framework. Useful as a reference architecture even if you do not deploy Magentic-One itself.

### 3.6 Google ADK (Agent Development Kit)

Google's 2025 entrant (announced at Google Cloud Next, April 2025), optimized for Gemini and Vertex AI. Primary abstraction is agent classes with declarative tool registration. Strength: tight integration with Google Cloud (Vertex Model Garden, Cloud Functions, BigQuery as a context store). Weakness: the integration that is a strength on GCP is a lock-in cost off it. Reach for it when your stack is already on Vertex.

### 3.7 Claude Agent SDK (Anthropic, 2025)

Anthropic's first-party agent-building SDK. Primary abstraction is an agent process with declared tool definitions, optional subagents, and lifecycle hooks (`PreToolUse`, `PostToolUse`, `Stop`, `SubagentStop`). The hooks are the load-bearing piece for harness design — they are where you implement the permission-gating, audit-logging, and output-validation layers from section 5 without modifying the model loop. Cross-link `[[reference-llm-agent-security]]` §7 for the broader framing of agent-runtime security primitives that the SDK's hook model instantiates, and `[[reference-ai-assisted-coding-tool-security]]` §13-§14 for a concrete worked example of `~/.claude/settings.json` allow/ask/deny patterns and an MCP allowlist built on top of the SDK.

### 3.8 Inspect AI (UK AI Security Institute)

Evaluation-focused orchestrator. Primary abstraction: a `Task` (dataset + scorer) executed by a `Solver` (model + tools + control logic). Strength: built for adversarial evaluation, so the substrate supports the auditor/target/judge pattern from section 4 natively. Weakness: not production-shaped — Inspect AI is an evaluation harness, not an application framework. Reach for it when you are evaluating an agent's capabilities or vulnerabilities; reach for something else to deploy.

### 3.9 Honest 2026 framing

Framework choice is overrated relative to harness discipline. Most successful production agent deployments use a thin orchestration layer plus heavy harness work. The choice of LangGraph versus AutoGen versus Claude Agent SDK matters less than the answers to: what is the tool allowlist, what does the audit log capture, what is the cost cap, what schema validates output. A team that has not thought through the harness will not be saved by picking LangGraph; a team that has will not be sunk by picking CrewAI. Pick the framework whose mental model matches yours and spend the saved cycles on the harness.

## 4. Agent architectures — patterns, not frameworks

Architectures are the patterns; frameworks implement one or more. The interesting design choices live here, not in framework selection.

### 4.1 Single-agent plus tool-loop (ReAct, function-calling)

One agent, a goal, an action space (the tools), and an observation loop. The agent reasons about the next action, executes it via tool call, observes the result, and iterates until the goal is met or the budget is exhausted. The simplest production shape and the one most worth defaulting to. The Yao et al. 2022 ReAct paper named the pattern; nearly every modern agent reimplements some variant. Most "multi-agent" systems benefit from being collapsed back to this shape unless the multi-agent decomposition is paying for itself.

### 4.2 Planner plus worker

One LLM produces a plan (an ordered list of subtasks); separate LLMs or tools execute. HuggingGPT (Shen et al. 2023) and ChatDev-style systems exemplify the shape. Strength: explicit decomposition. The plan is a readable artifact, easier to audit than an opaque ReAct trace. Weakness: planner-worker handoff is a context-loss surface — the planner sees the goal, the worker sees the subtask, neither sees the whole. Mitigations include passing relevant goal context with each subtask and a final reconciliation step.

### 4.3 Hierarchical multi-agent

An orchestrator coordinates specialist agents, each with a narrower tool set or domain. Magentic-One's FileSurfer / WebSurfer / Coder split is the canonical reference architecture. The Claude Agent SDK's subagent pattern is the same idea exposed as an SDK primitive — the parent agent dispatches a subagent with a fresh context window and a tool subset. Useful when the task has obviously distinct sub-domains; less useful when the decomposition is forced.

### 4.4 Debate / dialectical

Multiple agents argue, a coordinator extracts consensus. Du et al. 2023's Multi-Agent Debate paper introduced this as a correctness-improvement technique for reasoning tasks. Useful when one model overconfidently hallucinates and a structurally-different second pass catches it. Expensive — each round multiplies token cost — and not always better than a single agent with a critique-revise loop. Reach for it on correctness-critical reasoning where the cost is justified.

### 4.5 Actor / consumer (event-driven)

Agents emit events; downstream agents subscribe. AutoGen v0.4 made this the framework's primary mode. Strength: asynchronous, scalable, observable through the event log. Production-shaped — the pattern matches how mature backend systems look. Weakness: complexity overhead; most agent problems do not need it.

### 4.6 CaMeL split (privileged-LLM + quarantined-LLM)

Debenedetti et al. arXiv:2503.18813 (Google DeepMind). Two LLMs: a privileged LLM that holds the user's intent and capability set, and a quarantined LLM that processes untrusted content (web pages, emails, repo files) but has no tool access. The privileged LLM treats the quarantined LLM's output as data, not as instructions. The structural defense against prompt injection: the surface that reads attacker-controlled content cannot act, and the surface that can act does not read attacker-controlled content directly. Cross-link `[[reference-agentic-web-capabilities]]` for the capability-attenuation framing this implements.

### 4.7 Auditor / target / judge

Three-role evaluation separation. The auditor probes the target through synthetic interactions; a separate judge model scores the resulting transcript. Anthropic's Petri productized this pattern. Cross-link `[[reference-steelman-doctrine]]` §9.1 for the doctrinal connection — Champion / Foil / Adjudicator is the same role triad applied to reasoning, and the structural reason it works is the same: separation of who-makes-the-claim from who-attacks-it from who-decides.

### 4.8 Honest framing on composition

Architectures are not exclusive. Production deployments compose them: a hierarchical multi-agent system whose orchestrator runs a planner-worker plan, whose workers each run a ReAct loop, whose tool outputs flow through a CaMeL-split quarantined summarizer, and whose final output is scored by an auditor-target-judge harness. The question is not which architecture is best; the question is which composition fits the task and is operable by the team that has to run it on a Friday at 4 PM when something breaks.

## 5. Harness design — the operational lever

Eight harness concerns determine whether the orchestration substrate is production-grade. The order is roughly the order of leverage: spend the first hour on (a), not on (h).

### 5.1 Tool allowlist

Which tools the agent can call. The single highest-leverage harness control. Default-deny with an explicit allowlist plus per-tool argument validation. Cross-link `[[reference-ai-assisted-coding-tool-security]]` §5 for the catastrophic-shell-execution analysis that motivates default-deny — the difference between a useful coding agent and a self-exfiltrating one is whether `curl | sh` is on the allowlist.

A useful framing: list the tools the agent needs to ship the task, then list the tools that exist beyond that, then justify each tool's presence individually. Most agents end up with a third the surface they started with and ship better for it.

### 5.2 Permission gating

`PreToolUse` hooks that block, prompt, or transform a tool call before it executes. The Claude Agent SDK pattern; the equivalent in other frameworks is a middleware decorator on tool functions. The hook gets the tool name, arguments, and current state; it returns allow, block, or modify. The high-leverage use cases:

- **Block** a `Bash` call whose command matches `rm -rf` or that touches a path outside the project root.
- **Prompt** the user on a `Write` to `.env` or anything under `.aws/` or `.ssh/`.
- **Transform** a `Bash` call to add `--dry-run` first, prompting for the real run only after the dry run succeeds.

A small permission-gating layer catches an enormous number of agent mistakes before they become commits.

### 5.3 Sub-agent isolation

When the parent agent dispatches a sub-agent, what does the sub-agent inherit? Permissions, secrets, working directory, conversation history, file handles. Default-isolation is the correct stance: the sub-agent gets a fresh context, a narrower tool allowlist, and only the explicitly-passed inputs. Default-share is the wrong stance — it makes the sub-agent a privilege-amplification vector for any prompt-injection that lands on the sub-agent's input.

The trade-off: isolation costs context. A sub-agent that does not know what the parent has already learned will redo work. The mitigation is to pass forward a short summary or specific artifacts (file paths, decisions), not the whole conversation.

### 5.4 Audit logging

Every tool call, every argument, every result, signed and shipped to an immutable log. OpenTelemetry GenAI semantic conventions (`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.tool.name`, and the span hierarchy) are the substrate. Cross-link `[[reference-detection-engineering]]` §10 for the runtime-detection framing — the log is the detection surface, not just the audit trail. Without an audit log, you cannot answer "what did the agent do last night" and you cannot answer "did the agent leak this secret"; with one, you can.

Object-lock the storage (S3 Object Lock, equivalent) so the agent (or anything compromising the agent) cannot retroactively delete the log of its own bad behavior.

### 5.5 Cost and latency budgets

Per-task token cap, per-tool-call cap, total wall-clock cap. Hard caps, not soft. Without them, an agent that loses context can compound-compute itself into a thousand-dollar run by re-reading the same files and re-querying the same APIs. A Claude Code session that does in twenty minutes what should have taken five has burned 4x the budget on context-thrashing, and the fix is a budget that surfaces the thrash, not a smarter model.

### 5.6 Output validation

The model's output is untrusted text. Validate against a schema — Pydantic in Python, Zod in TypeScript, JSON Schema as a portable substrate. Refuse outputs that do not parse. The agent will retry; that is cheaper than acting on malformed output. The most common production agent bug is "the model returned almost-valid JSON and the consumer crashed" — the harness catches this before the consumer sees it.

### 5.7 Context management

Window-of-attention strategy. Section 6 covers this in detail; flagged here because it lives in the harness, not the agent. The harness decides what stays in context, what gets compacted, what gets handed to a sub-agent, what gets written to a side-channel file. Cross-link the `claude-api` skill for prompt-cache patterns that make context management economic.

### 5.8 Reliability patterns

Idempotency, retry with backoff, circuit-breaker, timeout. Section 12 covers this in detail. Flagged here because the harness is where these patterns live — the model is stateless and does not know what was retried. Production-grade reliability has nothing to do with LLM intelligence; it is distributed-systems hygiene applied to a stochastic component.

## 6. Context management deep-dive

Most agent failures happen here. The model is capable; the context it is fed is wrong.

### 6.1 Three context substrates

- **Working context (the prompt).** What the model sees this turn. Most expensive to expand — every token in the prompt is paid per turn (modulo cache hits).
- **Persistent context (memory, RAG).** What the agent can retrieve. Latency cost on each retrieval call plus the cost of whatever ends up in working context.
- **Side-channel context (files, state).** What the harness writes outside the model. Cheap to write, but the model has to be told the file exists and given a tool to read it.

### 6.2 Patterns

**Sliding window.** Drop the oldest turns when the budget is exceeded. Simple, broadly applicable, loses long-task coherence. The agent forgets the third tool call it made an hour ago and re-makes it.

**Summarize-and-compact.** When the budget is approached, call the LLM to summarize prior turns and replace them with the summary. Cheaper context, fidelity loss. The summary captures what the summarizer-model thinks mattered, which is not always what mattered.

**Subagent-fork.** Dispatch a sub-agent with its own context window and the relevant inputs. The parent agent stays focused on the meta-task while the sub-agent burns through the sub-task's context. The pattern Claude Code's `Agent` tool implements. Cost: doubles the per-task compute. Benefit: parent retains the long view.

**RAG against authoritative source.** Instead of stuffing context, retrieve. Works well when the authoritative source has good metadata and the queries are well-formed. Works poorly when the embedding-similarity surface is noisy or the index drifts behind the source.

**Side-channel-via-files.** Instead of putting state in the conversation, write it to a file the agent reads on the next turn. The pattern Claude Code's `TodoWrite` (now the `TaskCreate` / `TaskUpdate` tools) and similar plan-state mechanisms implement. Strength: state is durable across the agent's own context resets and visible to the operator. Weakness: the agent has to remember to read the file.

### 6.3 Honest framing

The right pattern depends on the task. Long-horizon refactors want subagent-fork plus side-channel-via-files: the parent holds the plan, each sub-agent owns one file, the plan-state file tracks progress. Short Q&A wants a sliding window. Multi-document synthesis wants RAG. There is no general answer; there is a per-task answer that an honest design surface produces.

## 7. Applied: programming-language domain

Kurt's first focus area. The agent's value-add in this domain IS the language model's syntactic and semantic understanding; the harness's job is to make that understanding deterministic where possible.

### 7.1 Language-aware code agents

Agents that understand syntax, types, and scoping. Tree-sitter integration gives the agent reliable parse trees; Language Server Protocol integration gives it cross-reference, go-to-definition, and rename-symbol. Agents that operate on token streams alone fail on type-aware refactors because they cannot reason about which `Foo.bar` is which `Foo`. The harness pattern is to expose tree-sitter and LSP as tools — `find_references(symbol)`, `rename_symbol(old, new)`, `get_type(expression)` — so the agent gets language-aware operations as primitives rather than reconstructing them from text.

### 7.2 AST manipulation agents

The agent generates a transformation; an AST tool applies it deterministically. Semgrep autofix, jscodeshift, Comby, libCST in Python, ast-grep, OpenRewrite for Java. Strength: deterministic and reviewable — the transformation language is human-readable and the change set is exact. Weakness: each transformation language has its own quirks (Semgrep metavariable scoping rules; jscodeshift API churn between versions) and the agent has to internalize them. The harness pattern: a tight feedback loop where the agent proposes a transformation, the tool applies it to a small corpus, the agent reads the diff, and iterates until the transformation matches intent. The model is the transformation-writer; the AST tool is the executor.

### 7.3 Polyglot agents

A single agent navigating a Java service, a Python script, a JavaScript frontend, and a Go sidecar in the same repository. The compounding-context problem: each language has its own conventions, type system, build system, and footguns. Cross-link `[[reference-language-footguns-class]]` for the per-language unsafe-primitive catalogue the agent should consult before touching unfamiliar code. The harness pattern: a per-language config (lint command, test command, build command, footgun doc reference) that the agent loads when it enters a directory.

### 7.4 Refactor-planning agents

Large-scale renames, API migrations, deprecation rollouts. The two-stage pattern dominates: a planner agent reads the codebase and produces a transformation plan (which files, which symbols, which order); worker agents (often parallel sub-agents) execute per-file changes. The planner is single-instance and high-context; the workers are fan-out and narrow-context. Cross-link `[[reference-vr-methodology]]` — variant analysis is the same machinery applied to vulnerability search rather than refactoring: planner finds variants, workers verify or fix them.

### 7.5 Language-footgun detection agents

Agent loads the per-language footgun doc, scans the codebase, flags candidate points for review. Higher precision than free-form analysis because the doc constrains the surface. The agent does not have to invent what to look for; it has to find specific primitives (`Marshal.load`, `eval`, `BinaryFormatter`, `unsafe`, `transmute`, `mem::forget`) and reason about their context. The harness pattern: footgun doc is the source of truth, agent's output is structured (file, line, primitive, severity, rationale), structured output is fed to the human reviewer.

### 7.6 Type-driven refactoring

Rust, TypeScript with `strict`, Scala — strong type signals. Python, JavaScript, Ruby — weak type signals. Agent performance on refactors correlates with language type-strength: in a strongly-typed language the compiler tells the agent when the refactor is incorrect; in a weakly-typed language nothing tells the agent until runtime, by which time the production deploy has happened. The harness pattern in weakly-typed languages: heavier test coverage gating, mandatory `mypy --strict` or equivalent before commit, gradual-typing migration as a precursor to agent-driven refactor work.

### 7.7 Honest framing

For language-aware work, the agent's value-add IS the language model's syntactic and semantic understanding. Pure-text agents underperform LSP-aware agents on refactor benchmarks `[unverified specific advisory]` on the exact margin; the qualitative claim that LSP integration improves refactor quality is well-supported, the quantitative percentage is not. Production-grade language-aware coding agents in 2026 ship with LSP integration as a default, not a feature; if the agent you are evaluating does not, that is a signal.

## 8. Applied: software-architecture domain

Kurt's second focus area. The agent is weaker here than in the programming-language domain, and the harness has to carry more weight.

### 8.1 Large-codebase navigation agents

A codebase past 100K lines exceeds any single-context window. The challenge is that the model cannot see it all. Three approaches:

- **Symbolic exploration.** ctags, LSP `workspace/symbol`, `find` + `grep`, Aider's repo-map. The agent navigates by name. Works well when the codebase has consistent naming and the agent knows what to look for.
- **Embedding-based retrieval.** Cursor's codebase context. Embedding similarity surfaces relevant files for a query. Works when the query and the relevant code share vocabulary; fails when the relevant code is the answer in a different vocabulary than the question.
- **Skeleton-plus-drill.** `tree` for the directory structure, selective `Read` for promising files. The agent builds a mental model from the skeleton, then drills. Cheap and surprisingly effective; the canonical pattern Claude Code uses for repo onboarding.

The harness pattern: expose all three as tools, let the agent pick. Do not force one strategy.

### 8.2 Architectural-pattern recognition

Agent classifies a module's pattern: MVC, hexagonal, event-sourced, actor model, pipeline, state machine, ports-and-adapters. Useful for review work (does this module match its claimed pattern?), refactor work (what pattern would fit better?), and onboarding (what is this codebase doing?). Cross-link `[[reference-code-review-expertise]]` for the review-side framing — pattern recognition feeds severity assessment because a violation of an MVC boundary in an MVC codebase is more severe than the same violation in a codebase that never claimed MVC.

### 8.3 Design-doc synthesis

Agent produces an architecture overview from source. Strength: catches the implementation that drifted from the documentation, or produces documentation where none existed. Weakness: hallucination risk on subtle invariants — the agent will state with confidence that "the cache is invalidated on every write" when in fact it is invalidated only on writes to non-tombstone keys. The harness pattern: the synthesis output is a draft for human review, not a final artifact, and the human is expected to verify load-bearing invariants against the source.

### 8.4 Refactor-plan agents (architecture-level)

Distinct from §7.4's per-file workers. The architecture-level planner decides whether to extract a module, introduce an interface, split a service, or merge two components. The output is usually a PR description plus a rollout plan, not the code itself — the code comes from the workers. The harness pattern: planner produces a written artifact (a markdown file), human reviews and edits, workers execute the approved plan.

### 8.5 Multi-repo navigation

Organization-wide changes spanning N repositories. The orchestration challenge: each repo has its own CI configuration, its own conventions, its own owners. The canonical pattern is a coordinator agent that holds the overall change plan, dispatching a sub-agent per repository; the per-repo sub-agent reads that repo's conventions and applies the change in a way that matches them. Sourcegraph's batch changes mimic this shape from the outside. The harness pattern: a per-repo config (which CI to expect, which conventions to follow, who to assign for review) plus a global plan-state file the coordinator updates.

### 8.6 Dependency-graph navigation

The agent navigates the import graph rather than the file tree: `cargo tree`, `npm ls`, `pip show`, `mvn dependency:tree`, `go mod graph`. Useful for security-research applications where the dependency graph IS the attack surface — a CVE in a transitive dependency requires understanding the import path from your code to the vulnerable function. The harness pattern: dependency-graph tools as first-class agent primitives, not as ad-hoc shell calls.

### 8.7 Honest failure modes for software-architecture agents

Software-architecture agents are weaker than programming-language agents and weaker than static-analysis agents. The architecture is in the engineer's head as much as in the code. The agent does not know why this module exists for business reasons not visible in the code; it does not know which deprecated path is still load-bearing for a specific customer; it does not know which "cleanup" would break an unwritten contract with a downstream team. The agent's outputs in this domain should be treated as drafts to be edited by someone who knows the codebase, not as decisions. Cross-link `appsec_program_building_expertise.md` for the stakeholder-context discipline that surfaces the invisible-in-code constraints before the agent works against them.

A frank summary: in 2026, agents are useful for software-architecture work when paired with a human architect who treats the agent's outputs as fast-but-fallible drafts. Agents are not useful for software-architecture work when run unsupervised against a load-bearing codebase. Treat any vendor claim to the contrary as marketing.

## 9. Applied: static-analysis domain

Kurt's third focus area and Kurt's home domain. This section is the load-bearing applied section because static-analysis outputs are mechanically verifiable in a way that programming-language and software-architecture outputs are not — the rule fires or it does not, the variant matches or it does not, the FP triage agrees with the maintainer's later disposition or it does not. Verifiability is what makes static-analysis the domain where AI orchestration produces durable security-research outcomes.

### 9.1 Semgrep rule authoring agents

The canonical security-research orchestration target. The agent receives a vulnerability description plus a corpus of vulnerable-and-not-vulnerable code, and produces a Semgrep rule plus test cases. This pattern is implemented as production infrastructure in the workflow-authoring substrate this doc generalizes from.

The shape of a Semgrep rule-authoring agent:

1. Read the vulnerability description, the corpus (vulnerable and non-vulnerable examples), and the rule-authoring handbook.
2. Generate a first-pass rule (`pattern`, `pattern-either`, `pattern-not`, `metavariable-pattern`, language metavariable conventions).
3. Run the rule against the corpus.
4. Read the diff between expected and actual matches.
5. Refine. Iterate to precision target.

The harness pattern: Semgrep is a tool the agent calls, the corpus is fixed, the precision/recall metric is the success criterion. The agent's value-add is rule-shape exploration; the determinism comes from Semgrep itself. This is what makes the pattern work — the model proposes, Semgrep disposes.

### 9.2 CodeQL agents

Same shape, different query language. The agent generates a CodeQL query; CodeQL executes it; the matches feed back. CodeQL's predicate-based query language is more expressive than Semgrep's pattern language and harder for an LLM to write correctly from scratch — the agent benefits more from few-shot examples in CodeQL than in Semgrep. The harness pattern: a corpus of correctly-written queries the agent draws idioms from, plus a tight execute-observe-refine loop.

### 9.3 False-positive triage agents

Take a tool's findings — Semgrep, CodeQL, Snyk, custom — classify each as true positive, false positive, or defer, and attach evidence. Semgrep's `/fp` PR-comment triage and Semgrep Assistant's autotriage flows implement this pattern. The agent's value-add is consistency and thoroughness, not novel bug discovery — a triage agent that classifies a thousand findings with 90% maintainer-agreement is more useful than a research agent that finds one new bug, because the triage agent moves the backlog. The harness pattern: structured output (TP / FP / Defer plus rationale plus evidence pointers), human review on a sampled subset, calibration against the maintainer's later disposition.

### 9.4 Rule-coverage and variant-analysis agents

Given a CVE or a known-vulnerable pattern, find every variant in the codebase. The agent reads the original vulnerability, generalizes the pattern, searches the codebase, and reports candidates. Cross-link `[[reference-vr-methodology]]` for the variant-analysis discipline this implements. The harness pattern: the agent's output is a candidate list, not a finding list — each candidate goes to a human for verification, because the agent will over-generalize and the candidate-to-finding ratio is the operator's KPI.

### 9.5 Custom-tool agents

For non-Semgrep, non-CodeQL setups — a custom AST visitor in Python, a Coccinelle script, a Tree-sitter query. The agent generates the tool configuration and verifies output against a test corpus. The harness pattern is the same as §9.1: agent writes, tool executes, agent observes, agent refines.

### 9.6 Multi-tool orchestration

The same finding through Semgrep, CodeQL, Sourcegraph, and a custom tool, with a coordinator agent reconciling outputs. The premise is that each tool has different false-positive shapes and the intersection is higher-confidence than any single tool. The harness pattern: each tool runs independently, the coordinator agent receives the union of findings annotated with which tools fired, and the coordinator classifies. Lowers false-positive rate at the cost of compute.

### 9.7 Static-analysis with LLM-augmented decompilation

Agents that run static analysis on decompiled binaries. Ghidra plus an LLM decompiler-summary plus a Semgrep-like pattern matcher operating on the LLM's pseudo-source output. Cross-link `[[reference-reverse-engineering-binary-analysis]]` §11 for the LLM-augmented RE framing. The harness pattern: the LLM's decompiler output is a draft, the pattern matcher operates on it, candidates feed to a human who verifies against the original binary. The honest framing: this is useful for triage of large binary corpora, not for production-grade vulnerability finding without human verification.

### 9.8 Honest framing for security-research static-analysis agents

Static-analysis agents are most useful when their output is mechanically verifiable. The rule fires or it does not — that is verifiable. The variant matches the original pattern or it does not — that is verifiable. The triage classification agrees with the maintainer's later disposition or it does not — that is verifiable. Verifiability is what separates this domain from the software-architecture domain: a rule the agent writes can be tested against ground truth, a refactor plan the agent writes can only be evaluated by someone who knows the codebase.

The corollary: agents that produce unverifiable claims about static-analysis outputs — "this code is secure," "this codebase has no SQL injection," "I have audited this module" — are worse than useless. They are confidence-inflating. The harness should refuse to surface unverifiable claims from a static-analysis agent.

## 10. Agent benchmarks for software engineering and security research

Benchmarks calibrate expectations. They do not predict production utility. Use them to filter out clearly-broken agents, not to pick between competent ones.

### 10.1 SWE-bench and SWE-bench-verified

GitHub-issue-to-PR fix benchmark from Princeton. The canonical SE-agent benchmark. The verified subset is curated for solvability and is the more honest number. Honest framing: benchmark performance correlates poorly with production utility because real PRs require context (team conventions, deprecated paths, customer-specific constraints) that the benchmark does not capture. A 70% on SWE-bench-verified does not mean 70% of your team's PRs are agent-solvable; it means the agent is competent on the SWE-bench-verified distribution.

### 10.2 SWE-bench Multimodal

Extension to screenshots and videos for tasks where the issue includes a visual. Useful for frontend work where the bug report is a screenshot. Smaller corpus than SWE-bench.

### 10.3 MLE-bench

OpenAI's Kaggle-style ML engineering task benchmark. Tests whether an agent can do end-to-end ML pipeline construction. Of interest to security research only as a generalization signal for autonomy.

### 10.4 AgentBench

Multi-domain agent benchmark from Tsinghua. Covers operating-system tasks, database tasks, web shopping, and others. Useful as a breadth check.

### 10.5 AgentDojo

The prompt-injection-resistance benchmark used by the CaMeL paper. Measures whether an agent can complete tasks in the presence of injection attempts in tool output. The right benchmark for evaluating harness robustness, not raw capability.

### 10.6 Inspect AI evals

UK AI Security Institute's evaluation substrate. Useful for adversarial-ML evaluation and for security-research benchmarking where you want to write your own task. Inspect AI is the framework; the evals are user-supplied.

### 10.7 AIxCC

DARPA's AI Cyber Challenge. Cyber Reasoning Systems compete to find and fix vulnerabilities in code. The finals demonstration was the canonical at-scale showing of AI-augmented bug-hunting `[unverified specific advisory]` on current standings and specific team results since publication varies. Cross-link `[[reference-fuzzing-discipline]]` for the fuzzing-substrate framing — most AIxCC entries are fuzzer-plus-LLM hybrids, not pure LLM systems, and the lesson is that LLM agents compose well with deterministic tools and poorly with each other.

## 11. Cost and latency economics

The model gets the headlines; the harness pays the bills. Production economics for agent systems are dominated by two levers: prompt-cache hit rate and per-task budget discipline.

### 11.1 Per-task economics

A Claude Code session that takes 5 minutes and uses 50K tokens costs $X. The same task taking 50 minutes and 500K tokens because the harness loses context and re-reads files costs 10X. The cost ratio is not driven by model price — model price is fixed — it is driven by harness discipline. Harness improvements of 10X in cost-per-task are routine when teams switch from no-discipline to discipline; they are not a marketing claim, they are the difference between repeatedly reading the same `package.json` and reading it once.

### 11.2 Prompt-cache as load-bearing

Cache hit rates of 80%+ are achievable with disciplined system-prompt and context-block structuring: static prefix (system prompt, tool definitions, persistent context) ahead of dynamic suffix (current turn). Cache hits cost a fraction of a non-hit `[unverified specific advisory]` on exact ratio since pricing changes; the order of magnitude has been roughly 10% for Anthropic's Claude API and similar for other providers. Without caching, agent economics are marginal; with it, they are reasonable. Cross-link the `claude-api` skill for the specific caching patterns (cache_control breakpoints, ephemeral vs persistent caches, cache-aware system prompt structure).

### 11.3 Latency budget

Interactive use targets P50 under 3 minutes. Beyond 3 minutes, the operator context-switches; beyond 30 minutes, the operator disengages and the agent loses its supervisor. Delegated use can absorb longer wall-clock (overnight refactor runs) but degrades when the operator cannot follow up the next morning — the agent's report has to stand on its own. The harness pattern: hard latency caps with checkpointed progress so a wall-clock-out is a paused state, not a lost state.

### 11.4 Parallel-task economics

Dispatching 5 sub-agents in parallel costs ~5x compute but completes in ~1x wall-clock. The right trade-off when wall-clock matters (interactive runs, time-sensitive incident response). The wrong trade-off when wall-clock does not matter (overnight batch). The harness pattern: parallelism is a knob, not a default.

### 11.5 Failure-mode economics

Agents that retry on transient failure cost more per attempt but ship more reliably overall. The math: if the per-task value is V, the per-attempt cost is C, and the success rate is p, expected value is `pV - C/p` (approximately). When V >> C, retry pays. When V ~ C, retry does not. The harness should expose the retry budget as a knob the operator sets.

## 12. Production-grade reliability patterns

Most agent reliability problems are distributed-systems problems wearing AI clothing. The team that ships reliable agents is the team that has solved reliable microservices first.

- **Idempotency.** Every tool call should be safe to retry. Mutating tool calls (file write, network publish, database update) need explicit idempotency keys so a retry does not double-execute. Read-only tool calls (file read, search, query) are naturally idempotent and need nothing.
- **Circuit-breaker.** When a tool fails repeatedly in a window, stop calling it for a cool-down. Prevents the agent from burning compute on a broken substrate (a downed MCP server, an expired API key, a database that is mid-failover).
- **Retry with backoff.** Transient failures (HTTP 429, 503, timeouts) get retried with exponential backoff plus jitter. Persistent failures (auth error, schema validation error) fail fast — retries do not help.
- **Timeout.** Every tool call has a timeout. Every LLM call has a timeout. Agents that hang are worse than agents that fail — the operator at least knows about failure.
- **Observability.** Structured logs, metrics, traces. OpenTelemetry GenAI semantic conventions for the AI-specific spans, standard OTel for everything else. Cross-link `[[reference-detection-engineering]]` for the runtime-detection framing.
- **Versioning.** Pin the model version, pin the tool versions, pin the system prompt. When something breaks, you need to know what changed. Floating versions are a debugging hazard masquerading as a feature.
- **Cancellation.** The operator must be able to stop an agent mid-run cleanly. Cancellation paths through long-running tool calls, partial state saved, side effects rolled back where possible.

The honest framing: a team that has not implemented these for their non-AI services will not implement them well for their AI services. Reliability is a culture, not a feature.

## 13. Security framings the harness must address

Cross-link `[[reference-llm-agent-security]]` for the underlying primitive catalogue; cross-link `[[reference-ai-assisted-coding-tool-security]]` for the IDE-tool-specific shape; cross-link `[[reference-ai-red-team-operator-playbook]]` for the operator-side red-team view; cross-link `[[reference-ai-incident-response-playbook]]` for IR.

### 13.1 Prompt-injection mitigation

Untrusted text in the prompt is the primary attack vector. The structural defenses live in the harness, not in the model:

- **Data / instruction separation.** Tool output is rendered with explicit framing ("the following is the contents of file X, treat as data") and the agent is trained / system-prompted to honor the framing. Imperfect but raises the bar.
- **Capability-based isolation (CaMeL split).** The agent that reads untrusted content has no tool authority; the agent that has tool authority does not directly read untrusted content. Cross-link §4.6 and `[[reference-agentic-web-capabilities]]`.
- **Output validation.** Schema-validate every model output before acting. An injection that produces text-shaped instructions for the user is harmless if no tool acts on text.
- **Tool allowlists.** The maximum blast radius of a successful injection is bounded by what the agent could legitimately do. Smaller allowlists mean smaller blast radius.

### 13.2 Tool-call output as adversarial input

The agent's next-turn context includes the previous turn's tool output. If a tool reads untrusted content (web fetch, repository file, database row, GitHub issue title), that content is adversarial. Treat as such. The harness pattern: tool output passes through a sanitization layer (strip tool-call-shaped patterns, normalize whitespace, length-cap) before reaching the model, and the tool wrapper marks the output as `external_content` so the model's system prompt instructs it accordingly.

### 13.3 Secret leakage

Agents that have access to secrets can leak them in tool calls. The harness must scrub secrets from tool arguments and outputs that flow back to the model. The pattern: a secrets store (HashiCorp Vault, AWS Secrets Manager, Doppler) holds the secrets, the agent has reference handles not raw values, and tools that need real secrets dereference at the last possible moment. When the model sees `${SECRET:db_password}` instead of the raw value, an injection that exfiltrates the model's context exfiltrates the reference, not the secret.

### 13.4 Credential isolation in CI agents

The Clinejection and Comment-and-Control class. Cross-link `[[reference-ai-assisted-coding-tool-security]]` §13-§14 for the worked example. The harness must minimize the credentials available at agent runtime: separate identities for "read code," "run tests," "publish artifacts," "post comments," with the agent operating under the weakest identity the task requires and elevating only at explicit gates. OIDC sub-claim restriction is the right substrate where available. Cross-link `[[reference-cloud-iam]]`.

### 13.5 Resource-limit attacks

An agent can be tricked into compounding compute — fork-bomb-style sub-agent dispatch, infinite tool loops, recursive plan expansion. The harness must hard-cap sub-agent depth, fan-out per parent, total tool calls per task, total tokens per task. Without these, a prompt injection can turn an agent into a denial-of-service against its own operator's budget.

### 13.6 Cross-customer leakage in shared-tenancy

For agent services that run multi-tenant (most SaaS AI-PR-review platforms, most AI SOC platforms), the harness must enforce tenant isolation at every layer — context, cache, tool authority, audit log. A prompt injection that leaks customer A's source into customer B's review comment is the canonical failure mode. Cross-link `[[reference-ai-pr-review-platform]]` for the comparative framing.

## 14. Honest failure modes

What the harness cannot solve.

### 14.1 Model competence is the floor

The harness can constrain but cannot improve model intelligence. If the model cannot reason about the task, no harness rescues it. Picking a smaller model for cost reasons and then trying to harness-engineer around its limitations is a common failure mode; the right move is to pick the right-sized model and harness-engineer for safety, not for capability rescue.

### 14.2 Tool quality is the ceiling

Agents are bottlenecked on tool quality. A buggy Semgrep rule produces buggy findings regardless of harness; a search tool that returns stale results gives the agent stale context. Invest in the tools the agent uses before investing in the agent itself.

### 14.3 Spec ambiguity

Agents fail at tasks where the human could not articulate the success criterion either. The agent will produce something; whether that something is correct is undefined without a spec. The most-fixable agent failure mode is "the spec was three sentences and ambiguous." Specs that are precise enough to verify against are specs the agent can pursue.

### 14.4 Multi-step coherence degradation

Most agents lose coherence after roughly 20 tool calls. The exact threshold varies by model and harness `[unverified specific advisory]` on per-model coherence horizons; the qualitative claim that long tool-call chains degrade is broadly observed. Long-horizon tasks need explicit decomposition: planner-worker, side-channel-via-files, sub-agent fork with summarized handoff. The harness that does not enforce decomposition is the harness that produces 50-tool-call traces ending in apology.

### 14.5 Closed-world assumption

Agents assume the world does not change during the task. CI race conditions (the agent reads HEAD, plans, pushes; HEAD has moved), concurrent commits (the agent edits a file another agent is also editing), expiring tokens (the agent's auth expires mid-run) all violate this. Cross-link `[[reference-race-conditions-concurrency]]`. The harness pattern: read-modify-write protocols with optimistic concurrency control on the substrate, not on the agent.

### 14.6 The orchestration framework is not the bottleneck

Switching frameworks rarely fixes a broken deployment. The bottleneck is harness discipline, spec quality, and tool quality. Teams that re-platform from LangGraph to AutoGen to Claude Agent SDK looking for a fix usually find the same problems waiting on the other side. The fix lives in the harness layer the team has not yet built, not the framework layer the team keeps swapping.

## 15. Operational playbook for SE and security-research orchestration

A concrete twelve-point checklist for someone building an agent in this space. Clearing the list does not guarantee a useful agent — that requires a good spec, a competent model, and good tools — but failing to clear the list does guarantee an agent that breaks unpredictably.

1. **Define the success criterion in 1-3 sentences before writing code.** Write it down. Have someone else read it. Iterate until it is precise enough to verify against. If you cannot do this, do not build the agent.
2. **Pick the simplest framework that fits.** Do not add LangGraph if a single-agent ReAct loop ships the task. Framework complexity is a debt the operator pays.
3. **Default-deny tool allowlist.** Add tools one at a time. Each tool addition is reviewed for blast radius.
4. **Per-tool argument validation.** Schema-validate every tool call before execution. Refuse malformed.
5. **Audit log every tool call to immutable storage.** OpenTelemetry GenAI semantic conventions. Object-locked storage. Streamed to a SIEM where one exists.
6. **Hard cost cap per task.** Not soft, not advisory — hard, with task termination on hit.
7. **Hard latency cap per task.** Same as cost.
8. **Prompt-cache structured.** Static prefix, dynamic suffix. Measure hit rate. Target 80%+ for production.
9. **Sub-agent isolation by default.** Explicit, opt-in sharing of context and permissions when delegating.
10. **Output validation via schema.** Pydantic / Zod / JSON Schema. Refuse malformed; let the model retry.
11. **Versioning.** Pin model, system prompt, tool versions. Record the pinned versions in the audit log.
12. **Observability.** Structured logs, metrics, traces. Dashboards for cost-per-task, latency-per-task, success rate, cache hit rate, tool-call distribution. Alarms on anomalies.

A team that ships this checklist clears the harness bar. They still need spec, model, and tools to be good. But they have done the part that is theirs to do.

## 16. Cross-link cluster

- `[[reference-ai-assisted-coding-tool-security]]` — threat surface for AI coding tools (Cursor, Copilot, Cline, Claude Code, etc.); the outside-in view of the systems this doc builds.
- `[[reference-ai-pr-review-platform]]` — vendor comparative for AI-PR-review platforms; the productized form of static-analysis orchestration.
- `[[reference-ai-pr-review-iac-security]]` — IaC-specific AI-PR-review framing.
- `[[reference-llm-agent-security]]` — runtime threat model for LLM agents; the primitive catalogue this doc's §13 builds on.
- `[[reference-agentic-web-capabilities]]` — capability-discipline doctrine (POLA, confused deputy, CaMeL); the structural defense underlying §4.6 and §13.1.
- `[[reference-ai-red-team-operator-playbook]]` — operator-side red-team for AI tools; the offensive complement to this doc's harness focus.
- `[[reference-ai-incident-response-playbook]]` — IR for compromised AI tools.
- `[[reference-bug-hunting-first-principles]]` — Kurt's bug-hunting doctrine; what an SE or security agent should follow when given autonomy.
- `[[reference-vr-methodology]]` — VR methods meta-catalog; variant analysis is the canonical security-research agent task.
- `[[reference-code-review-expertise]]` — secure code review methodology; review-side agent framing for §8.2 and §9.3.
- `[[reference-language-footguns-class]]` — per-language unsafe-primitive catalogue the polyglot-agent of §7.3 should consult.
- `[[reference-reverse-engineering-binary-analysis]]` — RE methodology; the agent-on-decompiled-binary application of §9.7.
- `[[reference-detection-engineering]]` — runtime detection plus OpenTelemetry GenAI substrate; the observability layer of §5.4 and §12.
- `[[reference-steelman-doctrine]]` — Champion / Foil / Adjudicator separation; the doctrinal connection for §4.7 auditor / target / judge.
- `[[reference-race-conditions-concurrency]]` — concurrency primitives; the closed-world failure mode of §14.5.
- `[[reference-adversarial-ml-model-security]]` — model-level attacks; the layer below the orchestration layer this doc covers.
- `[[reference-cloud-iam]]` — identity primitives; the credential-isolation substrate of §13.4.
