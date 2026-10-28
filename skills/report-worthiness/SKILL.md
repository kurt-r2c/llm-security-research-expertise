---
name: report-worthiness
description: Decide whether a valid security finding is actually worth reporting or disclosing. Apply after severity triage, before writing a report, opening an issue, or contacting a vendor. Gates on impact durability, not CVSS.
---

# Report-Worthiness Gate

A finding can be technically valid and still not worth reporting. Severity
(CVSS, impact ceiling) measures worst-case harm in isolation. This gate measures
whether that harm is **real, durable, and costly to neutralize** — i.e. whether
a competent defender would care. Apply it after severity triage and before any
report, issue, advisory, or disclosure contact.

A finding is worth reporting only if **all three** hold. Fail any one → do not
report (note it, downgrade it, move on).

## The three gates

1. **Ongoing.** The impact persists while the attack runs or after it stops.
   Exclude impact that ends the instant the attacker stops, leaves no residue,
   and needs continuous effort to maintain.

2. **User-facing.** The impact degrades the product for real users or customers,
   exposes their data, or crosses a trust boundary between them. Exclude impact
   confined to the operator's own internal machinery — CI/CD, dev/test
   environments, ops dashboards, SRE tooling. "The team gets paged" is not
   user-facing harm.

3. **Not trivially invalidated by a minor capability degradation.** Ask: *can
   the defender neutralize this with a cheap, reactive action they'd happily
   accept until the attacker gives up?* If yes, it isn't worth reporting. The
   canonical cheap action is **blackholing or rate-limiting the route** until
   remote exploit attempts subside; also: a feature flag off, a WAF rule, an
   IP block, dropping an endpoint from the public edge. If the mitigation
   costs the defender almost nothing and loses no real capability, the finding
   has no leverage.

The third gate is the one most often missed. Run it explicitly: name the
cheapest reactive mitigation and ask whether the defender would shrug and apply
it. A finding only has weight if the fix the defender is *forced* into would
itself break the product for real users — i.e. they can't cheaply opt out of
the impact.

## Worth reporting vs. not

| Not worth reporting | Worth reporting |
|---|---|
| Unauth endpoint that deletes ephemeral / recreatable state (DoS of the operator's own infra) → defender blackholes the route | Unauth endpoint that exposes or corrupts other users' persistent data |
| Forged request that only triggers re-sync / re-fetch of authoritative state (no trusted argument propagates) | Forged request whose attacker-controlled arguments are trusted and drive a privileged action (deploy, merge, payment, grant) |
| Self-DoS / self-scope / self-XSS; impact confined to the attacker | Cross-user: account takeover, cross-tenant access, stored XSS hitting other users |
| Availability hit the defender can ride out by shedding a non-critical route | Availability hit that can only be stopped by taking down a user-critical service |
| Hardening gap / defense-in-depth with no demonstrated primary vuln | Auth bypass, priv-esc, RCE, persistent data exposure |

## Why this is orthogonal to severity

Severity answers "how bad if exploited." Report-worthiness answers "does
exploitation produce leverage the defender can't cheaply shrug off." A medium by
CVSS can fail all three gates (e.g. unauthenticated-but-recoverable DoS of a
non-user-facing control plane). When a finding fails this gate, say so plainly
and state the cheap mitigation that defeats it — that single sentence is the
whole argument for not reporting.

## Output

When closing a finding on this gate, record:
- which gate(s) it fails (ongoing / user-facing / trivially-invalidated),
- the specific cheap reactive mitigation that defeats it (if gate 3), and
- the one-line conclusion: *valid, but not worth reporting — <reason>.*
