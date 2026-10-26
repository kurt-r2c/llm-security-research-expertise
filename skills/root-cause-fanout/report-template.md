# <CVE-ID>: root-cause fan-out

Date: YYYY-MM-DD. Reported against: <product, as in the advisory>.

## Bedrock

| Field | Value | Source |
|---|---|---|
| Component | `library@version` | |
| Function | `file:function` | |
| Violated invariant | one line | |
| Affected range (component) | | |
| Fixed in (component) | version, commit | |
| Reported product's amplifiers | default exposure, missing error handling, privilege, size caps | |

Descent path: product -> ... -> bedrock, one line per hop with the evidence
for each hop (fix diff path, vendored dir, lockfile bump).

## Consumers

| Consumer | Mechanism (system / vendored / binding / runtime) | Version shipped | Affected? | Attacker data direction | Default or opt-in | Source |
|---|---|---|---|---|---|---|

Not checked: <mechanisms or ecosystems skipped, and why>.

## Other implementations

| Implementation | Relation (reference / port / independent) | Same invariant violated? | Behaviour on trigger input | Source |
|---|---|---|---|---|

## Side effects

Per consumer or implementation: memory corruption, abort, unhandled
exception, catchable error, silent partial output, resource amplification,
differentials between implementations.

## Open questions

What would change the blast radius if answered, and how to answer it.
