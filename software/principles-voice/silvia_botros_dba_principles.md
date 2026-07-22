# Staff-Level DBA Guiding Principles
## Synthesized from Silvia Botros (@dbsmasher)

> Silvia Botros is a Senior Principal Engineer / Senior Architect at Twilio (formerly SendGrid's
> first in-house DBA), and co-author of *High Performance MySQL, 4th Edition* (O'Reilly, 2021,
> with Jeremy Tinley). Her career arc—from self-taught optimization via the 2nd edition of HPMySQL
> to co-authoring the 4th—makes her one of the most operationally grounded MySQL practitioners
> writing today. This document synthesizes her public talks, blog posts, podcast appearances, and
> the 4th edition's content into a set of guiding principles for staff-level database work.
>
> Sources: blog.dbsmasher.com, LISA17 / SCaLE 16x / O'Reilly Velocity talks, Changelog Ship It!
> #118, Real World DevOps #001, On-Call Nightmares #44, staffeng.com, LeadDev, and the 4th edition
> table of contents and chapter summaries.

---

## 1. Core Philosophy

### Stability is a feature — and the primary deliverable

Database infrastructure that doesn't page anyone is not boring: it's done right. The goal of
database engineering is to make the data layer so reliable and predictable that engineers building
products on top of it can take it for granted. "Boring technology doesn't have to mean not
challenging."

The value of database work is measured in business continuity, not in clever optimizations. A
5-nines SLA on the write path is worth more than a 20% query speedup that only matters under
synthetic load.

### All databases are terrible — pick the right trade-offs

Every storage system has trade-offs. Schema-less NoSQL does not eliminate data structure
problems — it moves them from the database schema into application code, where they are harder
to discover, audit, and enforce. The CAP theorem is not a theoretical exercise: it is a
negotiating tool for conversations with stakeholders who demand zero-downtime failover and full
consistency simultaneously. Name the trade-off, put it on the table, and make a decision.

### The DBRE mental model replaces the old DBA mental model

Database Reliability Engineering (DBRE) is not a rebrand. It is a different frame:
- Old DBA model: database expert is a gatekeeper and specialist; all changes flow through them.
- DBRE model: database engineers embed reliability practices into developer workflows and tooling
  so that the organization does not depend on any single person.

Building toward a state where developers can safely operate databases without a DBA in the room
is the success condition, not a threat to job security.

### Force-multiply, don't code

At the staff/principal level, impact is measured in the number of teams and systems influenced,
not in lines of code produced. The correct scope for a principal database engineer is quarters
to years of ROI across product lines — a horizontal role, not ownership of one service. This
means writing guidance documents, running architecture reviews, building tooling others use, and
teaching patterns that scale.

---

## 2. Schema Design and Management

### Schema is a contract, not an implementation detail

Schema changes are among the riskiest operations in a production database system. Treat schema
migrations the same way you treat API contracts: design for backward compatibility, version
changes deliberately, and never assume you can roll back atomically under load.

Key practices:
- **Version control all schema changes.** Schema definitions belong in source control with the
  application code. DDL changes reviewed as pull requests, not run ad hoc by a DBA.
- **Online schema changes only in production.** Use tools like `pt-online-schema-change` or
  `gh-ost` for ALTER operations on large tables. Lock-based ALTER on a table with millions of rows
  causes write unavailability.
- **Test migrations in staging against production-scale data.** A migration that completes in
  seconds on a 10GB staging table may run for 8 hours on a 2TB production table.
- **Separate schema deployment from code deployment.** Never deploy application code and schema
  changes atomically. Deploy schema first (backward-compatible), deploy code, then optionally
  clean up old columns/tables after the rollout window.

### Normalization is a starting point, not a final state

Start normalized. Denormalize deliberately when you have measured evidence that join cost or read
amplification is a real bottleneck — not before. Premature denormalization creates consistency
problems that compound over time.

### Data belongs where it belongs

MySQL is not an object store. Static content, large blobs, and datasets that are only read in bulk
(e.g., daily reference data) belong in S3 or equivalent. Storing them in MySQL wastes InnoDB
buffer pool space on data that does not benefit from row-level locking or transactional semantics.

### Avoid data structures that cannot be indexed

If a query needs to search inside a JSON column or parse a delimited string to answer a WHERE
clause, the schema is working against you. JSON support in MySQL is useful for truly document-like
data, but do not use it as a way to avoid defining a schema.

---

## 3. Indexing for High Performance

### Indexes are the highest-leverage performance tool

Most query performance problems in production MySQL are index problems — either missing indexes,
incorrect index column order, or over-indexing that hurts write throughput. Before tuning server
parameters, examine query plans.

### The column order in a composite index determines its selectivity

A composite index `(a, b, c)` supports prefix lookups on `a`, `(a, b)`, and `(a, b, c)`. It does
not support lookups on `b` alone or `c` alone. Column order should be determined by:
1. Columns used in equality predicates first
2. Columns used in range predicates last
3. High-cardinality columns before low-cardinality columns, all else equal

### Covering indexes eliminate row lookups

A covering index includes all columns needed to satisfy a query, so InnoDB can return results
directly from the index B-tree without touching the primary key / clustered index. For
high-frequency read queries, designing covering indexes is often more impactful than any
server-side tuning.

### InnoDB's clustered primary key affects everything

In InnoDB, the primary key *is* the table data. Secondary indexes store the primary key value as
their row pointer. Consequences:
- A surrogate integer primary key keeps the clustered index compact and insertion-ordered, which
  is good for sequential writes.
- A UUID primary key causes random insertion into the clustered index, fragmenting the B-tree and
  causing buffer pool pressure. Use ordered UUIDs (UUID v7 / `UUID_TO_BIN` with swap_flag=1) or
  auto-increment integers when write throughput matters.
- Wide primary keys make every secondary index wider. Keep primary keys short.

### Index maintenance has a cost

Every secondary index increases write amplification. Before adding an index, verify it will
actually be used via `EXPLAIN`. After adding, monitor `Handler_read_*` counters and review
`sys.schema_unused_indexes` to identify dead weight.

---

## 4. Query Performance Optimization

### Measure before optimizing

The slow query log (`long_query_time`, `log_queries_not_using_indexes`) is the starting point.
Use `pt-query-digest` to aggregate and rank by total time, not just worst-case latency. The query
that runs 500ms once matters less than the query that runs 5ms but fires 50,000 times per minute.

Tooling: VividCortex (now SolarWinds DPM) for real-time visualization enables non-DBA engineers
to self-identify problem queries without needing DBA intervention — which is the goal.

### EXPLAIN is mandatory before any schema or query change

Read the `type` column in EXPLAIN output. In order from worst to best: `ALL` (full table scan),
`index` (full index scan), `range`, `ref`, `eq_ref`, `const`. Any `ALL` on a large table in a
query that runs more than a few times per minute is a problem.

Watch for:
- `Using filesort` — sort cannot use an index; add index or rewrite ORDER BY
- `Using temporary` — intermediate result materializes to a temp table; often signals a
  problematic GROUP BY or DISTINCT
- `rows` estimate — large estimates on join leading tables cascade into massive reads

### N+1 queries are a schema access pattern failure

N+1 query patterns (loading a list of N objects then querying each for related data) are the most
common application-layer query performance failure. The fix is almost never in the database — it
is in the ORM or data access layer. But the DBA is often the one who discovers it via the slow
log. Bridge the gap: show developers what the database sees, not just that a query is slow.

### Real-time requirements are a red flag

If the business requires MySQL to have sub-second write availability (failover completes in under
a second), that is a signal to reconsider the architecture. MySQL semi-synchronous replication,
properly tuned, achieves RPO of ~0 and RTO of 30–90 seconds. Demanding lower RTO means either:
- Moving to a distributed database (Vitess, TiDB, Aurora) with different trade-off profiles, or
- Caching reads aggressively enough that brief write unavailability is invisible to users, or
- Re-examining whether the "real-time" requirement is actually a requirement or an assumption

---

## 5. Server and OS Configuration

### InnoDB buffer pool is the most important server setting

Size the InnoDB buffer pool (`innodb_buffer_pool_size`) to fit the hot working set in RAM. On a
dedicated MySQL host, 70–80% of total RAM is a reasonable starting point. Use multiple buffer
pool instances (`innodb_buffer_pool_instances`) — one per GB of buffer pool, up to 64 — to reduce
mutex contention on multi-core hosts.

Monitor buffer pool efficiency via `Innodb_buffer_pool_reads` vs. `Innodb_buffer_pool_read_requests`.
A read hit ratio below 99% on an OLTP workload indicates working set does not fit in memory.

### Durability settings are a business decision, not a performance knob

`innodb_flush_log_at_trx_commit`:
- `1` (default): fsync on every commit. Full ACID durability. Required for financial data.
- `2`: write to OS cache on commit, fsync once per second. Lose up to 1 second of commits on
  OS crash. Acceptable for many non-financial workloads.
- `0`: fsync once per second. Lose up to 1 second even on MySQL crash.

`sync_binlog`:
- `1` (default MySQL 5.7.7+): sync binary log on every commit. Required for crash-safe replication.
- `0`: rely on OS. Do not use in production replication setups.

Do not change these settings without understanding the RPO implications. Document the choice.

### O_DIRECT for InnoDB, tune I/O scheduler for the storage type

Set `innodb_flush_method=O_DIRECT` to bypass the OS page cache for InnoDB data files — InnoDB has
its own buffer pool and double-buffering wastes RAM. For rotational disks, `deadline` or `noop`
I/O scheduler outperforms `cfq` for database workloads. For SSDs and NVMe, `noop` or `none` is
correct — these devices do their own scheduling.

### Thread and connection management

Connection overhead in MySQL is not free. Each connection consumes ~1MB of RAM for its stack and
buffers. At 1,000 connections, that is 1GB before any data is touched. Use a connection pool
(ProxySQL, PgBouncer-equivalent patterns) in front of MySQL for applications that cannot control
their connection count. Do not set `max_connections` to 10,000 hoping for the best.

---

## 6. Replication

### Understand what replication guarantees and what it does not

MySQL asynchronous replication is eventually consistent by default. Replicas lag. The amount of
lag depends on write throughput, replica hardware, and network — not on configuration alone. Any
application that reads from a replica and expects to see its own writes must handle replication
lag explicitly (read-your-writes via routing to primary, or `SELECT WAIT_FOR_EXECUTED_GTID`).

### GTID-based replication is non-negotiable for modern MySQL

Global Transaction Identifiers (GTIDs) make failover automatable. With GTIDs, a new primary can
pick up replication from any replica because the transaction identity is global, not
position-based. Without GTIDs, you must manually calculate binlog positions during failover —
this is error-prone under stress and slow.

Enable from the start on new clusters. Migrating an existing cluster to GTIDs online is possible
but operationally complex.

### Semi-synchronous replication changes the durability guarantee

With async replication, a primary crash after commit but before the binlog event reaches replicas
means that committed transaction is lost if a replica is promoted. Semi-synchronous replication
(`rpl_semi_sync_master_enabled`) holds the commit until at least one replica acknowledges receipt.
This trades some write latency (~network RTT) for zero data loss on failover.

Use semi-sync with `rpl_semi_sync_master_timeout` tuned so that if all replicas are unavailable,
it falls back to async rather than stalling writes indefinitely. The fallback is documented
behavior; plan for it.

### Crash-safe replicas require correct configuration

`relay_log_recovery=ON` and `sync_relay_log=1` are required for a replica to be crash-safe.
Without these, a replica crash can leave the relay log in an inconsistent state, causing
replication to break on restart. This is not hypothetical — it happens.

### Row-based replication is safer than statement-based for most workloads

Statement-based replication (SBR) is non-deterministic for queries that use `NOW()`, `RAND()`,
user-defined functions, or any non-deterministic behavior. Mixed-mode replication falls back to
row-based when the statement is flagged as unsafe, but the logic is complex and edge cases exist.
Default to row-based replication (`binlog_format=ROW`) unless you have a specific, measured
reason for SBR (e.g., very wide rows with low update cardinality making row images expensive).

### Replication topology: simple is better

The best replication topology is a single primary with a read pool of replicas. Discouraged:
- **Circular / ring replication:** A write on node A propagates to B, which replicates to C,
  which replicates back to A. A single broken link or split-brain event causes divergence that is
  difficult to detect and painful to repair.
- **Chained replicas (relay replicas):** Replica A replicates to replica B which replicates to
  replica C. Each hop adds lag. If the intermediate replica needs maintenance, the downstream
  replicas all stop.
- **Multi-source replication:** Complex to reason about, complex to fail over. Use it only when
  you have a concrete requirement (e.g., aggregating shards for reporting) and understand the
  failure modes.

Use MySQL Orchestrator (now Orchestrator/raft) for automated topology management and failover.
It provides a map of the replication graph, handles intermediate replica re-pointing after
promotion, and can be configured for fully automated failover.

---

## 7. High Availability and Failover

### RPO and RTO are separate knobs

- **RPO (Recovery Point Objective):** How much data can you lose? Semi-sync replication + crash-
  safe replicas approaches RPO=0.
- **RTO (Recovery Time Objective):** How long can the system be unavailable? Automated failover
  with Orchestrator + ProxySQL health checks achieves RTO of 30–90 seconds for most topologies.

Do not conflate these. Stakeholders often ask for "no downtime and no data loss" — which is
either distributed databases (different cost and complexity profile) or a misunderstanding of the
trade-off space. Name the trade-off.

### ProxySQL for transparent failover

ProxySQL sits between the application and MySQL, performing:
- Read/write splitting (route writes to primary, reads to replicas)
- Health checks and automatic removal of unhealthy backends
- Connection multiplexing (N application connections → M MySQL connections, where M << N)
- Query routing rules for functional partitioning
- Query mirroring for shadow testing schema changes

Integrate Orchestrator and ProxySQL so that when Orchestrator promotes a new primary, ProxySQL's
hostgroup configuration is updated automatically. This is the operational baseline for HA MySQL.

### Test failover regularly

Runbook-only failover that has never been tested is not HA — it is a plan. Schedule fire drills.
Run planned failovers during business hours with the team present so that the first time the
process runs under pressure is not during an actual incident. Document the time taken, the steps
that were unclear, and the state that was unexpected. Reduce RTO through iteration.

---

## 8. Scaling MySQL

### Distinguish read-bound from write-bound scaling

**Read-bound scaling:** Add replicas. Use ProxySQL to route reads across the pool. Use
`max_connections` budgeting across the pool to avoid replica overload. Cache aggressively at the
application layer (Redis/Memcached) for data with high read/write ratios and acceptable staleness.

**Write-bound scaling:** Adding replicas does not help. Options:
- **Functional sharding:** Split the database by domain/service boundary. Orders go to one
  cluster, inventory to another. Each cluster has its own primary and replica pool.
- **Horizontal sharding:** Partition a single large table across multiple clusters by a shard key
  (user ID, tenant ID, etc.). Vitess provides a sharding layer with transparent routing, online
  resharding, and connection pooling. This is a significant operational investment — do functional
  sharding first.
- **CQRS + event sourcing:** Move high-volume write paths off MySQL entirely into append-only
  event streams; rebuild read models asynchronously.

### Vitess for horizontal scale

Vitess provides MySQL-compatible horizontal sharding with:
- VTGate: query routing and aggregation across shards
- VTTablet: per-MySQL instance sidecar managing connections and health
- Online resharding without application downtime
- Connection pooling at the VTTablet level

The operational cost of Vitess is real. Do not adopt it before you have exhausted simpler scaling
strategies and have a team capable of operating it.

### Application-layer caching is a database scaling strategy

Caching is not cheating. For data that is read frequently and changes infrequently (reference
data, user profiles, configuration), a cache in front of MySQL is the correct architectural
answer. The database sees lower read load, the cache serves tail latency, and the application
gets faster responses. Design the cache invalidation strategy carefully — cache invalidation
failures are a common source of stale data bugs.

---

## 9. Backup and Recovery

### Backups that have not been restored are not backups

Test restores regularly. The backup process only matters insofar as the restore succeeds. Run
restore drills quarterly. Time the restore on production-scale data — a backup that takes 6 hours
to restore defines your minimum RTO in a catastrophic failure scenario.

### Physical backups for large datasets, logical for portability

For databases over ~100GB, physical backups (Percona XtraBackup, MySQL Enterprise Backup) are
dramatically faster than logical backups (`mysqldump`). XtraBackup performs a hot backup by
copying InnoDB data files and replaying the redo log — no table locks required.

`mysqldump` / `mysqlpump` / `mydumper` are appropriate for:
- Smaller databases where restore time is acceptable
- Schema-only exports
- Cross-version migrations where physical compatibility is uncertain
- Selective table exports

### Compression + encryption pipeline for physical backups

At scale, the backup pipeline is:
```
xtrabackup --stream=xbstream | pigz --processes=<N> | gpg2 --encrypt --recipient <key-id> | s3cmd put -
```

Key decisions:
- **Compression before encryption:** Encrypted data does not compress. Always compress first.
- **`pigz` over `gzip`:** Parallel gzip uses multiple cores; single-threaded gzip is the
  bottleneck on modern hardware with fast storage.
- **Asymmetric encryption (GPG2 public key):** XtraBackup's built-in symmetric encryption has
  known issues at scale (log block number mismatches causing restore failure at 1TB+). Asymmetric
  encryption with the private key stored separately (HashiCorp Vault or equivalent) means a
  compromised backup file does not expose the decryption key.

Verify backup integrity after upload: download a test file, verify GPG signature, run
`xtrabackup --prepare` on a staging host.

### Binary log retention for point-in-time recovery

Full physical backup + binary log stream enables point-in-time recovery (PITR) to any transaction
within the retention window. Configure `expire_logs_days` or `binlog_expire_logs_seconds` to
retain binary logs for at least as long as the backup retention window. Stream binary logs to S3
or equivalent in near-real-time to protect against primary host loss.

---

## 10. Monitoring and Observability (DBRE Approach)

### Performance Schema is the authoritative internal instrumentation

MySQL's Performance Schema (`performance_schema`) provides instrumented visibility into:
- Statement digests (`events_statements_summary_by_digest`) — aggregated query performance
- Wait events — where time is actually spent (I/O, locks, mutexes, network)
- Table I/O (`table_io_waits_summary_by_table`) — per-table access patterns
- Replication lag and channel status

The `sys` schema provides pre-built views on top of Performance Schema with human-readable
output. Start with `sys.statement_analysis` and `sys.io_global_by_wait_by_latency` for
rapid investigation.

### Four signals: error rate, latency, saturation, traffic (USE/RED)

Apply the USE method (Utilization, Saturation, Errors) to database infrastructure:
- **CPU:** saturation (run queue length) matters more than utilization percentage
- **InnoDB buffer pool:** hit ratio, dirty page percentage, read/write I/O rate
- **Disk I/O:** throughput vs. capacity, await time, queue depth
- **Replication lag:** seconds_behind_master is a lagging indicator; binlog position delta is faster
- **Connections:** active vs. max, sleeping connections (connection leak signal)
- **Lock waits:** `Innodb_row_lock_waits`, `Innodb_row_lock_time_avg`

### Non-DBAs must be able to self-diagnose query problems

One of the most valuable DBRE contributions is making database observability accessible to
developers. When engineers can see which of their queries are slow — without filing a ticket —
they fix problems earlier and learn faster. This means:
- Dashboard access for all engineers (VividCortex/DPM, Grafana+Prometheus+PMM)
- Alerts that fire on the service team's on-call rotation, not only the DBA
- Runbooks explaining how to interpret slow query data and read EXPLAIN output
- Query performance incorporated into code review for data-access-heavy changes

### Alert on symptoms, not just metrics

An alert that fires when CPU exceeds 80% may fire during legitimate batch jobs. An alert that
fires when p99 query latency exceeds the SLA threshold is always actionable. Design alerts around
user-visible impact:
- Replication lag > threshold (risk window for data loss or stale reads)
- Write latency p99 > SLA
- Replica health check failures (reduced read capacity, failover risk)
- Backup job failure

---

## 11. MySQL in the Cloud and Managed Databases

### Managed databases shift the operational concern, they do not eliminate it

Amazon RDS, Aurora, GCP Cloud SQL, and similar services eliminate OS patching, hardware
provisioning, and storage management. They do not eliminate:
- Schema design mistakes
- Index-free query patterns
- Replication lag from write-heavy workloads
- Access pattern mismatches between application behavior and database capabilities
- Connection pool exhaustion
- Compliance requirements (encryption at rest, audit logging, access control)

"You still need the pager, it's just different things." Moving to managed MySQL means your
incidents shift from "disk failure" to "Aurora reader endpoint not serving current data" or
"Cloud SQL failover took 90 seconds and the app didn't handle it."

### Aurora MySQL: know the architecture differences

Amazon Aurora for MySQL uses a shared distributed storage layer (6-way replication across 3 AZs)
instead of InnoDB's traditional storage. Implications:
- Crash recovery is near-instant (no redo log replay; storage is always consistent)
- Failover RTO is typically 30–60 seconds (cluster endpoint DNS propagation is often the limiter)
- Reader endpoints distribute reads across Aurora Replicas, which lag the writer by milliseconds
  in normal operation (shared storage means replica lag is not I/O-bound)
- `innodb_flush_log_at_trx_commit` and `sync_binlog` behavior is different from on-prem MySQL;
  Aurora manages durability at the storage layer
- The Aurora storage auto-scales but has a per-cluster I/O cost model — high-write workloads can
  be expensive; benchmark before committing

### Kubernetes MySQL: not the default answer

Running MySQL on Kubernetes (via operators: PlanetScale Vitess Operator, Percona Operator,
MySQL Operator for Kubernetes) is viable for stateless-friendly deployment patterns and enables
GitOps-style cluster management. However:
- Persistent volume I/O characteristics differ from bare-metal NVMe; benchmark on your storage class
- Pod scheduling must account for anti-affinity (primary and replica on different nodes/AZs)
- Operator maturity varies; understand what automated operations the operator performs and what
  it does not
- Network policies, service mesh overhead, and DNS TTLs all affect database connection behavior
- Do not run stateful workloads on Kubernetes without a clear story for PV backup and restore

---

## 12. Compliance and Security

### Compliance is a first-class database engineering concern

Security and compliance requirements affect every layer of database architecture. Build compliance
in from the start; retrofitting it onto an existing system is significantly more expensive.

**Encryption at rest:** Enable InnoDB tablespace encryption (`innodb_encrypt_tables`) and encrypt
binary logs. For managed services, use provider-managed encryption with customer-managed keys
(CMK) where compliance requires it (FedRAMP, some PCI DSS interpretations).

**Encryption in transit:** Require TLS for all connections (`require_secure_transport=ON`).
Do not allow unencrypted connections from application hosts or between replication participants.

**Audit logging:** SOC 2, PCI DSS, and HIPAA all require audit trails for database access.
MySQL Enterprise Audit or the open-source audit plugin (Percona / MariaDB Audit Plugin) logs
connections, queries, and schema changes. Route audit logs to a write-once destination the DBA
cannot modify.

**Access control:** Follow least privilege. Application accounts should have only the permissions
required for their function (`SELECT, INSERT, UPDATE, DELETE` on specific tables — not `ALL
PRIVILEGES ON *.*`). Separate accounts for application reads vs. writes vs. migrations vs.
monitoring. Rotate credentials regularly; integrate with a secrets manager (HashiCorp Vault,
AWS Secrets Manager).

**GDPR / data residency:** MySQL replication topology must respect data residency requirements.
Do not replicate personal data across region boundaries if doing so violates GDPR or Schrems II.
Use replication filters (`replicate_wild_ignore_table`) to exclude regulated tables from cross-
region replicas, or architect for data locality from the start.

### SOC 2 drives backup encryption requirements

SOC 2 Type II audits require demonstrable controls on data confidentiality, including backups.
A backup file on S3 must be encrypted with a key that is auditable and rotatable. Symmetric
encryption with a static key stored in a config file does not satisfy this. Use asymmetric
encryption with the private key stored in a secrets manager with access logging.

---

## 13. Team, Organizational, and Career Practices

### Eliminate the "database hero" model

Single-point-of-failure expertise is an organizational risk. The goal of a staff DBA is to
distribute enough database knowledge across the engineering organization that:
- Developers can write performant queries without DBA review
- On-call engineers can handle common database incidents from runbooks
- The DBA's time is spent on architectural decisions and force-multiplying tooling, not
  routine query tuning

This requires documentation, training, architecture review processes, and deliberate knowledge
transfer — not just "being available to help."

### Developers must be on-call for their own code

This applies to database engineers as well as application engineers. An engineer who claims
senior status but refuses on-call is a cultural liability. On-call responsibility drives better
design decisions — engineers who will be paged at 3am when a query causes lock escalation write
more careful queries.

When a developer's code causes a database incident, the correct response is a blameless
post-mortem and a runbook update — not escalation to the DBA team as a punishment proxy.

### Psychological safety is a prerequisite for automation

Automation requires engineers to admit when manual processes are unreliable. In blame cultures,
engineers hide failures instead of documenting them, which means automation is built on incorrect
assumptions. Before investing in database automation, verify that the team culture supports
transparent incident reporting and blameless post-mortems.

### Architecture reviews must be cross-functional

A database schema review conducted only by database engineers misses half the relevant
information. Schema design decisions affect query patterns (application engineers), data
pipelines (data/ETL engineers), compliance posture (security engineers), and cost (finance).
Effective architecture reviews include all these perspectives before a schema is committed.

### Document why, not just what

In the absence of documentation, humans fill the vacuum with assumptions — usually incorrect
ones. Every database configuration choice, topology decision, and schema constraint should have
a written rationale accessible to engineers who were not in the room when the decision was made.
A `technology-catalog.md` listing every tool in the data infrastructure, why it was chosen, and
what problem it solves is more valuable than any amount of tribal knowledge.

### Manage technical debt proactively

Databases accumulate technical debt faster than most systems because data outlives the code
that created it. A table with 12 years of schema migrations, half the columns unused, and no
documentation is a trap for every engineer who touches it. The DBA is often the one who
understands the full history; that knowledge must be externalized into documentation and
incrementally addressed, not carried in one person's head.

---

## 14. Tooling Reference

The following tooling stack reflects what Botros has documented using or recommending in
production MySQL environments:

| Category | Tool | Notes |
|----------|------|-------|
| Replication topology | MySQL Orchestrator (raft mode) | Automated failover, topology visualization |
| Query proxy | ProxySQL | R/W splitting, connection pooling, health checks |
| Online schema changes | `gh-ost` / `pt-online-schema-change` | Zero-downtime ALTER on large tables |
| Physical backup | Percona XtraBackup | Hot backup, streaming to S3 |
| Compression | `pigz` | Parallel gzip; use before encryption in pipeline |
| Backup encryption | GPG2 (asymmetric) + HashiCorp Vault | SOC 2 compliant; avoids XtraBackup symmetric issues |
| Query analysis | `pt-query-digest` | Slow log aggregation and ranking |
| Query visualization | VividCortex / SolarWinds DPM | Real-time query metrics for non-DBA engineers |
| Slow query visualization | Anemometer (Box) | UI for `pt-query-digest` output |
| Configuration management | Chef (orchestrator cookbook) | Automated MySQL config + Orchestrator deployment |
| Horizontal scale | Vitess | Sharding, VTGate routing, VTTablet sidecar |
| Monitoring | Percona Monitoring and Management (PMM) | Prometheus + Grafana stack for MySQL |

---

## 15. Summary: What Separates Staff-Level Database Work

A staff-level DBA of this caliber is distinguished not by deeper knowledge of MySQL internals
(though that matters), but by the following:

1. **Business translation:** Converts database constraints (CAP trade-offs, replication lag, RTO
   vs. RPO) into language and decisions that non-technical stakeholders can act on.

2. **Prevention over response:** Invests in schema review, architecture guidelines, and developer
   tooling that prevents incidents rather than responding to them after the fact.

3. **Organizational scope:** Operates across multiple product lines and teams, not within a single
   service. Influence is measured by how many teams improved their data layer practices.

4. **Deliberate knowledge distribution:** Actively works to eliminate single points of expertise,
   including themselves. Writes runbooks, mentors junior database engineers (1–2 per cohort,
   alongside 1–2 experienced), and builds tooling others can operate.

5. **Compliance and security as technical constraints:** Treats compliance requirements (SOC 2,
   PCI DSS, GDPR) as first-class architectural inputs, not late-stage audit requirements.

6. **Boring as the goal:** "Boring technology doesn't have to mean not challenging." The sign of
   excellent database infrastructure is that it is never in the incident log.

---

## 16. 2024–2026 Currency Layer

This section deepens the doc with developments since the 4th edition of *High Performance MySQL*
(2021) and Botros's last widely-circulated podcast appearance (Changelog *Ship It!* #118, 2024).
Botros's own public output has been sparse in 2024–2026 — no new blog cadence on dbsmasher.com or
LeadDev, no new books. She has remained active intermittently on `@dbsmasher` (X/Twitter and
adjacent platforms), surfacing in podcast and conference circuits but not publishing a new
book-scale work. The framing below treats the principles in this doc as load-bearing and applies
them to the database engineering landscape as it actually exists in 2026 — what the DBRE community
has shipped since the 4th edition, and where Botros's operational instincts still cut cleanly.

### 16.1 MySQL release-train churn: 8.4 LTS, the 9.x innovation track, and the upgrade discipline this forces

In 2024 Oracle restructured MySQL's release model. **MySQL 8.4** was published 2024-04-30 as the
new LTS branch (succeeding 8.0 LTS), and a parallel **MySQL 9.0 Innovation Release** shipped
2024-07-01 with a shorter support tail. The two cadences are explicitly stated in the upstream
release notes: 8.4 receives long-term bug-fix support; 9.x is the experimental edge where new
features (notably the `VECTOR` column type added in 9.0) appear first. Upgrade discipline that
this doc has always recommended — staged, evidence-driven, tested against production-scale data —
becomes load-bearing under the new cadence, because 8.0 → 8.4 → 9.x is not a single transparent
hop. Per the 8.4.0 release notes, **upgrading directly from 5.7 to 8.4 is unsupported**; you must
intermediate through 8.0. Botros's "stability is a feature" principle here translates to: stay on
the LTS track for production; track 9.x in lab environments to surface incompatibilities early;
never jump branches under pressure.

The 9.0 `VECTOR` type is the most visible product-roadmap signal. A column type whose
declaration `VECTOR(N)` reserves up to 16,383 4-byte floats per row, that cannot be used as any
kind of key, and that supports only equality comparison, is a deliberately constrained primitive
designed to be paired with retrieval infrastructure outside the row store. Treat it the same way
this doc treats JSON columns: useful for genuinely document-shaped data, dangerous when used as a
schema escape hatch.

- MySQL 8.4 Release Notes: https://dev.mysql.com/doc/relnotes/mysql/8.4/en/
- MySQL 8.4.0 changes (LTS): https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-0.html
- MySQL 9.0.0 changes (Innovation, VECTOR type): https://dev.mysql.com/doc/relnotes/mysql/9.0/en/news-9-0-0.html

### 16.2 Vitess maturity: 19, 20, and the gh-ost retirement

Vitess released **v19** in March 2024 and **v20** in June 2024 (each on the project's
roughly-quarterly cadence). Two items in those releases bear on the operational guidance in §6 and
§8 of this doc:

1. **Vitess 19 drops MySQL 5.7 support.** The upstream guidance now assumes 8.0+. If you run
   Vitess on 5.7 in production today, plan the underlying MySQL upgrade ahead of any further
   Vitess version bumps.
2. **Vitess 20 drops `gh-ost` for Online DDL.** The Vitess-native online schema change path is now
   the recommended primitive inside a Vitess deployment; `gh-ost` continues to exist as a
   standalone tool for non-Vitess MySQL but is no longer first-class inside the sharding layer.

Both changes reinforce this doc's posture that Vitess is a serious operational commitment, not a
drop-in. The component surface (VTGate, VTTablet, VTOrc, the operator) keeps evolving; staying
current with Vitess releases is itself a workstream.

- Vitess 19 announcement: https://vitess.io/blog/2024-03-06-announcing-vitess-19/
- Vitess 20 GA (CNCF): https://www.cncf.io/blog/2024/06/27/vitess-20-is-now-generally-available/
- Vitess releases index: https://vitess.io/docs/releases/

### 16.3 Schema-migration tooling: Spirit joins the gh-ost / pt-osc lineage

The §2 guidance to use `gh-ost` or `pt-online-schema-change` for online DDL on large tables
still holds, but a third tool has matured into the same operational class. **Spirit** (originally
**cashapp/spirit**, now under **block/spirit** after the Cash App → Block reorganization) is an
online schema change tool targeting MySQL 8.0+ exclusively. Three design points distinguish it
from the prior generation:

1. **Adaptive chunk sizing by target latency, not row count.** Spirit takes a target chunk-time
   (e.g., 500ms) and dynamically tunes chunk size to hit that target. `pt-online-schema-change`
   exposes `--chunk-size` and `--chunk-time` as tunables; Spirit defaults to closed-loop
   adjustment.
2. **Multi-threaded copy, leaning on MySQL 8.0's multi-threaded replication.** Single-threaded
   row copy was a real bottleneck on 5.7-era hardware; 8.0's replication subsystem makes parallel
   copy safe enough to ship.
3. **INSTANT DDL detection.** Spirit (and Vitess's Online DDL) detect when a requested change is
   expressible as MySQL 8.0+ INSTANT DDL — a pure metadata change with no table rebuild — and
   route to it transparently. This collapses minutes-to-hours of row-copy into a metadata
   round-trip for the common cases (adding a nullable column at the end, dropping certain
   defaults).

PlanetScale's own writeup ("The State of Online Schema Migrations in MySQL") makes the case that
operating staff in 2026 should know which path (`gh-ost`, `pt-osc`, Spirit, or Vitess-native) is
preferred for which scenario, rather than defaulting to whatever the team adopted years ago.
Apply Botros's "test migrations in staging against production-scale data" rule to the tool
selection itself: the right tool depends on table size, MySQL version, replication topology,
and the operational cost of misbehavior.

- block/spirit (canonical repo): https://github.com/block/spirit
- cashapp/spirit (predecessor): https://github.com/cashapp/spirit
- PlanetScale: State of Online Schema Migrations in MySQL: https://planetscale.com/blog/state-of-online-schema-migrations-in-mysql

### 16.4 Database observability: the DBM era

The §10 guidance — non-DBAs must be able to self-diagnose query problems; instrument the database
the way you instrument any other service — has been concretized in 2024–2026 by the rise of
dedicated DBM (Database Monitoring) products. **Datadog DBM** is the most visible: it now
supports MySQL, Postgres, Oracle, SQL Server, MongoDB, DocumentDB, and ClickHouse with statement
digests, query samples, blocking-query inspection, and (as of 2025) regression detection against
historical baselines. The product's framing — "developers can troubleshoot slow queries without
needing DBA expertise" — is a near-verbatim restatement of Botros's principle that the DBA's job
is to make the database observable to non-DBAs.

The 2026 operating model the doc should now reflect:

1. **Query digests live in the observability tier, not just in `pt-query-digest` output.** Slow
   log → `pt-query-digest` is still a valid investigation tool, but the always-on view should be
   in DataDog DBM, PMM, SolarWinds DPM, or an equivalent product. Engineers should not need to
   SSH to the primary to find their slow queries.
2. **Regressions are detected continuously.** Anomaly detection on p99 latency per normalized
   statement digest, baselined against the prior week, is now table stakes. Use this to catch
   the "query was fast yesterday, slow today" pattern that `pt-query-digest` flat aggregates
   cannot.
3. **Cost telemetry pairs with query telemetry.** Cloud MySQL workloads now expose per-query
   IO/CPU charges; observability should make the cost of a query visible to the team that owns it.

- Datadog DBM (overview): https://www.datadoghq.com/product/database-monitoring/
- Datadog DBM docs: https://docs.datadoghq.com/database_monitoring/
- Datadog DASH 2025 announcements: https://www.datadoghq.com/blog/dash-2025-new-feature-roundup-observe/

### 16.5 Distributed SQL has crossed the chasm — and MySQL is no longer the default

The §1 principle "all databases are terrible — pick the right trade-offs" hits hardest in 2026
because the *default* for a new green-field service is now genuinely contested. Three vectors
matter:

1. **CockroachDB, TiDB, YugabyteDB** are operationally mature, with thousands of production
   deployments and multi-year track records. Independent comparative benchmarks (TPC-C, 2024–2025
   surveys) put them in the same throughput class. The decision among them is now driven by
   workload shape (HTAP for TiDB; PostgreSQL-compatibility scoring puts YugabyteDB ahead of
   CockroachDB on a published Compatibility Index), license posture, and operator preference —
   not raw capability.
2. **Aurora DSQL (AWS, 2024 re:Invent)** is the most consequential cloud-vendor entrant. It is
   PostgreSQL-compatible, serverless, active-active across regions, and uses the AWS Time Sync
   Service (atomic-clock-anchored) for ordering — i.e., AWS's answer to Spanner's TrueTime. The
   architectural signal is that AWS now sells distributed-SQL-as-a-service in the same posture as
   DynamoDB: the customer never operates the cluster.
3. **PlanetScale Postgres + Metal (2024–2025)** marks the most visible vendor pivot. PlanetScale,
   which built its identity on Vitess-as-a-service for MySQL, shipped a Postgres offering on
   bare-metal NVMe in 2024 and made the $50/mo Metal tier generally available for Postgres in
   late 2025. Even the Vitess-anchored vendor now sells Postgres.

Read together, these signals do not invalidate any guidance in this doc — Botros's principles
apply unchanged to MySQL, Postgres, and distributed SQL alike. But the implicit assumption that
"production data layer = MySQL" is no longer free. A staff database engineer in 2026 should be
able to articulate, for any new system, why MySQL is the right answer (or why it isn't) in
language a stakeholder can act on: latency floor, failover guarantees, sharding ceiling, ecosystem
maturity, ops headcount, multi-region requirements.

- Aurora DSQL (AWS announcement): https://aws.amazon.com/about-aws/whats-new/2024/12/amazon-aurora-dsql-preview/
- Aurora DSQL technical writeup (InfoQ): https://www.infoq.com/news/2024/12/amazon-aurora-dsql/
- PlanetScale Postgres announcement: https://planetscale.com/blog/planetscale-for-postgres
- PlanetScale Metal GA for Postgres: https://planetscale.com/blog/50-dollar-planetscale-metal-is-ga-for-postgres
- Distributed SQL 2025 comparison: https://sanj.dev/post/distributed-sql-databases-comparison

### 16.6 HeatWave: vector store + GenAI inside MySQL

Oracle's **MySQL HeatWave** has continued evolving as the most opinionated cloud-MySQL offering.
The 2024–2025 release line added HeatWave GenAI: vector store ingestion via Auto Parallel Load,
HNSW (Hierarchical Navigable Small World) indexing for vector similarity search, hybrid
keyword+semantic retrieval, and integration with OCI Generative AI service embedding models.
This is the "AI for DBAs" path that Oracle is selling: a MySQL-shaped product where the database
itself does the embedding and retrieval workload, rather than handing it to a separate vector
store.

The Botros instinct here is to ask the cost question and the lock-in question: HeatWave-anchored
designs are hard to port off OCI, and the price model is structurally different from RDS or
self-hosted. Useful product to know exists; not a default.

- Introducing Vector Store and GenAI in MySQL HeatWave: https://blogs.oracle.com/mysql/introducing-vector-store-and-generative-ai-in-mysql-heatwave
- HeatWave 9.4.1 release notes (2025): https://dev.mysql.com/doc/relnotes/heatwave/en/news-9-4-1.html

### 16.7 "Shift left for SQL": pre-prod query analysis

The §4 principle "measure before optimizing" has a stronger 2026 form: catch the bad query
*before* it reaches production, not after. This shift-left framing — borrowed from security and
performance testing — has produced concrete tooling and discipline:

1. **Query plan validation in CI.** Pre-merge hooks that run `EXPLAIN` against changed SQL or
   ORM queries, fail the build on full table scans on large tables, and flag plan regressions
   against a baseline. This is the slow-log feedback loop, moved left to PR review.
2. **Migration safety review patterns.** Tools like Bytebase, Atlas, and Skeema treat migrations
   as code that is reviewed, linted, and tested in CI against a production-shaped schema
   snapshot before any DDL touches production. A migration that would lock a hot table for 20
   minutes should fail CI, not page on-call.
3. **Synthetic production-scale fixtures.** The "test migration in staging against
   production-scale data" rule from §2 becomes operationally feasible when the test environment
   is a managed branch (PlanetScale branches, Aurora cloning) that materializes
   production-shaped data on demand.

Cross-link: this dovetails directly with the per-dialect footgun catalog in
[`sql_dialect_footguns_expertise.md`](sql_dialect_footguns_expertise.md), which catalogs the
syntactic and semantic traps that pre-merge review needs to recognize. The shift-left tooling
described here is the infrastructure that *runs* the footgun catalog at the right point in the
lifecycle.

- Datadog: best practices for shift-left testing: https://www.datadoghq.com/blog/shift-left-testing-best-practices/
- PlanetScale: declarative schema changes: https://planetscale.com/blog/declarative-schema-changes

### 16.8 LLMs in database operations: where they help, where they don't

The 2024–2026 wave of LLM-assisted database tooling has produced both load-bearing wins and
genuine slop. Two patterns that hold up under Botros-style scrutiny:

1. **LLM-assisted query optimization on a feedback loop.** Datadog DBM's AI root-cause analysis,
   Snowflake Cortex, and similar products work because they pair LLM reasoning with concrete
   instrumentation: actual query plans, actual histograms, actual wait events. The LLM is a
   summarizer and pattern matcher; the truth is in the telemetry.
2. **Index recommendation with verification.** LLM-generated `CREATE INDEX` suggestions are
   useful only when paired with `EXPLAIN`-driven verification before the index ships. Index
   maintenance has a write-amplification cost (§3); accepting LLM recommendations without
   verification is exactly the failure mode the chapter on indexing was written against.

Patterns that do NOT hold up:

1. **LLM-generated migrations applied without review.** A migration written by an LLM is still a
   migration; the §2 discipline applies in full. The novelty of the author does not change the
   discipline.
2. **"AI DBA" framing as a replacement.** The DBRE model in §1 is explicitly about distributing
   database expertise into developer workflows and tooling. An LLM is one such tool — useful in
   the same way that VividCortex/DPM was useful — but not a replacement for staff-level judgment
   on architecture, on-call response, or compliance trade-offs.

### 16.9 What's missing in Botros's 2024–2026 public output

For honesty: there is no new book, no consistent blog cadence, and no 2024–2026 conference talk
visible in public listings that updates the 4th edition's posture for the current MySQL release
train, Vitess maturity, or distributed-SQL landscape. The Changelog *Ship It!* #118 appearance
(2024) remains the most recent long-form primary source. The principles in this doc are stable
*because* they are framed at the level of stance — stability is a feature, name the trade-off,
force-multiply — and stance survives a multi-year gap in primary publication. But the next
edition of this synthesis (or a 5th edition of *High Performance MySQL*, should one ship) will
need to integrate the items in §16.1–§16.8 into the core chapters rather than maintain them as a
trailing currency layer.

- Changelog *Ship It!* #118 with Silvia Botros: https://changelog.com/shipit/118
- Trends in Relational Databases 2024-2025 (Rapydo overview): https://www.rapydo.io/blog/trends-in-relational-databases-rdbms-for-2024-2025
