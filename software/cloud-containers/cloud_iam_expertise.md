# Cloud IAM — Trust Policies, Cross-Account Chains, and Workload Identity
## Synthesized from the AWS / Azure / GCP Offensive Research Corpus

> **Primary researchers and practitioners:**
>
> - **Nick Frichette** (`@Frichette_n`) — Staff Security Researcher at Datadog Security Labs;
>   creator and primary maintainer of **Hacking the Cloud**
>   (https://hackingthe.cloud), the canonical encyclopedia of offensive cloud techniques. His
>   AWS-specific corpus on IAM trust-policy abuse — including the 2024 AWS Amplify Cognito
>   identity-pool takeover (CVE-2024-28056) co-disclosed with AWS — is the practitioner reference
>   for "what does the trust-policy attack surface actually look like in 2024-2026."
> - **Spencer Gietzen** — co-creator of **Pacu** (RhinoSecurityLabs), the
>   "Metasploit for AWS" exploitation framework, and primary author of the
>   `RhinoSecurityLabs/AWS-IAM-Privilege-Escalation` enumeration of 21 documented privesc paths
>   (`iam:CreatePolicyVersion`, `iam:PassRole` + `lambda:CreateFunction`, etc.) that became the
>   community baseline for IAM privesc detection.
> - **Scott Piper** (`@0xdabbad00`) — proprietor of **Summit Route**. Created **flaws.cloud** and **flaws2.cloud** — the two CTF corpora
>   that introduced a generation of practitioners to IAM-misconfiguration attack patterns. Wiz
>   research partner on **cloudvulndb.org**.
> - **Aidan Steele** (`@__steele`) — independent AWS researcher; **awsteele.com** is the
>   reference blog for IAM/STS internals. Reverse-engineered the AKIA/ASIA access-key-ID
>   account-ID encoding; documented CloudShell credential plumbing. AWS Hero.
> - **Daniel Bohannon** (`@danielhbohannon`) — Principal Threat Researcher at **Permiso
>   Security** (CDR — Cloud Detection & Response); formerly Microsoft and Mandiant. Co-author of
>   the AWS abuse-detection corpus that informs much of the CloudTrail anomaly-detection
>   tradecraft cited in §9. (Note: Bohannon is at Permiso, not SpecterOps — corrected from the
>   spec.)
> - **Dirk-jan Mollema** (`@_dirkjan`) — proprietor of **Outsider Security**; the canonical
>   authority on Microsoft Entra ID / Azure AD attack research. Author of **ROADtools** and
>   **roadtx**, the primary Entra-ID enumeration and PRT-abuse frameworks. His blog
>   (https://dirkjanm.io) documents Primary Refresh Token theft, device-registration abuse, and
>   conditional-access bypass with the depth that no vendor doc reaches.
> - **Beau Bullock** (`@dafthack`) — Senior Security Analyst at
>   **Black Hills Information Security**; author of **MSOLSpray** and the
>   **Breaching the Cloud** training. His Azure / Entra ID red-team corpus (password-spray
>   tradecraft, OAuth consent phishing, Exchange Online ATO via add-ins) is the practitioner
>   reference for "what does Entra ID look like to a red team."
> - **Andy Robbins** (`@_wald0`) — Principal Security Researcher at **SpecterOps**; co-creator
>   of **BloodHound** and **AzureHound**. Architect of the BloodHound 4.0 Azure Update (with
>   Rohan Vazarkar and Ryan Hausknecht) that unified on-prem AD and Entra-ID attack-path
>   discovery. His Microsoft 2024 Midnight Blizzard breach analysis ("Microsoft Breach — What Happened?
>   What Should Azure Admins Do?") is canonical.
> - **Will Schroeder** (`@harmj0y`) — Principal Security Researcher at **SpecterOps**;
>   co-creator of BloodHound, PowerSploit, Empire, GhostPack, and the **Certified Pre-Owned**
>   AD CS research. Authority on the on-prem-AD ↔ cloud-IAM bridge — the same attack-graph
>   discipline that unmasked ESC1-ESC8 also unmasks hybrid AD trust paths into Entra.
> - **Shir Tamari** (`@shirtamari`) — Head of Research at **Wiz**.
>   Discoverer of **ChaosDB** (Azure Cosmos DB cross-tenant leak, Aug 2021), **OMIGOD**
>   (silently-deployed Azure OMI agent), and **ExtraReplica** (cross-account Azure
>   PostgreSQL).
> - **Christophe Tafani-Dereeper** (`@christophetd`) — Senior Cloud Security Researcher at
>   Datadog; core maintainer of **Stratus Red Team** (https://stratus-red-team.cloud), the
>   open-source cloud adversary-emulation framework. Stratus codifies AWS / Azure / GCP /
>   Kubernetes attack techniques as one-command detonations against a real cloud account, with
>   automatic warm-up and clean-up.
>
> Sources: hackingthe.cloud; flaws.cloud; flaws2.cloud; awsteele.com blog (2020-2026);
> securitylabs.datadoghq.com; dirkjanm.io blog and roadtools repo; blog.harmj0y.net;
> specterops.io blog; wiz.io blog (ChaosDB, OMIGOD, ExtraReplica writeups);
> blog.christophetd.fr; stratus-red-team.cloud; AWS / Azure / GCP official IAM documentation;
> CISA Cyber Safety Review Board Microsoft Storm-0558 / Midnight Blizzard reports; Mandiant
> UNC5537 Snowflake report (June 2024); Praetorian, Plerion, NCC Group, Rhino Security Labs
> AWS IAM privesc corpus.

---

## 1. The Cloud IAM Threat Model

### Identity is the new perimeter

The defining shift between on-prem and cloud security is the location of the trust boundary.
In the data-center model, the network perimeter (firewalls, VPN, DMZ) is primary; identity is
enforced by Active Directory **inside** that boundary. In the cloud model, there is no
internal network boundary in the same sense: every API call is an Internet-routable request
to a public endpoint authenticated by an identity token. Network controls (VPCs, Security
Groups, NSGs) are still useful, but the first and most-load-bearing boundary is IAM. A
compromised IAM principal *is* the compromise.

This shift is why the dominant cloud breaches of the last decade — Code Spaces (2014),
Capital One (2019), ChaosDB (2021), Storm-0558 (2023), Midnight Blizzard (2024),
Snowflake/UNC5537 (2024), AWS Amplify CVE-2024-28056 (2024) — are not RCE breaches. They are
IAM breaches. A scanner finding a CVE in a workload would not have prevented any of them.
Every one traces to (a) a misconfigured trust relationship, (b) a credential exposed outside
its intended boundary, or (c) a token-issuance service that issued tokens to the wrong
principal. Cross-link to [[distributed_authz_expertise.md]] §2 — cloud IAM is the
infrastructure-layer instance of the same trust-boundary discipline.

### Control plane vs data plane

Cloud providers separate the **control plane** (`ec2:RunInstances`, `s3:PutBucketPolicy`,
`iam:CreateUser`) from the **data plane** (`s3:GetObject`, `dynamodb:Query`, `kms:Decrypt`).
Both are authenticated by IAM, but the blast radius is asymmetric: a control-plane compromise
can re-shape the data-plane authorization graph. An attacker with `iam:UpdateAssumeRolePolicy`
does not need to escalate further — they can rewrite any role's trust policy. Code Spaces
(2014) was a pure control-plane attack: the attacker did not exfiltrate data; they deleted it
via `s3:DeleteBucket`, `ec2:TerminateInstances`, and EBS snapshot deletion. The business
never recovered.

### Resource-policy vs identity-policy duality

AWS and Azure implement a dual policy model: an identity can be granted permission to act,
**and** a resource (bucket / queue / key) can be granted permission to be acted upon. GCP
historically uses a resource-centric model, though bucket-level IAM is increasingly common.
For same-account access either policy suffices; for cross-account, both source identity
policy AND target resource policy must allow. Explicit `Deny` in any layer wins.

### The four IAM "currencies"

Every cloud IAM model decomposes into four primitives — vocabulary differs across providers
but mechanics are the same: **Principal** (AWS IAM User/Role/Service Account; Azure
User/SP/Managed Identity/Application; GCP User/SA/Group), **Permission** (AWS identity
policy + permission boundary; Azure RBAC role + Entra directory role; GCP IAM role),
**Resource** (S3 Bucket / KMS Key / SQS Queue; Storage Account / Key Vault / Resource Group;
GCS Bucket / BigQuery Dataset), **Trust Relationship** (AWS trust policy; Azure CA + app
consent; GCP SA IAM policy via `actAs`). Every cloud-IAM bug is a misconfiguration of one of
these or an edge between them.

### Defense-in-depth: IAM is necessary but not sufficient

IAM is the first boundary, but policy is data — typo-prone, subject to drift, frequently
authored without security review. Production cloud security stacks IAM with network policy
(VPC peering, Private Endpoints, no-public-IP), encryption (KMS with key policies that
duplicate the IAM check), audit (CloudTrail / Activity Log / Cloud Audit Logs), and
automated detection (IAM Access Analyzer, Defender, SCC). Cross-link to
[[detection_engineering_expertise.md]] §9.

---

## 2. AWS IAM in Depth

AWS IAM is the oldest, most-feature-dense, and most-attacked of the three clouds. The mental
model below is what an offensive practitioner brings to a new AWS account.

### IAM Users vs IAM Roles vs IAM Identity Center

**IAM Users** are long-lived identities with up to two long-lived access-key pairs (AKIA-
prefixed). They are the source of most credential-leakage incidents (committed to GitHub,
leaked in CI logs). AWS's own guidance is that IAM users are generally not the best choice
for managing access.

**IAM Roles** have no long-lived credentials; they are assumed via STS, producing temporary
ASIA-prefixed credentials with a session token. Roles are the right primitive for workloads
(EC2, ECS, Lambda), cross-account access, and federation.

**IAM Identity Center** (formerly AWS SSO) is the AWS-native federation broker: an external
IdP authenticates the human, Identity Center maps them to a role in one or more accounts,
the user gets temporary credentials via the access portal. Recommended for human access.

### The five-policy evaluation order

When an IAM principal calls an AWS API, AWS evaluates **five** policy types and computes an
effective decision. Understanding the order is essential because mistakes in trust-policy
authoring fail in subtle ways at the intersection of these layers.

| # | Policy Type | What It Does | Where Attached |
|---|---|---|---|
| 1 | Service Control Policy (SCP) | Org-wide guardrail; can only deny or limit | AWS Organizations OU / Account |
| 2 | Resource Policy | Grants cross-account access; statement attached to the resource | S3 bucket, KMS key, etc. |
| 3 | Permission Boundary | Caps the permissions of an identity even if its identity policy grants more | IAM User / Role |
| 4 | Session Policy | Further restricts a specific STS session | Passed in AssumeRole call |
| 5 | Identity Policy | Grants permissions to a principal | IAM User / Role |

Evaluation rule: any explicit `Deny` wins. Otherwise the request is allowed only if it
passes every layer: SCP AND (resource policy OR identity policy) AND permission boundary AND
session policy. Same-account needs one of resource/identity; cross-account needs both. A
permission boundary is **not** a grant — it caps what identity policy can do.

### Trust policies — the most-frequently-misconfigured surface

The trust policy on an IAM Role is the resource policy attached to the role: it declares
who can call `sts:AssumeRole`. Every cross-account, federated, and service-to-service path
passes through one. A naive `Principal: {"AWS": "arn:aws:iam::111122223333:root"}` permits
**anyone** in account 111122223333 — a coarse boundary. The trust policy AND the source-side
identity policy must both allow; a common error is "the trust policy is enough."

Condition keys that defend trust policies:

| Condition Key | Defends Against | Required For |
|---|---|---|
| `sts:ExternalId` | Confused deputy: a third party tricked into assuming your role | Every cross-account trust policy granted to a SaaS vendor |
| `aws:PrincipalOrgID` | Trust policy granting `Principal: "*"` to anyone in your org | Org-wide cross-account access |
| `aws:SourceAccount` | Service-linked role being passed an arbitrary `SourceArn` | Trust policies granted to AWS services (sns, s3, etc.) |
| `aws:SourceArn` | Same — confused deputy via service action | Trust policies granted to AWS services |
| `token.actions.githubusercontent.com:sub` | Arbitrary GHA workflow assuming role | GitHub OIDC trust policies |

The Frichette / Datadog **Amplified Exposure** disclosure (CVE-2024-28056) is the canonical
recent trust-policy abuse: Amplify-created roles permitted
`cognito-identity.amazonaws.com:amr = "unauthenticated"` without binding to a specific
identity-pool ID. An attacker could create a Cognito identity pool in their own account, mint
a Web Identity token, and `sts:AssumeRoleWithWebIdentity` against the victim's role. AWS
patched in two stages (Feb / Apr 2024); STS now rejects cross-account assumption of roles with these trust policies.
Reference: https://securitylabs.datadoghq.com/articles/amplified-exposure-how-aws-flaws-made-amplify-iam-roles-vulnerable-to-takeover/

### STS — the token issuance API

STS issues temporary credentials. Five primary calls: `AssumeRole` (any principal),
`AssumeRoleWithWebIdentity` (OIDC), `AssumeRoleWithSAML` (SAML), `GetSessionToken` (IAM user,
MFA-bound), `GetFederationToken` (IAM user, federated principal). The "cannot call
GetFederationToken from an assumed-role session" constraint is a **detection primitive** —
if CloudTrail shows it being invoked by AssumeRole-issued credentials, it is anomalous.
AWS recommends using regional STS endpoints.

### IMDS — the Instance Metadata Service

EC2 / ECS / EKS instances receive IAM credentials via
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Combined with SSRF in
workloads, this is the canonical "SSRF → credentials" chain. Cross-link to
[[ssrf_url_parsing_expertise.md]] §6.

**IMDSv1** responds to any HTTP GET — including a forged GET via SSRF. Capital One (2019)
used exactly this chain. **IMDSv2** defends three ways: (1) session-token authentication —
a PUT issues a token, subsequent GETs must present it (SSRF that forges only GETs cannot
complete); (2) IP-hop-limit-of-1 — the response packet's TTL is 1, so it cannot route off the
instance; (3) `HttpTokens=required` refuses IMDSv1 at the instance level. IMDSv2 is necessary
but not sufficient: a real SSRF originating *on* the instance still works (hop 0 inside, 1
out). Since March 2024, AWS lets accounts set IMDSv2 as the default for all new
instance launches.

### Service Control Policies and Permission Boundaries

**SCPs** are the org-level guardrail. An SCP attached to an OU caps maximum permissions for
every principal in every account in that OU; they only deny / restrict, never grant.
Baseline SCP set for production: deny `iam:UpdateAssumeRolePolicy` for non-admins, deny
`iam:CreateAccessKey` for users, deny `cloudtrail:StopLogging`, deny
`ec2:DisassociateIamInstanceProfile`, deny `s3:PutBucketPolicy` with `Principal: "*"`.

**Permission boundaries** are the delegation primitive: a "trusted admin" lets a team
self-service IAM authoring within a bounded subset. Without a boundary, `iam:CreateRole` is
effectively full IAM.

### The Pacu enumeration model

After foothold (leaked key, IMDS SSRF, etc.), the playbook is: `sts:GetCallerIdentity` →
enumerate identity policy via `iam:List/Get*` → simulate effective permissions via
`iam:SimulatePrincipalPolicy` → enumerate S3 / EC2 / Lambda / KMS / Secrets Manager → match
against the 21 documented privesc paths (Pacu's `iam__privesc_scan`) → establish persistence
(new access keys, new role with attacker-trusting policy, Lambda code replacement) → exfil →
anti-forensics (CloudTrail / GuardDuty disable, if SCP allows). Reference:
https://github.com/RhinoSecurityLabs/pacu and the AWS-IAM-Privilege-Escalation repo.

---

## 3. AWS-Specific Attack Patterns

This section enumerates the most-load-bearing privesc primitives. Most are documented in the
Rhino Security Labs corpus; some are recent additions from the DataDog / Plerion / Praetorian
research lanes.

### iam:PassRole — the primary privesc primitive

`iam:PassRole` permits associating a role with a service that will then run code with the
role's permissions. It is **not** assume; it is "give this role to a service that will
execute under it." Privesc forms:

- `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` — function runs as
  high-priv role
- `iam:PassRole` + `ec2:RunInstances` — instance with high-priv instance profile; query IMDS
- `iam:PassRole` + `cloudformation:CreateStack` — stack runs as role
- `iam:PassRole` + `codebuild:CreateProject` / `glue:CreateDevEndpoint` /
  `sagemaker:CreateNotebookInstance` — same shape across services

Defense: scope `iam:PassRole` to specific role ARNs, never `Resource: "*"`. Praetorian's
analysis: `iam:PassRole` on `*` is functionally admin. Reference:
https://www.praetorian.com/blog/privilege-escalation-in-aws-with-passrole-attacks/

### Other AWS privesc primitives

- **`iam:CreatePolicyVersion` + `SetAsDefault: true`** — rewrite a managed policy attached
  to a privileged identity to allow `*:*`. Old versions preserved; the active one is what
  evaluates.
- **`s3:PutBucketPolicy` / `s3:PutBucketAcl`** — grant attacker account access to the bucket;
  `Principal: "*"` plus no `aws:SourceAccount` is also the canonical public-exposure path.
  S3 Block Public Access is the structural defense.
- **`sts:AssumeRole` chain attacks** — if A trusts B trusts C, attacker in C hops C→B→A.
  Chains of 3+ hops are common; CloudTrail captures each hop but cross-account correlation
  is hard. Cartography / PMapper / IAM Access Analyzer model these. Aidan Steele note:
  pin detection on role ARN in `userIdentity`, not the attacker-controlled session-name.
- **`cloudformation:CreateStackSet` + `iam:PassRole`** — single API mutates dozens of
  accounts. Treat as org-admin equivalent.
- **`ssm:SendCommand`** — shell as root / SYSTEM on every SSM-managed instance, and IMDS
  from there. Second most-overlooked privesc after `iam:PassRole`. Stratus Red Team's
  `aws.execution.ssm-send-command` exercises the pattern.
- **`sts:GetFederationToken`** — anti-forensics pivot: federated-principal session breaks
  audit trail back to the IAM User. Alert on use outside a known federation broker.

### The Capital One breach (2019) anatomy

Paige Thompson exploited an SSRF in a ModSecurity WAF on EC2 to reach IMDSv1, retrieving the
WAF role's credentials. The role had `s3:ListAllMyBuckets` + `s3:GetObject` on
customer-data buckets. `aws s3 sync` exfiltrated 106M records. Root causes: SSRF + IMDSv1 +
overpermissive role (WAFs don't need to read customer data). Defenses that would have
prevented: IMDSv2 required, role scope reduced to logging-bucket writes, SCP denying broad
`s3:GetObject` on customer-data prefixes for non-data-plane roles, GuardDuty
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

### The Code Spaces destruction (2014)

Attacker gained access to Code Spaces' AWS control panel. Demanded ransom;
during recovery, attacker used backdoor logins to delete all EBS snapshots, S3
buckets, EC2 instances, AMIs. No off-AWS backups. Company ceased operations next day. The
canonical control-plane-destruction breach. Modern defense: locked-MFA root, off-cloud
backups, SCP-denied `cloudtrail:StopLogging`.

### The Snowflake / UNC5537 campaign (2024)

Mandiant tracked UNC5537 compromising ~165 Snowflake customer instances (AT&T,
Ticketmaster, Santander, LendingTree, Neiman Marcus). Root cause: stolen credentials from
infostealer malware (Vidar / Lumma / Risepro) dating to 2020-2022 dev-laptop infections,
combined with **no MFA**, no IP allow-list, no rotation (some credentials unrotated for as long as four years).
UNC5537 exploited no vulnerability — just valid creds and no MFA. Snowflake made MFA the default for password sign-ins on new accounts
after October 2024 and is phasing out single-factor password sign-ins through 2026. Lesson: the IdP layer is part of cloud IAM; federation to a
central IdP with universal MFA is the structural fix. Reference:
https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion

---

## 4. Azure / Microsoft Entra ID

### The rename, and what didn't change

In 2023, Microsoft renamed Azure Active Directory to Microsoft Entra ID. The branding
changed; the underlying service did not. Most documentation, tooling, and research from the
last decade refers to "Azure AD" — interpret as Entra ID. The Azure tenant model, the
Microsoft Graph API surface, the OAuth 2.0 / OpenID Connect endpoints, the Conditional Access
policy engine — all unchanged.

### Identity types

Entra ID has more identity types than AWS, reflecting its decade of layered design: **User**
(Member or Guest), **Service Principal** (an app's per-tenant instance), **Application** (the
multi-tenant definition; SP is the per-tenant projection), **Managed Identity** (system- or
user-assigned, bound to an Azure resource), **Group** (used in role assignment).

The Application vs Service Principal distinction is the most-confusing: an Application is
the multi-tenant definition (in the home tenant); a Service Principal is the per-tenant
representation. A multi-tenant app has one Application and N Service Principals — one per
tenant that consents. The Midnight Blizzard breach hinges on this distinction.

### Azure RBAC vs Entra ID directory roles — two systems often confused

Two distinct authorization systems:

| System | Scope | Examples | Manages |
|---|---|---|---|
| Azure RBAC | Subscription / RG / Resource | Owner, Contributor, Storage Blob Data Contributor | Azure resources (VMs, Storage, KV) |
| Entra Directory Roles | Tenant | Global Admin, User Admin, App Admin | Users, Groups, Apps, CA policies |

**Global Administrator** in Entra has full directory control but **no default access to
Azure resources**. They can elevate themselves (via "Access management for Azure resources"
toggle) to take RBAC ownership of all subscriptions — one of the highest-signal events;
alert on it. Inversely, Azure RBAC Owner cannot create users, grant directory roles, or
consent to OAuth apps. The systems meet at one point: RBAC subjects are Entra principals;
Entra auth is the source of truth for every Azure check.

### Conditional Access — the main enforcement layer

CA is Entra ID's policy engine. Conditions (user / group / app / location / device platform /
sign-in risk / client app type) gate controls (require MFA, require compliant device, block
access). Midnight Blizzard was a CA-gap breach: a legacy non-prod tenant had no CA-required
MFA; password spray succeeded; OAuth-app abuse from there reached production. Defense:
every tenant has baseline CA-MFA; legacy tenants are decommissioned.

### OAuth consent attacks (illicit consent grant)

Canonical Entra social-engineering attack: attacker registers a multi-tenant app requesting
`Mail.Read` / `Files.Read.All` / `User.Read.All`; sends victim a phishing link to
`login.microsoftonline.com/common/oauth2/authorize?client_id=<attacker_app>&scope=...`; if
victim clicks **Accept**, the attacker's SP in the victim's tenant gets a refresh token with
those scopes. Indefinite access via tokens, not passwords. Why it bypasses defenses: real
Microsoft domain, real password + real MFA, no malware. Password reset does **not** revoke;
remediation requires deleting the SP's `oauth2PermissionGrants` and refresh tokens via Graph.
Microsoft tightened defaults July 2025: users cannot consent to third-party
apps accessing files and sites by default. Reference:
https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants

### Pass-the-PRT (Primary Refresh Token)

Dirk-jan Mollema's research corpus is the reference. The PRT is a 90-day refresh token
issued to an Entra-joined device, bound by a TPM-stored key but exfiltrable by SYSTEM-level
code on the device. Once exfiltrated, mint access tokens for any Entra app from any device.
The on-prem-Windows → Entra-cloud bridge. **Phish for PRT** (Mollema) captures one directly
via a crafted device-registration flow; **roadtx** implements both variants. Defense:
CA-required "compliant device" (Intune-managed, not just Entra-joined); risk-based CA
re-prompts on PRT-cookie use from new device. Reference:
https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/

### Service Principal privilege escalation

`Application.ReadWrite.All` Graph permission lets an SP create new SPs, assign credentials
to any existing SP, and add itself to high-privilege Directory Roles. Effectively
"make me Global Administrator." Same for `RoleManagement.ReadWrite.Directory`. These
permissions are never granted to application SPs without JIT access + strong audit. Steve
Borosh's (`rvrsh3ll`) **TokenTactics** corpus covers SP-token abuse end-to-end.

### Cross-tenant access — B2B Collaboration

Default cross-tenant access permits inbound guests from any tenant. Attacker registers a
tenant, invites the victim's user as a Guest; if accepted, attacker has context in their
own tenant for further social engineering. Defense: tighten cross-tenant access to
allowlist trusted partner tenants only.

### The Midnight Blizzard breach (January 2024)

Russian APT29 compromised Microsoft's corporate tenant. Chain: (1) password spray against a
legacy non-prod test tenant account (no MFA) — compromised Nov 2023; (2) attacker
compromised a legacy test OAuth application with elevated access to the Microsoft corporate
environment; (3) attacker created malicious OAuth applications and a new user account to
grant them consent, then used the legacy test app to grant them the Exchange Online
`full_access_as_app` role; (4) read mail of senior leadership, legal, and security. The CSRB's April 2024 Storm-0558 review
cited it as evidence Microsoft had not yet implemented the necessary governance or
prioritization of security. Root causes: legacy test tenant
without MFA, OAuth app with cross-tenant production scope that audit missed, no anomaly
detection on rare-app token use. Defenses: mandatory CA in every tenant (no exceptions),
quarterly OAuth app inventory, detection on `MicrosoftGraph.Auth.Token` from rarely-used
apps. Reference:
https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/

### The ChaosDB / OMIGOD / ExtraReplica corpus

Wiz Research (Shir Tamari, Sagi Tzadik) drove the canonical Azure platform-isolation
disclosures: **ChaosDB** (Aug 2021, Cosmos DB Jupyter Notebook cross-tenant key leak);
**OMIGOD** (Sept 2021, CVE-2021-38647, silently-installed OMI agent with remote-unauth-root,
no customer documentation); **ExtraReplica** (Apr 2022, cross-account Azure PostgreSQL via
replication). Each reveals a shared-fate dimension: the provider's multi-tenancy
implementation can be the weakness, not customer IAM. Cross-link to
[[container_k8s_security.md]] §11 (managed-control-plane trust).

---

## 5. GCP IAM

GCP IAM is the youngest of the three and structurally cleaner — at the cost of some legacy
quirks.

### Resource hierarchy and inheritance

GCP resources are organized in a strict hierarchy:

```
Organization (one per company)
└── Folder (optional, nested up to 10 deep)
    └── Project (the unit of resource isolation)
        └── Resource (Compute instance, GCS bucket, etc.)
```

IAM policies attached at any level **inherit downward**: a binding at Organization grants the
principal that role on every project and resource. There is no explicit-deny at the inherited
level until **Deny policies** (introduced 2022, still less mature than AWS SCP) — historically
GCP IAM was allow-only. This means an over-broad org-level grant has fewer brakes than its AWS
equivalent.

### Service Accounts vs Workload Identity vs Workload Identity Federation

Three generations of workload identity:

| Generation | Credential | Posture |
|---|---|---|
| Service Account Keys (JSON) | Long-lived RSA private key | Risky — keys leak, rarely rotated |
| Workload Identity (GKE) | KSA→GSA, short-lived | Good — no long-lived secrets |
| Workload Identity Federation | External OIDC/SAML → GCP STS | Best — no GCP-stored credential |

**SA keys** are the GCP equivalent of AWS access keys. Once exported, they cannot be
revoked without explicit deletion. Leaked SA keys are the canonical GCP credential exposure.
Defense: Org Policy `iam.disableServiceAccountKeyCreation`; alert on
`iam.serviceAccountKeys.create`. **Workload Identity** binds a KSA to a GSA via KSA
annotation; pods get short-lived tokens via the GKE metadata server. **WIF** federates from
an external IdP directly to GCP — preferred for CI/CD.

### iam.serviceAccounts.actAs — the AWS iam:PassRole equivalent

To deploy a Compute instance / Cloud Function / Cloud Run / Dataflow / Scheduler with an SA
attached, the deployer needs `actAs` on that SA. Privesc forms mirror AWS PassRole:
`actAs` + `compute.instances.create` / `cloudfunctions.functions.create` /
`run.services.update` / `dataflow.jobs.create`. The stronger primitive is
`iam.serviceAccounts.getAccessToken` — direct impersonation producing OAuth tokens
immediately. Alert on grant. Reference:
https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/

### IAM Conditions and cross-project access

**IAM Conditions** add CEL-expression constraints to bindings — less feature-dense
than AWS condition keys, less consistently supported across GCP services; mature use case
is timeboxed JIT access.

**Cross-project bindings** are the default way GCP composes services (shared-services
project for DNS / logging, plus per-workload projects). The KSA is the security boundary
in GKE Workload Identity: anyone who creates pods under the annotated namespace + KSA can
act as the bound GSA. Cross-link to [[container_k8s_security.md]] §6. Cartography is the
practical multi-project introspection tool.

---

## 6. Workload Identity and OIDC Federation

The "no long-lived credentials in CI" doctrine is the single highest-ROI cloud-IAM hardening
of the 2024-2026 era. Long-lived secrets in CI/CD environments have been the modal cloud
breach precursor since the GitHub access-key-leak boom of 2017-2020. The structural fix is
OIDC federation: CI/CD platforms issue OIDC tokens bound to specific workflows; cloud trust
policies accept those tokens. **No secret is stored in CI.**

### GitHub Actions → AWS

A trust policy that accepts GitHub OIDC:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
      }
    }
  }]
}
```

The two condition keys are load-bearing:

- **`:aud = "sts.amazonaws.com"`** — bounds the token to the AWS STS audience. Required.
- **`:sub`** — bounds the token to a specific workflow context. The subject string format is:
  - `repo:OWNER/REPO:ref:refs/heads/BRANCH` — workflow triggered from a branch
  - `repo:OWNER/REPO:environment:ENV_NAME` — workflow with environment protection
  - `repo:OWNER/REPO:pull_request` — workflow from a pull request (use with caution)

The **unrestricted OIDC trust** anti-pattern is omitting `:sub` (or using `StringLike` with
`*`). Without it, **any GitHub Actions workflow on the public Internet** can assume your
role. Wiz documented this: https://www.wiz.io/blog/avoiding-mistakes-with-aws-oidc-integration-conditions

The `:sub` claim should match the deepest restriction available — environment-protected
workflows over branch-only, branch-pinned over no-branch. Cross-link to
[[cicd_supply_chain_expertise.md]] §7 (CI/CD identity to cloud).

### GitHub Actions → GCP Workload Identity Federation

GCP's equivalent uses attribute mapping from the OIDC token (`google.subject = assertion.sub`,
plus `attribute.repository` / `attribute.repository_owner`) and a Workload Identity Pool
Provider binding that restricts subjects (e.g. `attribute.repository_owner == "my-org"`).
The unrestricted-federation anti-pattern: condition too loose, or absent. Reference:
https://cloud.google.com/blog/products/identity-security/enabling-keyless-authentication-from-github-actions

### IRSA and EKS Pod Identity

**IRSA** (IAM Roles for Service Accounts): EKS pods get AWS credentials via OIDC federation
between the EKS cluster's OIDC issuer and AWS STS. KSA annotation (`eks.amazonaws.com/role-arn`)
plus an admission-controller-injected projected service-account token; pod calls
`sts:AssumeRoleWithWebIdentity`. The role trust policy scopes to OIDC issuer URL +
`system:serviceaccount:NAMESPACE:KSA_NAME`. Anyone who can create a pod with that KSA in
that namespace can use the role.

**EKS Pod Identity** (2023): replaces the OIDC flow with a node daemonset
(`eks-pod-identity-agent`) intercepting SDK metadata requests. Simpler — no per-cluster OIDC
provider, no per-cluster trust configuration. Same security boundary: KSA + namespace pair.
Use IRSA for multi-cluster / EKS-Anywhere / self-managed K8s; Pod Identity for new EKS
clusters in cloud; both coexist.

### Trust-policy hardening for OIDC federation

Common mistakes: (1) no `:sub` restriction — any GHA workflow on the public Internet can
assume the role; (2) `:sub` with `StringLike` and `*` in the wrong place
(`repo:my-org/*` permits any repo in the org, including a fork from a malicious
contributor); (3) no `:aud` restriction; (4) wildcard OIDC issuer. The sub-claim restriction
is the canonical OIDC-federation discipline — the cloud-IAM instance of the same principle
as [[cicd_supply_chain_expertise.md]] §2.

### OIDC vs SAML federation

OIDC tokens are JWT (JSON) — simple signature verification. SAML is XML with XML-DSig
canonicalization, with a much larger parser-confusion attack surface (signature wrapping,
namespace confusion, comment injection). Cross-link to
[[xml_parser_differential_expertise.md]] for the SAML parser-differential failure modes.
Prefer OIDC for new integrations; SAML only when the IdP doesn't speak OIDC.

---

## 7. Cross-Cloud IAM — the Multi-Cloud Reality

Most production orgs in 2026 are multi-cloud. The IAM story across clouds is messy because no
two provider IAMs map perfectly.

### The "AWS user with Azure permission" model

Dominant pattern: a single central IdP (Okta / Entra / Google Workspace) authenticates
humans; each cloud federates to that IdP (Okta → AWS Identity Center → roles; Okta → Entra
→ Azure RBAC; Okta → GCP via SAML or WIF). The IdP is now the universal trust anchor.
Compromise of the IdP is multi-cloud-fatal — why the Okta 2022-2023 breaches drew the
attention they did.

### Trust brokers and cross-cloud secrets

Some orgs run a homegrown trust broker (Cognito → AWS IAM; Auth0 → multi-cloud; custom
OAuth). Brokers add a trust-assumption layer; the Frichette Amplify research (CVE-2024-28056)
is a broker failure — Cognito federation with misconfigured policies. Same defense:
bind to specific audience, specific subject, never accept claims unverified.

**Cross-cloud secrets** are operationally expensive (rotation across clouds requires
SoT + replicator + cache-audit). Prefer eliminating the secret entirely via federation:
workload in A assumes a role in B via OIDC, no stored secret.

### Cross-cloud blast radius

A compromised credential in A that can call B is multi-cloud blast. Examples: AWS EC2 with
stored GCP SA JSON; Azure VM with AWS keys in env; K8s pod with both EKS Pod Identity and
GKE Workload Identity. Detection: inventory cross-cloud credential storage (any GCP SA JSON
outside Secrets Manager is a finding); apply egress controls (VPC Service Controls /
network policies); audit cross-cloud federation policies as rigorously as single-cloud.

---

## 8. Privilege Analysis Tooling

The cloud IAM tooling ecosystem is dense. Categorized by purpose:

### Offensive enumeration / exploitation

- **Pacu** (Rhino) — "Metasploit for AWS"; 50+ modules covering enumeration,
  privesc, persistence, exfil, anti-forensics. https://github.com/RhinoSecurityLabs/pacu
- **CloudGoat** (Rhino) — intentionally-vulnerable AWS labs for IAM-privesc training;
  `cloud_breach_s3` reproduces Capital One.
- **ROADtools / roadtx** (Mollema) — Entra enumeration, PRT extraction, device-registration
  abuse. https://github.com/dirkjanm/ROADtools
- **AzureHound** (SpecterOps) — Entra-ID-aware BloodHound collector.
- **TokenTactics** (Borosh / Cooke) — Microsoft Graph + Azure ARM token manipulation, PRT-cookie
  abuse.
- **MSOLSpray** (Bullock) — Entra password spray.

### Privilege analysis / graph modeling

- **PMapper** (NCC Group) — local IAM-permission simulator + privesc-path graph; offline
  after collection. https://github.com/nccgroup/PMapper
- **Cartography** (CNCF, originally Lyft) — Python tool pulling AWS / GCP / Azure / K8s /
  GitHub / Okta into Neo4j. Most-comprehensive cross-provider modeler.
- **BloodHound** (SpecterOps) — graph-based attack-path discovery; AD + Entra + hybrid.
- **Cloudsplaining** (Salesforce) — IAM-policy analysis; flags overpermissive identity
  policies.

### Native cloud tools

- **AWS IAM Access Analyzer** — automated reasoning for external-access detection;
  least-privilege generation from CloudTrail; pre-deployment policy validation. Free.
- **AWS GuardDuty** — managed threat detection;
  `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` is the canonical
  off-instance-credential detector.
- **Microsoft Defender for Cloud** — multi-cloud CSPM aggregation.
- **GCP Security Command Center** + IAM Recommender — least-privilege recommendations.

### Multi-cloud CSPM / CNAPP

- **Commercial**: Wiz (agentless leader), Orca, Lacework / FortiCNAPP, Prisma Cloud.
- **Open-source**: Prowler (572 AWS checks, actively maintained), ScoutSuite (multi-cloud,
  slowed since 2024), CloudSploit (Aqua, multi-cloud + GitHub).

### Adversary emulation

- **Stratus Red Team** (DataDog / Tafani-Dereeper) — opinionated attack-technique catalog
  with one-command detonate / cleanup for AWS / Azure / GCP / K8s. https://stratus-red-team.cloud
- **Leonidas** (WithSecure) — older AWS adversary emulation.

---

## 9. Detection — IAM-Shaped Patterns

### IAM-as-code Semgrep patterns

Cloud IAM is declared in IaC (Terraform / CloudFormation / Pulumi); Semgrep rules scan at PR
time. High-ROI patterns:

- **Wildcard `Action: "*"` + `Resource: "*"`** on an identity policy — admin-equivalent.
- **Cross-account trust policy missing `sts:ExternalId`** condition — confused-deputy risk.
- **OIDC trust policy missing `:sub` claim restriction** — any workflow on the public
  Internet can assume the role.
- **Long-lived access key in source** — `pattern-regex: 'AKIA[0-9A-Z]{16}'`.
- **EC2 instance without `http_tokens = "required"`** — IMDSv1 allowed.
- **S3 bucket without Block Public Access** enabled.
- **IAM policy with `iam:PassRole` on `Resource: "*"`** — admin-equivalent.

Production rules need richer matching (HCL / YAML / JSON / TypeScript variants) and triage.
A static-analysis authz-detection workflow lane (cross-link [[distributed_authz_expertise.md]] §11) is the
AI-shaped extension: per-CWE prompts that reason about IAM context, not just pattern-match.

### Runtime detection — CloudTrail / Activity Log patterns

- **Enumeration burst** — >50 `iam:List*` / `iam:Get*` calls within 60s from a principal
  that hasn't made these calls in 30 days (Pacu's initial enumeration).
- **`sts:AssumeRole` from unusual source** — outside the bound instance's region, from a
  never-before-seen principal, or to a role that's never been assumed.
- **`sts:GetFederationToken` from non-broker principal** — should only be called by your
  federation broker.
- **`iam:UpdateAssumeRolePolicy`** — anyone rewriting trust policy is high-signal. Alert
  always.
- **`cloudtrail:StopLogging` / `guardduty:DeleteDetector`** — anti-forensics. Alert always;
  deny via SCP.
- **Console login from impossible-travel geography** — Entra Identity Protection ships
  this; AWS requires custom rules over `ConsoleLogin` + IP geolocation; GCP via Cloud
  Logging + Security Command Center.
- **AssumeRole chain anomaly** — chains that traverse to roles outside the source's normal
  pattern. PMapper / Cartography graph the baseline; alert on new edges or chain-length
  growth. Reference: https://www.uptycs.com/blog/detecting-anomalous-aws-sessions-temporary-credentials

Cloud IAM detection sits in the broader detection-engineering discipline — same MITRE
ATT&CK Cloud Matrix categories, same maturity progression (atomic → correlation → ML →
graph-based attack-path inference), same FP-tuning discipline. Cross-link to
[[detection_engineering_expertise.md]] §9.

---

## 10. Defensive Patterns

### Principle of Least Authority applied to cloud IAM

Same principle, different stack. Every grant is the minimum sufficient for the workload's
documented function. Cross-link to [[agentic_web_capabilities_expertise.md]] — the
capability-discipline language ports directly: every grant is a capability issuance, every
role is a capability set, the goal is least authority (privilege is too coarse a unit).

### Operational rules

- **No long-lived credentials outside Secrets Manager / KMS / Vault.** AWS SCP denies
  `iam:CreateAccessKey`; GCP Org Policy `iam.disableServiceAccountKeyCreation`; Entra
  alerts on SP client-secret creation. Federate everything else.
- **OIDC federation for all CI/CD → cloud.** Cross-link to
  [[cicd_supply_chain_expertise.md]] §7.
- **Strict condition keys on every trust policy** — `sts:ExternalId` for vendor cross-account,
  `aws:PrincipalOrgID` for org-internal, `aws:SourceAccount` + `aws:SourceArn` for
  service-linked, `:aud` + `:sub` for OIDC, attribute mapping with `repository` /
  `repository_owner` for GCP WIF, `saml:aud` for SAML. A trust policy without conditions
  is a finding.
- **Centralized IdP with universal MFA.** One IdP (Okta / Entra / Google Workspace) is the
  source of human identity; every cloud federates; CA enforces MFA. UNC5537 / Snowflake
  shows this extends to SaaS — if Snowflake / Databricks isn't federated, you have a gap.
- **Baseline SCP / Org Policy set.** AWS: deny `iam:UpdateAssumeRolePolicy` for non-admins,
  deny `cloudtrail:StopLogging`, deny `s3:PutBucketAcl` allowing public, deny
  `ec2:RunInstances` outside approved regions, deny `iam:CreateUser`, require IMDSv2
  (`ec2:MetadataHttpTokens: "required"`). Azure: management-group + Conditional Access +
  Azure Policy. GCP: Org Policies + Deny Policies.
- **IAM Access Analyzer as continuous lint.** Enable at the org level; investigate every
  external-access finding; use unused-access reports (2023) to remove dormant permissions.
- **Quarterly IAM review** — rotate access keys >90 days old; review every cross-account
  trust; audit Entra apps for `Application.ReadWrite.*` / `RoleManagement.ReadWrite.*`
  grants; inventory GCP SA keys.

### Code review checklist

When reviewing a PR that touches cloud IAM, block if the PR:

1. Grants `*:*` / `Action: "*"` anywhere.
2. Adds a trust policy without `:sub` / `ExternalId` / `SourceAccount` / `OrgID` condition.
3. Grants `iam:PassRole` (or `iam.serviceAccounts.actAs`) on `Resource: "*"`.
4. Grants `iam:CreateAccessKey` / `iam:CreateLoginProfile` (federate instead).
5. Grants `iam:UpdateAssumeRolePolicy` to non-admins.
6. Creates an EC2 instance without `http_tokens = "required"`.
7. Creates an S3 bucket without Block Public Access.
8. Grants Entra `Application.ReadWrite.All` / `RoleManagement.ReadWrite.Directory` /
   `Directory.AccessAsUser.All` without justification.
9. Creates a GCP SA with a downloaded JSON key (use Workload Identity / WIF instead).
10. Adds a CA policy without break-glass exemption.
11. Removes an existing condition key without security review.
12. Adds a new federation trust (SAML/OIDC) without verifying IdP discovery URL + `:aud`.

Cross-link to [[code_review_expertise.md]] — cloud-IAM review is the resource-policy
instance of the same auditor-vs-developer pattern.

---

## 11. Variant Analysis — Under-Explored

### Cloud IAM for AI agents

When an LLM-driven agent needs cloud capabilities, the question is authentication shape and
blast radius. Naive approach — long-lived SA key — multiplies the credential-leak risk
because the agent runs adversarially-influenced inputs as a matter of normal operation.
Preferred: per-task short-lived STS sessions with scoped session policy (15-60 min);
capability-token model (specific S3 prefixes / specific Bedrock models / specific Lambda
ARNs, not generic role); human-in-loop approval for elevated operations. Cross-link to
[[agentic_web_capabilities_expertise.md]].

### Cross-cloud workload identity

Workload that needs both AWS and GCP: chain the federation. An EKS workload
exchanges its Kubernetes service-account token to GCP via WIF pointing at the EKS OIDC issuer; GCP→AWS
mirrors via AWS trust policy accepting `accounts.google.com` as OIDC issuer. No long-lived
secret crosses cloud boundaries.

### Edge / IoT device identity

AWS IoT Core, Azure Sphere, GCP Cloud IoT (deprecated): per-device X.509 certificate,
cloud-side trust anchor verifies, cert claim → per-device IAM scope. Failure modes: shared
CA without per-device pinning (one device's cert unlocks fleet); over-broad device policies
(`iot:*` rather than scoped `iot:Publish`); IoT cert-to-AWS-cred bridging via
`iot:AssumeRoleWithCertificate` (same trust-policy hygiene as AssumeRoleWithWebIdentity).

### Serverless IAM — per-function role boundaries

Every Lambda / Cloud Function / Azure Function has its own role with its own minimal policy.
Shared roles across functions defeat the boundary. Deployer role is distinct from execution
role: CI/CD has `lambda:UpdateFunctionCode`, the runtime role has data permissions.
Cross-link to [[container_k8s_security.md]] §6.

### Shadow IT cloud accounts and M&A IAM cleanup

Engineers create personal AWS / Azure / GCP accounts with corporate emails — outside SCP,
outside audit, the canonical insider-exfil channel. Detection: AWS Organizations /
Azure tenant / GCP customer email-domain audit, CASB network-egress to
`*.amazonaws.com` / `*.azure.com` / `*.googleapis.com` outside corporate boundary, vendor
billing scan.

**M&A IAM merge** is a multi-quarter project: account/subscription/project transfer, IdP
consolidation, SCP reconciliation, trust audit (B may have granted access to A's
competitors), stale-credential rotation. Wiz / Orca / commercial CSPM increasingly support
multi-org views.

---

## 12. References

### Primary cloud-IAM documentation

- **AWS IAM User Guide** — https://docs.aws.amazon.com/IAM/latest/UserGuide/
- **AWS IAM Policy Evaluation Logic** —
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- **AWS STS API Reference** — https://docs.aws.amazon.com/STS/latest/APIReference/
- **AWS IAM Access Analyzer** — https://aws.amazon.com/iam/access-analyzer/
- **AWS EC2 IMDS** —
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- **Microsoft Entra ID Documentation** — https://learn.microsoft.com/en-us/entra/
- **Microsoft Entra Conditional Access** —
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/
- **GCP IAM Documentation** — https://cloud.google.com/iam/docs
- **GCP Workload Identity Federation** —
  https://cloud.google.com/iam/docs/workload-identity-federation
- **GCP Service Accounts actAs** —
  https://cloud.google.com/iam/docs/service-accounts-actas

### Researcher blogs and corpora

- Nick Frichette — https://hackingthe.cloud/, https://frichetten.com/blog/
- Aidan Steele — https://awsteele.com/
- Scott Piper / Summit Route — https://summitroute.com/, http://flaws.cloud/,
  http://flaws2.cloud/, https://cloudvulndb.org/
- Dirk-jan Mollema / Outsider Security — https://dirkjanm.io/
- Beau Bullock / BHIS — https://www.blackhillsinfosec.com/team/beau-bullock/
- SpecterOps (Robbins, Schroeder) — https://specterops.io/blog/,
  https://blog.harmj0y.net/
- Wiz Research (Shir Tamari) — https://www.wiz.io/blog
- Christophe Tafani-Dereeper — https://blog.christophetd.fr/

### Tools

- Pacu — https://github.com/RhinoSecurityLabs/pacu
- AWS-IAM-Privilege-Escalation — https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
- CloudGoat — https://github.com/RhinoSecurityLabs/cloudgoat
- PMapper — https://github.com/nccgroup/PMapper
- Cartography — https://github.com/cartography-cncf/cartography
- BloodHound / AzureHound — https://github.com/SpecterOps/BloodHound,
  https://github.com/SpecterOps/AzureHound
- ROADtools — https://github.com/dirkjanm/ROADtools
- TokenTactics — https://github.com/rvrsh3ll/TokenTactics
- Stratus Red Team — https://github.com/DataDog/stratus-red-team
- Prowler / ScoutSuite / Cloudsplaining —
  https://github.com/prowler-cloud/prowler, https://github.com/nccgroup/ScoutSuite,
  https://github.com/salesforce/cloudsplaining

### Breach reports

- Code Spaces (2014) — https://www.breaches.cloud/incidents/codespaces/
- ChaosDB —
  https://www.wiz.io/blog/how-we-broke-the-cloud-with-two-lines-of-code-the-full-story-of-chaosdb
- ExtraReplica —
  https://www.wiz.io/blog/wiz-research-discovers-extrareplica-cross-account-database-vulnerability-in-azure-postgresql
- Storm-0558 CSRB (Apr 2024) —
  https://www.cisa.gov/sites/default/files/2024-04/CSRB_Review_of_the_Summer_2023_MEO_Intrusion_Final_508c.pdf
- Midnight Blizzard —
  https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- UNC5537 (Mandiant, Jun 2024) —
  https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- AWS Amplify CVE-2024-28056 (Datadog) —
  https://securitylabs.datadoghq.com/articles/amplified-exposure-how-aws-flaws-made-amplify-iam-roles-vulnerable-to-takeover/

### Cross-references within this repository

- [[container_k8s_security.md]] — workload-identity bridge (GKE Workload Identity, EKS IRSA /
  Pod Identity, AKS managed identities).
- [[distributed_authz_expertise.md]] — trust-boundary topology, federation discipline, the
  AuthN/AuthZ/binding three-step chain; cloud-IAM is the infrastructure-layer instance.
- [[cicd_supply_chain_expertise.md]] §7 — CI/CD identity to cloud; `:sub` claim discipline.
- [[detection_engineering_expertise.md]] §9 — CloudTrail / Activity Log / Audit Log;
  ATT&CK Cloud Matrix mapping.
- [[ssrf_url_parsing_expertise.md]] §6 — SSRF-to-IMDS chain; Capital One.
- [[dns_network_infrastructure.md]] — VPC peering, Private Endpoints, network-layer DiD.
- [[agentic_web_capabilities_expertise.md]] — capability discipline ports to IAM
  least-authority.
- [[appsec_program_building_expertise.md]] — org-level cloud-IAM program design.
- [[code_review_expertise.md]] — auditor-perspective IAM-as-code reviews.

---

## 13. Summary: What Defines Staff-Level Cloud IAM

1. **Identity is the perimeter.** Most cloud breaches trace to IAM, not RCE. The first
   defense is IAM; everything else is defense-in-depth on top of it.

2. **The policy evaluation order in AWS is non-negotiable** — RCP → SCP → resource policy →
   identity policy → permission boundary → session policy, with explicit deny winning
   everywhere. Knowing it is the difference between auditing and guessing.

3. **Trust policies are the most-frequently-misconfigured surface.** Every trust policy
   needs source-appropriate conditions: ExternalId for cross-account, OrgID for
   org-internal, `:sub` for OIDC, SourceAccount + SourceArn for service-linked. No
   conditions = finding.

4. **`iam:PassRole` (and `iam.serviceAccounts.actAs` in GCP) is the primary privesc
   primitive.** Scope to specific ARNs, never `*`. Combined with `lambda:CreateFunction` /
   `ec2:RunInstances` / `cloudformation:CreateStack`, it is admin-equivalent.

5. **IMDS is the canonical SSRF-to-credentials chain.** IMDSv2 + hop-limit-1 + token-required
   is minimum. Capital One is the reference; the controls would have prevented it.

6. **OIDC federation eliminates the long-lived-credential problem** in CI/CD and cross-cloud.
   The `:sub` claim restriction is load-bearing — without it, anyone with an issuer token can
   assume the role.

7. **Entra ID has three distinct policy systems** — Azure RBAC, Entra Directory Roles,
   Conditional Access — routinely conflated. Global Administrator does not include Azure
   RBAC by default.

8. **OAuth consent attacks bypass MFA.** Real Microsoft domain, real password, real MFA;
   defense is tenant-level consent restriction, not user training.

9. **The Primary Refresh Token is the on-prem → cloud bridge.** SYSTEM on an Entra-joined
   device exfils a 90-day PRT. Defense is device-compliance CA + TPM-bound PRT (Mollema).

10. **GCP Service Account keys are the canonical credential exposure.** Disable creation via
    Org Policy `iam.disableServiceAccountKeyCreation`; use Workload Identity / WIF.

11. **The IdP is the universal trust anchor in modern stacks.** Compromising Okta / Entra is
    multi-cloud-fatal. UNC5537 / Snowflake is the proof: IdP MFA enforcement is the
    load-bearing control across all downstream cloud + SaaS auth.

12. **Modern (2023-2026) breaches are not RCE breaches.** Midnight Blizzard, UNC5537,
    Amplify CVE-2024-28056, Storm-0558 — all IAM / federation / token-issuance breaches.
    Defense must match the threat shape.

13. **Detection at the audit-log layer is essential.** CloudTrail / Azure Activity Log / GCP
    Audit Log are the primary forensic substrates; atomic detections feed correlation,
    correlation feeds graph-based attack-path inference. [[detection_engineering_expertise.md]] §9.

14. **IAM is policy-as-code, reviewable like code.** Semgrep + IAM Access Analyzer +
    commercial CNAPPs catch most misconfigurations at PR time; the §10 checklist is the
    human gate.

15. **Cloud IAM is the infrastructure-layer instance of the distributed-AuthZ discipline.**
    Same vocabulary (principal / permission / resource / trust), same failure modes,
    same defense discipline (least authority, identity binding, audit). Cross-link to
    [[distributed_authz_expertise.md]] §12.
