---
title: AI-PR-Review for IaC (Pulumi / Terraform / K8s) — Security Expertise
last_updated: 2026-05-15
status: v1 (initial — IaC-specific sibling to ai_pr_review_platform_expertise.md)
cross_links:
  - ai_pr_review_platform_expertise.md
  - cloud_iam_expertise.md
  - supply_chain_provenance_expertise.md
  - cicd_supply_chain_expertise.md
  - ai_assisted_coding_tool_security_expertise.md
  - llm_agent_security_expertise.md
  - detection_engineering_expertise.md
  - container_k8s_security.md
  - agentic_web_capabilities_expertise.md
  - appsec_program_building_expertise.md
---

# AI-PR-Review for IaC (Pulumi / Terraform / K8s) — Security Expertise

Sibling to [[reference-ai-pr-review-platform]] covering the IaC-specific threat model. Where the general AI-PR-review doc treats reviewer-vs-attacker dynamics at the source-code level, this doc treats the same dynamics when the reviewed PR carries *apply-time authority over cloud resources*: IAM, network, KMS, state files. The blast radius of a wrongly-approved IaC PR is the production cloud account, not a single application.

**Author:** autonomous-loop /loop session, 2026-05-15. Sibling to AI-PR-review platform doc (shipped shift 2 lane C).

## 1. Why IaC review is a different threat model

An IaC PR is not a source-code change. It is a *declaration of the cloud's desired state*. When the PR merges and the CD pipeline runs `terraform apply` (or `pulumi up`, or `kubectl apply -f`), the cloud reshapes itself to match. The reviewer's approval is the gate between the human-authored declaration and the cloud-control-plane mutation.

This changes the threat model in three specific ways relative to source-code PR review:

- **Blast radius is the cloud account, not the application.** A wrongly-approved app-source PR ships a bug or a regression; a wrongly-approved IaC PR can wildcard an IAM role, open a security group to `0.0.0.0/0`, delete a KMS customer-managed key (with the seven-to-thirty-day deletion window cancellable only inside that window), or move a Terraform state file out from under the team. Cross-link [[reference-cloud-iam]] §2 "AWS IAM in Depth" for the full privesc primitive catalog the reviewer must understand.
- **The diff lies.** Terraform `plan` output is the canonical reviewer artifact, but the plan can be misleading. A resource rename in HCL can show up as a destroy-then-create plan; a `moved` block converts that to a no-op; a missing `moved` block silently deletes data. The reviewer who reads `plan` output as ground truth is reading a high-fidelity but lossy representation.
- **AI velocity amplifies blast radius.** AI reviewers operate at high tool-use rate. A general-purpose reviewer that approves three hundred PRs a week, twenty of which touch IaC, only needs to misclassify one to widen an IAM role. Auto-approve on IaC PRs is structurally more dangerous than auto-approve on source-code PRs because the failure mode is "cloud account compromised," not "test suite broken."

The downstream consequence is that "the same AI reviewer that handles source-code PRs" is the wrong default for IaC. Either the reviewer needs IaC-specific knowledge (the cloud-context-aware platforms in §3), or IaC PRs need a dedicated reviewer with cloud awareness, or IaC PRs need human-only review on a stricter approval policy.

## 2. IaC ecosystem landscape (2024-2026)

A reviewer that understands "IaC" but treats it as one language is structurally wrong. The ecosystem fragments into ~8 substrates, each with distinct semantics, drift behavior, and approval surface.

- **Terraform / OpenTofu.** HashiCorp Terraform shipped under MPL 2.0 until August 2023, when HashiCorp moved to the Business Source License (BSL 1.1). The OpenTofu fork (originally OpenTF, hosted by the Linux Foundation) emerged in response and was first released January 2024. IBM acquired HashiCorp April 2024 (announced; closed February 2025 [unverified exact close date]). As of 2026 the practical situation is bifurcated: Terraform Enterprise customers stay on Terraform; many community users moved to OpenTofu; provider ecosystem is largely shared. Reviewers must handle both — module syntax is identical, but the registry endpoints and license posture differ.
- **Pulumi.** Founded 2017. General-purpose programming languages (TypeScript, Python, Go, .NET, Java, YAML) compile to a "deployment plan" via the Pulumi engine. Component resources allow encapsulation; state stored in Pulumi Service or in customer-managed backends (S3, Azure Blob, etc.). The reviewer's challenge: the IaC is *code*, so the reviewer must handle conditional logic, loops, and dynamic resource creation that Terraform's HCL constrains.
- **AWS CDK and CDKTF.** AWS Cloud Development Kit (TypeScript / Python / Java / Go / .NET) compiles to CloudFormation; CDKTF (CDK for Terraform) compiles to Terraform JSON. Same code-as-IaC challenge as Pulumi.
- **Crossplane.** Kubernetes-native IaC: cloud resources expressed as Kubernetes Custom Resources (XRs) and Compositions. Drift detection via Kubernetes controllers. The reviewer is reviewing Kubernetes YAML that has cloud-control-plane semantics — both the K8s RBAC surface and the cloud-IAM surface apply simultaneously.
- **Helm and Kustomize.** Kubernetes package management. Helm charts are templated YAML (Go templates over Kubernetes manifests); Kustomize uses overlays. Both inherit the K8s RBAC, hostPath, privileged-container threat model. Cross-link [[reference-container-k8s-security]] for full coverage.
- **cdk8s.** AWS-sponsored project for generating Kubernetes manifests from TypeScript / Python / Java / Go. Same code-as-IaC challenge applied to K8s.
- **Bicep.** Microsoft's DSL over ARM templates. Domain-specific syntax that compiles to JSON ARM. Used primarily in Azure shops. Reviewer must understand resource provider versioning and ARM template semantics.
- **CloudFormation, ARM (Azure), Deployment Manager (GCP).** Native template languages. Deployment Manager was deprecated by Google in 2023 with a recommended migration to Terraform or Config Connector. CloudFormation remains the canonical AWS substrate; ARM remains the canonical Azure substrate.

Honest distribution-of-use snapshot for 2024-2026: most IaC in active production is still Terraform (Enterprise + OSS + OpenTofu combined), with Pulumi as a meaningful and growing minority and CloudFormation persistent in AWS-only shops. Bicep is dominant in Azure-native organizations. Crossplane and cdk8s remain smaller but high-leverage where adopted. [unverified] precise market-share figures — vendor surveys (HashiCorp State of Cloud Strategy, Pulumi user surveys) are not independent and selection-biased.

## 3. AI-review platforms that handle IaC specifically

Most general-purpose AI reviewers from [[reference-ai-pr-review-platform]] §1 nominally accept Terraform, Pulumi, and Kubernetes YAML as input. The question is whether they understand *cloud-context semantics* — does the reviewer know that opening a security group to `0.0.0.0/0` on port 22 is bad, that an IAM policy with `Resource: "*"` and `Action: "*"` is a privesc primitive, that a KMS key deletion in this account would orphan three encrypted S3 buckets?

| Platform | IaC coverage | Cloud-context-aware | Provenance / attestation | Enterprise SSO/SCIM | Pricing tier |
|---|---|---|---|---|---|
| **Snyk IaC / Snyk Cloud** | Terraform, CloudFormation, ARM, K8s YAML, Helm, Kustomize | Yes — Snyk Cloud joins IaC findings to live cloud config for context | Snyk-built rule packs; sigstore / cosign image signing supported on Snyk Container side | SSO + SCIM enterprise | Free → Team → Enterprise (per-developer) |
| **Wiz Code** | Terraform, CloudFormation, K8s YAML, Helm | Yes — Wiz Code is part of the Wiz Cloud platform; IaC findings join the Security Graph with live cloud context | Sigstore awareness for container build context | SSO + SCIM enterprise | Enterprise-only |
| **Prisma Cloud Code Security (Bridgecrew)** | Terraform, CloudFormation, ARM, K8s YAML, Helm, Kustomize, Serverless | Yes — Palo Alto's Prisma Cloud joins IaC to live cloud config | Sigstore/cosign for container; provenance via Prisma Cloud platform | Enterprise SSO + SCIM | Enterprise per-asset pricing |
| **Aqua / Trivy** | Terraform, CloudFormation, K8s YAML, Dockerfile | Partial — Trivy IaC scans without cloud context; Aqua Platform adds runtime context | Trivy supports sigstore verification | Enterprise via Aqua | OSS Trivy + Aqua commercial |
| **Spectral (Check Point)** | Terraform, CloudFormation, K8s YAML | Limited cloud-context | [unverified] | Enterprise | Acquired by Check Point 2021 |
| **CodeRabbit** | Terraform / HCL, K8s YAML files reviewed; "experimental" Pulumi support | No structural cloud-context awareness — LLM may pattern-match `0.0.0.0/0` but does not know your VPC topology | None (general AI reviewer) | SSO via paid plan | Free → Pro $24/dev/mo |
| **Greptile** | All file types via LLM; no IaC-specific tooling | No structural cloud-context | None | SSO enterprise | Paid |
| **Cursor BugBot** | All file types via LLM; no IaC-specific tooling | No structural cloud-context | None | Cursor org plan | Folded into Cursor plans |
| **qodo Merge / PR-Agent** | All file types; can be configured with custom prompts for IaC | No native cloud-context (custom prompts only) | Self-hostable | Self-hosted SSO | OSS + paid |
| **Semgrep Assistant + Semgrep IaC rules** | Terraform, CloudFormation, K8s YAML, Dockerfile via Semgrep IaC rule packs; AI triage on findings | Indirect — Semgrep rules are deterministic; AI layer does triage, not cloud-graph context | Semgrep platform supports SBOM context | SSO + SCIM enterprise | Free → Team → Enterprise |
| **Open-source feed-ins (Checkov, tfsec, KICS, terrascan, cfn-nag)** | Checkov covers all major IaC types; tfsec is Terraform-only; KICS broad; cfn-nag CloudFormation-only; terrascan multi-cloud | Static-rule-only; not cloud-context | None natively; integrate with sigstore-signed pipelines downstream | N/A | OSS |

The structural gap: general-purpose AI reviewers (CodeRabbit, Greptile, Cursor BugBot) do not understand your cloud topology. They can pattern-match `0.0.0.0/0` and `Action: "*"` because those patterns are well-attested in training data, but they cannot reason about "this security-group opening is fine because this subnet has no route to the internet" or "this IAM policy widening is dangerous because this role is assumable by a third-party SaaS integration."

Specialized IaC platforms (Snyk Cloud, Wiz Code, Prisma Cloud Code Security) bring cloud-context backplane — they know your VPC topology, your IAM principals, your KMS key aliases — and use it during review. As of 2024-2026 these are the only tools with structurally cloud-context-aware AI review.

Semgrep IaC is a middle path: deterministic rules (so the false-negative class is bounded by the rule corpus, not LLM pattern-matching luck) with optional AI triage on top. Cross-link [[reference-ai-pr-review-platform]] §11 for the broader Semgrep Assistant comparative positioning.

## 4. Threat-actor split for IaC AI-review

Parallel to [[reference-ai-pr-review-platform]] §4. Four actors with IaC-specific failure modes.

### 4.1 Repo-as-attacker

A malicious PR — opened by an external contributor on a public-source IaC repo, or by a compromised internal account on a private one — that the AI reviewer approves. Specific IaC failure modes:

- A `terraform apply` that adds a deliberately-malformed `aws_iam_policy` with `Action: "*"` and `Resource: "*"` and an opaque rationale ("required for X compliance audit, will be revoked Friday").
- A Pulumi `ComponentResource` whose internal logic conditionally creates an attacker-controlled IAM role only when a specific environment variable is set.
- A Kustomize overlay that quietly removes a `NetworkPolicy` while ostensibly fixing an unrelated label.

The AI reviewer that pattern-matches `Action: "*"` will catch the first; the AI reviewer that does not execute the Pulumi program against a staging account will miss the second; the AI reviewer that does not diff effective K8s manifests post-Kustomize will miss the third.

### 4.2 Module-as-attacker

The IaC analogue of npm / PyPI supply-chain attack. Terraform Registry modules and Pulumi packages are third-party code that runs at `terraform init` (provider download) and `terraform plan` (data-source resolution). A compromised or typosquatted module can:

- Add a hidden resource (a bastion EC2 instance, an attacker-controlled IAM role, an outbound network rule).
- Exfiltrate `data` source contents via the provider — for example, a Terraform provider that reads `data.aws_caller_identity.current` and POSTs the account ID to an attacker endpoint as a "telemetry" call.
- Use post-plan hooks (where supported) to read state-file contents.

Real reference: typosquatting on the public Terraform Registry has been observed; precise CVE / GHSA enumeration is sparse because the Registry is not a CNA and incidents are rarely reported with stable identifiers. The pattern is well-attested in vendor blog posts from HashiCorp and Snyk. [unverified] specific incident counts.

Cross-link [[reference-supply-chain-provenance]] §"The four-level ladder" for the SLSA L0-L3 framing applied to IaC modules. The Terraform Registry does not enforce SLSA levels; Pulumi Registry similarly does not. Module-version-pinning (`~> 4.0.5` vs `>= 4.0`) is the load-bearing customer-side defense, and the AI reviewer must flag pin-loosening as a regression.

### 4.3 State-file-as-attacker

Terraform state files (`terraform.tfstate`) are the canonical attacker target inside an IaC workflow. They contain:

- **Sensitive resource attributes.** RDS master passwords, generated TLS private keys, Kubernetes service-account tokens, Secrets Manager secret values referenced via data sources.
- **Account and identity metadata.** AWS account IDs, IAM role ARNs, GitHub OIDC subject claims, account-id-to-name mappings.
- **Resource graph.** The full topology of what exists in the cloud — KMS key aliases, VPC CIDR ranges, security-group rules, S3 bucket names.

A state-file leak is equivalent to a full cloud-topology disclosure plus several high-value secret leaks. The S3 backend with no encryption, no versioning, no access logging, and `BlockPublicAccess` disabled is the canonical anti-pattern. The Pulumi Service-managed state is encrypted-at-rest by default; the customer-managed-backend variant (S3 / Azure Blob / etc.) inherits the same anti-patterns as Terraform.

The AI reviewer's role here: catch state-backend configuration regressions in PRs. A PR that changes `backend "s3"` config to remove `encrypt = true` or to remove `dynamodb_table` (state locking) is a regression and must be flagged. Most general-purpose reviewers will not catch this.

### 4.4 Operator-as-attacker

The insider who has `terraform apply` rights and wants to use AI-review approval as cover for a malicious change. The AI reviewer's role here is to deter and to leave audit trails: a PR opened by an operator, approved by the bot, applied by the same operator, is a single-actor workflow with no separation of duties.

The structural answer is not AI-review; it is workflow design. Separate the role that opens IaC PRs from the role that approves them from the role that runs `terraform apply`. AI review is a participant in the approval gate, not a substitute for it.

## 5. High-leverage IaC attack patterns the AI reviewer must catch

A concrete checklist of the patterns where AI-review-failure is most expensive. Pair with Semgrep IaC rule packs, Checkov, tfsec, KICS.

- **IAM wildcard policy.** `Action: "*"` paired with `Resource: "*"` and a permissive `Principal`. `iam:PassRole` with `*` is the classic privesc primitive — cross-link [[reference-cloud-iam]] §"PassRole — the primary privesc primitive." `sts:AssumeRole` trust policies with `Principal: "*"` and an unscoped `Condition` are also load-bearing.
- **Cross-account trust opening.** `trust_policy` adding a new account ID without rationale. Especially dangerous: trust to a non-org account, or trust without an `aws:PrincipalOrgID` or `sts:ExternalId` condition.
- **Security group / NACL 0.0.0.0/0.** Adding `0.0.0.0/0` to ingress, especially on port 22 (SSH), 3389 (RDP), 5432 (Postgres), 3306 (MySQL), or 6379 (Redis). The canonical anti-pattern.
- **KMS key deletion or key-policy widening.** A `terraform destroy` of an `aws_kms_key` triggers the 7-30 day deletion window; cancellable only inside the window; orphans every resource encrypted by that key. Key-policy widening — adding a new principal with `kms:Decrypt` — is a quiet privesc.
- **S3 bucket public-ACL.** Removing `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, or `RestrictPublicBuckets` from a bucket's public-access-block config. Each of these is a structural defense layer; removing them in PR is a regression.
- **VPC peering or Transit Gateway attachment.** Opening connectivity from production to a less-trusted account (sandbox, dev, a third-party). The reviewer must understand the trust direction.
- **Terraform state-backend regression.** Removing `encrypt = true`, removing `dynamodb_table` (locking), removing `versioning = true` on the state bucket, or moving the state file to a backend without access logging.
- **K8s RBAC `cluster-admin` binding.** A `ClusterRoleBinding` that grants `cluster-admin` to a `ServiceAccount`, especially one not in `kube-system`. Cross-link [[reference-container-k8s-security]] for the broader K8s RBAC threat model.
- **K8s `hostPath`, `privileged: true`, dangerous capabilities.** A `Pod` spec with `hostPath` mount, `privileged: true`, `hostNetwork: true`, or capabilities like `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`. Each is a container-escape primitive.
- **Module-version-pin removal.** Loosening `~> 4.0.5` to `>= 4.0` or to no pin at all. Allows future module updates (potentially malicious) to deploy without further review.
- **CloudTrail / GuardDuty / Config disablement.** Removing `aws_cloudtrail`, `aws_guardduty_detector`, or `aws_config_configuration_recorder` resources. The reviewer must treat detection-control regression as a security finding, not a cost optimization.
- **OIDC trust-policy `sub` claim widening.** A GitHub OIDC trust policy whose `sub` condition changes from `repo:org/repo:ref:refs/heads/main` to `repo:org/*:*`. Cross-link [[reference-cloud-iam]] §"OIDC sub-claim restriction."

Each pattern has a canonical Semgrep IaC rule, a Checkov check, and a tfsec/KICS equivalent. The AI reviewer's value-add is contextual reasoning — "is this widening justified by the PR description?" — not pattern detection itself, which deterministic tools already do well.

## 6. MCP and agentic IaC tooling — emerging surface

As of 2026 the agentic IaC tooling ecosystem is young and the threat surface is correspondingly under-mapped. Three categories worth knowing.

- **HashiCorp Terraform MCP server.** HashiCorp shipped a Model Context Protocol server enabling LLM clients to interact with Terraform state, plans, and modules. The threat shape: an agent with MCP access can read state-file contents via the server interface. A prompt-injection into an agent connected to the Terraform MCP server can exfiltrate state.
- **Pulumi MCP / Pulumi AI.** Pulumi shipped agentic features in 2024-2025 [unverified exact ship dates] including a "Pulumi AI" code-generation pathway and MCP-style integrations. Same threat surface as the Terraform case.
- **AWS Cloud Operations MCP / cloud-control agents.** AWS published cloud-control APIs accessible via MCP for several services. [unverified] specific MCP server coverage as of 2026-05-15. The threat shape generalizes: an agent with cloud-control-API access via MCP is an `iam:*` away from full account compromise.

The structural concern: an AI reviewer that itself uses MCP for "cloud-context lookup" is now part of the agent attack surface. A prompt-injected reviewer can be coerced into calling its own MCP tools to exfiltrate state or to issue control-plane mutations. The CaMeL pattern (privileged-LLM / quarantined-LLM split) from [[reference-agentic-web-capabilities]] is the architectural answer; cross-link [[reference-ai-assisted-coding-tool-security]] §6 for the broader MCP threat-model coverage.

A specific class to monitor: "agent calls `terraform apply` via MCP without human gate" is the IaC analogue of the Comment-and-Control class from [[reference-ai-pr-review-platform]] §4.2. Any agent with `terraform apply` capability plus untrusted-text-in-prompt is a state-mutation primitive.

## 7. The "plan vs apply" approval boundary

Terraform's two-phase model is load-bearing for the AI-review threat model. `terraform plan` computes the diff between desired state (HCL) and observed state (state file); `terraform apply` performs the mutation. The reviewer reads the `plan` output and decides whether to approve.

The failure modes:

- **The plan is misleading.** A resource rename in HCL — for example, renaming `aws_s3_bucket.data` to `aws_s3_bucket.data_v2` — appears in `plan` as `destroy data` + `create data_v2`. With a `moved` block, Terraform recognizes the rename and produces a no-op plan. Without the `moved` block, the bucket and all its contents are destroyed and a new empty bucket is created. The reviewer who reads "destroy + create" as routine refactoring is approving data loss.
- **The plan does not show all side effects.** Provider-level lifecycle actions — for example, an RDS replacement triggering a snapshot deletion, or a Lambda code update triggering version pinning — are summarized but not detailed. Reviewer must read the resource's `lifecycle` block and the provider's documented behavior.
- **The plan can lie about timing.** `prevent_destroy = true` blocks `terraform apply` from destroying a resource, but the plan still computes the diff. Reviewer sees a destroy plan that won't execute; CI fails; operator removes the `prevent_destroy` to make CI pass; next apply destroys the resource. The defensive lifecycle config and the reviewer's reading of it must align.
- **The plan does not account for drift.** Between plan and apply, the cloud state may have changed. Long-lived plans (Terraform Cloud's "Apply" step delayed by 30 minutes for human review) are particularly at risk.

CI/CD platforms handle this differently:

- **Atlantis** (self-hosted Terraform automation). Runs `plan` on every PR; comments the plan as a PR comment; requires manual `atlantis apply` command on the PR before applying. The plan is in plain view, but the AI reviewer that approves the PR is approving the plan as comments-in-the-PR.
- **Terraform Cloud / HCP Terraform** (managed Atlantis equivalent). Plan and apply gated by VCS integration; configurable human-+1 requirement.
- **Spacelift, env0, Scalr.** Commercial Terraform CD platforms with policy-as-code (OPA) integration. Plan output diffed against policy; AI review can be one of several gates.
- **GitHub Actions / GitLab CI direct.** Custom workflow with `plan` step (usually on PR) and `apply` step (usually gated on merge to main). The simplest model and the one where the reviewer's role is clearest.

The reviewer's task across all of these: read the *plan output*, understand what `apply` will do, evaluate whether the change is intended and safe. An AI reviewer that does not see the plan output — only the HCL diff — is reading half the artifact.

The structural recommendation for AI-IaC-review:

- The AI reviewer must consume the plan output as input, not just the HCL diff.
- The reviewer's approval must not gate `apply`. Human +1 on `apply` is non-negotiable.
- The plan output should be enriched with diff-of-diff (current plan vs last applied state) to surface drift.

## 8. Detection patterns specific to IaC AI-review

Pair with [[reference-detection-engineering]] §10 for the broader AI-tool telemetry framework.

### 8.1 Bot-behavior anomalies (IaC-specific)

- **Approve spike on IAM/network resource types.** Baseline the bot's per-resource-type approve rate. A sudden surge in approvals on `aws_iam_*`, `aws_security_group`, `aws_kms_key`, or `Kubernetes:ClusterRoleBinding` resources warrants review.
- **Approve without plan-output reference.** Reviewer's comment does not reference any element of the plan output. Likely cause: reviewer is operating on HCL diff only, not plan output, and is missing context.
- **Comment containing state-file path or contents.** Reviewer's comment references `terraform.tfstate` content, IAM role ARNs not in the diff, or KMS key aliases not in the diff. Exfil signal.
- **Comment recommending `prevent_destroy` removal or lifecycle relaxation.** Reviewer suggesting the *removal of a safety mechanism* is suspicious — prompt-injection-resistant reviewers should not propose loosening safety controls without strong rationale.

### 8.2 Cloud-side detection

- **CloudTrail `GetObject` on state files.** `s3://*/terraform.tfstate*` access by unexpected principals. The CI's IAM role should be the only legitimate accessor; reviewer-platform principals accessing state are anomalous.
- **`iam:PassRole`, `iam:UpdateAssumeRolePolicy`, `iam:PutRolePolicy` events** by the CI's apply role on roles not in the current PR's plan. Suggests scope creep or compromise.
- **`kms:ScheduleKeyDeletion` events.** Any key-deletion event is a high-fidelity alert; cross-reference against the PR that approved the change.
- **`ec2:AuthorizeSecurityGroupIngress` for `0.0.0.0/0`** outside change-window. Even if the PR review approved it, applying outside business hours warrants review.
- **`sts:AssumeRole` from a new external account.** Trust-policy changes that take effect produce observable AssumeRole events; correlate them with the PR that approved the trust change.

### 8.3 Drift accumulation

Long-running drift between IaC and cloud-state is its own attack surface. Two patterns:

- **Approved-but-not-applied drift.** AI reviewer approves a change; `apply` does not run for 30+ days (e.g., the team has not merged the PR); cloud state evolves independently. When the PR finally merges, the plan no longer reflects the intended change.
- **Applied-but-not-reflected drift.** Operator runs `terraform apply` directly outside the CI workflow; state file updates; PR was never opened. AI reviewer at next PR sees a baseline that was changed without review.

Drift-detection cadence (daily `terraform plan` on a schedule, alerting on non-empty plans) is the structural defense. AI reviewers should incorporate drift as part of their input; "this PR is on top of a 47-resource drift baseline" is a signal the reviewer must communicate.

### 8.4 Alerting model

| Signal | Severity | False-positive likelihood |
|---|---|---|
| Bot approves `aws_iam_*` change without referencing IAM-policy text in comment | HIGH | MEDIUM (terse-comment bots) |
| Bot approves `0.0.0.0/0` SG ingress | CRITICAL | LOW |
| Bot comment recommends removing `prevent_destroy` | HIGH | LOW |
| Bot comment contains KMS key alias or role ARN not in diff | HIGH | LOW |
| State file accessed by reviewer-platform principal | CRITICAL | LOW |
| `kms:ScheduleKeyDeletion` triggered post-bot-approve | CRITICAL | LOW |
| PR with non-empty drift baseline approved by bot | MEDIUM | MEDIUM (drift is common in some shops) |

The first three are CRITICAL or HIGH with LOW FP-likelihood; enable as page-able alerts. Others route to a daily digest with manual review.

## 9. Hardening checklist for an org adopting AI-IaC-review

Fifteen items, parallel to [[reference-ai-pr-review-platform]] §8.

1. **Human +1 on `terraform apply` is non-negotiable.** No bot approval should ever gate apply. CI workflow must require a second human reviewer specifically for apply, not just for merge.
2. **AI reviewer cannot self-approve.** Bot review marked as "Comment" review type, not "Approve." Branch protection ignores bot approvals.
3. **State files encrypted at rest, versioned, access-logged.** For S3 backend: `encrypt = true`, `dynamodb_table` for locking, `versioning { enabled = true }`, server-access logging to a separate bucket, `BlockPublicAccess` enforced. Equivalent for Azure Blob and GCS backends.
4. **State-bucket access via IAM, not bucket policy with wildcards.** Only the CI's IAM role and a documented break-glass role should have `s3:GetObject` and `s3:PutObject` on the state bucket.
5. **OIDC `sub` claim restriction for the CI's cloud-apply role.** GitHub OIDC trust policy must restrict `sub` to `repo:org/repo:ref:refs/heads/main` (or equivalent), not `repo:org/*`. Cross-link [[reference-cloud-iam]] §"OIDC sub-claim restriction" and [[reference-cicd-supply-chain]].
6. **Module-version pinning.** Every `module` block specifies an exact version or a `~>` minor-pin. PR loosening pins is a regression flagged by AI reviewer and human reviewer.
7. **Sigstore signing of internal modules where supported.** For modules published to an internal Terraform Registry or Pulumi private registry, sign with cosign / sigstore and verify at consumption. Cross-link [[reference-supply-chain-provenance]] §"The sigstore trinity."
8. **Separate CI roles for plan and apply.** The role used for `terraform plan` is read-only (`*:Get*`, `*:List*`, `*:Describe*`). The role used for `terraform apply` has mutation scopes. Plan role is invoked on every PR; apply role only after merge and only with human-+1.
9. **Drift detection on a schedule.** Daily `terraform plan` against production, alerting on non-empty plans. The detection-engineering function owns the alert; AppSec owns the investigation.
10. **Anomaly alerting on IAM/network changes.** Every `iam:*Policy*`, `iam:PassRole`, `iam:UpdateAssumeRolePolicy`, `ec2:AuthorizeSecurityGroupIngress` event in production tagged in SIEM and reviewed against PR provenance.
11. **CloudTrail on the state bucket.** S3 server-access logging is one layer; CloudTrail data events on the state bucket is the second. Alert on access by unexpected principals.
12. **AI reviewer must consume plan output, not just HCL diff.** Configure the reviewer integration (Atlantis comment, Terraform Cloud webhook, etc.) so the AI sees `terraform plan` output. Verify in pilot.
13. **Self-hosted or air-gapped reviewer for sensitive accounts.** Production accounts handling regulated data should not have IaC reviewed by SaaS AI reviewers if the alternative is feasible. Self-host qodo or Semgrep Assistant on-prem. Cross-link [[reference-ai-pr-review-platform]] §9.
14. **MCP server allowlist.** If the AI reviewer connects to Terraform MCP, Pulumi MCP, or cloud-control MCP servers, those servers must be on an explicit allowlist with version pinning. Cross-link [[reference-ai-assisted-coding-tool-security]] §13.
15. **Vendor diligence + tabletop.** Run the §12 onboarding playbook before adoption; tabletop a vendor-compromise scenario (PEM-file leak, state-file exfil) before production rollout.

## 10. Semgrep IaC rule corpus + Semgrep Assistant comparative position

Semgrep IaC ships rule packs for Terraform / HCL, CloudFormation, Kubernetes YAML, Dockerfile, and other declarative substrates. Rules are deterministic — pattern-matching over AST or syntactic forms with pattern-not exceptions. As of 2026 the rule corpus covers the high-leverage attack patterns from §5: IAM wildcard policies, security-group `0.0.0.0/0`, KMS key-policy widening, S3 public-ACL, K8s `hostPath` / `privileged: true` / `cluster-admin` bindings.

Semgrep Assistant adds an AI triage layer over these findings — explanation, false-positive triage suggestion, remediation drafting — but does not generate new findings de novo. Cross-link [[reference-ai-pr-review-platform]] §11 for the broader comparative positioning.

Strengths:

- **Bounded false-negative class.** Findings come from deterministic rules. The reviewer-platform's pattern-matching luck is not the bound; the rule corpus is.
- **Auditable precision.** Rules can be tuned; findings can be marked false-positive with rationale; the AI triage learns from prior decisions in the same repo.
- **Source-of-truth deterministic.** No "the LLM didn't notice" failure mode for in-scope rules.

Honest gap statement:

- **Cloud-context-dependent findings are weaker.** Semgrep IaC rules pattern-match on text. They cannot reason about "this SG opening is fine because this VPC is air-gapped" or "this IAM policy is dangerous because this role is assumable by a third-party SaaS." Cloud-context-aware platforms (Snyk Cloud, Wiz Code, Prisma Cloud Code Security) cover this surface more directly. The Semgrep Assistant team has acknowledged this gap publicly [unverified specific public statement] and Semgrep's strategic position has been to focus on the deterministic-rule core.
- **Cross-file reasoning is limited.** Semgrep's primary strength is single-file pattern-matching. IaC findings that require reasoning across module boundaries (e.g., "this module's output is consumed unsafely by that module") are harder for Semgrep to express compared to cloud-graph-backed tools.

A program-level pattern worth considering: Semgrep IaC + Assistant for the deterministic security-rule base; a cloud-context-aware platform (Snyk Cloud / Wiz Code / Prisma Cloud Code Security) for the topology-aware findings; a general-purpose AI reviewer (qodo self-hosted) for style and design feedback on the HCL / Pulumi / K8s YAML itself. Three tools, three lanes; explicit overlap in the security-rule lane is acceptable for defense-in-depth.

## 11. Vendor-side threat model for AI-IaC-review SaaS

What does the vendor learn about your cloud topology, and what's the blast radius if that learning leaks? Parallel to [[reference-ai-pr-review-platform]] §12.

### 11.1 Cloud-topology disclosure surface

When a vendor's AI-IaC-review platform processes your PRs, the vendor's systems observe — and likely embed, cache, or log — the following:

- **Account identifiers.** AWS account IDs, Azure subscription IDs, GCP project IDs. Per se not sensitive but powerful pivot fodder for an attacker who exfiltrates a vendor's analytics index.
- **IAM principal names.** Role ARNs, user ARNs, service-account names. These name humans and services at the customer; correlation across customer PRs reveals organizational structure.
- **Network topology.** VPC CIDRs, subnet IDs, security-group rules, peering relationships. Effectively a partial cloud-network diagram.
- **KMS key aliases and policies.** Key-policy text references principals, which references organizational structure.
- **Resource naming conventions.** Bucket names, parameter store paths, secret names. Convention reveals service architecture.

Cross-customer leakage in shared-tenancy embedding indexes is the highest-leverage failure mode. If the vendor uses a shared vector store across customers, one customer's topology may surface as nearest-neighbor context to another customer's review. The mitigation is per-customer namespacing of embedding indexes; the diligence question is "do you namespace?"

### 11.2 Multi-tenant SaaS specifics

- **Embedding-index isolation.** Per-customer or per-organization vector stores. Single shared store across customers is a tenant-isolation failure.
- **LLM cache key scoping.** Provider-side prompt caching (Anthropic, OpenAI) keyed per organization API key, not per prompt content. Vendor must ensure each customer's reviews use a customer-scoped key.
- **Log isolation.** Vendor logs containing PR content must be per-customer-namespaced and access-controlled. Cross-tenant log queries (vendor's internal debugging) must be audited.
- **Fine-tuning isolation.** If the vendor offers customer-specific fine-tuning ("learn from our team's review preferences"), per-customer LoRA adapters with strict isolation, not shared fine-tuned weights.

### 11.3 Data residency for IaC analysis

Regulated industries (EU customers under GDPR, US financial services under DORA, US gov under FedRAMP) require data-residency commitments. AI-IaC-review platforms that process IaC content in a US-region LLM endpoint for an EU customer have GDPR exposure. Vendor must offer per-region LLM endpoints (Bedrock in `eu-west-1`, Azure OpenAI in `westeurope`) for EU residency.

The strictest customers (defense, intelligence community, some critical infrastructure) require self-hosted or air-gapped deployment. Cross-link [[reference-ai-pr-review-platform]] §9 for the self-host trade-offs.

### 11.4 Vendor-side asset prioritization

For a vendor team building an AI-IaC-review platform, the asset priorities are similar to the general AI-PR-review case from [[reference-ai-pr-review-platform]] §12.1 with IaC-specific additions:

1. The GitHub App PEM file (or equivalent VCS-integration secret).
2. Customer IaC content (Terraform / Pulumi / K8s YAML) plus any state-file content if the platform processes that.
3. Customer cloud-topology embedding indexes.
4. LLM provider API keys.
5. Customer-specific learned-rule data / triage history.
6. Standard SaaS assets (database, cache, internal-service tokens).

Threat scenarios worth tabletop-ing: a PR-injection into the reviewer exfiltrates *another customer's* cloud-topology embedding; a state-file content leaked into a public PR comment; an LLM provider's training pipeline ingests customer state-file content via vendor logs. The structural defenses (CaMeL split, per-customer namespacing, egress filter, sandbox-everything-external) are inherited from [[reference-ai-pr-review-platform]] §12.4.

## 12. AppSec-lead 12-item onboarding playbook for AI-IaC-review

A practical checklist for AppSec leads selecting and onboarding an AI-IaC-review platform. Pair with [[reference-appsec-program-building]] §"Vendor onboarding."

1. **Cloud-context awareness.** Does the platform structurally understand your cloud topology, or does it pattern-match on text? Snyk Cloud / Wiz Code / Prisma Cloud Code Security are structurally context-aware. CodeRabbit / Greptile / Cursor BugBot are text-only.
2. **Plan-output consumption.** Does the platform consume `terraform plan` output (or the Pulumi equivalent) as input, not just the HCL diff? Confirm in pilot, not just in marketing.
3. **State-file access posture.** Does the platform read your state files? If yes, under what credential, with what access logging? If no, how does it reason about lifecycle changes?
4. **Human +1 on `apply`.** Confirm the platform's integration model preserves human +1 on `terraform apply` — bot approval cannot satisfy the apply gate.
5. **Provenance / sigstore support.** Does the platform's own container images and CLI artifacts have SLSA L2+ provenance and sigstore signatures? Cross-link [[reference-supply-chain-provenance]].
6. **Module-supply-chain awareness.** Does the platform flag module-version-pin loosening? Typosquatted module sources? Unsigned module loads?
7. **MCP server allowlisting.** If the platform uses MCP, what servers does it connect to? Is there a customer-side allowlist? Version pinning?
8. **Drift-detection cadence.** Does the platform incorporate drift state into its review? "This PR is on top of N-resource drift" should be visible in the review.
9. **Tenant-isolation architecture.** Per-customer embedding index? Per-customer LLM cache key? Per-customer log namespace? Cloud-topology data isolation specifically.
10. **Data residency.** Per-region LLM endpoint for regulated customers. Documented in writing in the DPA or equivalent.
11. **Audit-log export for IaC-specific actions.** Bot's per-PR review actions exportable to SIEM with IaC-resource-type tagging.
12. **Off-boarding plan.** What happens to your cloud-topology embedding index when you terminate the contract? Retention policy in writing.

A scorecard with these 12 dimensions, scored 1-5 per vendor, gives a useful comparative view. Items 1, 2, 4, 9, and 10 are load-bearing for regulated-industry deployment; a vendor that scores below 3 on any of these is deferred regardless of feature richness.

## 13. Open questions and research gaps

Five to eight questions where the corpus and public literature do not yet have clean answers as of 2026-05-15.

1. **Empirical FP/FN benchmark for AI-IaC-review.** No independent benchmark exists publicly. Vendors publish their own metrics on hand-picked corpora; cross-vendor comparison is therefore self-selected. The research opportunity: a public corpus of intentionally-misconfigured IaC PRs with ground-truth labels, scored across all platforms in §3. Analogous to OWASP Benchmark for SAST but for IaC-AI-review.
2. **Game-theoretic incentive analysis.** The AI-IaC-review vendor's revenue depends on the approve-rate signal that customers value ("our bot accelerates your team"). The vendor's incentive on edge-case findings is to under-flag (approve-rate looks better) rather than over-flag. The structural mismatch with customer security incentives merits Akerlof "market for lemons" treatment. Cross-link the game-theory expertise doc when extending.
3. **SLSA-for-IaC.** What does provenance look like for a Terraform module ecosystem? The Terraform Registry does not enforce SLSA levels; module signing is not the default. A SLSA L3 ladder applied to Terraform / Pulumi modules — with verifiable build provenance from a hermetic builder, sigstore-signed artifacts, and TUF root-of-trust — is plausible but not yet adopted at scale. Cross-link [[reference-supply-chain-provenance]] §3.
4. **AI reviewer's role in `terraform import` and `moved` semantics.** Reviewer correctness on `import` blocks and `moved` blocks specifically — both are easy to get wrong and easy to use to obscure malicious changes. Empirical study of reviewer hit-rate on these constructs is overdue.
5. **Cloud-context-aware AI review without cloud-credential exposure to the vendor.** Customers want the reviewer to know "this SG opening is fine because this VPC is air-gapped" — but giving the vendor live read-credentials to the customer cloud is itself a blast-radius increase. Architectural pattern: customer-side proxy that exposes only graph-summary data to the reviewer, not credentials. [unverified] specific vendor implementations.
6. **State-file-as-policy-input.** Can `terraform.tfstate` be a policy-input artifact (read-only, with redaction) to the reviewer, enabling "is this change consistent with current state" reasoning, without leaking sensitive state contents to the vendor? Open research question.
7. **Drift-aware review semantics.** What is the right reviewer behavior when the cloud state has drifted since last apply? Block the PR? Surface the drift? Auto-correct? Different orgs answer differently; no shared best-practice exists.
8. **Compositional review across IaC + app code in the same PR.** Many PRs touch both Terraform and application source. The reviewer's behavior across this boundary — "this app-source change requires the IaC change" reasoning — is not well-developed by current platforms.

---

## Cross-reference summary

This doc cross-links to:

- [[reference-ai-pr-review-platform]] — sibling doc; this is the IaC-specific specialization.
- [[reference-cloud-iam]] — PassRole privesc primitive, OIDC sub-claim discipline, trust-policy threat model.
- [[reference-supply-chain-provenance]] — SLSA L0-L3 ladder, sigstore trinity, module-signing provenance.
- [[reference-cicd-supply-chain]] — GitHub Actions pwn_request class as it applies to Terraform-applying pipelines.
- [[reference-ai-assisted-coding-tool-security]] — MCP threat model, AI tool sandbox architecture.
- [[reference-llm-agent-security]] — prompt-injection primitive catalog, agent runtime threat model.
- [[reference-detection-engineering]] — AI-runtime telemetry and detection rule patterns.
- [[reference-container-k8s-security]] — K8s RBAC, hostPath, privileged-container threat model.
- [[reference-agentic-web-capabilities]] — CaMeL pattern, capability-attenuation doctrine for agent runtimes.
- [[reference-appsec-program-building]] — vendor-onboarding workflow, program-level decisions.

## Status and known gaps

Initial v1 doc, 2026-05-15. Drafted as IaC-specific sibling to the AI-PR-review platform doc.

De-scoped to fit size budget:

- Per-vendor pentest / SOC2 review (paywalled / NDA content).
- Concrete Sigma / KQL / SPL detection rule corpus for §8 patterns — lives more naturally in [[reference-detection-engineering]].
- Deep treatment of Crossplane composition functions and the corresponding review threat model.
- Pulumi automation-API specific agent surface (the agent-running-Pulumi-programs class).
- Terraform Cloud / HCP Terraform run-task / sentinel integration specifics.
