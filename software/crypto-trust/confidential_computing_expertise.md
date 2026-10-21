# Confidential Computing — TEEs, Attestation, and Encrypted-Data-In-Use
## Synthesized from Jo Van Bulck, Marina Minkin, Daniel Gruss, David Kaplan, Mark Russinovich, Mike Bursell, Felix Schuster, Ravi Sahita, the Apple Platform Security and PCC teams, the NVIDIA Confidential Computing team, and Kurt Boberg

> **Researchers and primary sources:**
>
> - **Jo Van Bulck** (KU Leuven, imec-DistriNet). Lead author of *Foreshadow* (USENIX Security 2018), *LVI* (IEEE S&P 2020), and the **SGX-Step** attack framework (SysTEX 2017 / ACSAC 2023). The canonical academic adversary of Intel SGX. Cross-referenced in [[reference-hardware-side-channels]].
> - **Marina Minkin** (Technion at *Foreshadow*; later University of Michigan EECS). Co-author of *Foreshadow* and *Fallout* (CCS 2019); contributor to *CacheOut*. Connecting SGX attacks to the MDS / RIDL / ZombieLoad family.
> - **Daniel Gruss** (Graz University of Technology, IAIK). Co-author of *Meltdown* (USENIX Security 2018) and *Spectre* (IEEE S&P 2019, Distinguished Paper); co-author of *ÆPIC Leak* (CVE-2022-21233, USENIX Security 2022) and *Plundervolt* (IEEE S&P 2020). Author of *Practical Enclave Malware with Intel SGX* (arXiv:1902.03256, 2019).
> - **David Kaplan** (Senior Fellow, AMD Product Security Office). Principal architect of **AMD SEV / SEV-ES / SEV-SNP**. Author of *Hardware VM Isolation in the Cloud* (ACM Queue 21(4), 2023).
> - **Mark Russinovich** (CTO, Microsoft Azure; Technical Fellow; PhD CMU). Co-author of *Toward Confidential Cloud Computing* (ACM Queue 19(1), 2021). The highest-profile production-side voice on TEEs and "confidential computing as default" for hyperscaler cloud.
> - **Mike Bursell** (Executive Director, Confidential Computing Consortium; co-founder, Profian and **Enarx**; formerly Red Hat). Author of *Trust in Computer Systems and the Cloud* (Wiley, 2021).
> - **Felix Schuster** (Co-founder/CEO, **Edgeless Systems**; formerly Microsoft Research). Author of *VC3* (IEEE S&P 2015) — an early production-shape SGX application. Built **EGo**, **Marblerun**, **Contrast**.
> - **Ravi Sahita** (Rivos; previously Intel Principal Engineer). Lead author of *CoVE: Towards Confidential Computing on RISC-V Platforms* (arXiv:2304.06167, 2023) — the RISC-V analog to TDX / SEV-SNP / CCA.
> - **The Apple Platform Security and Private Cloud Compute teams.** Authors of the *Private Cloud Compute Security Guide* (security.apple.com, June 2024+) and the *Apple Platform Security Guide*. PCC is the first hyperscaler-scale "verifiable cloud" with public technical documentation.
> - **The NVIDIA Confidential Computing team** (notably Rob Nertney, author of *Confidential Compute on NVIDIA Hopper H100*, WP-11459-001, 2023). First production GPU TEE; the CPU↔GPU encrypted-DMA bridge is the substrate for confidential AI inference at scale.
> - **Jason Kim, Daniel Genkin, Yuval Yarom** (Georgia Tech / Ruhr University Bochum). Authors of *SLAP* (IEEE S&P 2025) and *FLOP* (USENIX Security 2025) on Apple Silicon load-address and load-value prediction; Genkin is also senior author on **TEE.Fail** (Georgia Tech + Purdue, IEEE S&P 2026), the DDR5 memory-bus interposition attack against Intel SGX/TDX and AMD SEV-SNP. The Genkin lab is the dominant 2024-2026 academic adversary of consumer-silicon TEE primitives. Cross-referenced in [[reference-macos-apple-security]] and [[reference-hardware-side-channels]].
> - **Boru Chen et al.** (UIUC / UT Austin / Georgia Tech / Berkeley / Washington / CMU). Authors of *GoFetch* (USENIX Security 2024) on Apple Silicon's data memory-dependent prefetcher (DMP) breaking constant-time crypto including post-quantum CRYSTALS-Kyber and Dilithium. Implications for SEP and any TEE workload running constant-time crypto on M-class silicon.
> - **The Anthropic Security and Infrastructure teams** (Confidential Inference paper, June 2025). First major foundation-model vendor to publish an end-to-end architecture for TEE-backed inference with TPM-rooted attestation, signed-loader CI, and envelope-encrypted model weights.
> - **Kurt Boberg** (`@lapt0r`, Semgrep Staff Security Researcher). Author of "Security Like It's 1977: Capabilities for the Modern Agentic Web" (semgrep.dev/blog, 28 January 2026). The capability-discipline framing in §1 is in dialogue with that post.
>
> Sources: usenix.org (Foreshadow, LVI, SGX-Step, ÆPIC, CIPHERLEAKS, VC3); ieeexplore.ieee.org (Plundervolt, *Meltdown*/*Spectre*, LVI); vanbulck.net; gruss.cc; queue.acm.org (Kaplan 2023, Russinovich et al. 2021); confidentialcomputing.io; security.apple.com/documentation/private-cloud-compute; nvidia.com; intel.com; amd.com; arm.com; enarx.dev; edgeless.systems; teaclave.apache.org; aws.amazon.com/ec2/nitro/nitro-enclaves; cloud.google.com/confidential-computing; semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/.

---

## 1. Why Confidential Computing Matters

**The three states of data.** Classical security recognizes data at rest (encrypted on disk) and data in transit (encrypted on the wire). The third — **data in use** — has historically been undefended: plaintext in CPU registers, cache, DRAM during computation. Threat model: anyone with code execution on the same physical machine (privileged OS, hypervisor, peer VM via side channel, cloud operator, malicious insider, compromised firmware). Confidential computing encrypts data **during use** via a hardware-backed *trusted execution environment* (TEE): a region where code and data are isolated by silicon-enforced primitives — encrypted DRAM, integrity-protected page tables, attestable measurements. The CCC's working definition restricts the term to *hardware-based* TEEs with three properties: data confidentiality, data integrity, code integrity at runtime.

**Why the trust-the-OS model is broken.** Classical Unix / Windows trust rested on a layered chain: applications trust OS, OS trusts firmware, firmware trusts hardware. Cloud broke it. The tenant no longer owns the OS, hypervisor, firmware, or silicon. Every cloud workload is asked to trust the hypervisor, host OS, firmware (UEFI, BMC, ME / PSP), deployment pipeline, operator's employees, and silicon supply chain. For most workloads this is acceptable. For health-care data, financial PII, AI on customer prompts, MPC, blockchain key custody, government workloads on commercial cloud — it is not.

**The minimal-TCB framing.** The **Trusted Computing Base** is the set of components whose correct operation is required for the security policy to hold. Classical cloud VM TCB: entire guest OS + hypervisor + host OS + firmware + silicon — tens of millions of LoC plus billions of transistors. SGX enclave TCB: silicon + SGX microcode + enclave code. Confidential VM (TDX, SEV-SNP, CCA Realm) TCB: silicon + small trusted firmware mediator + guest VM. Minimal-TCB is the *primary* property confidential computing offers; encrypted memory and attestation are mechanisms.

**Verifiable execution environment.** The deepest claim is not "the data is encrypted" — it is that the *execution environment is verifiable*. The TEE produces a cryptographically signed attestation: "this measurement of code, this configuration, signed by a key rooted in silicon." A remote party refuses to release secrets unless the attestation matches. The TEE is a *capability* in the precise sense of [[reference-agentic-web-capabilities]] §1 — an unforgeable, verifiable handle on a specific execution-environment-with-known-code. A capability is unforgeable because the runtime won't synthesize one; a TEE attestation is unforgeable because the silicon won't. Both substitute structural unforgeability for ambient trust. A TEE is the *hardware-rooted capability for code-identity*.

**The 2026 reality: AI inference on private data.** The use case that converted confidential computing from a niche technology into a mainstream cloud feature is AI inference on private data. Foundation models are trained by organizations whose weights are valuable IP they cannot share. Users have private prompts and context. Inference requires both in plaintext at the same time — a trust deadlock without confidential computing. CC breaks the deadlock by giving *both parties* an attestable claim about the execution environment. Neither party trusts the other; both trust the TEE. Apple **Private Cloud Compute** (June 2024) is the first hyperscaler-scale instance with public documentation. NVIDIA H100 Confidential Computing (CUDA 12.2 Update 1, August 2023) is the GPU enabler. Anthropic, OpenAI, Azure AI, and Google Cloud all use the same pattern in 2026. Confidential AI inference is the *killer application* justifying the silicon and software investment across Intel, AMD, NVIDIA, and Apple.

---

## 2. The TEE Landscape

The taxonomy organizes by *trust unit* — what is the smallest thing a TEE protects?

| Family | Trust unit | Vendor | Status (2026) |
|---|---|---|---|
| Intel SGX (classic) | Process subset (enclave) | Intel | Deprecated on client (Rocket Lake+); supported on Xeon |
| Intel SGX Scalable (SGX2) | Process subset (large enclave) | Intel | Supported on 3rd Gen Xeon Scalable; superseded by TDX |
| Intel TDX | Full VM (Trust Domain) | Intel | GA on 4th Gen Xeon Scalable (Sapphire Rapids, 2023); Module 1.5 on 5th Gen + Xeon 6 / Granite Rapids (2025+) |
| AMD SEV / SEV-ES / SEV-SNP | Full VM | AMD | GA on EPYC; SEV-SNP integrity-protected (Milan+, 2021); full SEV-SNP across EPYC 9005 *Turin* (Zen 5, 2024+) with **TDISP** for encrypted device-memory sharing |
| Arm TrustZone | Two-world (Normal/Secure) | Arm | Ubiquitous in mobile; coarse-grained |
| Arm CCA (RME) | Full VM (Realm) | Arm | Architecture published 2021 |
| RISC-V CoVE / Keystone | Full VM or enclave | Open / Rivos / academic | Specs developing 2024-2026 |
| IBM Z Secure Execution | KVM guest / LPAR | IBM | Production on z15, z16 |
| NVIDIA H100/H200/B200/GB200 CC | GPU context | NVIDIA | Early access via CUDA 12.2 Update 1 (H100, 2023); GA in CUDA 12.4; Blackwell B200/GB200 first **TEE-I/O** GPU with inline NVLink encryption (2024-2025) |
| Apple Secure Enclave / PCC | App or PCC node | Apple | Ubiquitous client (SEP); production PCC since June 2024 |
| AWS Nitro Enclaves | EC2 sub-instance | AWS | GA since 2020 |

**Intel SGX.** Introduced with Skylake (2015). The application carves out an **enclave** whose memory lives in the **Enclave Page Cache** (EPC), encrypted by the Memory Encryption Engine with a hardware-rooted key. The CPU enforces that EPC pages can only be read or written by enclave-mode code; OS and hypervisor see only ciphertext. Page tables for enclave memory are validated by SGX microcode against the **EPCM** so the OS cannot remap an enclave page to a fake one. Defining trade-off: small trust unit (a few hundred KB), but the developer must split the application into trusted (in-enclave) and untrusted halves with explicit `ECALL` / `OCALL`. By 2022, Intel **deprecated SGX on client CPUs** (Rocket Lake+); TDX is the cloud successor. SGX remains supported on Xeon through 2026 with EPC in the tens or hundreds of GB on 3rd Gen Scalable and later. SGX's primary contribution to the field is its *attack corpus* (§4).

**Intel TDX.** Shifts the trust unit from "process subset" to "full VM." A TDX guest is a **Trust Domain** (TD). The hypervisor can schedule, page, and migrate the TD but cannot read its memory or registers. Architecture: **SEAM (Secure Arbitration Mode)** — a new CPU operating mode below VMX root hosting the **TDX module** (Intel-signed code mediating between hypervisor and TD); **Multi-Key Total Memory Encryption (MKTME)** with per-TD ephemeral keys; TD attestation via TDREPORT → SGX Quoting Enclave → DCAP quote signed by an Intel-rooted attestation key. TDX trades SGX's fine-grained trust unit for *unmodified-guest portability*. A TDX-aware Linux kernel runs in a TD with no application-level changes. TDX is the model the rest of the industry is converging on. **TDX Module 1.5** (latest public 1.5 release 1.5.34 as of 2026) is the production module version for 4th and 5th Gen Xeon Scalable and Xeon 6 / **Granite Rapids** parts; the Intel TDX Enabling Guide formally covers Granite Rapids deployment. The Module 1.5 spec adds Live Migration support and partitioned TDs; Module 2.0 releases are also published on GitHub. Source: Intel TDX Module 1.5 Base Architecture Specification (intel.com/content/.../733575); intel/tdx-module on GitHub; Intel TDX Enabling Guide.

**AMD SEV / SEV-ES / SEV-SNP.** Three generations: **SEV** (Naples, 2017) encrypts guest VM memory with a per-VM key held by the **AMD Secure Processor** (AMD-SP); confidentiality only. **SEV-ES** (Rome, 2019) also encrypts register state on VMExit. **SEV-SNP** (Milan, 2021) adds **integrity protection** via Reverse Map Table (RMP) entries binding each physical page to its expected GPA and owner. SNP is the first AMD generation defending against a malicious hypervisor remapping or replaying memory pages — approximately the AMD analog of Intel TDX. Principal differences from TDX: silicon (AMD-SP is an Arm Cortex-A5 on the EPYC die; TDX module is x86 code in SEAM); attestation flow (DCAP / Intel Trust Authority for TDX; SNP attestation report + AMD KDS for SEV-SNP). Kaplan's 2023 ACM Queue paper is the canonical reference. SEV-SNP is the version cloud providers deploy. **5th Gen EPYC 9005 *Turin* (Zen 5, 2024)**: full SEV-SNP support across the lineup, **TEE Device Interface Security Protocol (TDISP)** for confidential VMs to share encrypted memory with accelerators, plus **Ciphertext Hiding** (defense against ciphertext side channels of the CIPHERLEAKS family). Phoronix (February 2026) measured ~5% geometric-mean SEV-SNP overhead on EPYC 9005, with database and web-server workloads at 10-15%. The introduction of TDISP on Turin is the AMD-side counterpart to NVIDIA Blackwell's TEE-I/O — together they form the encrypted-DMA-over-PCIe path for confidential CPU↔GPU pipelines without bounce buffers. Source: amd.com/en/products/processors/server/epyc/confidential-computing.html; AMD SEV-SNP whitepaper.

**Arm TrustZone.** The oldest commercial TEE family (ARMv6, early 2000s). Every modern Arm Cortex-A SoC partitions the CPU into a **Normal World** and a **Secure World**; the Secure World runs a small trusted OS (OP-TEE is the open-source reference). Trust unit is *the entire Secure World* — there is only one. Substrate for mobile DRM (Widevine L1, FairPlay), mobile payment (Samsung Knox), embedded secure boot. Widely deployed but too coarse for cloud confidential-computing.

**Arm CCA.** Arm's response to TDX and SEV-SNP (Armv9-A, 2021). Extends TrustZone's two-world model into four worlds: Normal, Secure, **Realm**, **Root**. The Realm world is the new confidential-VM substrate. Components: **Realm Management Extension (RME)** ISA support (per-page Granule Protection Table, encrypted-memory region IDs); **Realm Management Monitor (TF-RMM)** trusted firmware; **Realm VMs**. CCA's structural innovation is the use of **EAT** (IETF RATS Entity Attestation Token) as the attestation wire format — TEE-agnostic, letting verifiers consume CCA / TDX / SEV-SNP through a uniform pipeline. Silicon shipping 2025-2026: **Neoverse V3** Armv9 server cores on the server side. Linux kernel Realm guest support mainline as of 6.13; TF-RMM 1.0 released by trustedfirmware.org. Production cloud deployment of CCA Realms remains rare in early 2026 — the architecture is shipping in silicon, but cloud-vendor offerings comparable to TDX or SEV-SNP have not yet GA'd. Source: arm.com/architecture/security-features/arm-confidential-compute-architecture.

**RISC-V (Keystone, CoVE).** **Keystone** (UC Berkeley / MIT, 2017+) is an open-source TEE framework running on standard RISC-V hardware with PMP and a small Security Monitor. **CoVE — Confidential Virtual machine Extensions** (Sahita et al., Rivos, arXiv:2304.06167, 2023) is the RISC-V analog of TDX / SEV-SNP / CCA — active RVI Task Group as of 2026. RISC-V CC matters because it is the only open-ISA confidential-computing line — every other family requires trusting a closed silicon supply chain and a closed firmware blob. CoVE is the path toward an *attestable open-silicon TEE*, meaningful for government and high-assurance workloads.

**IBM Z Secure Execution.** IBM Z has had hardware encryption since z14. The confidential-VM piece is **Secure Execution for Linux** (z15, 2019; expanded on z16): a KVM guest opaque to the host KVM hypervisor, attested by an IBM-signed quote, protected by Z's **Ultravisor**. Z's silicon was designed from inception for multi-tenant trust isolation (LPAR / PR/SM since the 1990s); confidential-execution semantics are far more thoroughly tested than the x86 analogs. The defining disadvantage: small market. IBM Cloud Hyper Protect Services is the cloud wrapper.

**NVIDIA H100/H200/B200/GB200 Confidential Computing.** The first production GPU TEE. Hopper H100 (CC early access via CUDA 12.2 Update 1, August 2023; GA in CUDA 12.4): on-die hardware root of trust, encrypted firmware, measured/attested boot, CPU-GPU **encrypted PCIe DMA** mode. H200 (2024) extends Hopper with larger HBM3e and faster encrypted-DMA but the CC architecture is functionally unchanged from H100. **Blackwell B200 / GB200** (2024-2025) is the architectural inflection: the **first TEE-I/O capable GPU in the industry**. TEE-I/O eliminates the host-side bounce buffer that Hopper CC requires — the CPU TEE can DMA directly into GPU-CVM private memory via **TDISP** (TEE Device Interface Security Protocol), **SPDM**, and **PCIe IDE** (Integrity and Data Encryption). Blackwell also adds **inline NVLink encryption** with peer-to-peer key establishment, enabling multi-GPU and GB200 NVL72-scale confidential workloads (training as well as inference) over encrypted NVLink fabric. NVIDIA reports Blackwell CC delivers "nearly identical throughput performance compared to unencrypted modes" — a major step from the ~5-10% Hopper overhead toward CC-as-default. The CC mode generally: CPU runs a confidential VM; GPU boots into CC mode with on-die RoT firmware verification; CPU and GPU perform an SPDM 1.1+ handshake establishing AES-GCM session keys; all CPU↔GPU and (on Blackwell) GPU↔GPU traffic is encrypted; GPU produces an attestation quote signed by an NVIDIA-rooted device certificate. The attestation flow integrates with Intel Trust Authority for *composite attestation* covering both CPU and GPU TEEs. Source: NVIDIA Secure AI with Blackwell and Hopper GPUs whitepaper (docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf); *NVIDIA GPU Confidential Computing Demystified* (arXiv:2507.02770).

**Remote attestation requirement common to all.** Every TEE family solves the same higher-order problem: prove to a remote party that the workload is running in a real TEE with a known measurement. The structure is uniform: (1) hardware-rooted device key (burned in at fab, certified by the vendor); (2) per-platform certificate chain to the vendor CA; (3) per-execution measurement (hash of loaded code and configuration); (4) per-quote freshness binding (nonce from the challenger); (5) signed quote tying (3) and (4) under the device key. §3 unpacks attestation in depth.

---

## 3. Remote Attestation

Attestation is the binding question of confidential computing: *how does a remote party verify what is running inside the TEE?*

**The attestation problem.** A relying party (R) wants to release a secret S to a workload W. R needs to know: (1) W is running in a real TEE; (2) W's code matches an expected reference measurement; (3) W's configuration is acceptable (debug disabled, current TCB level); (4) the attestation is fresh; (5) the platform's TCB is at a current security level. The TEE provides a *quote*: a signed structure containing measurement, configuration, freshness nonce, and a signature under a hardware-rooted attestation key. R verifies the signature, checks the certificate chain to a vendor-trusted root, validates measurement and configuration, and only then releases S. Pattern is structurally identical across TEE families.

**Intel SGX attestation: EPID and DCAP.** SGX has two attestation systems. **EPID (Enhanced Privacy ID)** is a group-signature scheme requiring Intel Attestation Service (IAS); phased out. **DCAP (Data Center Attestation Primitives)** is the modern replacement used by all SGX deployments and by TDX. DCAP flow: the platform's Provisioning Certification Key (PCK) certificate is fetched from Intel Provisioning Certification Service (PCS). An *attestation key* is derived inside the SGX Quoting Enclave (QE) and signed by the PCK. When an enclave attests, it produces a *REPORT* with the enclave measurement (MRENCLAVE), signer (MRSIGNER), and user data; the QE wraps it into a *quote* signed by the attestation key. The relying party verifies the quote signature, the QE signature on the attestation key, the PCK certificate chain to Intel, and must consult Intel's TCB recovery service: Intel publishes a *TCB level* indicating required microcode and SVN. A quote from a platform behind on TCB level should be rejected.

**AMD SEV-SNP attestation.** SEV-SNP produces an **attestation report** signed by the AMD Secure Processor, containing the launch measurement, the platform's TCB level, the guest's policy field, a freshness nonce, and a signature by the **Versioned Chip Endorsement Key (VCEK)** — a per-chip key derived from chip-unique values and current TCB level. The VCEK is certified by the AMD Key Distribution Service (KDS); the relying party fetches the certificate chain from KDS, validates to the AMD root CA, and enforces a TCB-version policy. A guest can supply an **ID block** at launch to commit to a measurement and reject mismatched launches.

**Intel TDX attestation.** TDX reuses SGX DCAP. A TD requests a TDREPORT from the TDX module via TDCALL. The TDREPORT is consumed by the TDX-aware SGX Quoting Enclave, which wraps it into a quote following the DCAP path. The TDREPORT measurement (MRTD) covers the initial TD state, including the virtual firmware (TDVF); the OS kernel, boot parameters, and initrd are measured by TDVF into RTMRs. Runtime measurements (RTMRs) capture state changes after launch — analogous to a TPM's PCRs.

**Arm CCA attestation.** CCA produces a **Realm token** containing the Realm's measurement (RIM) and runtime extensions (REMs), signed by a Realm Initial Attestation Token Key tied to the platform. CBOR-encoded, following IETF EAT. The structural innovation: EAT is TEE-agnostic, letting a verifier consume CCA / TDX / SEV-SNP through a uniform pipeline. This is the standardization path the industry is converging on.

**NVIDIA GPU attestation.** Produces an **attestation report** signed by a per-device key rooted in the on-die RoT, containing GPU firmware measurements (NVDEC, NVENC, security ucode versions), CC mode state (CC enabled, devtools disabled), a nonce, and a signature chained to the NVIDIA Device Root CA. Two verification paths: **Local Verifier** (NVAttestation library fetches Reference Integrity Manifest from NVIDIA) and **Remote Verifier** (NRAS or Intel Trust Authority for composite attestation). In production confidential-AI, CPU and GPU attestations are *composited* into a single token.

**Verification services: managed attestation.** Most production deployments offload to a cloud-side attestation service: **Intel Trust Authority** (formerly Project Amber, GA 2023; multi-cloud SaaS verifying SGX, TDX, NVIDIA GPU CC; issues JWT / OIDC tokens); **Microsoft Azure Attestation (MAA)** (multi-TEE verifier for Azure); **Google Cloud Confidential Space attestation service** (OIDC issuer with workload-identity federation); **AWS Nitro Attestation** (local-verifier; COSE-signed CBOR documents that AWS KMS validates inline). Cross-link to [[reference-supply-chain-provenance]]: attestation is a *supply-chain artifact*. The signed quote is a claim about the provenance of the running code; the certificate chain is the provenance of the silicon; the TCB-level policy is the provenance of the firmware. PCC's transparency log (§7) is the most concrete instance.

**The "freshness binding" pitfall.** Attestation quotes are not session tokens. A quote attests to *the state at the moment of generation*, plus a nonce supplied by the verifier. Without nonce binding, an attacker can replay an old (clean) attestation from a now-compromised platform. Canonical pattern: relying party generates a random nonce; workload includes the nonce in REPORTDATA / REPORT_DATA / USER_DATA; resulting quote covers the nonce by signature; relying party verifies the nonce matches. Failures here are common in custom pipelines.

---

## 4. SGX Attacks — The Canonical TEE Attack Corpus

SGX has been broken repeatedly; the corpus is a sub-discipline. Cross-link to [[reference-hardware-side-channels]].

**Foreshadow (USENIX Security 2018).** Van Bulck, Minkin, Weisse, Genkin, Kasikci, Piessens, Silberstein, Wenisch, Yarom, Strackx. **L1 Terminal Fault (L1TF):** when an SGX enclave evicts a memory operation that touches a "not present" page, the CPU speculatively forwards L1 cache contents to dependent instructions before the fault is delivered. A sibling-hyperthread attacker probes L1 to recover the speculated values. Foreshadow extracted RSA signing keys from production SGX architectural enclaves — including the Quoting Enclave, holding the platform's attestation key. With the QE's key, researchers could *forge attestations for arbitrary enclaves*. The deepest possible breakage: not just leaking data, but breaking SGX's attestation foundation. Intel responded with microcode flushing L1 on enclave entry, marking L1TF-vulnerable platforms as untrusted in DCAP, and re-keying attestation roots via TCB recovery. Lessons: (1) attestation keys cannot be reused across TCB-recovery events; (2) microarchitectural side channels can break attestation, not just leak data; (3) any TEE must have a TCB-recovery mechanism that revokes old quotes.

**SgxPectre (IEEE EuroS&P 2019).** Spectre v2 (branch target injection) against SGX. By poisoning the BTB before the enclave runs, the OS-attacker steers the enclave's speculative execution into gadgets that leak enclave secrets to measurable cache state. The prototype of "Spectre against TEEs."

**Plundervolt (IEEE S&P 2020).** Murdock, Oswald, Garcia, Van Bulck, Gruss, Piessens. The Intel undocumented voltage-control MSR `0x150` (accessible from kernel mode) can undervolt the CPU during enclave execution. Tuned undervolt induces faults in cryptographic operations (AES-NI, RSA-CRT); Bellcore-style analysis converts into key recovery. The first software-only fault-injection attack against SGX. Intel disabled the undervolt interface via microcode (CVE-2019-11157). Defensive pattern: **redundant computation with checksumming**.

**LVI: Load Value Injection (IEEE S&P 2020).** Van Bulck, Moghimi, Schwarz, Lipp, Minkin, Genkin, Yarom, Sunar, Gruss, Piessens. The flip side of Meltdown: instead of leaking out, **inject in**. A faulting load in a victim enclave transiently uses attacker-controlled values from microarchitectural buffers; the transient computation can be steered into gadgets that bypass enclave invariants. Structurally the hardest transient-execution attack to mitigate because it works through *any* load that might fault. Intel mitigation requires `lfence` after every load, blacklisting `ret`, recompiling all enclave code; overhead 2-19×. Intel CVE-2020-0551. Lesson: TEE mitigations sometimes require *compiler-level* changes.

**ÆPIC Leak (USENIX Security 2022, CVE-2022-21233).** Borrello, Kogler, Schwarzl, Lipp, Gruss, Schwarz. The APIC MMIO region returns uninitialized data on certain reads on Sunny Cove and Cypress Cove CPUs. The uninitialized data is stale L2 superqueue values, including data from SGX enclaves on the same physical core. The *first architectural* CPU vulnerability — not a microarchitectural side channel, a deterministic architectural bug. Fix: microcode flushes L2 superqueue on APIC reads + SGX TCB recovery. Lessons: "architectural" doesn't mean "deterministic-safe"; any peripheral register read can leak SGX state; TCB-recovery is load-bearing.

**SGX-Step (SysTEX 2017 / ACSAC 2023, Van Bulck et al.).** Not an attack but a *framework*: a Linux kernel module + userspace library that single-steps an SGX enclave by configuring untrusted page table entries and APIC timer interrupts. The substrate that made many of the above attacks practically reproducible. GPLv3 on GitHub (`jovanbulck/sgx-step`).

**General lesson.** Every TEE family inherits the attack surface of its underlying silicon. SGX inherited Skylake's; TDX inherits Sapphire Rapids'; SEV-SNP inherits Zen 3's; NVIDIA H100 CC inherits Hopper's. There is no clean-slate TEE silicon. Structural defenses: (a) TCB recovery mechanisms revoking compromised platforms; (b) microcode and compiler updates through those mechanisms; (c) defense-in-depth in the workload itself.

**Apple Silicon cross-reference (2024-2025).** The Apple Secure Enclave Processor (SEP) and PCC nodes inherit M-series microarchitecture. Three recent results that constrain Apple-side TEE assumptions, all from the Genkin lab and collaborators (cross-link to [[reference-macos-apple-security]], [[reference-hardware-side-channels]]):
>
> - **GoFetch** (Chen et al., USENIX Security 2024). The data memory-dependent prefetcher (DMP) on M1/M2/M3 activates on loaded data that "looks like" a pointer, leaking secret-dependent memory-access patterns even from formally constant-time crypto code. Demonstrated key recovery against OpenSSL Diffie-Hellman, Go RSA, **CRYSTALS-Kyber and Dilithium** (NIST PQC standards FIPS 203 / 204). On M3 the DIT (Data Independent Timing) bit disables the DMP; on M1/M2 there is no clean software mitigation. Disclosed to Apple December 5, 2023. PQC-signed attestation on M-class silicon must run with DIT set or accept the leak. Source: gofetch.fail.
> - **SLAP** (Kim, Chuang, Genkin, Yarom; IEEE S&P 2025). A *Load Address Predictor* (LAP) on M2/A15-and-later speculatively forwards data from a predicted load address; the predicted address can be steered by an adversary into out-of-bounds reads, enabling cross-origin Safari and Chrome content extraction. Disclosed to Apple May 24, 2024. Source: predictors.fail; semiengineering.com.
> - **FLOP** (Kim, Chuang, Genkin, Yarom; USENIX Security 2025). A *Load Value Predictor* (LVP) on M3/A17-and-later speculatively forwards predicted *data values* before they arrive from memory; an adversary can induce type-confusion in the predicted value, breaking Webkit / Chrome sandbox boundaries. Disclosed to Apple September 3, 2024.
>
> SLAP and FLOP are speculative-execution attacks against a *new class* of predictor (address and value, respectively) that Apple introduced and the rest of the industry has avoided. The "MIE + PAC + side-channel arms race" framing: Apple's Memory Integrity Enforcement, Pointer Authentication Codes, and per-process JIT hardening are not enough on their own — every microarchitectural performance optimization that depends on speculation creates new side channels. GoFetch's PQC implication is concretely load-bearing for any TEE migration to PQC-signed attestation on M-class hardware.

---

## 5. SEV-SNP Attacks

Smaller than the SGX corpus but instructive.

**SEVurity and the integrity-protection gap (EuroSec 2018, IEEE S&P 2020).** Morbitzer et al. (SEVered), Wilke et al. (SEVurity). Early SEV (pre-SNP) had no memory-integrity protection — the hypervisor could remap guest physical pages, replay old encrypted blocks, or rewind VM state. The defense was SEV-ES (encrypted state) and then SEV-SNP (RMP integrity protection). Lesson: encryption without integrity is not confidentiality.

**CIPHERLEAKS (USENIX Security 2021).** Li et al. The XEX mode used by SEV's memory encryption preserves a one-to-one plaintext-ciphertext mapping per physical address. The hypervisor can read the encrypted VMSA ciphertext after every VMExit. By monitoring ciphertext changes across `vmrun` cycles, the hypervisor infers plaintext changes — recovering RSA and ECDSA secrets from constant-time OpenSSL. Affects SEV-ES and **even SEV-SNP**. CVE-2020-12966; AMD bulletin AMD-SB-1013. Fix: AMD firmware patch adding randomness to the VMSA ciphertext, or software-side randomization of cryptographic intermediates. Lesson: side-channel-resistant cryptography written for plaintext-side timing is *not* automatically resistant to ciphertext-side leaks. Follow-up: *A Systematic Look at Ciphertext Side Channels on AMD SEV-SNP* (Li et al., IEEE S&P 2022).

**SEV-Step (Wilke et al., 2024).** Following SGX-Step, a single-stepping framework for SEV-SNP VMs using APIC timer interrupts. Enabled fine-grained probe-and-resolve attacks against SEV-SNP guest code.

**TEE.Fail (Chuang, Seto, Berrios, van Schaik, Garman, Genkin; IEEE S&P 2026).** Georgia Tech / Purdue / van Schaik LLC. Practical **DDR5 memory-bus interposition** attack: a hand-soldered interposer placed between the CPU and DIMM slot captures all memory traffic; the entire build costs under $1,000 and fits in a briefcase. Exploits the **deterministic encryption** modes used by Intel SGX, Intel TDX, and AMD SEV-SNP (even SEV-SNP with **Ciphertext Hiding** enabled on Zen 4/5) — the same plaintext written to the same address always encrypts to the same ciphertext, so the interposer can recover plaintext patterns and ultimately extract ECDSA private keys and forge attestation quotes. Also indirectly breaks NVIDIA GPU CC via compromised CPU-side attestations. Intel's response (INTEL-2025-10-28-001-TEE.fail) and AMD's bulletin both classify interposer attacks as *outside the design threat model* — no firmware mitigation is planned; physical security of servers is the declared mitigation. Practical takeaway: *physical-access* attacks against confidential VMs are now in scope for production threat models. Cloud-hosted TEEs whose physical security depends on data-center locks (rather than silicon resistance to bus snooping) are reduced in trust accordingly. Workloads with adversaries who can plausibly attack physical hosts (nation-state, malicious-insider with data-center access, certain edge-deployment scenarios) should not rely on x86 SEV-SNP / TDX confidentiality alone. Source: tee.fail; intel.com/.../intel-security-announcement-2025-10-28-001.html.

**Trust-the-AMD-SP and defense-in-depth.** Every SEV-SNP attestation is signed by the AMD Secure Processor — an on-die Arm Cortex-A5 running closed-source AMD firmware. The single-vendor trust-root is structural; same is true of SGX (closed Intel microcode) and CCA (closed Arm RME silicon). Open-silicon TEE (RISC-V CoVE) is the only path to *inspectable trust root*. Production SEV-SNP deployments should layer: (1) AMD-SP attestation report; (2) guest-side measurements; (3) workload-level integrity; (4) external monitoring. The CCC's doctrine — explicit in CoCo's KBS / Trustee — requires all layers to pass before releasing any secret.

---

## 6. NVIDIA Confidential Computing (H100, H200, B200)

The first production GPU TEE; the substrate for confidential AI inference at scale.

**Architecture.** Hopper H100 (CC early access via CUDA 12.2 Update 1, August 2023; GA with CUDA 12.4) added: on-die hardware root of trust; encrypted firmware; measured/attested boot; confidential mode (boot-time switch enabling encrypted-PCIe and CC attestation, disabling performance counters); encrypted PCIe DMA via SPDM 1.1 handshake (DMTF spec) establishing AES-GCM session keys; GPU TEE memory protection (on-package HBM is not encrypted but is considered physically protected; CC mode blocks direct access to GPU memory). H200 (2024) and Blackwell B200 (2024-2025) inherit and extend with larger HBM, faster encrypted-DMA, tighter NVLink integration.

**Composite trust model: CPU TEE + GPU TEE.** A confidential AI inference pipeline:

1. CPU runs a TDX or SEV-SNP confidential VM holding the application, encrypted weights, encrypted prompt.
2. GPU brought up in CC mode; CPU TEE attests the GPU.
3. Both attestations submitted to a relying-party verifier (Intel Trust Authority is canonical).
4. Verifier issues a composite token covering both halves.
5. Relying party releases encrypted weights and prompt to the CPU TEE.
6. CPU TEE establishes encrypted-DMA session with GPU; decrypts inside, ships ciphertext over encrypted-DMA.
7. GPU runs inference inside the GPU TEE; output returned via encrypted-DMA.

At no point is plaintext visible outside a TEE. The cloud operator sees only encrypted memory, encrypted bus traffic, signed attestations.

**Attestation paths.** **Local Verifier** (NVAttestation library; fetches Reference Integrity Manifest from NVIDIA; validates in-process); **Remote Verifier** (NRAS, optionally OIDC-wrapped). For composite CPU+GPU, *Intel Trust Authority* is canonical (integrated NVIDIA RIM consumption in 2023).

**Production deployments.** Apple PCC (§7) on custom Apple silicon; Azure Confidential Computing for GPUs with TDX or SEV-SNP pairing; GCP Confidential Space + H100 CC + Intel TDX. Performance overhead in CC mode is low single-digit percent for inference (NVIDIA benchmarks).

**Training in CC mode.** More challenging than inference — requires high-bandwidth multi-GPU communication (NVLink, NVSwitch). NVLink encryption matured with Hopper; B200 brings tighter integration. Confidential training is feasible at small scale but rare in production. Intermediate model: *federated + confidential* — each participant trains locally in a confidential VM; only encrypted gradients aggregate at a confidential central node. Cross-link to [[reference-privacy-engineering]] §6.

---

## 7. Apple Private Cloud Compute (PCC)

Announced at WWDC 2024. The first hyperscaler-scale "verifiable cloud" with public technical documentation, public source-code releases of attestation-validation tooling, and a Sigstore-Rekor-style transparency log of published software builds.

### 7.1 The five pillars

PCC is engineered around five claims from Apple's June 2024 *Private Cloud Compute* security paper:

1. **Stateless computation.** PCC uses personal data only to fulfill the request. Data is not retained, logged, or made available to anyone — including Apple staff — outside the request lifetime.
2. **Enforceable guarantees.** All guarantees are *technically enforceable*, not policy-declared. No guarantee depends on "we promise our employees won't access it."
3. **No privileged runtime access.** PCC has no privileged shell, no SSH for ops, no kernel debugger access in production.
4. **Non-targetability.** Through OHTTP relays, load balancers, and target diffusion, an attacker (including an Apple insider) cannot reliably steer a specific user's request to a specific PCC node.
5. **Verifiable transparency.** Apple publishes every production PCC software image for independent binary inspection. Researchers verify images against measurements in a transparency log. Once a release is signed into the log, it cannot be removed without detection.

Pillars 1, 2, 3 narrow the TCB and remove privileged backdoors; 4 prevents pre-positioning; 5 lets external researchers verify 1-3 are true. What is specifically *Apple* is the silicon (custom A-/M-series with Secure Enclave variants) and the willingness to publish the full software stack.

### 7.2 Hardware

PCC runs on custom Apple silicon servers — appliances with M-series-class processors and integrated Secure Enclave variants. Apple controls chip, board, OS, firmware, deployment pipeline. The SEP-equivalent in PCC nodes is closely related to the consumer SEP — an L4-microkernel-based subsystem with its own RoT, AES engine, protected memory — anchoring the attestation chain (boot ROM signs bootloader; bootloader measures and signs OS; OS measures and signs workloads). The custom-silicon choice is structural: PCC's "no privileged runtime access" pillar requires no off-the-shelf JTAG / BMC interface — standard servers ship BMCs with full host memory access that cannot be retrofitted out.

### 7.3 Software

Every PCC release is built from vetted source, measured cryptographically, signed by Apple's PCC signing key, submitted to the **PCC Transparency Log** (append-only, analogous to Sigstore Rekor / Certificate Transparency), and published for independent binary inspection within 90 days. Apple has open-sourced trust-validation tooling: **CloudAttestation** (constructs and validates attestations); **Thimble** (the `privatecloudcomputed` daemon on the user's device that enforces verifiable transparency); **splunkloggingd** (filters logs against accidental data disclosure); **srd_tools** (Virtual Research Environment for inspection). All four are published under a limited-use license at `github.com/apple/security-pcc`.

**Virtual Research Environment (VRE) — public release October 24, 2024.** Apple's most concrete commitment to verifiable transparency. The VRE ships in `macOS Sequoia 15.1 Developer Preview` and runs the PCC node software in a virtual machine on the researcher's local Apple silicon Mac (16 GB+ unified memory). It includes a **virtual Secure Enclave Processor (SEP)** — *the first time SEP has been available for direct researcher inspection* — and a virtualization-adapted boot path and kernel. The VRE makes it possible to: (a) run unmodified PCC node software locally and exercise the attestation flow; (b) inspect the SEP-equivalent boot and key-derivation logic; (c) test workload behavior under custom inputs; (d) iterate on bug-bounty submissions without touching production. Apple expanded the bug bounty alongside the VRE to up to **$1,000,000 for arbitrary code execution on a PCC node compromising user request data**, with three primary categories: accidental disclosure, external compromise, and physical / internal-access threats. Source: security.apple.com/blog/pcc-security-research/; security.apple.com/blog/private-cloud-compute/; github.com/apple/security-pcc.

**Independent analysis: Trail of Bits (June 2024).** Trail of Bits' *PCC: Bold step forward, not without flaws* (blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/) is the most rigorous public critique of the PCC announcement. Key technical findings: (1) **Apple owns the attestation root** — "enclaves and attestation will provide only limited guarantees to end-users, as Apple effectively owns the attestation keys," meaning users cannot independently verify silicon-level integrity without trusting Apple; (2) **Custom-GPU TCB risk** — Apple's GPUs are less battle-tested than Nvidia's; the **LeftoverLocals** vulnerability (CVE-2023-4969) still affected M2 GPUs at the time of analysis, enabling LLM-output extraction via GPU memory leakage; (3) **Metal does not enforce GPU memory safety**, leaving exposure to side-channel attacks (the non-targetability pillar partially mitigates this); (4) **ML stack runtime risk** — Apple's Swift-based ML stack avoids the Python-runtime exploitation patterns common to other vendors; (5) **The data-decryption requirement** — PCC must access plaintext at compute time because homomorphic encryption doesn't scale for current ML workloads; the entire PCC architecture is "TEE-required because crypto is too slow," not "TEE-as-defense-in-depth."

**The PCC + Apple Intelligence production reality.** Apple Intelligence in iOS 18 / macOS Sequoia (shipped late 2024) routes requests to on-device models when possible and to PCC nodes only for queries exceeding device capability. The routing decision is made on-device; the device uses Thimble to verify the PCC node's attestation against the transparency log before releasing the request. The cloud fraction is the PCC threat surface.

### 7.4 User-side enforcement: Thimble

The load-bearing piece is **Thimble** on the user's device. Before sending a request, Thimble fetches the current fleet's measurements from the transparency log, obtains an attestation from the candidate PCC node, verifies the measurement against log entries, and only then releases the (end-to-end encrypted) request. The device refuses to talk to a node whose measurement is not in the log — meaning Apple cannot run unpublished code on PCC nodes without being noticed by every device consulting the log. Cross-link to [[reference-supply-chain-provenance]] §11: PCC's mechanism is *exactly* the construction used by Sigstore Rekor and Certificate Transparency, applied to "what code runs in the cloud."

### 7.5 Cross-link to capability discipline

A traditional cloud API is *ambient-authority*; a PCC request is *capability-bounded*: the device verifies known-measured code is running; the cloud cannot execute code outside that codebase without detection; the codebase is constrained by design to operate on the request data only for the request lifetime. The transparency log is the *public ledger* of capabilities the cloud is allowed to exercise. Thimble is the *capability checker*. The "no privileged runtime access" pillar is the *no synthesis* rule. Cross-link to [[reference-agentic-web-capabilities]] §1-2.

### 7.6 Why PCC matters

Three reasons beyond the technology: (1) **architectural reference** — a technically-detailed design other hyperscalers can imitate; (2) **bug-bounty precedent** — Apple is willing to be *publicly broken* if its claims are false; (3) **capability discipline at scale** — before PCC, capability-rooted verifiable computing was a niche topic. Honest assessment: PCC depends on trusting Apple at the silicon and supply-chain level. The transparency log makes code auditable; silicon and deployment pipeline are not. For workloads where "trust Apple" is acceptable, PCC is the strongest cloud privacy story. For workloads where the user does not want to trust any single vendor, no current technology provides hyperscaler-scale confidential computing without trusting at least one silicon vendor and one cloud operator.

---

## 8. Programming Model and Frameworks

The TEE programming model has been historically painful; frameworks smooth that pain with varying success.

- **Open Enclave SDK (Microsoft, CCC).** Hardware-agnostic C / C++ SDK targeting Intel SGX and (with OP-TEE) Arm TrustZone. Single API surface for `oe_create_enclave` / `oe_call_enclave`. Designed for SGX-style fine-grained trust units; less natural for confidential-VM workloads.
- **Apache Teaclave.** Started as a FaaS platform for SGX; pivoted (2024-2025) to memory-safe TA SDKs: **Teaclave SGX SDK** (Rust for Intel SGX); **Teaclave TrustZone SDK** (Rust for Arm TrustZone via OP-TEE); experimental Java TEE SDK. Memory-safe TA development is the selling point — historic GlobalPlatform TA APIs are C-only with the usual buffer-overflow corpus.
- **Enarx (Profian / CCC).** WebAssembly-based deployment. Author in any language that compiles to Wasm; Enarx packages into a "Keep" — a TEE-deployed runtime. Same Wasm artifact runs unmodified on SGX, SEV-SNP, or other TEE backends. Attestation handled by Enarx; application sees an attestation API rather than a per-platform stack. Costs: Wasm trust model (the Wasm runtime is part of the TCB); performance overhead 1.5-3× vs native. Cross-link to [[reference-agentic-web-capabilities]] §7 — Enarx's Wasm and the Bytecode Alliance's Component Model are complementary (Wasm provides language abstraction; the Component Model provides capability-typed composition).
- **Fortanix EDP.** Rust-native SDK for Intel SGX. Existing Rust programs compile for SGX without rewriting. Mature for SGX-on-Xeon production.
- **EGo (Edgeless Systems).** Go-native SDK for SGX. Adapts the Go compiler (`ego-go`) to produce enclave-compatible binaries; CLI for signing and packaging. Edgeless Systems also produces **MarbleRun** (K8s-native enclave orchestration) and **Contrast** (CoCo-compatible runtime).
- **Confidential Containers (CoCo) — CNCF project.** Brings confidential VMs to Kubernetes. Each pod runs inside its own TEE (TDX, SEV-SNP, IBM Z, or NVIDIA H100 CC). Uses **Kata Containers** as substrate — Kata runs each pod in a microVM; CoCo upgrades the microVM to a confidential VM. The **Trustee / KBS** handles attestation verification and secret release. Contributors: Alibaba, AMD, ARM, Edgeless, IBM, Intel, Microsoft, NVIDIA, Red Hat, Rivos. The canonical Kubernetes-native confidential-computing project in 2026. **Maturity update 2024-2026:** CoCo entered CNCF Sandbox March 2022. **OpenShift sandboxed containers v1.7.0** (Red Hat) ships CoCo as tech preview on Azure for both Intel TDX and AMD SEV-SNP, plus IBM Z / LinuxONE Secure Execution. **Azure Kubernetes Service (AKS) Confidential Containers** is in preview on AMD SEV-SNP. Trustee design clarification: in production the KBS itself must run in a trusted environment (often its own TEE), with the trustee-operator handling orchestration. Source: confidentialcontainers.org; developers.redhat.com/articles/2025/07/10/how-debug-confidential-containers-securely; learn.microsoft.com/en-us/azure/aks/confidential-containers-overview.
- **Veracruz.** CCC project from 2020-2022 focused on confidential MPC; less actively maintained in 2026.
- **Asylo (Google) — deprecated.** Open-sourced 2018, archived April 2026. Use Confidential Space / CoCo instead.

The dominant 2026 pattern is *Open Enclave for SGX, CoCo for confidential VMs, NVIDIA H100 CC for GPU, with a shared attestation backbone*. Full-stack abstractions (Enarx, Veracruz) haven't taken over because (1) most production workloads don't need cross-TEE portability, and (2) the abstraction layer adds latency and attack surface so "deploy native" wins for performance-sensitive workloads. The exception is *cross-cloud confidential workloads*, where CoCo + a managed attestation broker is the canonical solution.

---

## 9. Cloud Confidential Computing Offerings

**Microsoft Azure Confidential Computing.** The most aggressive hyperscaler adopter (Russinovich's leadership is load-bearing): DCsv3 / DCsv2-series (Intel SGX VMs, declining); DCasv5 / ECasv5 / DCadsv5 / ECadsv5-series (AMD SEV-SNP); DCe / ECe-series (Intel TDX); Azure Confidential Ledger (append-only ledger inside SGX); Azure Attestation (MAA, managed verifier for SGX, TDX, SEV-SNP); Azure Confidential Containers on AKS (CoCo-based); GPU confidential VMs (composite with NVIDIA H100 CC). Russinovich's public position is that confidential computing should become the default for all Azure VMs.

**AWS Nitro Enclaves.** Structurally different. Instead of TDX / SEV-SNP, AWS built the **Nitro System** — a custom hypervisor + Nitro Cards (PCIe-attached secure subsystems) handling VM isolation. A **Nitro Enclave** is a sub-instance of an EC2 parent: fully isolated, no persistent storage, no external network, no interactive access. Only path is a *vsock* channel to the parent. Attestation is a CBOR / COSE-signed document from the Nitro Hypervisor with PCRs of the enclave image; can be a condition in AWS KMS key policies — KMS returns decrypted keys only if the enclave attests with expected PCRs. Nitro Enclaves are *not* hardware-rooted in CPU silicon; the trust root is AWS Nitro firmware on the Nitro Card. Weaker than TDX / SEV-SNP confidentiality-from-cloud-operator, stronger than vanilla EC2. AWS also offers AMD SEV-SNP confidential instances (M6a, C6a, R6a).

**Google Cloud Confidential Computing.** Two products: **Confidential VMs** (AMD SEV-SNP since 2024, Intel TDX since 2024 on C3 machines; drop-in compatible with standard GCE images); **Confidential Space** (managed workload platform — runs container images in hardened attested TEE-backed VMs with workload-identity federation; third-party data collaborators release secrets only if workload attests cleanly). Confidential Space is the most fully-realized "confidential multi-party computation" platform among hyperscalers. **2024-2025 state:** Confidential GKE Nodes on SEV-SNP GA; **Confidential VM and Confidential GKE Nodes with NVIDIA H100 GPUs on A3 machines GA** (Intel TDX on the CPU + NVIDIA CC on the GPU — Google Cloud's first confidential GPU offering); Confidential Space on C3 with TDX GA, with H100-GPU Confidential Space in preview. **Vertex AI Workbench Confidential Computing** is available but SEV-only as of early 2026 — TDX and GPU support are rolling out. Source: cloud.google.com/blog/products/identity-security/from-clicks-to-clusters-confidential-computing-expands-with-intel-tdx; docs.cloud.google.com/confidential-computing.

**IBM Cloud Hyper Protect Services.** Z-based offering — IBM Z mainframes (z15 / z16) plus LinuxONE, providing confidential Linux KVM guests via Secure Execution. Used heavily in financial services and government. Smaller market than x86 hyperscalers; mature confidential-execution semantics.

**The "managed attestation service" trend.** Every hyperscaler is converging on the same shape: a managed attestation service that verifies hardware-rooted quotes from heterogeneous TEEs and issues a uniform OIDC token; the token drives workload-identity federation with cloud IAM. Application doesn't have to handle SGX / TDX / SEV-SNP / NVIDIA RIM verification logic; cloud IAM gets a single identity primitive regardless of TEE family; cross-cloud policies are expressible if claims are uniform (the EAT IETF spec is the standardization effort). By 2027 the major confidential workloads will likely use managed attestation rather than building verification in-application.

**Confidential AI offerings.** Azure Confidential ML (inference endpoints on H100 CC); GCP Confidential Space + ML (inference on SEV-SNP or TDX + H100 CC; federated learning); Apple PCC (§7). Cross-link to [[reference-llm-agent-security]] §3 — a confidential MCP server is a natural application.

**Anthropic Confidential Inference (June 18, 2025).** First major foundation-model vendor to publish an end-to-end architecture document for TEE-backed inference. *Confidential Inference via Trusted Virtual Machines* (anthropic.com/research/confidential-inference-trusted-vms) describes a two-stage pipeline:

> 1. **API Server** processes the prompt and emits tokens.
> 2. **Inference Server** runs Claude on hardware accelerators and emits completion tokens.

The architecture uses a **TPM-rooted attestation chain**: each boot stage is measured into TPM PCRs, producing a hash attesting "the loader server is isolated the way we expect, is running our signed and reviewed code." A **separate trusted loader VM** acts as a "virtual accelerator" and refuses to accept programs that are not signed by Anthropic's secure CI. **Model weights are stored encrypted**, with decryption keys released by a keyserver only after it checks the attestation; weights are decrypted inside the loader and never leave the TEE in plaintext. User data is decrypted at two points (API and inference) inside the TEE. The document explicitly flags that "not all accelerators fully support confidential computing yet" and signals Anthropic is "exploring models of confidential computing where other parties validate the trusted code and manage independent keyservers." Cross-link to [[reference-llm-agent-security]] and [[reference-adversarial-ml-model-security]]: the architecture defends against (a) cloud-operator visibility into prompts and completions, (b) model-weight exfiltration by the cloud or insiders, (c) substitution of a tampered inference binary in production. It does *not* defend against side-channel attacks on the accelerator (constant-time is the workload's responsibility), TEE.Fail-class physical attacks, or compromise of Anthropic's CI / signing infrastructure. Source: anthropic.com/research/confidential-inference-trusted-vms; assets.anthropic.com/m/c52125297b85a42/original/Confidential_Inference_Paper.pdf.

---

## 10. Application Patterns

**Confidential inference.** The dominant 2026 use case. Model operator encrypts weights with a key released only to attested TEEs; user encrypts prompts likewise; confidential VM + GPU TEE attest; verifier releases both keys; TEE decrypts and computes; output is encrypted and returned. Plaintext is never visible outside a TEE. Production examples: Apple PCC; selected OpenAI / Azure-Confidential-ML paths. Overhead is low single-digit percent.

**Confidential training.** Same pattern as inference but requires high-bandwidth multi-GPU communication. Hopper's NVLink encryption and Blackwell's NVSwitch encryption are catching up; production confidential training is feasible at small scale. Common production pattern: *federated + confidential* — each participant trains locally in a confidential VM; only encrypted gradients aggregate at a confidential central node. Cross-link to [[reference-adversarial-ml-model-security]] §5 and [[reference-privacy-engineering]] §6. Confidential training still needs DP if model-inversion / membership-inference is in scope.

**Confidential multi-party computation.** Three or more parties pool encrypted data inside a shared TEE for joint computation. Use cases: cross-bank fraud detection, cross-government threat intelligence, multi-vendor vulnerability-reporting. GCP Confidential Space is canonical. Each party encrypts with their own KMS keys; the attestation service authorizes a known-measured workload to receive decrypted data from all parties; the workload runs the joint computation; only the aggregate is decrypted outside. This pattern *replaces* classical secret-sharing-based MPC for many use cases — TEE-MPC is much faster (often 100-1000×) at the cost of trusting the silicon vendor.

**Confidential RAG.** A private corpus is encrypted; only an attested RAG TEE can decrypt for in-context indexing and retrieval. The user's query is encrypted; the LLM runs in the TEE; only the answer is decrypted to the user. Enterprise pattern in 2026: RAG over confidential internal documents (legal contracts, M&A research, proprietary R&D) where the cloud operator cannot see documents or queries.

**Confidential vector database.** The index, embeddings, and query vectors live inside a TEE. Confidential semantic search over health records; confidential code-search inside SDLC platforms. Vector DBs want to be large and distributed; confidential vector DBs are usually deployed as confidential VMs with the entire DB image inside; sharding requires per-shard attestation and encrypted-RPC.

**Confidential blockchain.** Smart contracts running inside a TEE so the executor does not see plaintext contract state. **Oasis Network (Sapphire ParaTime)** — Ethereum-compatible confidential smart contracts on Intel SGX in production since December 2022. **Secret Network** — Cosmos-based confidential smart contracts on SGX. **Intel TDX-based L1s** — emerging. The structural critique: the single-vendor trust root (every Oasis node trusts Intel SGX firmware) means a "decentralized" blockchain is centralized at the silicon-trust layer.

**Confidential MCP servers.** A new pattern: the user's MCP host (LLM agent) wants to invoke tools on third-party MCP servers without those servers seeing prompt content or agent reasoning. The MCP server runs in a confidential VM, attested to the user. The MCP client connects over TLS terminated inside the TEE. Tool invocations and arguments are decrypted only inside the TEE. The TEE's audit logs are encrypted; only the user holds the decryption key. This is the application of capability discipline (cross-link to [[reference-agentic-web-capabilities]] §5) to MCP: the user grants a capability to a TEE whose code they have verified; the server operator cannot use the capability for anything beyond what the verified code does. Cross-link to [[reference-llm-agent-security]] §3.

**Confidential federated identity.** A verifiable IdP runs in a TEE; the verifier can be certain the IdP's signing key has not been exfiltrated and is only used by code matching a known measurement. Useful for high-assurance identity infrastructure (national digital-identity) where IdP compromise would be catastrophic. Pilots exist (EU's eIDAS 2.0); production deployments rare.

**Confidential supply-chain attestation.** The build pipeline runs inside a TEE; the artifact is signed by a key released only to the attested build environment. The signature attests "this artifact was produced by this build pipeline running this code inside a TEE." Composes with SLSA / Sigstore (cross-link to [[reference-supply-chain-provenance]]). Meaningful because *most* supply-chain attacks today compromise the build pipeline, not the artifact.

---

## 11. The "Is This Really Secure?" Question

Confidential computing is real, useful, structurally sound, but not a panacea.

**Side channels persist.** Memory encryption does not defend against cache timing, branch-prediction timing, frequency timing (Hertzbleed), power analysis, or microarchitectural data leaks. Every TEE family inherits the side-channel surface of its silicon. Defensive doctrine: *constant-time cryptography even inside the TEE* — the TEE is a complementary layer, not a substitute. New transient-execution attacks land every 6-18 months. TCB recovery works but disclosure-to-mitigation latency is real.

**The single-vendor trust-root critique.** Each TEE family requires trusting *exactly one* silicon vendor. There is no way to inspect the SGX microcode, TDX module, AMD-SP firmware, NVIDIA on-die RoT, or Apple's silicon. The vendor's signing key is the trust root; if compromised, every quote is fraudulent. No known compromises of major TEE signing keys as of 2026, but *concentration of trust* is structural. RISC-V CoVE is the only path toward open-silicon TEEs.

**Supply-chain implications.** The fab → chip → key-injection → deployment pipeline has many points where a capable adversary could insert a backdoor. The threat model assumes silicon is honest; nation-state-scale adversaries who can compromise fab or key-injection are outside scope. For classified data processing, confidential computing on commodity silicon is *not sufficient* — additionally use HSMs, air-gapped infrastructure, defense-in-depth.

**The "TEE-as-claim is marketing" trap.** Red flags: "confidential by encryption" without integrity protection (SEV pre-SNP); "confidential via container isolation" without hardware backing (a regular Linux container with seccomp is not a TEE); "confidential by policy" ("we promise our employees don't access it"). A real offering supports attestation — the relying party verifies the workload is running in a specific TEE family with a known measurement. No hardware-rooted attestation quote means not confidential computing.

**Defense-in-depth inside the TEE.** Encrypt data at rest separately; constant-time cryptography inside the TEE; validate input rigorously (the TEE protects against external tampering, not malicious input the workload mishandles); layer attestation with workload-level integrity checks; plan for TCB-recovery events. The anti-pattern "we run in a TEE, we don't need to do anything else" is a recurring failure.

**The post-Foreshadow trust-rebuild cycle.** Every major TEE attack family forces a TCB-recovery: Foreshadow → SGX TCB level revision + attestation re-keying; ÆPIC Leak → TCB revision; LVI → TCB revision + compiler-level mitigations; CIPHERLEAKS → AMD bulletin + software mitigations; TEE.Fail (2025) → declared outside the Intel / AMD threat model; no firmware mitigation planned. A workload that "passes attestation today" may not pass tomorrow; deployment systems must handle this gracefully.

**TEE vs MPC vs HE: when each is right.**

| Property | TEE | MPC (classical) | Homomorphic Encryption |
|---|---|---|---|
| Trust root | Hardware vendor | Cryptographic assumption | Cryptographic assumption |
| Performance overhead | 1.05-1.2× | 100-10000× | 1000-1000000× |
| Multi-party | Yes (via attestation) | Yes (native) | Limited (FHE is single-party) |
| Side-channel resistant | No (workload must add) | Yes (cryptographic) | Yes (cryptographic) |
| Vendor dependence | High | None | None |

Use TEE when performance matters and trusting a silicon vendor is acceptable. Use MPC when multi-party trust assumptions are minimal and the computation is simple. Use HE when only the data owner sees plaintext and the computation suits FHE primitives. In 2026 TEE-based confidential computing has eclipsed MPC and HE for the *majority* of workloads where any one would have been the right answer five years ago. The exception is workloads where the silicon-vendor trust root is unacceptable; for those, MPC remains the only option. Cross-link to [[reference-cryptography]] §8 (FHE) and [[reference-privacy-engineering]] §5-6 (MPC, DP).

---

## 12. Detection and Monitoring

**Attestation health monitoring.** Track attestation success rate (a sudden drop suggests TCB-recovery events, expired certificates, or platform compromise); TCB level distribution (alert when behind on a published recovery); quote freshness (old quotes shouldn't be accepted; enforce nonce binding); signing-key rotation (track when AMD KDS / Intel PCS issues new keys).

**TEE-internal logging discipline.** Logs that leave the TEE must filter aggressively — anything in the log is by definition outside the TEE. PCC's `splunkloggingd` is the production reference: filter log content against an allowlist before emission. Default for workloads without such a filter: *do not log inside the TEE*. Save diagnostic state inside; expose only aggregate metrics (success count, latency p50, error class) through a hardened-emit channel.

**Continuous attestation.** A single attestation at workload start is a one-shot. For long-running workloads, require *periodic re-attestation* — TEE produces a new quote at intervals; relying party invalidates session state on validation failure. Frequency depends on workload (every request for sensitive ops; every hour for background services). Asymmetric and cheap; use for any high-value workload.

**Cloud-CC monitoring integrations.** AWS: CloudWatch metrics on Nitro Enclave health, KMS attestation-key usage, attestation-failure rates. Azure: Azure Monitor on Confidential VM lifecycle, MAA throughput, failures. GCP: Cloud Logging on Confidential Space attestation, OIDC token issuance, workload-identity federation. Cross-link to [[reference-detection-engineering]]. TEE-internal events are *invisible* to host-side detection; detection moves to the perimeter — attestation flows, network ingress/egress, KMS key-release patterns.

**Anomaly detection on attestation patterns.** Monitor attestation requests to your verifier: sudden bursts from new platforms (possible recon for physical-access attacks); repeated failures from the same platform (possible misconfiguration or compromise); requests from platforms silent for months (possible attacker reawakening); requests with malformed nonces or unusual TCB-level claims (possible attestation-forgery attempt). Build these into your verifier's monitoring layer.

---

## 13. Defensive Patterns and Adoption Guidance

**Choose TEE by use case.**

- **Confidential inference / training (AI):** Intel TDX or AMD SEV-SNP + NVIDIA H100/H200/B200 CC; composite via Intel Trust Authority.
- **Confidential containers in Kubernetes:** CoCo (TDX or SEV-SNP) + Trustee KBS.
- **Confidential VM workloads (general-purpose):** Intel TDX or AMD SEV-SNP, picked by hyperscaler availability.
- **Fine-grained enclave for legacy SGX-shaped workloads:** Intel SGX on Xeon.
- **AWS-native enclave-style:** AWS Nitro Enclaves + KMS attestation conditions.
- **Multi-party confidential computation:** GCP Confidential Space.
- **Mobile / firmware DRM / mobile key custody:** Arm TrustZone via OP-TEE.
- **Mainframe shop:** IBM Z Secure Execution on z16.

**Always verify attestation before sharing secrets.** The load-bearing pattern. *Never* release secrets to a TEE without verifying attestation. The naive "I deployed my app; surely it's secure" pattern fails because nothing prevents a malicious operator from running unmodified code outside the TEE and accepting the secret. Flow: generate a fresh nonce; request attestation including the nonce; verify signature, certificate chain, measurement, TCB level, nonce binding; *only if all checks pass*, release the secret over a TLS channel terminated inside the TEE.

**Plan for TCB-recovery events.** TCB-recovery events recur for any active TEE family. Each event invalidates prior attestations. Detect TCB-recovery (poll vendor advisories, KDS / PCS updates); update minimum-acceptable-TCB policy in the verifier; re-attest active workloads; restart workloads on un-microcoded hosts. For long-running workloads, continuous attestation + a TCB-level policy is the structural answer.

**Combine TEE with traditional crypto.** Don't trust the TEE alone. Encrypt at rest separately (KMS-wrapped storage). Rotate session keys frequently. Use mTLS or E2EE for data paths to the TEE. Use constant-time cryptography inside the TEE. The TEE protects runtime memory and computation; it does not protect data at rest, data in transit (TEE outbound traffic is still subject to wire-level threats), or computational side channels inside the TEE.

**Open-source the TEE-internal code.** The PCC pattern (§7) is generalizable: publish code that runs inside the TEE; sign every release into an append-only transparency log; have relying parties verify the log. Particularly valuable for confidential-MPC and confidential-inference where multiple parties depend on TEE code being honest. Without published code, parties trust both silicon vendor and cloud operator's deployment process; with published code, they trust only the silicon vendor. Cross-link to [[reference-supply-chain-provenance]] §11.

**Performance test early.** Even single-digit-percent overhead matters at scale. Benchmark VM exit/entry overhead under TDX or SEV-SNP; encrypted-DMA bandwidth between CPU and GPU TEEs; attestation latency at workload start; continuous-attestation overhead; KMS roundtrips for secret release. 3% per-call on a 1M-RPS service is meaningful.

**Use a managed attestation service when possible.** In-application attestation verification is high-effort and high-risk. Vendor-managed services (Intel Trust Authority, Azure MAA, GCP Confidential Space attestation, AWS Nitro + KMS) are well-tested, handle TCB-level enforcement automatically, integrate with cloud IAM.

### Code-review checklist for confidential workloads

1. Does the relying party verify attestation *before* releasing any secret?
2. Is the attestation nonce fresh and bound by signature?
3. Is the certificate chain validated to a vendor root the relying-party trusts?
4. Is the measurement compared against an *expected* reference value (not just "any measurement")?
5. Is the TCB-level checked against a current minimum-acceptable policy?
6. Are TEE-internal logs filtered against an allowlist before emission?
7. Are cryptographic operations inside the TEE constant-time?
8. Is data at rest encrypted with keys distinct from session keys?
9. Are continuous-attestation policies in place for long-running workloads?
10. Are TCB-recovery events handled gracefully (re-attestation, restart, alerting)?
11. Is the TEE-internal code published or otherwise auditable?
12. Are KMS key-release policies bound to attestation claims (not just to IAM identity)?

### Cross-link to broader security disciplines

- [[reference-cryptography]] — constant-time-inside-the-TEE; KMS / HSM integration.
- [[reference-hardware-side-channels]] — transient-execution and cache attacks constraining TEE security (SLAP, FLOP, GoFetch, TEE.Fail).
- [[reference-agentic-web-capabilities]] — capability discipline PCC and confidential MCP servers instantiate.
- [[reference-supply-chain-provenance]] — transparency-log construction PCC adopts.
- [[reference-privacy-engineering]] — MPC / DP alternatives; federated learning.
- [[reference-llm-agent-security]] — agent-runtime threats confidential inference mitigates; Anthropic confidential-inference architecture.
- [[reference-adversarial-ml-model-security]] — privacy attacks TEE-based inference defends against.
- [[reference-detection-engineering]] — logging and detection appropriate for confidential workloads.
- [[reference-macos-apple-security]] — SEP, MIE, PAC, JIT hardening; SLAP / FLOP / GoFetch microarchitectural research against Apple Silicon.
- [[reference-macos-memory-corruption-investigation]] — heap-spray and binary-format surgery patterns relevant to SEP / PCC node memory bugs.
- [[reference-mobile-security]] — Arm TrustZone, mobile SEP variants, mobile-device confidential-computing boundaries.
- [[reference-post-quantum-cryptography]] — PQC-signed attestation migration; GoFetch leak of CRYSTALS-Kyber and Dilithium constrains M-class deployment.

---

## 14. Variant Analysis — Under-Explored Frontiers

**TEE for AI agent runtimes.** An agent runtime is a natural fit: tool catalog can be measured (relying party sees what tools the agent has access to); reasoning chain can be encrypted (no operator visibility into chain-of-thought); tool invocations can be attested-on-arrival (tool provider verifies the request is from a known-measured agent in a TEE, not a synthetic request from a confused-deputy attacker). The capability discipline that [[reference-agentic-web-capabilities]] argues for is precisely what a confidential agent runtime imposes by construction. Deployable in 2026 with H100 CC + TDX / SEV-SNP and a managed attestation service. The technology is mature; the discipline isn't widely adopted yet.

**Multi-party confidential AI.** Three or more organizations share encrypted training data and a shared model inside a confidential TEE. No party sees others' data; no party sees the joint model in plaintext unless it's the agreed output. Use cases: cross-pharma drug discovery, cross-bank fraud detection, cross-government threat intelligence. GCP Confidential Space is canonical; production deployments are starting to land in 2025-2026.

**TEE for federated identity.** A national-level digital-identity system needs an IdP that cannot be compromised even by the operator. A TEE-hosted IdP with attested signing keys, published code, and a transparency log of signing operations could provide this. Critique: shifts the trust root from operator-key-management to silicon-vendor — sometimes meaningful, sometimes sideways.

**TEE-attested supply-chain artifacts.** A build pipeline inside a TEE produces artifacts signed by a key released only to that TEE, attesting the signature to a known-measured build environment. Composes with SLSA / Sigstore (cross-link to [[reference-supply-chain-provenance]]). *Most* supply-chain attacks compromise the build pipeline, not the artifact. A TEE-hosted build pipeline forces the attacker to either compromise the silicon vendor or the published TEE code (visible in the transparency log) — both significantly harder than compromising a typical build server.

**Decentralized TEE networks.** Secret Network and Oasis Network are production instances. Deep critique: trust root is still single-vendor (Intel SGX for most). A decentralized blockchain on a centralized silicon-trust-root has at best the weaker of the two security properties. Real "decentralized confidential computing" requires multiple-vendor TEEs operating in agreement, which no production network has implemented.

**TEE for cryptocurrency exchange MPC.** Exchange custody keys held inside a TEE-based MPC quorum with attested-and-policy-conditioned key release. Production deployments exist (Fireblocks); technology is mature.

**Quantum-resistant attestation.** Today's TEE attestations are signed with ECDSA or RSA — vulnerable to a sufficiently-capable quantum adversary. NIST has published PQC standards (FIPS 203 / 204 / 205); migration to PQC-signed attestation will likely happen 2026-2030. Cross-link to [[reference-cryptography]] §7-8. Non-trivial because silicon attestation keys are baked in at fab. Migration requires either (a) re-fab with PQC keys or (b) a hybrid where silicon key signs a PQC key used for attestation. Most vendors pursue (b).

**The "TEE as the new HSM" reality.** Historically "we need confidential cryptographic key custody" was answered by an HSM (FIPS-140-certified appliance, tamper-resistant boundary, small attack surface, slow, expensive). In 2026 TEEs are replacing HSMs for many workloads. A confidential VM with SEV-SNP and hardware-rooted attestation is cheap, fast, and offers similar trust properties to a low-end HSM. For workloads requiring HSM-level assurance, dedicated HSMs remain right; for workloads where the HSM was chosen by default ("we needed somewhere to hold a key"), a TEE is increasingly the cheaper / faster / equivalently-secure answer.

---

## 15. References

### Standards and consortia

- Confidential Computing Consortium. https://confidentialcomputing.io
- CCC, *A Technical Analysis of Confidential Computing* v1.3 (2022). https://confidentialcomputing.io/wp-content/uploads/sites/85/2023/01/CCC-A-Technical-Analysis-of-Confidential-Computing-v1.3_unlocked.pdf
- IETF RATS Working Group (EAT). https://datatracker.ietf.org/wg/rats/

### Intel SGX and TDX

- Intel SGX Developer Reference. https://www.intel.com/content/www/us/en/developer/articles/training/intel-sgx-software-development.html
- Intel TDX. https://www.intel.com/content/www/us/en/products/docs/accelerator-engines/trust-domain-extensions.html
- Intel TDX Module v1.5 Base Architecture Specification. https://www.intel.com/content/www/us/en/content-details/733575/intel-tdx-module-v1-5-base-architecture-specification.html — PDF: https://cdrdv2-public.intel.com/733575/intel-tdx-module-1.5-base-spec-348549002.pdf
- Intel TDX Module ABI Reference v1.5. https://cdrdv2-public.intel.com/795475/intel-tdx-module-1.5-abi-spec-348551003.pdf
- intel/tdx-module (GitHub, source + releases). https://github.com/intel/tdx-module — https://github.com/intel/confidential-computing.tdx.tdx-module/releases
- Intel TDX Enabling Guide (covers 5th Gen Xeon + Xeon 6 / Granite Rapids). https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/01/introduction/index.html
- Intel TDX security research. https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/tdx-security-research-and-assurance.html
- Intel Trust Authority (formerly Project Amber; GA 2023). https://www.intel.com/content/www/us/en/security/trust-authority.html — Docs: https://docs.trustauthority.intel.com/main/articles/articles/ita/whats-new.html
- DCAP reference. https://github.com/intel/SGXDataCenterAttestationPrimitives
- Intel Security Announcement INTEL-2025-10-28-001 (TEE.Fail). https://www.intel.com/content/www/us/en/security-center/announcement/intel-security-announcement-2025-10-28-001.html

### AMD SEV / SEV-SNP

- David Kaplan, *Hardware VM Isolation in the Cloud*, ACM Queue 21(4), 2023. https://dl.acm.org/doi/abs/10.1145/3623392
- AMD SEV-SNP whitepaper. https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf
- AMD Confidential Computing (EPYC product page, includes Turin / 9005-series TDISP). https://www.amd.com/en/products/processors/server/epyc/confidential-computing.html
- AMD SEV / SEV-SNP developer hub. https://www.amd.com/en/developer/sev.html
- Phoronix, *Evaluating The Performance Cost To AMD SEV-SNP On Modern EPYC VMs Review* (EPYC 9005 / Turin benchmarks). https://www.phoronix.com/review/amd-epyc-9005-sev-snp
- Ubuntu Server documentation, *Confidential Computing with AMD*. https://ubuntu.com/server/docs/how-to/virtualisation/sev-snp/
- AMD SB-3021 (CIPHERLEAKS). https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3021.html
- AMD KDS. https://kdsintf.amd.com/

### Arm CCA

- Arm CCA. https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture
- Arm CCA Linux kernel docs. https://docs.kernel.org/arch/arm64/arm-cca.html
- Li et al., *Design and Verification of the Arm CCA*, OSDI 2022. https://www.cs.columbia.edu/~rgu/publications/osdi22-li.pdf
- TF-RMM. https://www.trustedfirmware.org/projects/tf-rmm/
- Cortex-A720 product page (Armv9.2-A). https://www.arm.com/products/silicon-ip-cpu/cortex-a/cortex-a720
- Cortex-A720 Core Technical Reference Manual. https://developer.arm.com/documentation/102530/latest/
- Arm Learning Paths, *Get started with Realm Management Extension (RME): Arm CCA*. https://learn.arm.com/learning-paths/cross-platform/cca_rme/cca/

### RISC-V

- Sahita et al., *CoVE* (arXiv:2304.06167). https://arxiv.org/pdf/2304.06167
- Keystone. https://keystone-enclave.org/

### NVIDIA Confidential Computing

- NVIDIA, *Confidential Compute on Hopper H100* (WP-11459-001). https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf
- NVIDIA, *Secure AI with Blackwell and Hopper GPUs* (TEE-I/O, NVLink encryption, GB200). https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf
- NVIDIA AI Security with Confidential Computing. https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/
- NVIDIA Blackwell Architecture (B200, GB200, NVL72). https://www.nvidia.com/en-us/data-center/technologies/blackwell-architecture/
- GB200 NVL72. https://www.nvidia.com/en-us/data-center/gb200-nvl72/
- NVIDIA Deployment Guide for Confidential Computing (DU-12302-001). https://docs.nvidia.com/cc-deployment-guide-tdx.pdf
- NVIDIA Confidential Computing on H100 GPUs. https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/
- *NVIDIA GPU Confidential Computing Demystified* (arXiv:2507.02770). https://arxiv.org/html/2507.02770v1
- Nertney, *Remote Attestation for NVIDIA Hopper and Blackwell GPUs, CPUs, and Beyond* (OC3 2025). https://cdn.prod.website-files.com/63c54a346e01f30e726f97cf/67f00a27564271b2f87c4988_Rob%20Nertney%20OC3%202025%20-%20Nvidia%20Blackwell.pdf
- *Creating the First Confidential GPUs*, Communications of the ACM. https://cacm.acm.org/practice/creating-the-first-confidential-gpus/
- Zhu et al., *Confidential Computing on nVIDIA Hopper GPUs: A Performance Benchmark Study* (arXiv:2409.03992). https://arxiv.org/html/2409.03992v3
- NVTrust. https://docs.nvidia.com/nvtrust/index.html
- Intel Trust Authority GPU attestation. https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html

### Apple Private Cloud Compute

- *Private Cloud Compute: A new frontier for AI privacy*. https://security.apple.com/blog/private-cloud-compute/
- *Private Cloud Compute Security Guide*. https://security.apple.com/documentation/private-cloud-compute
- *Security research on PCC* (VRE + source release, October 24, 2024). https://security.apple.com/blog/pcc-security-research/
- Apple Platform Security Guide. https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf
- apple/security-pcc (CloudAttestation, Thimble, splunkloggingd, srd_tools). https://github.com/apple/security-pcc
- Trail of Bits, *PCC: Bold step forward, not without flaws* (June 14, 2024). https://blog.trailofbits.com/2024/06/14/pcc-bold-step-forward-not-without-flaws/
- BleepingComputer, *Apple creates Private Cloud Compute VM to let researchers find bugs*. https://www.bleepingcomputer.com/news/apple/apple-creates-private-cloud-compute-vm-to-let-researchers-find-bugs/
- The Register, *Apple opens Private Cloud Compute to public scrutiny*. https://www.theregister.com/2024/10/25/apple_private_cloud_compute/

### Attack corpora

- Van Bulck et al., *Foreshadow*, USENIX Security 2018. https://www.usenix.org/conference/usenixsecurity18/presentation/bulck — https://foreshadowattack.eu/
- Van Bulck et al., *LVI*, IEEE S&P 2020. https://lviattack.eu/
- Murdock et al., *Plundervolt*, IEEE S&P 2020. https://plundervolt.com/doc/plundervolt.pdf
- Borrello et al., *ÆPIC Leak*, USENIX Security 2022. https://gruss.cc/files/aepic.pdf — https://aepicleak.com/
- Van Bulck et al., *SGX-Step*, SysTEX 2017 / ACSAC 2023. https://github.com/jovanbulck/sgx-step
- Chen et al., *SgxPectre*, EuroS&P 2019.
- Li et al., *CIPHERLEAKS*, USENIX Security 2021. https://www.usenix.org/conference/usenixsecurity21/presentation/li-mengyuan
- Li et al., *Ciphertext Side Channels on AMD SEV-SNP*, IEEE S&P 2022. https://yinqian.org/papers/sp22b.pdf
- TEE.Fail (Chuang, Seto, Berrios, van Schaik, Garman, Genkin; IEEE S&P 2026). https://tee.fail/ — https://www.bleepingcomputer.com/news/security/teefail-attack-breaks-confidential-computing-on-intel-amd-nvidia-cpus/
- Chen et al., *GoFetch: Breaking Constant-Time Cryptographic Implementations Using Data Memory-Dependent Prefetchers*, USENIX Security 2024. https://gofetch.fail/ — https://gofetch.fail/files/gofetch.pdf — https://www.usenix.org/conference/usenixsecurity24/presentation/chen-boru — code: https://github.com/FPSG-UIUC/GoFetch
- Kim, Chuang, Genkin, Yarom, *SLAP & FLOP: Data Speculation Attacks on Apple Silicon*, IEEE S&P 2025 / USENIX Security 2025. https://predictors.fail/ — code: https://github.com/slap-flop/slap-artifacts — FLOP artifact: https://zenodo.org/records/14680908

### Cloud confidential computing

- Russinovich et al., *Toward Confidential Cloud Computing*, ACM Queue May 2021. https://queue.acm.org/detail.cfm?id=3456125
- Azure Confidential Computing. https://azure.microsoft.com/en-us/solutions/confidential-compute/
- Azure Attestation. https://learn.microsoft.com/en-us/azure/attestation/
- AWS Nitro Enclaves. https://aws.amazon.com/ec2/nitro/nitro-enclaves/ — https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
- GCP Confidential Space. https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview
- GCP Confidential VM overview. https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview
- Google Cloud blog, *How Confidential Computing lays the foundation for trusted AI*. https://cloud.google.com/blog/products/identity-security/how-confidential-computing-lays-the-foundation-for-trusted-ai
- Google Cloud blog, *Next '24: Expanding Confidential Computing for AI workloads*. https://cloud.google.com/blog/products/identity-security/expanding-confidential-computing-for-ai-workloads-next24
- Google Cloud blog, *From clicks to clusters: Confidential Computing expands with Intel TDX*. https://cloud.google.com/blog/products/identity-security/from-clicks-to-clusters-confidential-computing-expands-with-intel-tdx
- IBM Cloud Hyper Protect. https://www.ibm.com/cloud/hyper-protect-services

### Confidential AI deployments

- Anthropic, *Confidential Inference via Trusted Virtual Machines* (June 18, 2025). https://www.anthropic.com/research/confidential-inference-trusted-vms — paper: https://assets.anthropic.com/m/c52125297b85a42/original/Confidential_Inference_Paper.pdf

### SDKs and frameworks

- Open Enclave SDK. https://openenclave.io/sdk/
- Apache Teaclave. https://teaclave.apache.org/
- Enarx. https://enarx.dev/
- Fortanix EDP. https://edp.fortanix.com/
- Edgeless Systems EGo / Marblerun. https://github.com/edgelesssys/ego — https://github.com/edgelesssys/marblerun
- Confidential Containers (CoCo). https://confidentialcontainers.org/ — CNCF page: https://www.cncf.io/projects/confidential-containers/
- CoCo Attestation Setup. https://confidentialcontainers.org/docs/attestation/coco-setup/
- Trustee / KBS. https://github.com/confidential-containers/trustee
- Red Hat, *Exploring the OpenShift confidential containers solution*. https://www.redhat.com/en/blog/exploring-openshift-confidential-containers-solution
- Microsoft, *Confidential Containers (preview) with Azure Kubernetes Service (AKS)*. https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview

### Confidential blockchain

- Oasis Network. https://docs.oasis.io/ — https://oasis.net/security-and-tees
- Secret Network. https://docs.scrt.network/

### Capability discipline

- Boberg, *Security Like It's 1977*. https://semgrep.dev/blog/2026/security-like-its-1977-capabilities-for-the-modern-agentic-web/
- See: [[reference-agentic-web-capabilities]], [[reference-llm-agent-security]], [[reference-supply-chain-provenance]], [[reference-cryptography]], [[reference-hardware-side-channels]], [[reference-privacy-engineering]], [[reference-detection-engineering]], [[reference-adversarial-ml-model-security]].
