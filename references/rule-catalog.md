# Wiz rule catalog — where the authoritative data lives per finding type

Companion to `SKILL.md`. **Read the entry for the rule you are working on before you decide
where the CVEs, exposure, identity or data facts come from** — the answer differs by rule
family, and getting it wrong silently under- or over-reports the finding.

The short version:

| Finding family | Named CVEs come from | Context comes from |
|---|---|---|
| Graph-control / toxic combination (`wc-id-140`, `308`, `481`, `1104`, `1458`, `1894`, `2922`, `2924`) | `vulnerabilityFindings` (`hasInitialAccessPotential: true`) — evidence *samples* paths and under-reports | Issue `evidenceQueryResults` for exposure / identity / secrets / sensitive data |
| Endpoint-scoped exposed software (`wc-id-1716`, and privileged variant `wc-id-1713`) | Issue `evidenceQueryResults` — asset-scoped `vulnerabilityFindings` over-reports every CVE on the container | The `ENDPOINT` → `HOSTED_TECHNOLOGY` chain in the same evidence |
| Malware (`wc-id-535`) | n/a — no CVEs | `MALWARE_INSTANCE` entities in evidence (file presence, not execution) |
| Cleartext storage-account keys (`wc-id-927`) | n/a — rule has no initial-access leg, so no CVE tab | Evidence chain `SERVERLESS → ENDPOINT → SECRET_INSTANCE → SECRET_DATA → STORAGE_ACCOUNT` |

Detail, with the validation date for each instance, follows.

## Rule instances and CVE scoping

- **Graph-control / toxic-combination findings (e.g. "Internet-facing VM/serverless with initial access
  vulnerabilities and data access to sensitive data"):** `get` is GENERIC — it names neither the CVEs,
  the exposed endpoints, the over-privileged identity, nor the sensitive data. Those live in the
  **Security Graph evidence**: query the issue's `evidenceQueryResults` (via the `raw` command — see
  `scripts/wiz_fetch.py raw --query-file ...`). Each `nodes[].entities[]` is a `GraphEntity` with `id name type
  properties`; the useful types are `SECURITY_TOOL_FINDING` (CVEs), `ENDPOINT` (public exposure),
  `SERVICE_ACCOUNT` + `ACCESS_ROLE_BINDING`/`IAM_BINDING` (privilege), and `DATA_FINDING` (PII etc.).
  Use evidence ONLY for exposure/identity/data context (endpoints, service account, IAM access types).
  **NEVER derive the CVE list — not even the named initial-access CVEs — from `evidenceQueryResults`.**
  It *samples* paths, so it silently under-reports: on one such finding (2026-07-03) the
  sampled evidence showed a single initial-access CVE (ecdsa) while the authoritative
  `vulnerabilityFindings` query returned **three** (adding python-jose (Critical) + aiohttp). Always
  pull CVEs from `vulnerabilityFindings` (see below). `--has-ticket true|false` filters `list` by
  service-ticket presence.
  **Confirmed graph-control instances:** wc-id-140 ("…with initial access vulnerabilities and data access to
  sensitive data"), and **wc-id-1458 "Internet-facing VM/serverless with sensitive data has initial access
  vulnerabilities" (validated 2026-07-08).** On wc-id-1458 the evidence carried only `ENDPOINT` + `DATA_FINDING`
  (no identity/privilege dimension); the initial-access CVEs came from `vulnerabilityFindings`
  (`hasInitialAccessPotential:true`). **When the internet-facing leg is a REQUIRED/inherent service, resolving
  the CVEs — not removing exposure — is the lever that closes the finding (learned 2026-07-08).** A graph-control
  finding closes by breaking ANY one leg (exposure / sensitive-data / initial-access CVE), but if the exposed
  port is a required service (e.g. 636/LDAPS for an S/MIME gateway) or the sensitive data is the workload's
  function, those legs can't be removed — so make the CVE leg the P0 and do NOT reflexively write "remove the
  exposure" as the primary action; state that the required exposure is inherent and the finding closes on CVE
  remediation + vendor Not-Affected exceptions.
  **wc-id-308 "Publicly exposed VM/serverless with initial access vulnerabilities and cleartext SSH private
  keys that can be used to access other resources" (validated 2026-07-14).** Same graph-control pattern, but
  the "data/credential" leg is **cleartext SSH private keys**, not `DATA_FINDING`: evidence carries `ENDPOINT`
  (public exposure) + **`SECRET_INSTANCE` entities** (`properties.keyType` = `SecretTypePrivateKey`; `name`
  like "OpenSSH/PuTTY Private Key in Certificates and Keys"; `path`/`displayPath` = on-disk key file) + the
  **lateral-movement targets as `VIRTUAL_MACHINE` entities** in the same paths (the hosts whose trusted public
  key matches the stolen private key). CVEs STILL come from `vulnerabilityFindings` (`hasInitialAccessPotential:
  true`) — do NOT derive them from evidence. A **single shared private key reused across a fleet** is the worst
  case (one stolen key → whole blast radius incl. CI/CD + DBs); flag the shared key + its reach count. A sibling
  rule swaps the tail for "…to access VMs with high privileges" (separate Issue/severity — this is **wc-id-481**,
  validated 2026-07-17: SAME evidence shape but the lateral target is a `VIRTUAL_MACHINE` with
  `properties.hasHighPrivileges:true` running a high-priv `SERVICE_ACCOUNT`. **wc-id-481 and wc-id-308 on the same
  assets are two separate Wiz Issues (different rule IDs) sharing ONE root cause** — same servers + same shared
  cleartext key + overlapping init-access CVE pool, identical fix; when the wc-id-308 set is already ticketed,
  folding the un-ticketed sibling into the SAME INC — associate its issues to the existing INC + move to In
  Progress, no new ticket — is a valid path. Surface the overlap and confirm fold-vs-new before raising a duplicate
  INC.) **Reinforced the
  per-owner split:** a filter that returns N "assets" can still span multiple owners/apps — ALWAYS read every
  asset's `entitySnapshot.tags` (TechnicalOwner/Application) and split into one report + one INC per owner, even
  when the hostnames look similar.
  **wc-id-2924 "Internet-facing VM/serverless (medium exposure) with initial access vulnerabilities and
  cleartext cloud keys granting high privileges" (validated 2026-07-14).** Graph-control HIGH; the "credential"
  leg is a **cleartext CLOUD key** (e.g. a GCP service-account JSON key baked into the container image),
  distinct from wc-id-308's SSH keys. Evidence carries `ENDPOINT` (public exposure) + `SECRET_INSTANCE`/
  `SECRET_DATA` (the cloud-key file, `properties.path`) + the `SERVICE_ACCOUNT` it belongs to +
  `ACCESS_ROLE_PERMISSION` entities enumerating the high-priv grants, plus `SUBSCRIPTION` entities showing the
  SA's cross-project reach (often into PROD). The Wiz UI splits these into panels: External Exposure Risk /
  Insecure Use of Secrets Risk / Unprotected Principal Risk ("Has High Privileges: Yes") / Vulnerability Risk.
  The "(medium exposure)" is the exposure LEVEL, not the Issue severity (HIGH). P0 = remove/rotate the
  cleartext key + least-privilege the SA; P1 = patch the initial-access CVEs + restrict exposure. CVEs come
  from `vulnerabilityFindings`, scoped to the Issue (see the ASSET-vs-ISSUE reconciliation note below).
  **wc-id-1104 "Internet-facing VM/serverless with initial access vulnerabilities and cleartext cloud keys WITH
  DATA ACCESS TO SENSITIVE DATA" (validated 2026-07-15).** The FULLEST four-leg graph-control variant — the
  wc-id-2924 pattern PLUS a sensitive-data leg. Evidence carries all four: `ENDPOINT` (public exposure) +
  `SECRET_INSTANCE`/`SECRET_DATA` (cleartext cloud-key file baked into the image) + `SERVICE_ACCOUNT` (here
  `hasHighPrivileges` AND `hasAdminPrivileges` = true) with `ACCESS_ROLE_BINDING` entities listing the project-
  admin grants (projectIamAdmin, serviceAccountAdmin, secretmanager/cloudkms/storage/bigquery/compute admin …) +
  `DATA_FINDING` (`dataCategory:DataCategoryPII`, `classifierLabels:Confidential`, `totalMatchCount` = record
  count) + `BUCKET`. CVEs STILL come from `vulnerabilityFindings` (`hasInitialAccessPotential:true`) — NOT
  evidence (the sampled evidence surfaced only 1 SECURITY_TOOL_FINDING while the authoritative query returned
  several). The Issue is **CRITICAL from the toxic combination even when every individual CVE is only High.**
  **Wiz-UI CVE-count reconciliation: the UI "Related Findings" panel counts finding INSTANCES (one per file path
  — requirements.txt + each `.dist-info/METADATA` copy under /app and /usr/local), so it OVER-counts vs unique
  CVEs** — always dedupe by `vulnerabilityExternalId` and treat the UI number as instances (the include-vs-exclude
  call on an OS-package CVE with no fix is the user's, per the UI/evidence). When the user has already raised the
  INC via the Wiz "normal export" and it is linked + In Progress, this is **report-only** (build + false-positive
  check; no new ticket, no association, no status change).
  **wc-id-2922 "Internet-facing VM/serverless (medium exposure) with initial access vulnerabilities and data access
  to sensitive data" (validated 2026-07-21, 54 issues).** A three-leg graph-control HIGH: `ENDPOINT` (public,
  medium exposure, `httpGETStatus 403` to anon — internet-reachable but auth-gated; "(medium exposure)" is the
  exposure LEVEL, not the severity) + `DATA_FINDING` (sensitive-data leg: PII/Email `Confidential` +
  Financial/Credit-Cards `Restricted`) + high-priv `SERVICE_ACCOUNT` (e.g. a Firebase Admin SDK SA,
  `hasHighPrivileges:true`). **NO cleartext-key leg** (unlike the 2924/1104/1370 siblings). CVEs STILL come from
  `vulnerabilityFindings` (`hasInitialAccessPotential:true`) — here a single common dependency across all 54
  workloads. **Reinforced the per-owner split + "verify ownership, never assume":** the 54 were the SAME ~11
  serverless functions replicated across 7 projects = ONE product → ONE report + ONE INC (prod P0 / dev P1); a lone
  outlier under the same rule in a different project = a different owner → excluded. Ownership was in NEITHER the
  resource tags (only cloud-managed tags, no owner/team) NOR the Wiz `projects` (internal scanning scopes, empty
  `projectOwners`/`securityChampions`) → derived from the project→product mapping and, unconfirmed, routed to the
  default VM group (Suggested Owner "To be confirmed"). For a large associate+status pass, re-derive ground truth
  (`serviceTickets`+`status` for all IDs in one `issuesV2 filterBy:{id:[...]}` call) BEFORE associating so re-runs
  never double-link, then batch `associateServiceTicket` + `updateIssue→IN_PROGRESS` ≤8 aliases each.
  **wc-id-927 "Publicly exposed resource with cleartext storage account keys/SAS tokens allowing high privileges
  to a storage account" (validated 2026-07-17, 4 Azure Function Apps).** The AZURE storage-account-key cousin of
  wc-id-2924/wc-id-1104, but with **NO CVE / initial-access leg** — the rule name has no "initial access
  vulnerabilities", so nothing comes from `vulnerabilityFindings` and there is NO CVE Details tab. Three legs, ALL
  from the issue `evidenceQueryResults` (chain `SERVERLESS → ENDPOINT → SECRET_INSTANCE → SECRET_DATA →
  STORAGE_ACCOUNT`): `ENDPOINT` (public exposure — `exposureLevel_name:High`, 200 without auth) +
  `SECRET_INSTANCE`/`SECRET_DATA` (the cleartext **Azure Storage Account access key**, `type:SecretTypeCloudKey`,
  High confidence, `snippet`=`AccountName=<sa>;AccountKey=…`, `path`=on-disk config e.g. `/appsettings.json`,
  `isEncrypted:false`, `isManaged:false`) + `STORAGE_ACCOUNT` (the privileged TARGET — a storage-account access
  KEY is all-or-nothing full control of the whole account; here also `accessibleFrom.internet:True` over HTTPS,
  weak min TLS 1.0). The privileged leg is a **`STORAGE_ACCOUNT` entity**, NOT a `SERVICE_ACCOUNT` +
  `ACCESS_ROLE_PERMISSION` chain like the GCP variants. **Worst case = the SAME key reused across several public
  apps** (identical `keyHash` / same account) — one leak from any app compromises the whole account; flag the
  shared-key blast radius. P0 = rotate the key + remove from config (managed identity, or Key Vault reference);
  P1 = least-priv scoped RBAC/SAS + network-restrict the storage account + endpoint auth; P2 = min TLS 1.2.
  **Sibling rules share the same wct-id risk categories** ("Internal resource with cleartext storage account
  keys/SAS tokens…" (internal) and "Private code repository with cleartext storage account key/SAS token…" (repo
  leak)). A Wiz UI **risk-category** filter (`risk includesAny wct-id-5/3032/907/3959`) returns ALL of them
  together — a risk-CATEGORY filter, NOT a `sourceRule` filter. The API `IssueFilters` field is **`riskEqualsAny`**
  (a plain list of `wct-id` strings; the UI's `risk.includesAny` maps to it — also `riskEqualsAll`/`riskIsSet`;
  validated 2026-07-21). It is VERY broad (those 4 categories = 11,457 open/no-ticket HIGH-INFO issues on this tenant) —
  it confirms a whole family, never one rule. To isolate a rule: run it, read the `sourceRule.id` (`wc-id-…`) off
  the results, then re-query `sourceRule:{id:[...]}` (optionally add a distinctive `search` phrase). Always confirm
  the per-rule count with the user before building.
- **"Exposed vulnerable software on VM/serverless" (rule wc-id-1716) — AND its privileged variant "Exposed
  vulnerable software on privileged VM/serverless" (rule wc-id-1713) — are ENDPOINT-SCOPED, the OPPOSITE of
  the graph-control rule above (wc-id-1716 validated 2026-07-07; wc-id-1713 validated 2026-07-08).** These
  rules flag ONLY the software actually served on the public application endpoint — the `HOSTED_TECHNOLOGY`
  reached via the `ENDPOINT` (e.g. the Node.js runtime) and its initial-access CVE(s). For THESE rules the
  issue's `evidenceQueryResults` IS authoritative for the named CVE(s): the chain is `SERVERLESS → ENDPOINT →
  HOSTED_TECHNOLOGY → SECURITY_TOOL_FINDING`.
  Do NOT use asset-scoped `vulnerabilityFindings` to name the CVEs here — it OVER-reports every initial-access
  CVE anywhere on the container (a case seen 2026-07-07 returned 5–8 npm-library CVEs — tar/rollup/vite/h3/
  node-forge — while Wiz showed only the one endpoint-served CVE, Node.js CVE-2025-55130). The backing Wiz
  graph query additionally requires `clientSide IS_SET false` + `widelyUsedAsSubDependency IS_SET false` (the
  latter is a Boolean on `VulnerabilityFindingFilters`), but that filter alone does NOT reproduce the scope —
  the endpoint→hosted-technology linkage is the real narrowing. **Always confirm the CVE count against what
  the user sees in the Wiz UI.** (An "Exposed vulnerable software" Issue can be rated Medium even when the
  exposed CVE is Critical — exposure detected, runtime reachability unconfirmed; report as the Issue's Medium
  severity but flag the Critical CVE prominently.)
  **`1713` "privileged" vs `1716` plain:** same endpoint-scoped exposed-software finding with the same
  endpoint-served CVE; the difference is the toxic-combination — a **high-privilege service account** on the
  exposed workload escalates it from **Medium (1716)** to **Critical (1713)**. The same asset + same CVE can
  therefore appear under BOTH rules as separate Issues with different severity/tickets. Report the privilege
  dimension in "Why this is Critical" for the 1713 variant.
- **"VM/serverless infected with a critical severity malware" (rule wc-id-535) — malware detail lives in the
  issue EVIDENCE as `MALWARE_INSTANCE` entities (validated 2026-07-09).** `get` is generic; the named malware +
  file paths come from `evidenceQueryResults` — each `MALWARE_INSTANCE` entity's `properties` carry `name`
  (e.g. `Win64.Trojan.Rpdactaele`), `path`/`displayPath`, `familyName`, `type` (Trojan/Backdoor/HackTool/Exploit/
  Ransomware/WebShell), `platform`, `severityLevel`, `detectionType` (`...HashBased` | `...YARARule`), `source`
  (`...ReversingLabs` | `...Wiz`), `scannerMatch`/`scannerCount`, `md5`/`sha1`/`sha256`. `evidenceQueryResults.
  totalCount` = number of flagged files (a Metasploit-laden Kali box → hundreds). Paginate the evidence
  (`first:500` + `after` via `pageInfo`), discard the huge VM-entity blob, keep only `MALWARE_INSTANCE`. These are
  static file-PRESENCE matches (hash reputation / YARA) — NOT proof of execution / C2 / lateral movement. A variant
  rule "VM infected with critical severity malware hosting a self-hosted runner" flags the same hosts. **On
  offensive-security / pentest hosts (names like `Kali*` / `*PT`; resource tag `service`="Offensive Security") the
  "malware" is almost always the team's own tooling** — Metasploit, Cobalt Strike, Mimikatz, exploitdb, SecLists,
  PowerShell Empire, Sliver, Ghostpack, atomic-red-team, nanodump, JuicyPotato — in standard tool dirs or the
  owners' Downloads/Desktop/personal folders = false positive. Disposition is **confirm-with-owner → suppress in
  Wiz (detection exception) → close**, NOT remediation (see the soft internal confirm-and-close Hard rule in `SKILL.md`).
- **`vulnerabilityFindings` — complete CVE list for a resource (validated 2026-06-24):**
  Query directly via `scripts/wiz_fetch.py raw` (or a standalone paginator — see
  `references/graphql-notes.md`) using
  `assetExternalId: { equals: "<instance-id>" }` + `severity: [CRITICAL, HIGH]` +
  `status: [OPEN, IN_PROGRESS]` + `isClientSide: false`. Use `first: 500` with cursor pagination
  (`pageInfo { hasNextPage endCursor }`) — a single VM can have 2,000+ raw findings (same CVE
  across many file paths); deduplicate by `vulnerabilityExternalId`.
  **Working `VulnerabilityFinding` fields on this tenant (validated 2026-07-03):** `name`,
  `vulnerabilityExternalId`, `severity`, `status`, `hasInitialAccessPotential` (usable as BOTH a
  `filterBy` filter AND a returned field), `detailedName` (the library/package name — e.g. `python-jose`,
  `aiohttp`), `remediation` (e.g. `pip install --upgrade aiohttp`), `fixedVersion` (null when no fix
  exists, e.g. ecdsa), `detectionMethod`, `firstDetectedAt`, and `vulnerableAsset` (a UNION — use inline
  fragments, e.g. `... on VulnerableAssetServerless { name externalId type cloudPlatform region
  subscriptionName subscriptionExternalId }`). This gives library + fix action per CVE without touching
  evidence. (CVSS/EPSS/KEV are still absent — see `references/graphql-notes.md`.)
  **CVE scope strategy for graph-control findings (e.g. wc-id-140):**
  - `hasInitialAccessPotential: true` returns only the CVEs that *trigger* the Wiz issue — this is the
    AUTHORITATIVE source for the report's named findings (correct for closing the finding), too narrow
    for a complete picture.
  - **BUT this filter is ASSET-scoped, not ISSUE-scoped — reconcile against the Issue's own evidence + the
    Wiz UI risk panel (learned 2026-07-14).** `vulnerabilityFindings` by `assetExternalId` +
    `hasInitialAccessPotential:true` returns every initial-access CVE on the whole asset, which can include
    CVEs NOT part of THIS Issue's attack path (e.g. an OS-package CVE on the container not reachable via the
    exposed app). Example: an asset-scoped query returned 3 (2 Python libs + 1 OS `perl-base` PACKAGE CVE)
    while the Issue evidence + Wiz UI showed exactly 2. When they disagree, the **Issue evidence + UI win**
    for the named CVEs; still confirm the fix action per CVE from `vulnerabilityFindings`, and ALWAYS confirm
    the count against the Wiz UI before finalizing.
  - Without that filter you see the full surface (example: 171 unique CVEs on one VM vs. 7 with the
    filter). Many of the extras are old nested npm CVEs (handlebars, lodash, minimist, etc.) or
    vulnerabilities in agent binaries (golang-stdlib inside Octopus Deploy).
  - **For the report**: include only the `hasInitialAccessPotential` CVEs as named findings. Add a
    single remediation line covering the broader set: *"Run `npm audit fix` after targeted library
    updates to resolve remaining transitive dependency vulnerabilities. Raise a separate ticket for
    any agent binary upgrades (e.g. Octopus Deploy, Datadog Agent) needed to address golang-stdlib /
    embedded library CVEs."* Listing 100+ CVEs overwhelms remediators without adding actionable value
    — the fix action is identical (update the library once).
  - **No-fix OS-package CVEs → FLAG and CONFIRM with the user per finding; do NOT decide silently.** A CVE
    detected as an OS base package (`detectionMethod: PACKAGE`) with `fixedVersion: null` (e.g. `perl-base`) has
    NO actionable per-CVE fix (it only clears on a patched base image from the vendor). Surface it and let the
    user decide. **Prompt to use:** *"Heads-up — this finding includes an OS base-package CVE with no fix
    available yet: `<CVE-ID>` (`<package> <version>`, detected as an OS package, no fixed version). There's no
    per-CVE patch — it only clears when the vendor ships a patched base image. How do you want to handle it?
    (a) exclude it from the named CVEs and cover it with one hygiene line ('rebuild on a patched base image once
    a fix ships') — my default suggestion, for consistency; (b) name it as a finding; (c) something else."* Lead
    with (a) as the recommendation but WAIT for the user's call. Apply **going forward only — do NOT retro-edit
    already-delivered reports.**
