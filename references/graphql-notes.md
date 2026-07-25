# Wiz GraphQL notes — schema quirks, filters and mutations

Companion to `SKILL.md`. **Read this before writing or debugging a Wiz GraphQL query**, and add
to it whenever a new field, filter or payload shape is confirmed. Ordered roughly by how often
each one bites.

> **Scope of these notes:** every schema quirk below was validated against a single Wiz SaaS
> tenant. Field availability, filter types, and mutation payload shapes differ between tenants
> and Wiz versions — if a query here fails validation on yours, the GraphQL error names the
> offending field; trim it and record the difference rather than assuming the note is wrong.

- **`gql()` import signature from `wiz_fetch` (confirmed 2026-07-10):** When writing a standalone script
  that imports from `wiz_fetch`, the correct call is `gql(api_url, auth_headers, query, variables)` and
  `resolve_auth()` returns a **tuple `(auth_headers, api_url)`** — unpack as
  `auth_headers, api_url = resolve_auth()` before calling `gql`. Passing args in the wrong order causes a
  `TypeError: missing 1 required positional argument` rather than a clear error.
- **Wiz UI CSV export vs `vulnerabilityFindings` API count discrepancy (confirmed 2026-07-10):** The Wiz UI
  "Export to CSV" silently excludes non-VM asset types (e.g. GCP Cloud SQL instances, Azure databases
  flagged via `CLOUD_API` detection). The `vulnerabilityFindings` API returns ALL asset types, including
  those that surface as `UNKNOWN` type with an empty `vulnerableAsset {}`. When the UI total and API total
  differ, look at the UNKNOWN-type nodes first — they are almost always the gap (e.g. 726 API vs 704 CSV =
  22 Cloud SQL instances). The CSV count is the correct VM-scoped number.
- openpyxl `save` raises `PermissionError [Errno 13]` when the workbook is open in Excel.
- For incremental edits, use `load_workbook(path)` and patch only the affected cells — never run the
  full build script. The user applies manual formatting after each build; a full rebuild destroys it.
  Reserve a full rebuild only for the very first generation or when explicitly requested.
- Empty Wiz columns often collapse on the first openpyxl load+save anyway; still verify the trim.
- **Never run structural column operations (delete_cols / insert_cols) twice on the same file.**
  Before deleting or inserting a column, read the current header row to confirm the column is still at
  the expected position. Running `delete_cols(5)` twice deletes two different columns — the first removes
  the intended column, the second removes whatever shifted into position 5. Always verify column
  positions from the live file before any structural edit.
- When deleting a column that is part of merged ranges, openpyxl may not adjust the merge coordinates
  automatically. Pattern: snapshot all merged ranges → unmerge all → delete column → re-merge with
  adjusted coordinates (cols >= deleted_col shift left by 1).
- **Never print the cred/secret.** `login` caches the session cookie (or token) to `~/.wiz/token.json`;
  `status`/`login` output only endpoint + `authMode` + expiry, never the cred. Long-lived service-account
  creds belong in env, not on disk.
- `wiz_fetch.py` targets the `issuesV2` schema. If a tenant rejects a field, the GraphQL error is
  reported verbatim — trim that field from `QUERY_LIST`/`QUERY_GET`. **Already trimmed for this tenant:**
  removed `controlDescription` from the `Control` fragment (not in this tenant's schema; kept
  `resolutionRecommendation`).
- Cookie-mode creds have no JWT `exp`, so `status` can't show expiry. When `list`/`get` hit a
  401/403, just re-run `login` — the persisted browser profile usually makes it one click (no Okta).
  **These cookie sessions are currently VERY short-lived (~1-2 min observed 2026-07-01)** — a
  session that worked seconds ago can 401 mid-workflow. Do the API work in tight bursts right after
  `login`, and give any multi-step gather checkpoint/resume logic (see below). For writes (`updateIssue`,
  `associateServiceTicket`), trust the mutation's own returned fields as confirmation if the follow-up
  `get` 401s — the write already committed.
- `login` needs `playwright` but NOT its bundled Chromium (corporate TLS breaks that download); it drives
  installed Edge/Chrome via `--channel`. If launch fails, try the other channel.
- **`scripts/wiz_fetch.py raw` DOES support `--query`, `--query-file`, and `--variables` (JSON string)** — this
  build has them (an earlier note saying otherwise was stale). Use it directly for schema introspection,
  `evidenceQueryResults`, `updateIssue`/`associateServiceTicket` mutations, etc. Only *cursor pagination*
  still needs a loop; either call `raw` repeatedly with an updated `after` variable, or write a standalone
  paginator. Best practice: a standalone script that imports `gql, resolve_auth` from `wiz_fetch` (identical
  auth) and CHECKPOINTS each query's result to disk (skip-if-exists on re-run), so a mid-fetch 401 loses
  nothing. Validated 2026-07-01.
- **Validated graph-evidence query (validated 2026-07-01)** — for a graph-control finding, pull CVEs / endpoints
  / sensitive data / identity from the issue's evidence in ONE call:
  `issuesV2(filterBy:{id:$id}, first:1){nodes{id evidenceQueryResults(first:250){totalCount maxCountReached
  nodes{entities{id name type properties}}}}}` with variable `$id: [String!]` (note the `!` — `[String]`
  fails validation). Group `entities` by `type`; skip null entities. Useful types + key `properties`:
  `SECURITY_TOOL_FINDING` (name=CVE, nvdSeverity, remediation, isInitialAccessPotential, dataSourceLink),
  `HOSTED_TECHNOLOGY` (name, version), `ENDPOINT` (host, portStart), `DATA_FINDING` (dataCategory,
  classifierLabels, contextLabels, totalMatchCount), `SERVICE_ACCOUNT`, `ACCESS_ROLE_BINDING` (role names),
  `IAM_BINDING` (accessTypes incl. `HighPrivilege`). CVSS numeric score / EPSS / KEV are NOT in these
  properties on this tenant — report `nvdSeverity` + exploit availability from the description instead.
- **Owner — CHECK THE RESOURCE TAGS FIRST, and match tag keys by PATTERN, not by exact name
  (corrected 2026-07-03; broadened 2026-07-26).** The owner IS sometimes on the resource: the
  `SERVERLESS`/`VIRTUAL_MACHINE` entity's `properties.tags` dict can carry `TechnicalOwner`, `Owner`,
  `TechnicalOwnerEmail`, `OwnerEmail`, `AdditionalOwnerEmail`, `Team`, `CostCenter` — but those are just
  the keys seen so far, **not a closed list**. Different orgs and teams use different conventions
  (`app_owner`, `service-owner`, `maintainer`, `custodian`, `squad`, `DL`, …), and casing/separators vary
  (`TechnicalOwner` / `technical_owner` / `technical-owner`). So normalise each tag key (lowercase, strip
  `_-. `) and match on ownership-signalling substrings rather than equality — see the Suggested Owner hard
  rule in `SKILL.md` for the candidate list and the confirm-with-user procedure.
  Pull tags from the evidence entity properties or `vulnerableAsset` before asking. **Some resources are
  well-tagged** (e.g. an AWS Lambda → `TechnicalOwner: <a person's name>`); **many serverless resources
  are NOT** (only `environment`/`managed_by`/`project`/`project_prefix`) and their Wiz
  `Project.projectOwners`/`securityChampions` are empty, because Wiz projects are often internal scanning
  scopes rather than the app team. So: read tags → present whatever you found, with the key it came from,
  for the user to confirm (the email tag is often absent even when a name is present); if nothing matches,
  say so and ask. Do not spend many calls spelunking issue `entity.properties`/`CloudAccount` — there is no
  owner field there.
- **Owner-not-verified → route SNOW to `<your default VM group>`, but keep it OUT of the report
  (2026-07-03).** When the Technical Owner name is known but not fully verifiable (e.g. no email) or is
  unknown, set the SNOW **Assignment Group** to `<your default VM group>` with **Assigned To
  blank**, and in the deliverable set **Suggested Owner = "To be confirmed"** — never name a
  triage/identification group (they identify, they don't remediate) or an unconfirmed owner in the
  report itself.
- **No ticket-ID reverse lookup in GraphQL** — `IssueFilters` on this tenant does not expose a
  `serviceTicket` or `hasServiceTickets` field, so you cannot query "all issues linked to INC#"
  directly. `scripts/wiz_fetch.py list --has-ticket true` works (returns all issues that have any ticket), but
  there is no way to filter by a specific ticket ID. Workaround: if you know the issue IDs, call `get`
  on each (which always returns `serviceTickets`). If you only have the ticket number, fetch all ticketed
  issues and filter client-side: `[i for i in issues if any(t["externalId"] == target for t in i["serviceTickets"])]`.
- **Filter issues by source rule — `sourceRule: { id: [...] }` (confirmed 2026-07-10).** To replicate a
  Wiz UI `sourceRule equals <rule-id>` view via API, use
  `filterBy: { severity:[CRITICAL], sourceRule: { id: ["<rule-id>"] }, hasServiceTicket: true }`.
  `sourceRule` is an `IssueSourceRuleFilters` **object** with an `id` list — a bare string list
  (`sourceRule: ["<rule-id>"]`) fails with `"IssueSourceRuleFilters cannot represent value"`. This is the
  clean way to pull every Issue for one control (all statuses/revisions) — e.g. to verify whether an
  incident's rule is fully Resolved or a new revision has re-opened it.
- **Batch alias limit** — Aliasing many `issue(id: ...)` calls in a single GraphQL query hits
  `"Maximum root fields limit exceeded"`. Keep batches to **≤8 aliases** per request.
- **Resolved/archived issues return NOT_FOUND** — `issue(id: ...)` returns `{"message": "Resource not
  found"}` for issues that Wiz has archived after closure. This is not an error — treat it as
  confirmation the issue is closed/resolved. Do not surface it as a lookup failure to the user.
- **GraphQL mutation writes can execute even when the response returns `GRAPHQL_VALIDATION_FAILED`.** If
  the return field selection is invalid (e.g. querying `issue` or `successCount` on a payload type that
  doesn't have them), the server rejects the response shape but may still commit the write. Always
  re-query affected resources to verify actual state before retrying a failed mutation. This caused 8
  duplicate `associateServiceTicket` associations in one session (2026-06-29) — the first batch errored
  on return fields but the associations went through.
- **`associateServiceTicket` mutation (validated 2026-06-29):** Input fields: `issueId`, `ticketId`,
  `ticketUrl`. Return type: `AssociateServiceTicketPayload { serviceTicket { externalId } }`. Do NOT use
  `externalId` as an input field name — it is wrong and will fail schema validation. Do NOT query `issue`
  or `successCount` on the payload — neither field exists in this tenant's schema.
- **`disassociateServiceTicket` mutation:** Takes `serviceTicketId: ID!` as a **top-level
  argument** (NOT inside an `input:` wrapper). Return type is `DisassociateServiceTicketPayload { _stub }`
  — `_stub` is the only queryable field. To find the Wiz-internal service ticket ID to remove, first
  query `issue(id: "...") { serviceTickets { id externalId } }` and identify the duplicate by `id`.
  Usage: `mutation { disassociateServiceTicket(serviceTicketId: "<wiz-svc-ticket-id>") { _stub } }`.
- **`vulnerabilityFindings` unavailable fields on this tenant:** The following fields do NOT exist in this
  tenant's `VulnerabilityFinding` schema and will cause `GRAPHQL_VALIDATION_FAILED`: `cvssScore`,
  `epssScore`, `cvss { }`, `epss { }`, `hasKEVEntry`, `dataSourceLink`. For CVSS score, EPSS
  probability, and KEV status, use the `SECURITY_TOOL_FINDING` entity properties returned in
  `evidenceQueryResults` (fields: `cvssScore`, `epssScore`, `dataSourceLink` are present there as raw
  properties).
- **`vulnerabilityExternalId` filter — plain string as a literal, but `[String!]` as a variable (variable form
  confirmed 2026-07-10).** As a bare literal use `filterBy: { vulnerabilityExternalId:
  "CVE-2026-46817" }` (the wrapped `{ equals: "…" }` form causes `GRAPHQL_VALIDATION_FAILED`). But when
  you pass it via a typed GraphQL VARIABLE it must be declared `[String!]` (a list) — `$cve: String`
  fails with `"Variable $cve of type String used in position expecting type [String!]"` (same quirk as
  `assetExternalId`). Use `query($cve: [String!]) { … vulnerabilityExternalId: $cve … }` and pass
  `{"cve": ["CVE-2026-46817"]}`.
- **`assetExternalId: { equals: … }` wants a LIST when using a variable (learned 2026-07-08).** A bare
  literal coerces (`assetExternalId: { equals: "i-0abc…" }` works), but a typed GraphQL variable must be
  declared `[String!]` and passed as a list — `$eid: String!` fails with `BAD_USER_INPUT "Variable $eid of
  type String! used in position expecting type [String!]"`. Use
  `query($eid: [String!]) { … assetExternalId: { equals: $eid } … }` and pass `{"eid": ["i-0abc…"]}`.
- **CVE-2023-4863 (libwebp) attribution — Wiz flags the PACKAGE that bundles libwebp, not the OS lib
  (learned 2026-07-08).** On Linux app servers the finding for CVE-2023-4863 is a `LIBRARY` detection against
  the Python **`pillow`** package (version read from `<Pkg>.dist-info/METADATA`), **fixed in Pillow 10.0.1**
  (ships patched libwebp 1.3.2) — NOT the OS `libwebp` RPM, and not necessarily the newest Pillow present. It
  is a package-PRESENCE finding: a patched OS RPM and "the process wasn't loading WebP at runtime" do NOT
  clear it; the vulnerable package must be upgraded/removed from disk. Beware multiple Python envs on one host
  (e.g. `python3.6` Pillow 8.4.0 vulnerable while `python3.9` Pillow 11.3.0 is fine). Always report the exact
  `detailedName` + `version` + `locationPath`.
- **`vulnerabilityFindings.totalCount` can return 0 while `nodes` returns thousands (learned
  2026-07-03).** When filtering by `vulnerabilityExternalId` (a CVE-wide query, not asset-scoped),
  `totalCount` came back `0` even though pagination returned 3,917 real node records. Do NOT gate logic
  on `totalCount` for this filter — trust the per-node `status` / `firstDetectedAt` fields and paginate
  via `pageInfo.hasNextPage`/`endCursor`. Scope to an account client-side with
  `vulnerableAsset.subscriptionExternalId`.
- **Validating an ephemeral-node finding (Karpenter / auto-scaling) — check the CVE, not the Issue
  (learned 2026-07-03).** A graph-control Issue on `COMPUTE_INSTANCE_GROUP` ephemeral fleet nodes
  (`Ephemeral_aws:ec2:fleet-id_fleet-…`) auto-**RESOLVES** when the instances rotate out — that is
  exposure removal, NOT a patch. To confirm whether the CVE was actually fixed, query
  `vulnerabilityFindings` by the CVE (plain-string `vulnerabilityExternalId`, `isClientSide:false`),
  scope to the account's `subscriptionExternalId`, and read the CURRENT named nodes' `status`.
  If the CVE is still `OPEN` on live nodes (esp. a node first-detected AFTER the Issues resolved →
  new nodes still spinning up vulnerable), the correct state is **"Exposure Mitigated — Patch Pending,"**
  and the SNOW incident should stay open.
  **The authoritative per-node CVE list for an ephemeral fleet is reachable via the node's SYNTHETIC
  asset externalId (learned 2026-07-24, wc-id-1894).** For a `COMPUTE_INSTANCE_GROUP` Issue the
  `entitySnapshot.externalId` is the fleet id (`Ephemeral_aws:ec2:fleet-id_fleet-…`), and querying
  `vulnerabilityFindings` with `assetExternalId:{equals:"<that fleet id>"}` returns **0**. But the
  issue's `evidenceQueryResults` carries the underlying node as a `VIRTUAL_MACHINE` whose `externalId`
  is a **`wiz-representative##Ephemeral_aws:ec2:fleet-id_fleet-…`** synthetic id — passing THAT to
  `vulnerabilityFindings` (`assetExternalId:{equals:$eid}` + `hasInitialAccessPotential:true` +
  `isClientSide:false`) returns the real initial-access CVE set per node. This is the clean way to get
  the authoritative CVEs for an ephemeral graph-control finding without spelunking live instance ids.
  (Confirmed the evidence UNDER-reports here too: sampled evidence showed 6 glib2 CVEs while
  `vulnerabilityFindings` returned 7 — so still pull CVEs from `vulnerabilityFindings`, never evidence.)
  **wc-id-1894 "Publicly exposed VM with high privileges and initial access vulnerabilities that were
  validated in runtime" is a confirmed graph-control instance (validated 2026-07-24, EKS Karpenter
  fleets on a managed Kubernetes platform).** Three legs from evidence: public `ENDPOINT` (cluster ingress, exposure Medium/4XX), a
  high-priv worker-node `SERVICE_ACCOUNT`/IAM role (`…-eks-worker`, `hasHighPrivileges:true`), and
  runtime-validated OS-package CVEs (glib2 / perl-IO-Compress on Amazon Linux 2023) — CVEs from
  `vulnerabilityFindings` via the synthetic id above. All CVEs `detectionMethod:PACKAGE` with fixes →
  the finding closes by **rebuilding the node base AMI + rotating nodes** (+ least-privilege the node
  role via IRSA/EKS Pod Identity + IMDSv2 hop-limit 1); the public exposure is INHERENT (production web
  cluster) so exposure removal is NOT the close lever. Individual CVEs were High while the Issue is
  Critical (toxic combination). One rule / 25 issues split into 2 per-owner reports/INCs across two
  accounts — read every asset's tags, never assume one owner.
- **Asset name comes from `vulnerableAsset`, NOT the file path (learned 2026-07-01).** On a
  `vulnerabilityFinding`, the real asset/VM name is in `vulnerableAsset` — a **UNION** (`VulnerableAssetVirtualMachine`,
  `...Serverless`, `...Container`, `...Common`, etc.), so query with inline fragments:
  `vulnerableAsset { ... on VulnerableAssetVirtualMachine { name externalId type cloudPlatform region subscriptionName subscriptionExternalId isUsedOnPrem } }`.
  Do NOT derive the asset name from `locationPath`/file path — Oracle EBS context files (e.g.
  `CORF_<host>.xml`, `CORFTEST_<host>.xml`) embed a legacy SID/hostname that differs from the VM name.
  This caused the CVE-2026-46817 Oracle EBS report to label the assets by their legacy file-path hostnames
  (from the file names) when the true VM names were the actual VM hostnames — corrected on INC#.
  Keep the real file paths verbatim in Details (they are audit evidence); fix only the asset-name labels.
- **Serverless (Cloud Run / Lambda): the entity name is a REVISION, not the service (learned 2026-07-03).**
  For a `SERVERLESS` entity the `entitySnapshot.name`/`vulnerableAsset.name` is a Cloud Run **revision**
  (`nativeType: run#revision`, e.g. `example-backend-api-00001-gln`). The real remediation asset
  is the **service**, parsed from `externalId` (`.../services/<service>/revisions/<revision>`); the full
  project id carries a suffix (`gcp-acme-dev-app-18d7`) and `cloudProviderURL` is the console link.
  Label reader-facing tabs by **service** (+ console URL); keep the revision only in Details. (AWS Lambda
  `externalId` is the ARN `arn:aws:lambda:<region>:<acct>:function:<name>` — the name there IS the asset.)
- **Cloud Run / serverless revisions auto-resolve when rotated → issue counts drift (learned 2026-07-03).**
  A HIGH filtered list dropped from 91 → 85 within one afternoon; the 6 that left were all `RESOLVED`,
  ticket-less, ephemeral revisions (a new revision deployed, so the old one stopped running and Wiz removed
  the exposure — "exposure mitigated", NOT patched). Before building/associating, **re-run the `list` and
  diff against your earlier pull**; a dropped issue that is `RESOLVED` + no ticket + a revision-suffixed
  name is revision rotation, not remediation — report on the current live set. The vulnerable dependency
  may still ship in the new revision (a new issue id).
- **Standalone `vulnerabilityFindings` with no Wiz Issues:** `associateServiceTicket` only accepts an
  `issueId` — it cannot be called for standalone vulnerability findings. Always check
  `relatedIssueAnalytics { issueCount }` early and flag to the user if `issueCount: 0`. INC tracking
  must be done externally. Example: CVE-2026-46817 (Oracle EBS) — INC# tracked externally only.
- **`updateIssue` mutation (validated 2026-06-30):** Batch update status for multiple issues:
  `mutation { u1: updateIssue(input: { id: "...", patch: { status: IN_PROGRESS } }) { issue { id status } } }`.
  ≤8 aliases per batch. Confirmed working for all 6 wc-id-1713 issues.

