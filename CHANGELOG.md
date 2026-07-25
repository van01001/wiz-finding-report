# Changelog — wiz-finding-report

Audit trail of patterns and conventions learned while operating this skill. Split out of `SKILL.md` to keep the operational instructions lean; the skill itself does not need to load this file to run.

> Note: the entries below record patterns and conventions learned while operating this skill.
> Organization-specific identifiers (incident numbers, owner names, assignment groups) have been
> generalized in this portable copy; the methodology and Wiz control patterns are unchanged.

### 2026-07-26 (publication pass — structure, sanitization, TLS default)
Pre-publication review of the whole skill. Behaviour of the report workflow is unchanged; what
changed is the reference builder, the always-loaded context size, and the defaults.

**`build_report.py` now matches the rules it documents.** It was generating merged title / subtitle /
section-header rows whose non-top-left cells had **no border at all** (`B1`, `G1`, `C2`, `D3` carried
`borderId 0`) — the exact defect the 2026-07-14 border rule exists to prevent — because the styling
helpers only touch a merge's anchor cell. Added an `all_borders(ws)` final pass over each sheet's used
range (merges left intact, `FF000000`), applied immediately before save. Verified by mapping every
cell's `s` → `xf` → `borderId` in `xl/styles.xml`: 372/372 and 432/432 cells now carry four thin
`FF000000` sides. Also fixed: `Status` was hardcoded `In Progress` (contradicting the 2026-07-21
build-as-`Open` rule), and the severity badge was hardcoded RED instead of following the palette map.

**`--demo` flag → the shipped sample is generated, never hand-scrubbed.** The previous
`assets/sample_report.xlsx` had survived sanitization only partially (a real cloud project number, three
internal service shortnames, a real Wiz project name, and the author's real name in `docProps`), and two
of those strings were visible in the committed PNG. Values in the builder are now written as
`V(placeholder, demo)`, so one script produces both the `[EXAMPLE]` skeleton and a wholly fictional
`acme-*` sample — the demo cannot drift from the layout, and cannot contain real data.

**SKILL.md split for context cost: 1002 → 646 lines (88.6 KB → 51.9 KB).** The per-rule catalog and the
GraphQL gotchas were ~40% of a file that loads on *every* invocation while being needed only
situationally. Moved verbatim to `references/rule-catalog.md` and `references/graphql-notes.md`, with
pointers in SKILL.md that state the one thing you must know up front (which source is authoritative for
which rule family) and tell Claude to open the catalog before pulling CVEs.

**TLS is verified by default, with a fallback instead of a blanket opt-out.** `wiz_fetch.py` previously
disabled certificate verification for every request unless `WIZ_VERIFY_SSL=1`. Now a single `_urlopen()`
tries verified first and retries unverified **only** on a certificate error, warning once on stderr;
`WIZ_VERIFY_SSL=1` fails hard, `WIZ_INSECURE_SSL=1` skips the verified attempt. Works unchanged behind a
TLS-inspecting proxy while actually verifying elsewhere. All four branches tested against
`expired.badssl.com` / `self-signed.badssl.com` / a valid cert.

**Smaller fixes.** JS literals in `snow_ticket_creator.py` now built with `json.dumps` rather than
`repr` — repr proved JS-compatible for everything we send (tested: quotes, newlines, backslashes,
U+2028, emoji), so this is idiom not a bug fix; dropped an unused import; documented why `page_fetch`
leaves its query params unencoded (the callers pre-escape them). README gained a rule-family→source
table, a workflow sequence diagram, a scope-and-safety section and macOS/Linux wrappers, and lost a
`requests` dependency it never had. Residual org identifiers removed throughout; tenant-specific schema
notes now carry a caveat that they were validated against one tenant. MIT license added.

### 2026-07-24 (wc-id-1894 — ephemeral EKS graph-control; synthetic-asset-id CVE technique)
**New confirmed graph-control instance — wc-id-1894** "Publicly exposed VM with high privileges and initial
access vulnerabilities that were validated in runtime" (EKS Karpenter fleets on a managed Kubernetes
platform). Three legs: public cluster
`ENDPOINT` (exposure Medium/4XX) + high-priv worker-node IAM role (`…-eks-worker`, `hasHighPrivileges:true`) +
runtime-validated OS-package CVEs (glib2/perl-IO-Compress on Amazon Linux 2023). Individual CVEs High, Issue
Critical (toxic combination). All CVEs `detectionMethod:PACKAGE` with fixes → closes by rebuilding the node
base AMI + rotating nodes (+ least-priv node role via IRSA/EKS Pod Identity + IMDSv2 hop-limit 1); public
exposure INHERENT (prod web cluster) so exposure removal is NOT the close lever.

**New technique — authoritative CVEs for an ephemeral fleet node come from its SYNTHETIC asset id.** A
`COMPUTE_INSTANCE_GROUP` Issue's `entitySnapshot.externalId` is the fleet id (`Ephemeral_aws:ec2:fleet-id_…`),
which returns **0** from `vulnerabilityFindings`. The issue's `evidenceQueryResults` carries the node as a
`VIRTUAL_MACHINE` whose `externalId` is `wiz-representative##Ephemeral_aws:ec2:fleet-id_…` — pass THAT to
`vulnerabilityFindings` (`assetExternalId:{equals:$eid}` + `hasInitialAccessPotential:true`) for the real
per-node CVE set. Evidence still UNDER-reported (6 glib2 vs the 7 the query returned) — always pull CVEs from
`vulnerabilityFindings`, never evidence. Documented in the ephemeral-node Gotcha.

**Per-owner split reinforced (again).** The pasted URL was the generic Critical/no-ticket filter (not
rule-specific) → matched the rule by name (25 issues). Reading every asset's tags showed 2 owners/accounts →
2 reports + 2 INCs (Prod cluster vs PreProd cluster).

### 2026-07-21 (wc-id-2922 — 54-issue serverless graph-control; risk-category filter API field)
**New confirmed graph-control instance — wc-id-2922** "Internet-facing VM/serverless (medium exposure) with
initial access vulnerabilities and data access to sensitive data". Three legs (ENDPOINT medium/auth-gated +
DATA_FINDING PII+CC + high-priv Firebase Admin SDK SA); NO cleartext-key leg; CVEs from `vulnerabilityFindings`
(single common dependency across all 54). Documented in "Getting the finding".

**The Wiz UI `risk` category filter maps to the API `IssueFilters` field `riskEqualsAny`** (also `riskEqualsAll`/
`riskIsSet`). Corrects the prior "`list` can't reproduce it" note. Plain list of `wct-id` strings, VERY broad
(returned 11,457 issues) — confirms a family, not one rule; read `sourceRule.id` off the results and re-query
`sourceRule:{id:[...]}` to isolate a rule. Always confirm the per-rule count with the user.

**Report status is `Open` until the incident is raised (user correction).** Don't pre-set `In Progress` at build
time for an un-ticketed finding; `Open` badge = neutral DARK_GREY `595959`. Flip to In Progress only after INC
creation + association.

**A just-built report with no manual edits → change the build script and REGENERATE, don't `load_workbook`-patch**
(load/save corrupts merged-cell borders, styles `<borders count>` 2→6).

**Per-owner split reinforced when resources are untagged** — same functions replicated across N projects = one
product/owner = one report/INC; owner absent from both resource tags AND Wiz `projects` → project→product mapping,
unconfirmed → default VM group, Suggested Owner "To be confirmed". Idempotent associate+status pattern (re-derive
ground truth before associating so re-runs never double-link).

### 2026-07-17 (session 2 — wc-id-481 sibling folded into an existing INC)
**New confirmed graph-control instance — wc-id-481 "Publicly exposed VM/serverless with initial access
vulnerabilities and cleartext SSH private keys that can be used to access VMs with high privileges."** The
"…access VMs with high privileges" sibling of wc-id-308: identical evidence shape (ENDPOINT + SECRET_INSTANCE
`SecretTypePrivateKey` + SECRET_DATA `SecretTypeSSHAuthorizedKey`), but the lateral target is a `VIRTUAL_MACHINE`
with `hasHighPrivileges:true` running a high-priv `SERVICE_ACCOUNT`. CVEs from `vulnerabilityFindings`
(`hasInitialAccessPotential:true`), NOT evidence.

**Sibling rule on already-ticketed assets → fold into the existing INC (user's call).** wc-id-481 and wc-id-308
were two separate Wiz Issues (different rule IDs) sharing ONE root cause on the SAME servers (same shared key,
overlapping CVEs, identical fix). When the sibling is un-ticketed and the other set is already on an INC, associate
the new issues to that INC + move to In Progress (no duplicate INC). Surface the overlap and confirm fold-vs-new
before ticketing.

**Cross-check the filter URL vs the named finding.** A pasted filter URL may be stale/leftover from a prior
session (here a `risk includesAny wct-id-*` cleartext-storage filter while the user named a Spring4Shell CVE);
decode it, flag the mismatch, and go with the named finding rather than trusting the URL.

### 2026-07-16 (Log4Shell / wc-id-609 — endpoint-CVE exposure; SNOW offering + Type of Assistance)
**New finding handled — wc-id-609 "Publicly exposed unprivileged VM/serverless vulnerable to CVE-2021-44228
(Log4Shell)."** A specific-CVE + public-exposure rule (not graph-control): scope the report to the one named
CVE, pulled authoritatively from `vulnerabilityFindings` filtered by `vulnerabilityExternalId`. Check the whole
Log4Shell family (45046/45105/44832) in case more than one is present. The Issue can be **HIGH** (the
"unprivileged" variant) while the CVE is **Critical (CVSS 10.0, CISA KEV)** — report as the Issue's severity but
flag the Critical CVE + urgency prominently. Take public endpoints exactly from the issue `evidenceQueryResults`
ENDPOINT entities (confirm completeness via `totalCount`). Always run the history check (query the rule's other
Issues + tracker) — the same finding may already be ticketed on sibling assets, giving a proven fix path.

**SNOW form — `offering` must be set EXPLICITLY, and new `type_of_assistance` field (user rule).** Leaving
`offering` blank made the type-ahead click the first suggestion, wrongly selecting "Domain Management" — always
write `offering:"Vulnerability Management"`. Added a **"Type of Assistance"** choice dropdown (just beneath
Offering) → always `"Service Request"`; `snow_ticket_creator.py` now reads pending-JSON `type_of_assistance`
(default "Service Request") and sets it via a new `set_choice_by_label(frame, label, value)` helper (finds the
`<select>` by visible label, picks the matching option, fires `change` + mirrors to `g_form`).

**Assignment Group when the owner is in several groups — ask, don't just leave blank (user pref).** Pre-look-up
the candidates and surface them for the user to confirm (they'll pick, but want to be asked).

### 2026-07-15
**New confirmed graph-control instance — wc-id-1104 (full four-leg variant).** "Internet-facing VM/serverless
with initial access vulnerabilities and cleartext cloud keys WITH DATA ACCESS TO SENSITIVE DATA" — the wc-id-2924
pattern PLUS a `DATA_FINDING` sensitive-data leg. Evidence = ENDPOINT + SECRET_INSTANCE/SECRET_DATA (cleartext
cloud key) + SERVICE_ACCOUNT (hasHighPrivileges + hasAdminPrivileges) + ACCESS_ROLE_BINDING (project-admin roles)
+ DATA_FINDING (PII, Confidential) + BUCKET. CVEs from `vulnerabilityFindings` — the Issue is CRITICAL from the
toxic combination even when every individual CVE is only High. Documented in "Getting the finding".

**Wiz UI "Related Findings" count = finding INSTANCES, not unique CVEs.** The same library is flagged per file
path (requirements.txt + each installed `.dist-info/METADATA`), so the UI over-counts; always dedupe by
`vulnerabilityExternalId` and reconcile the UI number as instances.

**Report-only path when the user already raised the INC via the Wiz "normal export".** INC already linked + In
Progress → build the report (and verify false-positive on request); do NOT create a new ticket, associate, or
change status. Subtitle may carry the INC (existing linked ticket).

### 2026-07-14
**Border colour must be 8-hex ARGB `FF000000`, not 6-hex `000000` (invisible-border bug).**
`Side(style="thin", color="000000")` serialises to `00000000` (alpha 00 = transparent) — the border is set
on all four sides but renders INVISIBLE in Excel. Fixed the Styling rule to require `FF000000` and the
`xl/styles.xml` verifier to FAIL any border whose colour is `00000000`.

**Finding Summary = 2-column label|value; column A is the LABEL width (~26), never a serial width.** Column A
built at width 5 crushed every label. Use A≈26 / B≈118, endpoints/keys as bulleted text in column B, label
"Finding" for the rule name, and keep Wiz Issue ID/URL OUT of the Finding Summary (Details only). Only true
serial columns (#/Step in multi-column tables) should be narrow.

**CVE scope for graph-control findings is ISSUE-scoped, not asset-scoped.** `vulnerabilityFindings` by
`assetExternalId` + `hasInitialAccessPotential:true` can over-report vs. the Issue (e.g. an OS-package CVE not
on the exposed-app path). When asset-scoped disagrees with the Issue evidence/UI, the Issue evidence/UI define
the named CVEs; always confirm the count against the Wiz UI.

**New confirmed graph-control instance — wc-id-2924 (cleartext CLOUD key variant).** Credential leg =
`SECRET_INSTANCE`/`SECRET_DATA` cloud-key file (e.g. GCP SA JSON key in the image); privilege leg =
`SERVICE_ACCOUNT` + `ACCESS_ROLE_PERMISSION`; exposure leg = `ENDPOINT`(s). "(medium exposure)" = exposure
level, not the Issue severity (HIGH). Documented in "Getting the finding".

### 2026-07-10
**Filter issues by source rule via API — `sourceRule: { id: [...] }`.** `IssueSourceRuleFilters` is an object
with an `id` list (a bare string list errors "IssueSourceRuleFilters cannot represent value"); combine with
`severity` + `hasServiceTicket` to replicate a Wiz UI rule view and verify whether a control is fully Resolved
or a new revision has re-opened it. Also: `vulnerabilityExternalId` as a typed variable needs `[String!]`
(list), same as `assetExternalId`.

**New Hard rule — closing a Critical toxic-combination finding that resolved via revision rotation.** A
Critical graph-control Issue on redeploying workloads closes as `OBJECT_DELETED` (rotation) and re-opens on
new revisions as a family of lower-severity component-rule Issues, often under new incidents. When all of a
Critical incident's Issues are Resolved and no Critical re-triggers, close it as **superseded** (residual
continues under the HIGH follow-up incidents), not "fully remediated"; deliver a closure note that ALSO
advises on the remaining items/exceptions. Verify via the `sourceRule` filter.

### 2026-07-09
**New finding type — "VM/serverless infected with a critical severity malware" (wc-id-535).** Malware detail lives
in the issue's `evidenceQueryResults` as `MALWARE_INSTANCE` entities (`name`/`path`/`familyName`/`type`/
`detectionType`/`source`/`scannerMatch`/hashes); `evidenceQueryResults.totalCount` = flagged-file count. Static
file-PRESENCE (hash reputation / YARA), not execution. On OffSec/pentest hosts (`Kali*` / `*PT`, service tag
"Offensive Security") the hits are the team's own tooling (Metasploit / Cobalt Strike / Mimikatz / exploitdb /
SecLists / Empire / Sliver / Ghostpack) → false positive; disposition is suppress-and-close, not remediation.

**New Hard rule — soft INTERNAL confirm-and-close report.** For a finding the user wants to verify with the owner and
close silently (no remediation team, no SNOW): subtle language, reframed tabs (Detections by Host / Files to Confirm /
Detection Samples / Details), no SLA/Target-Date, skip all SNOW + Wiz-association steps, covering note via clipboard.
Ask up front for recipient / artifact / closing-ask.

### 2026-07-08 (session 3)
**wc-id-1458 confirmed graph-control instance + "required exposure" insight.** "Internet-facing VM/serverless with
sensitive data has initial access vulnerabilities" behaves like wc-id-140: CVEs from `vulnerabilityFindings`
(`hasInitialAccessPotential:true`), exposure/PII from `evidenceQueryResults` (ENDPOINT + DATA_FINDING; no identity
dimension). New rule: **when the internet-facing leg is a REQUIRED/inherent service (e.g. 636/LDAPS for an S/MIME
gateway), the finding closes by clearing the CVEs, not by removing exposure** — make the CVE leg P0.

**Mine an existing incident's ServiceNow thread before finalizing; fold in vendor "Not Affected" assessments.**
Added a per-CVE **Status column** to CVE Details (Not Affected → GREEN, "log a Not-Affected policy exception");
**only mark the vendor's explicitly-named CVEs**, and surface prior progress in a Remediation Progress section.

**User correction — a progress work note must convey the finding is STILL ACTIVE and frame the remainder as the
team's OPEN action items,** not a "re-assessment complete / N Not Affected" recap that reads as wrapping up.

### 2026-07-08 (session 2)
**Remediation-verification: reconcile the EXACT flagged component.** When a team claims a fix, pull the
`vulnerabilityFinding` for the CVE + `assetExternalId` and read `locationPath`/`version`/`detailedName`/
`fixedVersion` — the team frequently validated a different artifact/path (a legacy copy in an old backup
dir, or an older runtime/package env while only the newest was checked). Give the exact path + version + fix
in ONE reply and state the sequence: fix first, rescan second. Added Hard rule.

**Remediation replies — clipboard / on-screen only, never `.eml` files (user rule).** The reply is plain
text; the user pastes it into whichever channel the team used (email or SNOW work note). Do not create
draft-email files or infer a format from the channel. Added Hard rule.

**New Gotchas.** (1) `assetExternalId: { equals: $var }` needs a `[String!]` variable (list); a `String!`
variable fails "used in position expecting type [String!]"; a bare literal coerces. (2) CVE-2023-4863
(libwebp) is attributed by Wiz to the Python **pillow** package (fixed Pillow 10.0.1), read from dist-info
METADATA — a package-presence finding a patched OS RPM / non-loaded runtime does NOT clear; watch for
multiple Python envs on one host.

### 2026-07-08
**wc-id-1713 ("Exposed vulnerable software on privileged VM/serverless") is ALSO endpoint-scoped.** Same
endpoint-served-CVE scope as wc-id-1716; the "privileged" toxic-combination (high-privilege SA) is what
escalates the SAME exposed-software CVE from Medium (wc-id-1716) to Critical (wc-id-1713) — the same asset +
CVE can appear under both rules as separate Issues with different severity/tickets.

**New Hard rule — status-update report for a partially-remediated finding.** Re-query live status, keep all
originally-reported assets (Resolved ones marked with reason, open ones highlighted with full detail), keep the
original Date Reported/SLA target, re-verify open CVEs from current evidence. Do NOT alter the original
ServiceNow description (erases original scope; the creator script can't edit an incident anyway) — deliver
progress as a ServiceNow **work note** and re-upload the refreshed report. No new ticket / no new Wiz
association when the incident is already linked and the open issues are already In Progress.

### 2026-07-07
**New finding type — "Exposed vulnerable software on VM/serverless" (wc-id-1716) is ENDPOINT-SCOPED.** Name
only the CVE(s) on the software served on the public endpoint (evidence chain `SERVERLESS → ENDPOINT →
HOSTED_TECHNOLOGY → SECURITY_TOOL_FINDING`) — for THIS rule `evidenceQueryResults` IS authoritative (opposite
of the graph-control rule). Asset-scoped `vulnerabilityFindings` OVER-reports (a case returned 5–8 npm CVEs vs
the 1 endpoint-served Node.js CVE the user saw). Documented the `widelyUsedAsSubDependency` Boolean filter
(helps but doesn't fully reproduce scope). Always confirm the CVE count against the Wiz UI.

**SNOW — owner lacks ITIL access routing.** When the Technical Owner is known but can't be Assigned To (no ITIL
access): Assigned To blank, **Affected User = owner email** (`u_affected_user`), **Assignment Group =
`<your no-ITIL routing group>`**. `snow_ticket_creator.py` now supports pending-JSON `affected_user_email`
/`affected_user_display` — sets `u_affected_user` when provided (previously it only ever cleared that field).

### 2026-07-03 (session 2)
**Full 'All Borders' on every sheet.** Every cell — incl. cells inside merged ranges — must have thin
4-side borders. MergedCells reject `.border` after merge → unmerge → border all → re-merge as a final
pass; verify via raw `xl/styles.xml`, not `load_workbook` (can't read merged-cell borders). Added to Styling.

**`snow_ticket_creator.py` only CREATES incidents — cannot edit an existing one.** When folding more assets
into an existing INC, regenerate the pending JSON, give the user the updated Title + Description, let them
edit + re-upload; do the Wiz association separately.

**Folding same-product assets into an already-reported INC.** New instances of an already-reported product
→ associate the EXISTING INC to ONLY the NEW issue IDs (never re-associate already-linked issues —
re-association creates duplicate service-ticket links), rebuild the report to include them, add to the log,
and have the user update the ticket. Verify by re-querying `issuesV2` for the exact IDs (status +
`serviceTickets`) and confirming no issue has >1 ticket.

**Verifying a claimed remediation.** Read timestamps correctly: finding `lastDetectedAt` = last vuln scan;
asset `graphEntity.lastSeen`/`updatedAt` = cloud-inventory refresh, not a re-scan. Agentless assets (no
sensor) re-validate only on the next scheduled scan. `detectionMethod: FILE_PATH` version detections:
deleting the evidence file clears the finding but doesn't patch — confirm the actual upgrade. When replying
to remediation teams, drop tool internals; give the actionable ask. Added as a Hard rule.

### 2026-07-03
**CVE fetch — never derive CVEs (even the named initial-access ones) from `evidenceQueryResults`.**
It samples paths and silently under-reports: on one such finding the sampled evidence showed 1 initial-access
CVE (ecdsa) while `vulnerabilityFindings` (`hasInitialAccessPotential: true`) returned 3 (added python-jose
Critical + aiohttp). `hasInitialAccessPotential` is the AUTHORITATIVE source for named findings and works as
both a filter and a returned field. Documented the working `VulnerabilityFinding` fields (`detailedName`,
`remediation`, `fixedVersion`, `vulnerableAsset` union, etc.) — library + fix per CVE without evidence.

**Styling — High severity is ORANGE (`ED7D31`), not amber.** Added the full severity→colour mapping
(Critical RED / High ORANGE / Medium AMBER / Low GREEN) to the palette and per-element rules; applies to the
Finding Summary badge, inline CVE tables, and CVE Details. (I shipped High in amber — same as P2/Medium — on
the first such build; corrected via targeted patch.)

**Technical Owner — check resource `properties.tags` FIRST** (`TechnicalOwner`/`Owner`/`OwnerEmail`/`Team`).
AWS resources are often well-tagged with an owner; most GCP Cloud Run resources are not, and Wiz
`Project.projectOwners` is empty (internal scanning projects). Corrects the prior "owner not in API" note.
**Owner-not-verified → route SNOW to `<your default VM group>` (Assigned To blank) but keep it and any
unconfirmed owner OUT of the report** (Suggested Owner = "To be confirmed").

**Serverless naming + count drift.** `SERVERLESS` entity name is a Cloud Run *revision* (`run#revision`); the
real asset is the *service* from `externalId` `.../services/<svc>/revisions/<rev>` — label by service, keep the
revision in Details. Cloud Run revisions auto-resolve when rotated, so filtered issue counts drift (91→85 in an
afternoon; the 6 dropped were RESOLVED, ticket-less revision rotations = exposure removed, not patched) — re-run
`list` and diff before building.

**One rule → many resources → per-owner reports.** A single rule can span dozens of resources across many
subscriptions (91 issues / 23 projects here). Split by owning team/subscription; one report + one INC per group.
Validated `associateServiceTicket(input:{issueId,ticketId,ticketUrl})` and batched `updateIssue → IN_PROGRESS`
again (INC#, 11 internet-facing Lambdas).

**SNOW Contact display = the caller's real ServiceNow name (resolved from the caller's email), not an
Excel-author-style string.** `snow_ticket_creator.py` now returns `(sid, name)` from `lookup_sys_id` and uses
the looked-up name as the Contact display automatically, so the Contact is never mislabelled.

**When editing a SharePoint/compliance-labelled `.xlsx`, don't use openpyxl load/save** — it strips
`customXml` (content-type + sensitivity/compliance metadata). Back up first and edit only the target sheet's
XML surgically via `zipfile` (inline strings, reuse an existing row's style index, update `<dimension>`),
copying every other zip part unchanged.

### 2026-07-01
**New top Hard rule — NEVER ASSUME; always verify against the authoritative source, or ask and confirm.**
The day's errors (asset name from file path, forced assignment group, auto-patching a delivered report,
inventing an expansion for an unfamiliar acronym) all traced to assuming. See Hard rules for the concrete checklist.

**Corrected Hard rules / logic**
- **ServiceNow Assignment Group is derived from the assignee's group membership** (`sys_user_grmember`),
  NOT a forced default. Forcing `<your default VM group>` when the owner isn't a member made SNOW
  clear the Assigned To. Single group → use it; several/none → leave blank for manual pick; no owner →
  fall back to the default. Set Assignment Group BEFORE Assigned To. Implemented in `snow_ticket_creator.py`.
- **Suggested Owner: confirm before patching a delivered report;** never auto-apply an owner change to a
  report already delivered/attached — propose and wait.
- **Asset name comes from `vulnerableAsset` (a UNION — inline fragments), not the file path / `locationPath`.**
  Oracle EBS context files (`CORF_<host>.xml`) embed a legacy hostname; caused the CVE-2026-46817 report to
  mislabel the true VM names as the legacy file-path hostnames (corrected on INC#; file paths kept).

**Corrected / added Gotchas**
- `scripts/wiz_fetch.py raw` DOES support `--query`/`--query-file`/`--variables` (prior "no flags" note was stale).
  Cursor pagination still needs a loop; prefer a standalone paginator importing `gql, resolve_auth` from
  `wiz_fetch` with per-query checkpointing (skip-if-exists) so a mid-fetch 401 loses nothing.
- Cookie sessions are currently VERY short-lived (~1-2 min); work in tight bursts after `login`; trust
  a mutation's returned fields as confirmation when the follow-up `get` 401s.
- Validated graph-evidence query for graph-control findings (`evidenceQueryResults`, `$id: [String!]`),
  with the useful entity types + properties (SECURITY_TOOL_FINDING, HOSTED_TECHNOLOGY, ENDPOINT,
  DATA_FINDING, SERVICE_ACCOUNT, ACCESS_ROLE_BINDING, IAM_BINDING). CVSS/EPSS/KEV not in these props on this tenant.
- Technical Owner is NOT exposed via standard API fields (issue `entity.properties`, `Project.projectOwners`,
  `CloudAccount`) on this tenant — ask the user rather than spelunking.

**Updated Workflow**
- New step 10: after associating a ticket, move the linked issues to `IN_PROGRESS` via `updateIssue`, then
  re-query (or trust the mutation's returned status if the session dies).

**ServiceNow auto-fill**
- `snow_ticket_creator.py` now persists the captured INC to `Output/snow_ticket_result.json` on submit (and
  a stub on timeout) so the INC survives the browser closing. ALWAYS read that file back after a run;
  prompt the user for the INC if `submitted:false`.

**Note (not a skill change):** on the current machine `python` resolves to the MS Store stub — scripts must
be run with the `py` launcher. Kept out of the shared skill text (env-specific); tracked in user memory.

### 2026-06-30
**Updated Styling**
- Worksheet tab names must be Title Case (e.g. "Finding Summary") — not ALL CAPS. User confirmed preference.

**Added ServiceNow auto-fill section**
- `snow_ticket_creator.py` — full Playwright-based SNOW incident creator. Reads from `Output/snow_ticket_pending.json`.
- Field mapping confirmed: caller via sys_id lookup, assigned_to for Technical Owner email, assignment_group for group names.
- Impact/Urgency matrix confirmed: CRITICAL→Group/Interruption, HIGH→Individual/Interruption, MEDIUM/LOW→Individual/Service Request.
- Known SNOW field IDs: No Matching CI checkbox = `ni.incident.u_no_service_offering`; Offering input = `sys_display.incident.service_offering`.
- Use `locator.click(click_count=3)` not `triple_click()` (unavailable in this Playwright version).
- Use in-page `fetch()` for REST API calls — `context.request` 401s even with persistent context.
- Auto-detect form submission by URL change; extract INC number from form automatically.
- Write `Output/snow_ticket_pending.json` as part of every report build (step 7 of workflow).

**Added to Gotchas**
- `vulnerabilityExternalId` filter: plain string, not `{ equals: "..." }` wrapper.
- Standalone vulnerability findings with no Issues: `associateServiceTicket` unavailable; flag proactively; track INC externally.
- `updateIssue` mutation validated: `patch: { status: IN_PROGRESS }`, ≤8 aliases per batch.

**Updated Workflow**
- Step 2: check `relatedIssueAnalytics.issueCount` early; flag standalone findings before building.
- Step 7: write `snow_ticket_pending.json` as part of every report build.

### 2026-06-29
**Added to Gotchas**
- GraphQL mutation partial execution warning: writes can commit even when response returns
  `GRAPHQL_VALIDATION_FAILED` on return field selection. Re-query after any failed mutation batch before
  retrying.
- `associateServiceTicket` schema: input `issueId`, `ticketId`, `ticketUrl`; return
  `{ serviceTicket { externalId } }`. Do not use `externalId` as input or query `issue`/`successCount`.
- `disassociateServiceTicket` schema: top-level `serviceTicketId` arg, return `{ _stub }`. Find the Wiz
  ticket ID from `issue { serviceTickets { id externalId } }` first.
- `vulnerabilityFindings` unavailable fields on this tenant: `cvssScore`, `epssScore`, `cvss`, `epss`,
  `hasKEVEntry`, `dataSourceLink` all absent from schema. Use `SECURITY_TOOL_FINDING` evidence properties
  instead for CVSS/EPSS details.

**Updated Hard rules**
- Suggested Owner = Technical Owner always; fall back to Owner only if Technical Owner absent. Never split
  by action type.

### 2026-06-25
**Added**
- Build script placement rule: one-off scripts go in `_build/<slug>.py`, not the working directory root.
  `build_report.py` stays at root as the permanent base scaffold. `_build/` is session-only and safe to
  delete after any session — it contains no outputs.

### 2026-06-24 (session 2)
**Added to Gotchas**
- No ticket-ID reverse lookup: `IssueFilters` on this tenant has no `serviceTicket`/`hasServiceTickets` field.
  `list --has-ticket true` lists all ticketed issues; filter client-side for a specific INC number.
- Batch alias limit: ≤8 `issue(id: ...)` aliases per query or `MAX_ROOT_FIELDS_LIMIT` is hit.
- Resolved/archived issues return `Resource not found` from `issue(id: ...)` — treat as closed, not error.

### 2026-06-24
**Added**
- `vulnerabilityFindings` pagination approach: `first: 500` + cursor, deduplicate by
  `vulnerabilityExternalId`. A single VM can return 2,000+ raw findings.
- CVE scope strategy for graph-control findings: `hasInitialAccessPotential: true` = issue-triggering
  CVEs only; remove it for the full surface. For reports, list only the `hasInitialAccessPotential`
  CVEs; cover the broader set with a single `npm audit fix` / binary-upgrade remediation line.
- Gotcha: `scripts/wiz_fetch.py raw` has no `--query-file`/`--variables-file`; use a standalone Python
  paginator reading `~/.wiz/token.json` directly for multi-page queries.

### 2026-06-23
**Added**
- Full validated colour palette with exact hex values and role descriptions.
- Priority badge label format: `P0 - Immediate` / `P1 - High` / `P2 - Medium` (previously just `P0` etc.).
- Status vocabulary rules: `In Progress`, `Open`, `Exposure Mitigated`, `Resolved` — raw API enum values
  (`IN_PROGRESS`, `ISSUE_FIXED`) must never appear in the deliverable.
- Wiz Issue vs Vulnerability Finding distinction: a Wiz Issue closing as `ISSUE_FIXED` may be exposure
  removal only. Must verify via `vulnerabilityFindings` API before marking as Resolved.
- Date Reported auto-detection: check `serviceTickets` on the issue — if a ticket exists, ask the user
  for the original report date; if none, default to today.
- File author metadata: `wb.properties.creator` and `wb.properties.lastModifiedBy` must be set to
  `"<report author from skill_config.json (analyst.report_author)>"` on every output workbook.
- Validation field rule: keep concise, never mention API calls or automation.
- Suggested Owner rule: do not append managed service providers unless they are the actual executor.
- CVE Details tab documented as an optional 6th tab for vulnerability-heavy findings.
- Self-learning section and this changelog.

**Updated**
- Workflow step 3 (was step 2): added ticket-detection prompt for Date Reported before confirming scope.
- Workflow step 5: explicitly states rebuild from scratch, never carry widths/heights from prior report.
- Hard rules: added Validation field rule, status vocabulary, Issue vs Finding distinction, Suggested
  Owner rule.
- Styling section: full rewrite with per-element rules replacing the previous brief bullet list.

**Removed**
- "Preserve any sheets the user has hand-tuned — do not rebuild a sheet whose row heights/edits they've
  adjusted unless asked; edit cells in place instead." — user confirmed reports must always be rebuilt
  from scratch; layout is subjective to the current finding's data volume.
- "Rebuilding a whole sheet discards manual formatting — prefer targeted cell edits on sheets the user
  has touched." — same reason as above.
