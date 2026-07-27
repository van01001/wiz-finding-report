---
name: wiz-finding-report
description: Transform a Wiz finding into a contextualized, remediation-ready workbook using the standardized SecOps format — tabs for Finding Summary, Attack Path, Remediation Plan, Affected Assets, and the trimmed Wiz source. Pulls the finding directly from the Wiz API when credentials are set, otherwise works from a raw export (.xlsx) or screenshot. Use whenever a user has a Wiz issue (by ID, URL, or filtered search) or a finding export and wants to make it actionable for a remediation team, or asks to apply "the finding format / our reporting format".
---

# Wiz Finding Report

Turn a generic Wiz export into a self-explanatory remediation deliverable. Raw Wiz exports are a single
`Details` row of templated boilerplate plus thousands of empty columns — they tell a remediation team
*nothing actionable*. This skill produces a workbook that does.

## Layout — where things live in this skill

```
SKILL.md                 this file (always loaded)
references/              read ON DEMAND, not preloaded
  rule-catalog.md          which source is authoritative per Wiz rule family
  graphql-notes.md         schema quirks, filter typing, mutation shapes
scripts/                 all executables — invoke as scripts/<name>
  wiz_fetch.py             Wiz GraphQL client: login/status/list/get/raw
  build_report.py          reference 5-tab builder + styling helpers
  snow_ticket_creator.py   ServiceNow incident auto-fill
  login.sh / .bat, snow_create_ticket.sh / .bat
templates/               copy these OUT, never edit in place
  skill_config.example.json, Asset_Owner_Registry.example.md
skill_config.json        YOUR settings, at the skill ROOT (git-ignored)
Output/                  generated reports, in the USER'S working directory
```

**Path resolution — read this before running anything.** Every path in this file (`scripts/…`,
`references/…`, `templates/…`) is relative to the **skill directory**, normally
`~/.claude/skills/wiz-finding-report`, and **NOT** to the user's working directory. The skill is invoked
from wherever the user happens to be working, so those are usually different places. Resolve skill paths
against the skill directory: `cd` into it before running a script, or pass an absolute path. If a relative
read of `references/…` fails, retry it under the skill directory before concluding the file is missing.

**The one exception is output.** `Output/` (deliverables) and `_build/` (one-off build scripts) are always
created in the **user's current working directory**, so their reports land next to their own work — never
inside the skill directory.

The `references/` files are **not** loaded when this skill starts; only this file is. Read them with the
Read tool at the moment you need them — the rule catalog before you pull CVEs, the GraphQL notes before you
write or debug a query. That is deliberate: it keeps the always-loaded instructions small while the
catalogs can grow without limit.

## First-run configuration (portable setup)

This skill is environment-agnostic. Before the first report in a new environment, establish the
local configuration so every connection and label uses **your** organization's values (the same
way the report's file-author name is applied):

1. Look for **`skill_config.json`** at the skill root (next to this file). If it is missing, copy
   **`templates/skill_config.example.json`** to `skill_config.json` and fill it in — or ask the user for the
   values and write the file for them. Collect:
   - **Analyst identity** — `analyst.name` (display name, used as the ServiceNow caller and report
     contact), `analyst.email`, and `analyst.report_author` (the workbook author-metadata string,
     e.g. `Lastname, Firstname`).
   - **Wiz** — `wiz.auth_mode` (`browser_sso` | `api_token` | `service_account`), `wiz.portal_url`
     (your IdP-initiated SSO link to Wiz, for browser sign-in), and `wiz.api_url` (your tenant
     GraphQL endpoint; `login` can capture this automatically).
   - **ServiceNow** — `servicenow.instance_url` (your ServiceNow base URL),
     `servicenow.default_assignment_group` (fallback group when no owner is known), and optional
     `servicenow.idp_login_host` (your SSO host, so ticket automation knows when you are still on the
     login page).
   - **Report wording** — `report.team_name`, `report.contact_line`, `report.sign_off`. Not every
     organization signs off "Regards, SecOps Team"; ask rather than assuming, and offer the defaults.
   - **SLA policy** — `sla_days` per severity. Ask whether the organization's remediation SLAs match the
     defaults (5/15/30/60/120 days) and record whatever they confirm. This drives every Target
     Remediation Date, so a wrong number here is wrong on every report.
2. `wiz_fetch.py` and `snow_ticket_creator.py` read `skill_config.json` automatically; environment
   variables (`WIZ_PORTAL_URL`, `WIZ_API_URL`, `WIZ_API_TOKEN`, `SNOW_INSTANCE_URL`) override it.
3. `skill_config.json` is git-ignored — your settings are never committed. Re-use it on every later
   run; only re-prompt if it is absent or the user asks to reconfigure.

Wherever a report needs the author name, the Wiz sign-in portal, the ServiceNow URL, or a default
assignment group, take it from `skill_config.json` — never hard-code a specific organization's value.

## Getting the finding — API first, manual fallback

**Preferred: pull from the Wiz API** with `scripts/wiz_fetch.py` (list/get are stdlib — no deps).

**Auth is browser sign-in by default** (no service account / admin needed). Run
`python scripts/wiz_fetch.py login` — it opens the user's *installed* Edge (`--channel msedge` default, or
`chrome`), the user signs in via **your organization's IdP** (SSO + MFA), and the script captures the tenant's GraphQL
endpoint + session credential, caching to `~/.wiz/token.json`. **This tenant uses an httpOnly
session COOKIE, not a bearer token** — the login flow detects that automatically (`authMode: cookie`)
and `list`/`get` send the cookie. The default portal URL is the user's Okta IdP link, so plain
`python scripts/wiz_fetch.py login` is enough. Profile persists in `~/.wiz/browser-profile`, so later logins
usually skip Okta entirely. `list`/`get` reuse the cached cred; on 401/403 re-run `login`. Requires
`playwright` (`python -m pip install --user playwright`) — NO browser download (drives installed
Edge/Chrome; bundled-Chromium download is blocked by corporate TLS interception). State:
`scripts/wiz_fetch.py status`. **Validated end-to-end against a real tenant 2026-06-12.**

- **Capture is human-driven (mirrors the user's ServiceNow downloader pattern).** In an interactive
  terminal it prints instructions, the user logs in at their own pace, then **presses ENTER**; it
  reloads to force a real GraphQL call and reads the cred. Non-tty (e.g. when Claude runs it via Bash):
  falls back to auto-detect — polls until the dashboard fires a GraphQL POST, up to `--timeout` (default
  300s). Token-vs-cookie is decided by inspecting the real endpoint's headers (`POST` to a path ending
  `/graphql`; NOT the `/assets/graphql-*.js` bundle — match strictly).
- **Corporate TLS interception (Zscaler):** API calls VERIFY certificates, and fall back to unverified
  **only** when the certificate itself is rejected (OpenSSL refuses the injected corporate CA), printing
  a one-time warning to stderr. That warning appearing once behind the proxy is expected — it is not an
  error, and the request succeeds. `WIZ_VERIFY_SSL=1` forces strict (fail, no fallback);
  `WIZ_INSECURE_SSL=1` skips the verified attempt entirely.
- **Keep the whole command on one line** (a wrapped `--portal-url` URL makes the shell run the URL as a
  separate command — this bit us repeatedly). The default Okta portal means you rarely need the flag.
- The window stays open until ENTER (interactive) or capture / `--timeout` (auto). If an Edge window
  "flashes and vanishes," Edge was already running and handed off the URL — close all Edge windows first
  (or switch `--channel`).
- Other auth paths still work if preferred: paste a token via `WIZ_API_TOKEN` (+ `WIZ_API_URL`), or a
  read-only service account via `WIZ_CLIENT_ID`/`WIZ_CLIENT_SECRET`/`WIZ_API_URL` (Wiz → Settings →
  Access Management → Service Accounts; scopes `read:issues`, `read:resources`, `read:vulnerabilities`).
- If no auth is available at all the script returns `{"error": "No Wiz credentials available..."}` —
  offer `login`, and fall back to the manual inputs below. Do NOT block on the API.
- **Filtered search → confirm → build** (the standard flow): run
  `python scripts/wiz_fetch.py list --severity CRITICAL,HIGH --status OPEN,IN_PROGRESS [--search "..."] [--project <id>]`.
  Show the user the returned issues (id, severity, rule, resource, created/due) and **ask which one(s)**
  to report on before building. Never auto-pick from a multi-result list.
- **One rule spanning many resources → split into per-owner reports (learned 2026-07-03).** A single Wiz
  rule can span dozens of resources across many subscriptions/teams (e.g. "Publicly exposed VM/serverless
  with high privileges…" = 91 issues over 23 GCP/AWS projects). Do NOT build one mega-report: a report
  carries ONE Technical Owner, ONE SNOW incident, ONE assignment group. Group by **owning team /
  subscription (or product family)** and raise one report + one INC per group. Confirm the CVE "common
  dependency" is not identical across groups (it usually varies — Next.js vs perl-base vs python-ecdsa,
  etc.); the report set and remediation differ by group. Present the grouping + counts and let the user
  choose scope and order before building.
- **Direct lookup**: `python scripts/wiz_fetch.py get --id <uuid>` or `--url "<wiz issue url>"` (the script parses
  the UUID out of the URL). Even for a direct URL/ID, it's fine to also run `list` to confirm context
  ("found N matching issues; using this one").
- The `get` JSON gives the concrete fields the report needs: severity, status, `createdAt` (→ Date
  Reported, drives the SLA/Target Date), `dueAt`, source rule + its recommendation, and `entitySnapshot`
  (resource name, type, cloud, region, subscription, externalId, providerId, cloudProviderURL). API data
  is authoritative — no AI-derived/to-verify flag needed.
- **Finding type decides where the CVEs come from — read `references/rule-catalog.md` BEFORE you
  pull them.** Getting this backwards silently misreports the finding. In short: for
  **graph-control / toxic-combination** rules the named CVEs come from `vulnerabilityFindings`
  (`hasInitialAccessPotential: true`) and NEVER from `evidenceQueryResults` (evidence *samples*
  paths, so it under-reports), while evidence supplies the exposure / identity / secret /
  sensitive-data legs. For **endpoint-scoped "Exposed vulnerable software"** rules (`wc-id-1716`
  and its privileged variant `wc-id-1713`) it is the OPPOSITE — the issue's evidence is
  authoritative for the CVE and asset-scoped `vulnerabilityFindings` over-reports. Malware
  (`wc-id-535`) has no CVE leg and reads `MALWARE_INSTANCE` entities; the cleartext
  storage-account-key rule (`wc-id-927`) has no CVE leg at all. The catalog carries the confirmed
  instance list, each rule's evidence shape, the `hasInitialAccessPotential` scoping strategy, the
  asset-vs-issue reconciliation rule, and the no-fix OS-package prompt — consult the entry for the
  rule in hand, and add a new entry when you validate one.
- **One rule spanning many resources → split into per-owner reports.** A single Wiz rule can span
  dozens of resources across many subscriptions/teams. Do NOT build one mega-report: a report
  carries ONE Technical Owner, ONE SNOW incident, ONE assignment group. Group by owning team /
  subscription (or product family) and raise one report + one INC per group. ALWAYS read every
  asset's `entitySnapshot.tags` (TechnicalOwner/Application) — a filter that returns N assets can
  still span multiple owners, even when the hostnames look similar. Present the grouping + counts
  and let the user choose scope and order before building.

**Manual fallback inputs** (no API access, or extra context the API lacks):
- The Wiz export `.xlsx` (the `Details` row: Title, Severity, Description, Resource Name/Region,
  Remediation Recommendation, Subscription, Wiz URL).
- Any supplementary Wiz endpoint export (real URLs, endpoint IDs, project IDs).
- The Wiz issue screenshot if provided (AI recommendation panel, risk panel, status/dates) — it often
  holds the *only* concrete details (service name, endpoints, exposure, service-account privilege).
- Confirm with the user whether screenshot-derived specifics are confirmed facts or should be flagged
  as AI-derived/to-verify.

## Output workbook structure (tab order)
1. **Finding Summary** — the contextual brief. Sections: Identification, Environment, Affected Workload,
   Vulnerable Endpoints, Plain-language Summary, Why this is <Severity> (justification), Contact.
2. **Attack Path** — table: Step | Stage | What happens | Control that should stop it. One row per stage
   of the exploit chain; each control is what breaks the chain at that step.
3. **Remediation Plan** — table: # | Issue | Affected resource | Recommended action | Priority | Suggested
   owner | Status. Concrete, prioritized (P0/P1/P2), mapped to specific resources/endpoints.
4. **Affected Assets** — table: Asset | Type | Identifier / URL | Wiz Endpoint ID | Region / Scope | Notes.
5. **Details** — the Wiz source export, trimmed to only populated columns (header row + data row),
   kept as the audit record. Goes LAST.

## Identification fields (SLA is the key value-add)
Include: Wiz Issue ID, Wiz URL, Severity, Status, **Date Reported**, **Remediation SLA**,
**Target Remediation Date** (= Date Reported + SLA, highlighted amber), Source Rule, Validation.

### Date Reported — auto-detect from serviceTickets
**Do NOT use `createdAt` from the Wiz API as Date Reported.**

Check the `serviceTickets` field on the issue (returned by `scripts/wiz_fetch.py get`):

- **`serviceTickets` is non-empty** → the finding has an existing incident ticket. Tell the user:
  *"This finding is linked to [INC...]. What date was this first reported to the remediation team?"*
  Use the date they provide. Do not guess or use `createdAt`.
- **`serviceTickets` is empty** → new finding with no prior ticket. Use **today's date** as Date Reported
  (the day the report is being prepared).

This distinction matters because existing incidents may have been raised weeks before the report is
generated, and the SLA clock started on the original report date, not today.

**SLA matrix (days to remediate by severity) — read `sla_days` from `skill_config.json` if present.**
Remediation SLAs are organization policy and differ between organizations, so these are DEFAULTS, not
constants. If `skill_config.json` has an `sla_days` block, use those numbers (ignoring keys that start with
`_`) and say which source you used when you present the Target Remediation Date. Only fall back to the
table below when the config is silent.

| Severity | SLA (default) |
|----------|-----|
| URGENT   | 5   |
| Critical | 15  |
| High     | 30  |
| Medium   | 60  |
| Low      | 120 |

Always compute and show the concrete Target Remediation Date, not just the day count. Do NOT add a
separate SLA legend tab to the live report — the per-finding timeline is enough for the remediation team.

## Contact block (end of Finding Summary)
**Take this from `skill_config.json` (`report.contact_line` + `report.sign_off`) — it is organization
wording, not a fixed string.** Render `contact_line`, a blank line, then `sign_off`. If `report` is absent
from the config, fall back to the default below and mention once that it can be customised. If
`report.sign_off` is set to `""`, omit the sign-off entirely rather than substituting anything.

Default (used only when the config says nothing):
> For any clarification or support, please contact the SecOps team.
>
> Regards,
> SecOps Team

Use `report.team_name` wherever a deliverable or ticket names the security team, instead of writing
"SecOps" literally.

## ServiceNow description template
When the user asks for a ServiceNow description, follow this VM pattern with full remediation detail:

```
Hi Team,

One or more vulnerabilities have been identified on the asset(s) listed below. Support is required to remediate the open findings in accordance with your organization's Vulnerability Management (VM) SLA.

Asset(s) Impacted:
[numbered list — asset name | GCP project / subscription | environment]

Vulnerability Name: [Wiz rule / finding name]

Vulnerabilities Identified:
- [CVE-ID] | CVSS [score] | [package/component] — [brief description]. Fix: [fix action]. Affects: [assets].

Sensitive Data at Risk:
- [data type]: [assets affected]

Remediation Actions Required:

P0 — Immediate (Production):
[numbered actions for production assets]

P1 — High (Development):
[numbered actions for development assets]

P2 — Medium:
[cross-cutting actions — DLP, audit logging etc.]

Recommendation: Please refer to the attached vulnerability report for detailed information on the affected asset(s) and recommended remediation guidance.

Important Notes:

A thorough impact assessment must be completed prior to implementing any changes in the production environment.
Remediation should be completed within the defined VM SLA timeline of [N] days.
"Please do not close this incident. The security team will validate the remediation and update the status to Resolved upon verification".

Contact the SecOps team for any clarification or support required.

Regards,
SecOps Team
```

Omit sections that are not applicable (e.g. no P2 row if there are no medium-priority actions; no
Sensitive Data row if no data findings). Keep CVE and remediation detail — the description is the
remediator's primary brief; the attached report is the supporting evidence.

## Hard rules (learned conventions — keep these consistent)
- **NEVER ASSUME — always verify against the authoritative source, or ask and confirm (2026-07-01).**
  This is the top rule; the day's biggest errors all came from assuming. Concretely:
  - **Asset facts** (names, environments, accounts, CVEs, owners) come from the Wiz API's authoritative
    field, not from an adjacent string. E.g. take the asset name from `vulnerableAsset { name }`, never
    from a file path (`CORF_<host>.xml` embeds a legacy hostname → mislabeled the real VM by a legacy hostname).
  - **Suggested Owner / Technical Owner** — never guess or default silently. It is not reliably in the API
    (see `references/graphql-notes.md` for where the owner tags do and don't live); ask the user
    and confirm the exact spelling of any name/email you decode.
  - **ServiceNow Assignment Group** — derive from the assignee's actual group membership; never force a
    default that the owner isn't a member of (it clears Assigned To). Ask if membership is ambiguous.
  - **Delivered artifacts** — once a report is delivered/attached, do NOT silently patch it (owner, names,
    scope). Propose the change and wait for confirmation before editing. **In particular, do NOT re-open the
    report to inject the INC# after the ticket is submitted (2026-07-10): the report is attached at submit
    time and the INC is only generated on first submission, so the attached copy inherently has no INC and
    patching the local copy afterward only creates a mismatch. The INC lives in the tracker + the ticket.**
  - **Filenames, labels, acronyms** — never invent an expansion for an unfamiliar acronym in a
    resource or file name; state the source of any
    shorthand and confirm if unsure.
  - When in doubt, present what you found, say what you're unsure about, and ask — do not proceed on a guess.
- **Reader-first: Wiz internals belong in Details only.** The Finding Summary and Affected Assets tabs
  are shared with the remediation team, who may have no Wiz access. Keep all Wiz-specific references
  (Control ID, Issue IDs, Wiz Endpoint IDs, Wiz project names, Wiz URLs) out of those tabs — they belong
  exclusively in the Details tab. Label fields in reader-facing tabs using plain language: "Affected
  Services" not "Total Wiz Issues"; state CVE facts directly without a "Wiz — " prefix; never open a
  summary with "Wiz has identified...".
- **Patch existing files; never rebuild to make incremental changes.** When editing an output workbook
  that already exists, use `openpyxl.load_workbook(path)`, make only the targeted cell/range changes,
  and save back to the same file. Never run the full build script for incremental edits — it destroys
  manual formatting (borders, cell edits, column widths) the user has applied. Reserve a full rebuild
  only for the very first generation of a new report, or when the user explicitly asks for one.
  - **EXCEPTION — a report you JUST built this session with NO user manual edits yet: change the build
    script and REGENERATE, do not `load_workbook`-patch it (learned 2026-07-21).** A `load_workbook` + save
    round-trip CORRUPTS merged-cell borders — it splits the clean single full-border style into several PARTIAL
    borders on the merged title/subtitle/section-header rows (verified: `xl/styles.xml` `<borders count>` jumped
    2→6 after a trivial status-text patch), because openpyxl can't round-trip a merged cell's border. Nothing
    manual to preserve on a just-built file → editing the build constant and re-running is cleaner and keeps
    borders intact (this is the "very first generation" case). Only `load_workbook`-patch a file that carries the
    user's manual formatting; even then, re-apply the full-border pass afterward and verify via raw `xl/styles.xml`.
- **No build/meta commentary in the deliverable.** Subtitles and headers describe content to the
  *reader*, never the authoring process. Never write things like "replaces the generic Wiz boilerplate",
  "sourced from API", "automatically generated", "trimmed to populated columns", or "via Wiz API"
  anywhere in a shared sheet.
- **Remediation = knowledge-sharing guidance, NOT prescriptive shell/CLI commands (user rule, 2026-07-10).**
  State clearly *what* to do — "upgrade the <package> library to a fixed release (≥ <fixed version>)",
  "rebuild the container image on <patched base>", "rotate the affected key" — and give the fix at a
  knowledge level, but do **NOT** paste literal commands (`pip install --upgrade …`, `pip show …`,
  `apt-get …`, `npm audit fix`, etc.) into the deliverable or the SNOW description. We rarely know the
  target environment (venv vs. system Python vs. container, prod change-control, etc.), so a copy-paste
  command is a liability. This applies to **every** tab **including Details**: even the Wiz-provided
  `remediation` string is often a literal command (`pip install --upgrade litellm`) — paraphrase it and
  relabel that Details column **"Remediation Guidance"** rather than pasting it verbatim. Always add
  "apply through your standard change-management process after an impact assessment" for production assets.
- **Validation field:** Keep concise — one line stating the CVE/finding facts directly. No "Wiz — "
  prefix. Example: `"CVE-2023-46604 confirmed present on affected resource; CISA KEV listed with active exploitation"`.
- **Keep the Wiz source tab; never delete it.** It's the audit trail. Trim empty columns but preserve the
  original header-row + data-row orientation and all values verbatim.
- **Serial numbers must be numeric**, not text (avoids Excel's "number stored as text" warning).
- **Use real identifiers** when available: full Cloud Run/service URLs, full project IDs (e.g.
  `...-b686` suffix). Wiz Endpoint IDs and Wiz Issue IDs belong in the Details tab only — not in
  Affected Assets or Finding Summary, as remediators cannot use them without Wiz access.
- **Correct vuln-class names** to Wiz's exact labels (e.g. "Default and Weak Credentials", "BOLA/IDOR").
- **Status values must be human-readable and consistent across ALL tabs.** Never expose raw API enum
  values (`IN_PROGRESS`, `ISSUE_FIXED`, `EXPOSURE_MITIGATED`). Use:
  - `Open` — not yet ticketed / no incident raised (the DEFAULT for a brand-new finding at report-build time,
    and for the Remediation Plan status column)
  - `In Progress` — ticketed and being worked (INC linked + Wiz issue moved to IN_PROGRESS)
  - `Exposure Mitigated` — Wiz Issue closed but underlying vulnerability still present
  - `Resolved` — fully remediated and confirmed clean
- **Report status is `Open` until the incident is actually raised (user correction, 2026-07-21).** Do NOT
  pre-set `In Progress` across Finding Summary / Affected Assets / Details at build time for an un-ticketed
  finding — it reads as if work has started. Build with `Open`; flip to `In Progress` only after the INC is
  created + issues associated + moved to IN_PROGRESS. The `Open` Finding-Summary badge has no dedicated palette
  colour → use neutral **DARK_GREY (`595959`)** with white text (NOT orange = In Progress; NOT green = Resolved).
  The report attached to SNOW at submit inherently shows the state at that moment (usually `Open`); don't silently
  re-patch the attached copy — offer a fresh local copy if the user wants one showing In Progress.
- **Wiz Issue ≠ Vulnerability Finding.** A Wiz Issue closing as `ISSUE_FIXED` may be due to exposure
  removal, not an actual patch. Always verify by querying `vulnerabilityFindings` for the resource. If
  the CVEs/libraries are still present, status is `Exposure Mitigated — Patch Pending`, not Resolved.
  Call this out explicitly in the Finding Summary, Remediation Plan, and Affected Assets.
- **Verifying a remediation team's claimed fix.** Confirm against Wiz before accepting a fix, and read the
  timestamps correctly: a finding's `lastDetectedAt` is the last *vulnerability* scan; an asset's
  `graphEntity.lastSeen`/`updatedAt` is only a **cloud-inventory refresh, NOT a re-scan** — never equate
  the two. For agentless assets (`deploymentCoverage_sensor_*_deploymentStatus: NotInstalled`) Wiz
  re-validates only on its next scheduled scan, and standalone findings can't be force-re-assessed.
  **`detectionMethod: FILE_PATH` version detections (e.g. an app version read from a config file): deleting
  the evidence file clears the finding but does NOT patch — the software is still the vulnerable version.**
  When replying to a remediation team, keep tool/scanner internals OUT — give them the actionable ask
  (confirm the actual patch/upgrade, not the deleted artifact) and keep the ticket open until a fresh scan
  validates for the right reason. Useful `vulnerabilityFinding` fields: `status`, `lastDetectedAt`,
  `resolvedAt`, `locationPath`, `version`, `detectionMethod`, + `vulnerableAsset { ...VM { scanSource
  graphEntity { lastSeen properties } } }`.
- **Reconcile the EXACT flagged component when verifying a claimed fix — the team often validated the wrong
  one.** Before accepting "we patched it," pull the `vulnerabilityFinding` for that CVE + `assetExternalId`
  and read `locationPath`, `version`, `detailedName`, `fixedVersion` — that names the precise artifact Wiz
  flags. Common traps: a legacy copy in an old backup directory the team's inventory missed, or an OLDER
  runtime/package env (e.g. `python3.6` Pillow 8.4.0 vulnerable while `python3.9` Pillow 11.3.0 is fine) when
  the team only checked the newest one. Give the team the exact path + version + fix in ONE reply, and state
  the sequence explicitly: **fix first, rescan second** — a rescan before removal just re-detects the on-disk
  artifact.
- **Remediation replies — deliver the reply text via the CLIPBOARD (`clip`, utf-16-le) or on screen only;
  NEVER create `.eml` / draft-email files.** The channel is the user's call and just follows however the team
  reached them (sometimes email, sometimes a SNOW work note) — the reply text is identical either way, and
  the user pastes it wherever they need. Don't infer a file/format from the channel; if it matters, the user
  will say. Keep scanner internals appropriate but give the concrete actionable path/version/fix so it
  resolves in one pass; sign with the user's real name, not the Excel-author string.
- **Suggested Owner — collect EVERY ownership signal, then have the user confirm. Do not look for one
  fixed tag name.** Tagging conventions differ by organization, by cloud, and often by team within the
  same org, so treating `TechnicalOwner` as the only source silently misses ownership that IS present
  under another key. Gather candidates from all of:
  - the resource's tags — `entitySnapshot.tags`, `vulnerableAsset` tags, and evidence entity
    `properties.tags` — matching keys **case- and separator-insensitively** on any of: `owner`,
    `technical_owner`, `technicalowner`, `app_owner`, `application_owner`, `service_owner`,
    `business_owner`, `product_owner`, `contact`, `maintainer`, `custodian`, `steward`, `responsible`,
    `team`, `squad`, `group`, `dl` / `distribution_list`, `email`, `cost_center`;
  - the local `Asset_Owner_Registry.md`, if the asset or its product family is already recorded;
  - any prior incident on the same asset (the assignee there is a strong signal);
  - Wiz `Project.projectOwners` / `securityChampions` — but treat these with suspicion, as Wiz projects
    are often internal scanning scopes rather than the owning team.

  Then, always:
  1. **Exactly one candidate** → show it *with the tag key it came from* and ask the user to confirm it is
     the right remediation owner.
  2. **Several candidates** → show them ALL with their keys, ordered most-to-least specific (an explicit
     technical/application-owner tag, then a generic owner tag, then team / contact / DL / cost centre),
     and ask which to use. Do not assume the most specific one wins — a stale `TechnicalOwner` tag beside
     a current `Team` tag is common.
  3. **No candidates** → say so plainly and ask.

  Never silently pick, never guess an email from a name, and never leave Suggested Owner blank. If the user
  cannot confirm an owner, write **"To be confirmed"** in the report and route the ticket to the default
  group. One contact per report — never split ownership by action type across rows. Do not append managed
  service providers (e.g. an outsourced infrastructure vendor) unless they are the actual remediation executor.
  **Format the owner as `Name (email)` — e.g. `Firstname Lastname (owner@example.com)` —
  CONSISTENTLY across every report and wherever the owner appears (user rule 2026-07-17). Do NOT write
  just the name in some reports and just the email in others; always give both, name first then the
  email in parentheses.**
- Dates are typed text by default; offer real Excel date cells / formula-driven due dates if the user
  wants to sort/compute across many findings.
- **Two-file split**: the finding workbook (shared with remediation) contains only the report tabs; the
  blank reusable template is produced on demand by `scripts/build_report.py` (the placeholder workbook it writes to `Output/`); it is not shipped as a separate file.
- **Status-update report for a partially-remediated finding (learned 2026-07-08).** When some of an existing
  report's issues have since resolved and the user wants a fresh report: re-query each original issue's LIVE
  status, keep ALL originally-reported assets, mark the fixed ones **Resolved** with the reason (e.g. "no
  longer flagged in Wiz", "environment decommissioned") and give the still-open ones full remediation detail
  (highlight them). Keep the original Date Reported / SLA target (the clock started on the first report date).
  **Re-verify the open assets' CVEs from current evidence — do not carry the old CVE list forward** (it may
  have over-reported; see the endpoint-scoped rule note). **Do NOT alter the original ServiceNow description**
  — editing it down to only the open assets makes the incident look like it was raised for those few only,
  erasing the original scope; the ticket-creator script can't edit an existing incident anyway. Deliver
  progress as a ServiceNow **work note** (Status Update — date; Resolved list + reasons; Still-Open list +
  remaining P0/P1/P2 + owner; SLA reminder + "do not close") and re-upload the refreshed report. No new ticket
  / no new Wiz association when the incident is already linked and the open issues are already In Progress.
- **Closing a Critical toxic-combination finding that resolved via revision rotation (learned 2026-07-10).**
  On constantly-redeploying workloads (e.g. Cloud Run) a Critical graph-control Issue typically closes as
  `resolutionReason: OBJECT_DELETED` (the flagged revision was replaced) and then RE-OPENS on the new
  revisions as a FAMILY of separate lower-severity component-rule Issues (public exposure / high privileges /
  initial access affecting a common dependency / data access to sensitive data), often under NEW incidents.
  When ALL of a Critical incident's Issues are Resolved and no Critical re-triggers on the current revisions,
  it is reasonable to CLOSE the Critical incident — but as **superseded** (closure driven by redeploy + any
  verified fix; residual continues under the HIGH follow-up incidents), NOT "fully remediated," and don't
  keep a Critical incident open to carry HIGH residual work. Deliver a **closure note that ALSO advises** on
  the remaining items + exceptions (clipboard) so the follow-up isn't dropped. Verify with the `sourceRule`
  filter + severity CRITICAL (all statuses) — confirm zero OPEN Critical for that rule on the services.
- **Reporting on an existing incident → MINE its ServiceNow comment/work-note thread FIRST (learned 2026-07-08).**
  When the finding already has an incident, read the ticket's thread before finalizing — it often carries a
  month of remediation progress and, critically, **vendor impact assessments** that reshape the report. Example:
  the vendor formally assessed several of the flagged CVEs as **Not Affected** (the appliance does not implement
  the vulnerable components). Fold these in: add a per-CVE **Status column** to CVE Details, mark them "Not
  Affected — <vendor>" (GREEN), and note "log a Wiz Not-Affected policy exception." **Only mark the CVEs the
  vendor EXPLICITLY named** — do NOT extend the vendor's reasoning to un-named CVEs. Surface prior progress
  (exposure work, open vendor cases, related risk exceptions) in a **Remediation Progress** section.
- **A progress work note must state the finding is STILL ACTIVE and frame the remaining work as the TEAM'S open
  action items (user correction, 2026-07-08).** Do not let a "re-assessment complete / N CVEs Not Affected"
  opener read as if the finding is wrapping up. Open with an explicit "this finding is still active — the Wiz
  issues remain <severity> and In Progress," and phrase each remaining item as still-open work for the
  remediation team to action (e.g. "the remaining N CVEs are still open and need to be remediated by …"), not a
  passive status recap. Keep the "do not close; SecOps validates via a fresh Wiz scan" reminder.
- **Soft INTERNAL confirm-and-close report (learned 2026-07-09).** When the user wants to check a finding with the
  **technical owner** to confirm whether it's real or an existing tool/script and "close it silently" — no
  remediation team, no SNOW — build a soft internal verification report, NOT the standard remediation package.
  Subtle/collaborative language (no "remediate now"; no SLA-hammer amber Target Date); reframe the tabs
  ("Detections by Host", "Files to Confirm" = owner-eyeball list of items in personal/Desktop/Downloads/cache
  locations, "Detection Samples", "Details" = audit record). Keep the honest Wiz severity badge but frame the
  Assessment as "consistent with authorized tooling — pending owner confirmation". SKIP every SNOW step (no
  `snow_ticket_pending.json`, no ServiceNow prompt, no `associateServiceTicket` / move-to-In-Progress). Deliver any
  covering note via the clipboard, never a `.eml`/file. Ask up front: recipient/owner, artifact (workbook / short
  note / both), and the closing ask (confirm → suppress & close vs. document accepted risk).

## Styling (openpyxl) — validated quality bar

**Never copy column widths or row heights from a previous report.** Layout is always subjective to the
current finding's data volume. Rebuild each report from scratch and size columns to content.

### Colour palette (exact hex — do not deviate)
| Role | Hex | Used for |
|------|-----|----------|
| NAVY | `1F3864` | Title rows, table column-header rows |
| BLUE | `2E5496` | Section headers (Identification, Environment…); **Low** severity badge |
| LIGHT_BLUE | `D9E1F2` | Label cells, subtitle row background |
| RED | `C00000` | **Critical** severity badge, P0 priority |
| ORANGE | `ED7D31` | **High** severity badge, In Progress status badge, P1 priority |
| AMBER_BADGE | `FFC000` | **Medium** severity badge, Exposure Mitigated status badge, P2 priority |
| AMBER_FILL | `FFF2CC` | Target Remediation Date cell background |
| GOLD | `7F6000` | Target Remediation Date text colour |
| GREEN | `70AD47` | Resolved status badge **only** — never a Low severity badge (green reads as "Resolved") |
| GREY | `F2F2F2` | Zebra alternate rows |
| WHITE | `FFFFFF` | All badge/header text |
| DARK_GREY | `595959` | Body text, subtitle text |

### Per-element rules
- **Title row:** NAVY fill, 15pt bold white, height ~30, left-aligned with indent 1. Worksheet tab name: **Title Case** (e.g. "Finding Summary", "Attack Path") — never ALL CAPS.
- **Subtitle row:** LIGHT_BLUE fill, 10pt italic dark grey, height ~18. Contains finding name + date (+ INC# ONLY if the finding already has one at build time — e.g. an existing/linked ticket or a status-update report; a brand-new INC from snow_ticket_creator is generated at submit AFTER the report is attached, so never re-patch the report to add it).
  Do NOT use it to describe how the report was made — content only.
- **Section headers (Finding Summary):** BLUE fill, 10pt bold white, merged across all columns.
- **Table column headers:** NAVY fill, 10pt bold white, centered.
- **Label cells (Finding Summary):** LIGHT_BLUE fill, 10pt bold navy, wrap left.
- **Value cells (Finding Summary):** No fill (transparent), 10pt dark grey, wrap left.
- **Severity badge:** 11pt bold white, fill by severity — **Critical → RED (`C00000`), High → ORANGE
  (`ED7D31`), Medium → AMBER_BADGE (`FFC000`), Low → BLUE (`2E5496`)**. This mapping applies to EVERY
  severity badge — the main Finding Summary badge, per-CVE severity cells in any inline table, and the
  CVE Details tab — so a High finding never renders in the same amber as a P2/Medium (this bit us on the
  one report 2026-07-03: High was mistakenly amber). **Low severity is BLUE, NOT green
  (corrected 2026-07-10, user): green (`70AD47`) is the Resolved-status colour, so a green Low badge reads
  as "already resolved." Reserve green for the Resolved status badge only.**
- **Target Date cell:** AMBER_FILL background, 10pt bold GOLD text.
- **Status badges (server/asset tables):** Coloured fill + white bold text (see palette above).
- **Priority badges:** Coloured fill + white bold 10pt. Label format **must be**:
  `P0 - Immediate` / `P1 - High` / `P2 - Medium` — never just `P0`, `P1`, `P2`.
- **Status column in Remediation Plan:** Plain text `Open` (no fill) for standard open items.
  Use amber badge `Exposure Mitigated — Patch Pending` only for partial-remediation states.
- **Zebra rows:** Alternate GREY (`F2F2F2`) and transparent. Never use white fill — leave transparent.
- **All data cells:** thin border four sides, wrap text enabled.
- **FULL 'All Borders' on every sheet.** Every cell in each sheet's used range must have **thin BLACK**
  borders on all four sides (a faint grey like `BFBFBF` reads as "no borders" — corrected
  2026-07-09) — **including cells inside merged ranges** (title, subtitle, section headers, summary
  rows). Apply as a final pass before save: **leave the merges INTACT and set a thin 4-side border on
  every cell in the used range** — `for row in ws.iter_rows(...): for c in row: c.border = B4`. **On
  openpyxl 3.1.5 the `.border` setter DOES apply to `MergedCell` objects, so merge-first / border-second
  is the correct method (verified 2026-07-10).** Do **NOT** unmerge → border → re-merge (the method
  previously documented here): re-merging AFTER bordering resets the non-top-left cells (B1/C1/… of every
  merged range) and drops their borders, leaving merged title/subtitle/section-header rows missing their
  right + interior edges. **CRITICAL — the border colour MUST be the 8-hex ARGB `FF000000`, NOT the 6-hex
  `000000` (learned 2026-07-14).** `Side(style="thin", color="000000")` makes openpyxl serialise the colour
  as `00000000` — alpha `00` = **fully transparent**, an INVISIBLE border that looks identical to "no
  borders" in Excel even though all four sides are set. Always pass `color="FF000000"`. **Verify via raw
  `xl/styles.xml`** (map each cell's `s` → `xf` → `borderId`, confirm all four thin sides AND that every
  `<color rgb>` in that border is `FF000000` — a `00000000` colour must FAIL), **NOT via `load_workbook`
  cell.border reads** — openpyxl cannot read a merged cell's border on reload and will falsely report cells
  "missing".
- Freeze the header row on the Details tab (`A2` or `A3` depending on whether there's a title row).

## Workflow
1. **Establish configuration, then check auth.** First ensure `skill_config.json` exists (see
   "First-run configuration" above); if it is missing, set it up with the user. Then run
   `python scripts/wiz_fetch.py status`.
   - If `loggedIn: true` and `expired: false` → tell the user the existing session is active and ask
     if they want to continue with it or re-authenticate.
   - Otherwise, present the three options and wait for the user to choose before proceeding:

     > **How would you like to authenticate with Wiz?**
     >
     > **A – Browser SSO (recommended)** — opens your installed Edge/Chrome, you sign in via your organization's IdP (Okta / Entra ID / Ping),
     > session is cached locally. No admin rights or service account needed.
     > Run: `python scripts/wiz_fetch.py login`
     >
     > **B – API token** — set `WIZ_API_TOKEN` and `WIZ_API_URL` as environment variables, then
     > re-invoke the skill. Suitable if you have a personal API token from Wiz Settings.
     >
     > **C – Service account** — set `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, and `WIZ_API_URL`.
     > Requires a Wiz service account (Settings → Access Management → Service Accounts;
     > scopes: `read:issues`, `read:resources`, `read:vulnerabilities`).

   Once auth is confirmed, proceed to step 2.

2. **Get the finding.** Use `scripts/wiz_fetch.py list` or `get` (see "Getting the finding" above).
   If the user has handed over an export `.xlsx` or screenshot instead, use those as manual inputs.
   For a filtered search, show the matches and ask the user which one to report on before building.
   Dump key→value to see what fields are populated.
   **For standalone `vulnerabilityFindings` (no Wiz Issue):** Check `relatedIssueAnalytics { issueCount }`
   on each finding early. If `issueCount: 0` for all findings, proactively tell the user:
   *"These are standalone vulnerability findings with no linked Wiz Issues — the ServiceNow ticket cannot
   be associated back in Wiz. You'll need to track the INC number externally."* Also flag to consider
   raising with the Wiz team.
3. **Determine Date Reported.** Inspect the `serviceTickets` field in the `get` response:
   - **Ticket present** (e.g. `INC#`) → say: *"This finding is linked to [INC...]. What date was
     this first reported to the remediation team?"* and wait for the user's answer.
   - **No ticket** → silently use today's date as Date Reported. No need to ask.
4. **Confirm scope** with the user (which tabs, confirmed vs. AI-derived facts) via a brief question.
5. **Build with openpyxl from scratch.** Always save to a subfolder named `Output` inside the current
   working directory (`os.makedirs("Output", exist_ok=True)`). Size all columns and rows to the current
   finding's content — never carry widths or heights over from a previous report.
   **Build script placement:** Write one-off report build scripts to `_build/` (not the working directory
   root): `os.makedirs("_build", exist_ok=True)`, save as `_build/build_<finding-slug>.py`. The permanent
   base scaffold lives in the skill at `scripts/build_report.py` — copy its helpers, never edit it for a
   specific finding. After a successful build, inform the user they
   can delete `_build/` at any time — it contains no outputs, only the session scripts.
   **Always set file author metadata** immediately after creating the workbook:
   ```python
   wb.properties.creator = "<report author from skill_config.json (analyst.report_author)>"
   wb.properties.lastModifiedBy = "<report author from skill_config.json (analyst.report_author)>"
   ```
6. If save fails with `PermissionError`, the file is open in Excel — ask the user to close it, or write
   to a copy (still inside `Output/`).
7. Show the user the rebuilt content, the full output path, and any observations for the standard.
   **Also write `Output/snow_ticket_pending.json`** with the ticket data so `snow_ticket_creator.py`
   picks it up automatically. Fields: `severity`, `short_description`, `caller_email`, `caller_display`,
   `assignment_group`, `assigned_to_email` (Technical Owner email if known), `assigned_to_display`,
   `category`, `offering`, `type_of_assistance`, `description` (VM description template). **Always set
   `offering: "Vulnerability Management"` explicitly — never leave it blank** (a blank offering makes the
   type-ahead click the first suggestion, which has wrongly selected "Domain Management"). **Always set
   `type_of_assistance: "Service Request"`** (the choice dropdown just beneath Offering).
   Title format: `SecOps Vuln | <N> Assets Impacted | <Severity> | <Finding Title> - Wiz`
   For **standalone CVE findings that can't be linked in Wiz**, put the CVE in `<Finding Title>` alongside
   the descriptive name (e.g. `Outdated litellm Python Library - CVE-2026-59821`) so the ticket is traceable
   without a Wiz link — match the tracker's Title; not the bare CVE alone (user pref 2026-07-10).
8. **Close with a ServiceNow ticket prompt.** After delivering the report, always ask:
   > "Would you like to associate a ServiceNow ticket with these Wiz issues? If so, please share the
   > Ticket Number and URL."
   When the user provides them, follow step 9 before applying.
9. **Associate ServiceNow ticket — check first, then apply.**
   Before associating a ticket with any Wiz issue, run `scripts/wiz_fetch.py get --id <id>` on every issue and
   inspect the `serviceTickets` field. Present a summary:
   - Issues that already have a ticket linked → show which ticket ID is attached and **ask the user to
     confirm** before overwriting or adding another.
   - Issues with no ticket → proceed to associate without asking.
   Only call the `associateServiceTicket` mutation on issues the user has explicitly cleared.
   Mutation input: `issueId`, `ticketId` (e.g. `INC#`), `ticketUrl`.
10. **Move associated issues to In Progress.** Immediately after a ticket is associated, set each linked
   issue's Wiz status to `IN_PROGRESS` via the `updateIssue` mutation (≤8 aliases/batch), then re-query to
   confirm. A ticketed finding that is being worked should not remain `OPEN`. This matches the Finding
   Summary status (`In Progress`) in the deliverable. Verify with `get` (or trust the mutation's returned
   `issue { status }` if the session dies right after — cookie sessions on this tenant are short-lived).

## ServiceNow auto-fill (snow_ticket_creator.py)
`scripts/snow_ticket_creator.py` automates incident creation in your ServiceNow instance. Run via
`python scripts/snow_ticket_creator.py` from the skill root (no separate CMD window needed).
Reads ticket data from `Output/snow_ticket_pending.json` (written by step 7 above). Uses Playwright with
a persistent Edge profile at `~/.snow/browser-profile`; auto-detects your IdP/SSO login; detects form submission
by URL change; prints the INC number automatically when the ticket is saved.

**It only CREATES new incidents — it cannot EDIT an existing one.** If a ticket's scope changes (e.g. more
assets folded into an existing INC), you cannot update its Title/Description/attachment via the script.
Regenerate the pending JSON for the new asset count, hand the user the exact updated Title + Description
(offer to place it on their clipboard via `clip`), and let them edit + re-upload the report on the existing
INC. Do the Wiz-side association independently.

**INC capture is persisted — the browser closes fast, so never rely on stdout alone.** On submit the
script writes `Output/snow_ticket_result.json` (`{inc, url, short_description, capturedAt, submitted}`)
the moment the INC is detected, and writes a stub even on timeout. After the run, ALWAYS read that file
to recover the INC (do not assume it was lost). If `submitted:false`, the user may still have submitted
after the 10-min window — ask them for the INC + URL, then proceed to associate. Once you have the INC,
associate it to the issues (workflow step 9) and move them to In Progress (step 10).

**Field mapping (validated against a ServiceNow instance):**
- `short_description` → g_form.setValue
- `caller_id` (Contact) → sys_id lookup by `caller_email` via in-page fetch(), then g_form.setValue(field,
  sys_id, display). **The Contact DISPLAY must be the caller's real ServiceNow name resolved from the email
  lookup — not any Excel-author-style label.** `snow_ticket_creator.py` now uses the looked-up name for the
  display automatically (lookup returns `(sid, name)`), so the Contact is never mislabelled.
- `assigned_to` → Technical Owner **email** (not a group); looked up same way. Ask user if unclear.
- `assignment_group` → **derived from the assignee's own group membership, NOT a forced default** (see
  Assignment Group rule below). sys_id looked up in `sys_user_group`; membership from `sys_user_grmember`.
- `category` → g_form.setValue('category', 'security')
- `impact` / `urgency` → CRITICAL: Group/Interruption; HIGH: Individual/Interruption; MEDIUM/LOW: Individual/Service Request
- "No Matching Configuration Item" checkbox → confirmed field id: `ni.incident.u_no_service_offering`
- **Affected User** → field id `u_affected_user`. Auto-populates from the caller; the script clears it by
  default. If pending-JSON `affected_user_email` is set, the script instead looks it up by email and SETS
  `u_affected_user` to that person (used for the no-ITIL-access owner routing below).
- Offering field → confirmed display input id: `sys_display.incident.service_offering`. **Set the pending
  JSON `offering` to `"Vulnerability Management"` EXPLICITLY — a blank value makes the type-ahead select the
  first suggestion (wrongly "Domain Management" on INC#, user fixed by hand).**
- **`type_of_assistance` → choice dropdown just beneath Offering (added 2026-07-16). Default `"Service
  Request"`.** Handled by `set_choice_by_label(frame, "Type of Assistance", value)` which finds the
  `<select>` by its visible label, picks the option whose text matches, fires `change`, and mirrors to
  `g_form.setValue`. Include `type_of_assistance:"Service Request"` in the pending JSON.
- `description` → g_form.setValue (filled last to avoid autocomplete interference)
- Major Incident popup → auto-dismissed by polling every 300ms for 1.5s after impact and urgency changes

**Key rules:**
- Technical Owner email → `assigned_to` (Assigned To).
- **Assignment Group rule (corrected 2026-07-01):** the group MUST be one the Assigned-To owner actually
  belongs to — never a forced default. Setting a group the owner isn't a member of makes ServiceNow
  **clear the Assigned To** (this bit us — the user had to re-enter it). Logic the script now follows:
  look up the owner's groups via `sys_user_grmember` (`user=<sid>`, fields `group.sys_id,group.name`);
  if the owner is in **exactly one** group → set that group; if **several / none** → leave Assignment
  Group **blank for manual pick**; only when there is **NO owner** → default `<your default VM group>`.
  Set Assignment Group **before** Assigned To so the (member) owner is not cleared. This mirrors the
  analyst's manual step: enter the owner in Assigned To, click the Assignment Group search to see their
  groups, and if only one is shown, assign it. **When the owner is in SEVERAL groups, don't just leave it
  blank silently — pre-look-up the memberships and SURFACE the candidate groups for the user to confirm
  which one to use (user pref 2026-07-16); the user is happy to pick, but wants to be asked.**
- **Owner lacks ITIL access (validated 2026-07-07):** when the Technical Owner is known but cannot be set as
  Assigned To (no ITIL access), route as: **Assigned To blank** (`assigned_to_email: ""`), **Affected User =
  the owner's email** (pending-JSON `affected_user_email` → `u_affected_user`), and **Assignment Group =
  `<your no-ITIL routing group>`** (set it directly in the pending JSON; with Assigned To blank the
  membership-derivation is skipped and this value is used as-is). This is distinct from the owner-unknown case
  (→ `<your default VM group>`, Affected User cleared).
- `assigned_to_display` in the pending JSON is a hint only — the email→sys_id lookup is authoritative.
- in-page `fetch()` (via `page.evaluate`) carries session cookies — use this, not `context.request` (401s).
- `locator.click(click_count=3)` to select-all, not `locator.triple_click()` (unavailable in this Playwright version).
- Submission detection: poll for URL changing from `sys_id=-1` to a real sys_id; extract INC number via g_form.

## Gotchas

Wiz GraphQL schema quirks, filter typing, mutation payload shapes and pagination traps live in
**`references/graphql-notes.md`** — **read it before writing or debugging any Wiz query.** It
covers the `gql()`/`resolve_auth()` import signature, cookie-session lifetime, `[String!]`
variable coercion on `assetExternalId`/`vulnerabilityExternalId`, `sourceRule`/`riskEqualsAny`
filters, the ≤8-alias batch limit, mutations that commit while returning a validation error,
`associateServiceTicket`/`disassociateServiceTicket`/`updateIssue` shapes, fields absent from
`VulnerabilityFinding`, owner-tag lookup, ephemeral-fleet synthetic asset ids, and the
openpyxl/Excel failure modes. Add to it whenever you confirm something new.

Two that are load-bearing enough to keep here:
- **Never print the cred/secret.** `login` caches the session cookie or token to
  `~/.wiz/token.json` (0600); `status`/`login` print only endpoint, `authMode` and expiry.
- **Resolved/archived issues return NOT_FOUND** — `issue(id: ...)` returning "Resource not found"
  is confirmation the issue is closed, not a lookup failure. Do not surface it as an error.

## Asset → Owner registry (optional but recommended)

Ownership is frequently **not** reliable in the Wiz API — resource tags are often incomplete, and
Wiz "projects" may be internal scanning scopes rather than the owning team. Maintain a local
**`Asset_Owner_Registry.md`** (start from `templates/Asset_Owner_Registry.example.md`) mapping each asset or
product to its confirmed technical owner, owner email, and assignment group, with the source and a
last-confirmed date. **Check it before** building a report or raising a ticket (surface the recorded
owner for the user to confirm), and **update it after** every report. Populate rows only from an
authoritative source (resource tags, a prior incident, or the user's confirmation) — never guess an
owner. Keep this file local to your environment; it is your data, not part of the shared skill.

## Self-learning — how this skill stays current
Nothing here happens automatically: learning means **you write the lesson into these files** at the end of
a session, so the next run starts from it. Do it explicitly, and tell the user what you recorded.

After each report session, review the conversation and file each lesson where it belongs:

| What you learned | Where it goes |
|---|---|
| A correction from the user ("don't do X", "change this to Y") | Hard rules or Styling, in this file |
| An approach the user confirmed worked well | the relevant section here, so it isn't dropped next time |
| A new GraphQL field, filter, schema quirk or pagination trap | `references/graphql-notes.md` |
| A new rule family / finding type, or a new instance of a known one | `references/rule-catalog.md` |
| A confirmed asset → owner mapping | `Asset_Owner_Registry.md` (local, git-ignored) |
| An organization-specific VALUE — team name, sign-off, SLA days, assignment group, author string | `skill_config.json`, **never** hard-coded into this file |

**That last row is the important distinction.** A *rule* ("always show the target date") belongs in this
file and is shared by everyone who installs the skill. A *value* ("our team signs off as the Cloud Security
Office", "our HIGH SLA is 45 days") belongs in `skill_config.json`, which is per-installation and
git-ignored. If a user corrects a value, update the config and confirm it — do not edit this file to suit
one organization.

When a user pushes back on wording or a convention, treat it as durable: apply it, record it in the right
place per the table, and say which file you changed so they can review it.

Keep this file lean — it loads on every invocation. Situational detail belongs in `references/`;
what stays here is the workflow, the hard rules and the styling bar. Update the memory entry
`wiz-finding-report-standard.md` alongside so they stay in sync, and record the dated audit trail
in `CHANGELOG.md` (what changed and why).

---

## Changelog

Moved to **`CHANGELOG.md`** to keep this file lean. See it for the dated audit trail of
learned patterns, Wiz control instances, and schema quirks.
