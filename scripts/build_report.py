#!/usr/bin/env python3
"""
Reference implementation — SecOps Wiz Finding Report
Demonstrates the standard 5-tab workbook structure and shared styling helpers.

For a real finding, the skill writes a one-off version of this script to _build/
with finding-specific data populated from the Wiz API.

Replace every value marked [EXAMPLE] with real data before running.

    python scripts/build_report.py          # placeholder workbook → Output/
    python scripts/build_report.py --demo   # synthetic sample → assets/sample_report.xlsx

Each value below is written as V(placeholder, demo) so the two datasets sit side by
side. The --demo dataset is entirely fictional (acme-*) and is what ships as this
repository's sample, so the published demo can never contain real finding data.
"""

import os
import sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

DEMO = "--demo" in sys.argv

def V(placeholder, demo):
    """Pick the synthetic demo value under --demo, else the [EXAMPLE] placeholder."""
    return demo if DEMO else placeholder

# ── Colour palette (do not deviate) ──────────────────────────────────────────
NAVY        = "1F3864"; BLUE       = "2E5496"; LIGHT_BLUE  = "D9E1F2"
RED         = "C00000"; ORANGE     = "ED7D31"; AMBER_BADGE = "FFC000"
AMBER_FILL  = "FFF2CC"; GOLD       = "7F6000"; GREEN       = "70AD47"
GREY        = "F2F2F2"; WHITE      = "FFFFFF"; DARK_GREY   = "595959"

# Border colour MUST be 8-hex ARGB. A 6-hex "000000" serialises with alpha 00 =
# fully transparent, i.e. an invisible border that looks identical to no borders.
TH = Side(style="thin", color="FF000000")

SEV_FILL = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": AMBER_BADGE, "LOW": BLUE}

# ── Styling helpers ───────────────────────────────────────────────────────────
def F(h):   return PatternFill("solid", fgColor=h) if h else PatternFill(fill_type=None)
def Ft(h=DARK_GREY, sz=10, b=False, it=False):
    return Font(color=h, size=sz, bold=b, italic=it, name="Calibri")
def Bdr(): return Border(left=TH, right=TH, top=TH, bottom=TH)
def Al(h="left", v="center", w=True, ind=0):
    return Alignment(horizontal=h, vertical=v, wrap_text=w, indent=ind)

def sty(c, fill=None, fh=DARK_GREY, sz=10, b=False, it=False, ha="left", ind=0):
    if fill: c.fill = F(fill)
    c.font = Ft(fh, sz, b, it); c.alignment = Al(ha, "center", True, ind); c.border = Bdr()

def sev_fill(label):
    """Severity badge colour. Low is BLUE, never GREEN — green is the Resolved
    status colour, so a green Low badge reads as 'already resolved'."""
    u = (label or "").upper()
    return next((v for k, v in SEV_FILL.items() if k in u), RED)

def all_borders(ws):
    """Final pass — thin black border on EVERY cell of the used range, merges left
    intact. The helpers above only style a merged range's top-left cell, so without
    this pass merged title / subtitle / section-header rows lose their right and
    interior edges. Do NOT unmerge → border → re-merge: re-merging afterwards resets
    the non-top-left cells and drops the borders again."""
    for row in ws.iter_rows(min_row=1, max_row=ws.max_row,
                            min_col=1, max_col=ws.max_column):
        for c in row:
            c.border = Bdr()

def title(ws, row, text, n, h=30):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=n)
    c = ws.cell(row, 1, text); sty(c, NAVY, WHITE, 15, True, ha="left", ind=1)
    ws.row_dimensions[row].height = h

def subtitle(ws, row, text, n, h=18):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=n)
    c = ws.cell(row, 1, text); sty(c, LIGHT_BLUE, DARK_GREY, 10, False, True, ha="left", ind=1)
    ws.row_dimensions[row].height = h

def sec(ws, row, text, n, h=18):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=n)
    c = ws.cell(row, 1, text); sty(c, BLUE, WHITE, 10, True, ha="left", ind=1)
    ws.row_dimensions[row].height = h

def lv(ws, row, lbl, val, lc=1, vc=2, vs=1, h=None, vfill=None, vfh=DARK_GREY, vb=False):
    c = ws.cell(row, lc, lbl); sty(c, LIGHT_BLUE, NAVY, 10, True, ind=1)
    if vs > 1: ws.merge_cells(start_row=row, start_column=vc, end_row=row, end_column=vc+vs-1)
    c2 = ws.cell(row, vc, val); sty(c2, vfill, vfh, 10, vb, ind=1)
    if h: ws.row_dimensions[row].height = h

def th(ws, row, cols, h=20):
    for ci, t in enumerate(cols, 1):
        c = ws.cell(row, ci, t); sty(c, NAVY, WHITE, 10, True, ha="center")
    ws.row_dimensions[row].height = h

def td(ws, row, col, val, rf=None, fh=DARK_GREY, b=False, ha="left"):
    c = ws.cell(row, col, val); sty(c, rf, fh, 10, b, ha=ha); return c

def pri(ws, row, col, p):
    m = {"P0 - Immediate": RED, "P1 - High": ORANGE, "P2 - Medium": AMBER_BADGE}
    c = ws.cell(row, col, p); sty(c, m.get(p, GREY), WHITE, 10, True, ha="center")

def cw(ws, widths):
    for i, w in enumerate(widths, 1): ws.column_dimensions[get_column_letter(i)].width = w


# ── Finding data (replace with real values) ───────────────────────────────────
AUTHOR   = V("[EXAMPLE: Surname, Firstname]", "Wiz Finding Report Skill")
FINDING  = V("[EXAMPLE: Finding title]",
             "Internet-facing Serverless: Initial Access Vulnerabilities & Sensitive Data Access")
DR       = V("[EXAMPLE: 2026-06-24]", "20XX-05-04")   # Date Reported
DT       = V("[EXAMPLE: 2026-07-09]", "20XX-05-19")   # Target Remediation Date (DR + SLA)
RULE     = V("[EXAMPLE: Wiz source rule name]",
             "Internet-facing VM/serverless with initial access vulnerabilities "
             "and data access to sensitive data")
SEVERITY = V("[EXAMPLE: CRITICAL]", "CRITICAL")
SLA      = V("[EXAMPLE: 15 days (Critical)]", "15 days (Critical)")
# Status is Open until the incident is actually raised — never pre-set In Progress.
STATUS   = "Open"
WIZ_ISSUE_ID = V("[EXAMPLE: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]",
                 "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
WIZ_URL      = V("[EXAMPLE: https://app.wiz.io/issues#~(issue~'<uuid>)]",
                 "https://app.wiz.io/issues#~(issue~'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)")
VALIDATION = V("[EXAMPLE: CVE-YYYY-NNNNN confirmed present on affected resource; "
               "CISA KEV listed with active exploitation]",
               "CVE-20XX-11111 (npm:example-lib path traversal, CVSS 7.7, active exploit) "
               "confirmed on acme-backend-api and acme-innovation-engine revisions; "
               "CVE-20XX-22222 (runtime permission-model bypass, CVSS 9.1) confirmed on "
               "acme-ai-service.")
CLOUD    = V("[EXAMPLE: GCP / Azure / AWS]", "GCP")
REGION   = V("[EXAMPLE: us-central1]", "us-central1")
PROJECTS = V("[EXAMPLE: project-id]",
             "gcp-acme-prod-webapp-a1b2  |  gcp-acme-dev-ai-g7h8  |  gcp-acme-dev-engine-i9j0")
SERVICES = V("[EXAMPLE: service-name (N revisions)]",
             "acme-backend-api (Production)  |  acme-ai-service, acme-innovation-engine "
             "(Development)")
RES_TYPE = V("[EXAMPLE: Cloud Run Revision]", "Cloud Run Revision (Serverless / GCP)")
SENSITIVE = V("[EXAMPLE: PII/Email  |  Financial/Credit Cards]",
              "PII/Email (Confidential)  |  Financial/Credit Cards (Restricted)")

SUMMARY = V("[EXAMPLE: Plain-language description of the finding, what is exposed, "
            "and the risk to the business.]",
            "Three internet-facing serverless services are running code with known "
            "exploitable vulnerabilities, and each runs as a service account that can read "
            "storage holding customer PII and payment data. An attacker needs no credentials "
            "and no internal access: the endpoints are reachable from the public internet, "
            "working exploits for the vulnerable libraries are published, and a successful "
            "exploit inherits the service account's data access directly. The combination — "
            "public reachability, an exploitable entry point, and a privileged identity with "
            "a path to sensitive data — is what makes this Critical rather than three "
            "separate medium issues.")

WHY_HEADER = V("WHY THIS IS <SEVERITY>", "WHY THIS IS CRITICAL")
WHY = V([
    "• [EXAMPLE: Public exploit available — no advanced skill required for exploitation.]",
    "• [EXAMPLE: Endpoint is publicly reachable with no network-level access control.]",
    "• [EXAMPLE: Service account holds high-privilege IAM roles enabling lateral movement post-compromise.]",
    "• [EXAMPLE: Sensitive data directly accessible to a compromised identity.]",
], [
    "• Working public exploits exist for both CVEs — no specialist skill or internal access needed.",
    "• All three endpoints answer from the public internet with no network-level restriction.",
    "• The runtime service accounts hold broad storage and project roles, enabling lateral movement after a single compromise.",
    "• Customer PII and payment records are directly readable by the identities those services run as.",
    "• Each leg alone is manageable; chained together they form a complete path from the internet to regulated data.",
])

# res = resource (revision) · svc = service · prj = project · ep = endpoint · sa = identity
ASSETS = V([
    dict(res="[EXAMPLE: cloud-run-revision-name]", svc="[EXAMPLE: service-name]",
         prj="[EXAMPLE: cloud-project-id]", env="[EXAMPLE: Production]",
         cve="[EXAMPLE: CVE-YYYY-NNNNN]", ep="[EXAMPLE: https://service-name.a.run.app:443]",
         sa="[EXAMPLE: sa-name@project.iam.gserviceaccount.com]", data="[EXAMPLE: PII/Email]",
         pri="P0 - Immediate"),
    # Add additional assets here
], [
    dict(res="acme-backend-api-00042-xkq", svc="acme-backend-api",
         prj="gcp-acme-prod-webapp-a1b2", env="Production", cve="CVE-20XX-11111",
         ep="https://acme-backend-api-xxxxxxxxxx-uc.a.run.app:443",
         sa="sa-runtime@gcp-acme-prod-webapp-a1b2.iam.gserviceaccount.com",
         data="PII/Email  |  Financial/Credit Cards", pri="P0 - Immediate"),
    dict(res="acme-ai-service-00017-b4t", svc="acme-ai-service",
         prj="gcp-acme-dev-ai-g7h8", env="Development", cve="CVE-20XX-22222",
         ep="https://acme-ai-service-yyyyyyyyyy-uc.a.run.app:443",
         sa="sa-runtime@gcp-acme-dev-ai-g7h8.iam.gserviceaccount.com",
         data="PII/Email", pri="P1 - High"),
    dict(res="acme-innovation-engine-00009-m2p", svc="acme-innovation-engine",
         prj="gcp-acme-dev-engine-i9j0", env="Development", cve="CVE-20XX-11111",
         ep="https://acme-innovation-engine-zzzzzzzzzz-uc.a.run.app:443",
         sa="sa-runtime@gcp-acme-dev-engine-i9j0.iam.gserviceaccount.com",
         data="None classified", pri="P1 - High"),
])

ATTACK_SUBTITLE = V("[EXAMPLE: Attack path subtitle — what the chain looks like end-to-end]",
                    "From an unauthenticated internet request to customer PII in four steps")
STEPS = V([
    (1, "Reconnaissance",
     "[EXAMPLE: Attacker discovers the exposed endpoint via internet scanning.]",
     "[EXAMPLE: Restrict ingress — remove public access.]"),
    (2, "Initial Access — Exploit CVE",
     "[EXAMPLE: Attacker exploits CVE-YYYY-NNNNN. Public exploit available.]",
     "[EXAMPLE: Patch the vulnerable dependency / upgrade the runtime.]"),
    (3, "Credential Harvest",
     "[EXAMPLE: Executing code queries the metadata server to obtain a short-lived SA token.]",
     "[EXAMPLE: Assign least-privilege service accounts; remove high-risk IAM roles.]"),
    (4, "Data Access / Exfiltration",
     "[EXAMPLE: Over-privileged SA reads sensitive storage buckets and exfiltrates data.]",
     "[EXAMPLE: Bucket-level IAM, DLP scanning, egress controls, VPC Service Controls.]"),
], [
    (1, "Reconnaissance",
     "The service URLs are discoverable by internet-wide scanning; responses identify the "
     "runtime and library versions in use.",
     "Restrict ingress to internal or load-balancer-only, and require authentication on the "
     "endpoint."),
    (2, "Initial Access — Exploit CVE",
     "A crafted request exploits the vulnerable library (CVE-20XX-11111 path traversal, "
     "CVE-20XX-22222 permission-model bypass) to execute attacker-controlled code in the "
     "container. Public proof-of-concept code exists for both.",
     "Upgrade the affected libraries to a fixed release and redeploy on a patched base image."),
    (3, "Credential Harvest",
     "The executing code queries the instance metadata service and receives a short-lived "
     "access token for the service account the workload runs as.",
     "Run each service as a dedicated least-privilege service account; remove broad project "
     "roles so a stolen token is of limited value."),
    (4, "Data Access / Exfiltration",
     "Using that token the attacker lists and reads storage buckets containing customer PII "
     "and payment records, then copies them out over an ordinary HTTPS egress path.",
     "Bucket-level IAM instead of project-wide grants, DLP scanning, egress restrictions "
     "(VPC Service Controls), and alerting on unusual read volume."),
])

REMEDIATION = V([
    (1, "[EXAMPLE: CVE-YYYY-NNNNN — brief description, CVSS score (PRODUCTION)]",
     "[EXAMPLE: resource-name\nproject-id]",
     "[EXAMPLE: Upgrade package X from version A to B. Rebuild and redeploy. Confirm via Wiz re-scan.]",
     "P0 - Immediate", "[EXAMPLE: Team / Individual]", "Open"),
    (2, "[EXAMPLE: Internet-facing endpoint — publicly reachable, no IAM auth]",
     "[EXAMPLE: service-name]",
     "[EXAMPLE: Set ingress to internal-only. Remove allUsers. Require IAM auth.]",
     "P1 - High", "[EXAMPLE: Team / Individual]", "Open"),
    (3, "[EXAMPLE: Over-privileged service account — holds admin IAM roles]",
     "[EXAMPLE: sa-name@project.iam.gserviceaccount.com]",
     "[EXAMPLE: Remove roles/storage.admin, roles/iam.serviceAccountTokenCreator. Apply least-privilege custom role.]",
     "P2 - Medium", "[EXAMPLE: Team / Individual]", "Open"),
], [
    (1, "CVE-20XX-11111 — path traversal in the example-lib dependency, CVSS 7.7, "
        "active exploitation (PRODUCTION)",
     "acme-backend-api\ngcp-acme-prod-webapp-a1b2",
     "Upgrade the example-lib dependency to a fixed release, rebuild the container image and "
     "redeploy. Apply through your standard change-management process after an impact "
     "assessment. Confirm closure on the next Wiz scan.",
     "P0 - Immediate", "Firstname Lastname (owner@example.com)", "Open"),
    (2, "CVE-20XX-22222 — runtime permission-model bypass, CVSS 9.1 (DEVELOPMENT)",
     "acme-ai-service\ngcp-acme-dev-ai-g7h8",
     "Rebuild on a patched runtime base image and redeploy the affected revisions.",
     "P1 - High", "Firstname Lastname (owner@example.com)", "Open"),
    (3, "Internet-facing endpoints reachable without authentication",
     "acme-backend-api, acme-ai-service, acme-innovation-engine",
     "Where public reach is not a product requirement, set ingress to internal or "
     "load-balancer-only and require authentication. Where it is required, state that "
     "explicitly so the finding closes on the vulnerability leg instead.",
     "P1 - High", "Firstname Lastname (owner@example.com)", "Open"),
    (4, "Runtime service accounts hold broad storage and project roles",
     "sa-runtime@gcp-acme-prod-webapp-a1b2.iam.gserviceaccount.com",
     "Replace project-wide roles with least-privilege grants scoped to the specific buckets "
     "each service needs, and separate the production identity from the development ones.",
     "P2 - Medium", "Firstname Lastname (owner@example.com)", "Open"),
])


# ── Workbook ──────────────────────────────────────────────────────────────────
wb = Workbook()
wb.properties.creator = AUTHOR
wb.properties.lastModifiedBy = AUTHOR
wb.remove(wb.active)


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — FINDING SUMMARY
# ════════════════════════════════════════════════════════════════════════════
ws = wb.create_sheet("Finding Summary")
N = 7

title(ws, 1, "FINDING SUMMARY", N)
subtitle(ws, 2, f"{FINDING}  |  Reported: {DR}", N)

r = 3
sec(ws, r, "IDENTIFICATION", N); r += 1
lv(ws, r, "Wiz Issue ID",         WIZ_ISSUE_ID,                          1, 2, 6); r += 1
lv(ws, r, "Wiz URL",              WIZ_URL,                               1, 2, 6); r += 1
lv(ws, r, "Source Rule",          RULE,                                  1, 2, 6, h=32); r += 1

# Severity badge — fill follows the severity (Critical RED / High ORANGE /
# Medium AMBER / Low BLUE), never a fixed colour.
ws.row_dimensions[r].height = 22
c = ws.cell(r, 1, "Severity"); sty(c, LIGHT_BLUE, NAVY, 10, True, ind=1)
ws.merge_cells(start_row=r, start_column=2, end_row=r, end_column=7)
c2 = ws.cell(r, 2, SEVERITY); sty(c2, sev_fill(SEVERITY), WHITE, 11, True, ha="center")
r += 1

lv(ws, r, "Status",               STATUS,                                1, 2, 6); r += 1
lv(ws, r, "Date Reported",        DR,                                    1, 2, 6); r += 1
lv(ws, r, "Remediation SLA",      SLA,                                   1, 2, 6); r += 1

# Target date (amber)
ws.row_dimensions[r].height = 20
c = ws.cell(r, 1, "Target Remediation Date"); sty(c, LIGHT_BLUE, NAVY, 10, True, ind=1)
ws.merge_cells(start_row=r, start_column=2, end_row=r, end_column=7)
c2 = ws.cell(r, 2, DT); sty(c2, AMBER_FILL, GOLD, 10, True, ind=1)
r += 1

lv(ws, r, "Validation",           VALIDATION,                            1, 2, 6, h=42); r += 1

sec(ws, r, "ENVIRONMENT", N); r += 1
lv(ws, r, "Cloud Platform",       CLOUD,                                 1, 2, 6); r += 1
lv(ws, r, "Region",               REGION,                                1, 2, 6); r += 1
lv(ws, r, "Cloud Projects",       PROJECTS,                              1, 2, 6, h=28); r += 1

sec(ws, r, "AFFECTED WORKLOADS", N); r += 1
lv(ws, r, "Services",             SERVICES,                              1, 2, 6, h=28); r += 1
lv(ws, r, "Resource Type",        RES_TYPE,                              1, 2, 6); r += 1
lv(ws, r, "Sensitive Data",       SENSITIVE,                             1, 2, 6); r += 1

sec(ws, r, "VULNERABLE ENDPOINTS", N); r += 1
th(ws, r, ["#", "Service", "Cloud Project", "Endpoint", "Environment", "CVE", "Priority"]); r += 1
for i, a in enumerate(ASSETS, 1):
    rf = GREY if i % 2 == 0 else None
    td(ws, r, 1, i,         rf, ha="center")
    td(ws, r, 2, a["svc"],  rf)
    td(ws, r, 3, a["prj"],  rf)
    td(ws, r, 4, a["ep"],   rf)
    td(ws, r, 5, a["env"],  rf, ha="center")
    td(ws, r, 6, a["cve"],  rf)
    td(ws, r, 7, a["pri"],  rf)
    ws.row_dimensions[r].height = 30; r += 1

sec(ws, r, "PLAIN-LANGUAGE SUMMARY", N); r += 1
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=N)
c = ws.cell(r, 1, SUMMARY)
sty(c, None, DARK_GREY, 10, ha="left", ind=1); ws.row_dimensions[r].height = 76; r += 1

sec(ws, r, WHY_HEADER, N); r += 1
for b in WHY:
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=N)
    c = ws.cell(r, 1, b); sty(c, None, DARK_GREY, 10, ha="left", ind=1)
    ws.row_dimensions[r].height = 22; r += 1

sec(ws, r, "CONTACT", N); r += 1
ws.merge_cells(start_row=r, start_column=1, end_row=r+2, end_column=N)
c = ws.cell(r, 1, "For any clarification or support, please contact the SecOps team.\n\nRegards,\nSecOps Team")
sty(c, LIGHT_BLUE, DARK_GREY, 10, ha="left", ind=1)
ws.row_dimensions[r].height = 18; ws.row_dimensions[r+1].height = 18; ws.row_dimensions[r+2].height = 18

cw(ws, [28, 22, 28, 36, 14, 22, 16])


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — ATTACK PATH
# ════════════════════════════════════════════════════════════════════════════
ws2 = wb.create_sheet("Attack Path")
N2 = 4
title(ws2, 1, "ATTACK PATH", N2)
subtitle(ws2, 2, ATTACK_SUBTITLE, N2)

r2 = 3
th(ws2, r2, ["Step", "Stage", "What Happens", "Control That Should Stop It"]); r2 += 1

for s in STEPS:
    rf = GREY if s[0] % 2 == 0 else None
    td(ws2, r2, 1, s[0], rf, ha="center"); td(ws2, r2, 2, s[1], rf, b=True)
    td(ws2, r2, 3, s[2], rf);              td(ws2, r2, 4, s[3], rf)
    ws2.row_dimensions[r2].height = 76; r2 += 1

cw(ws2, [6, 24, 54, 46])


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — REMEDIATION PLAN
# ════════════════════════════════════════════════════════════════════════════
ws3 = wb.create_sheet("Remediation Plan")
N3 = 7
title(ws3, 1, "REMEDIATION PLAN", N3)
subtitle(ws3, 2, f"{FINDING}  |  Target: {DT}", N3)

r3 = 3
th(ws3, r3, ["#", "Issue / Finding", "Affected Resource(s)", "Recommended Action", "Priority", "Suggested Owner", "Status"]); r3 += 1

for row in REMEDIATION:
    rf = GREY if row[0] % 2 == 0 else None
    td(ws3, r3, 1, row[0], rf, ha="center")
    td(ws3, r3, 2, row[1], rf); td(ws3, r3, 3, row[2], rf)
    td(ws3, r3, 4, row[3], rf)
    pri(ws3, r3, 5, row[4])
    td(ws3, r3, 6, row[5], rf); td(ws3, r3, 7, row[6], rf)
    ws3.row_dimensions[r3].height = 76; r3 += 1

cw(ws3, [4, 32, 28, 44, 16, 26, 12])


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — AFFECTED ASSETS
# ════════════════════════════════════════════════════════════════════════════
ws4 = wb.create_sheet("Affected Assets")
N4 = 7
title(ws4, 1, "AFFECTED ASSETS", N4)
subtitle(ws4, 2, f"{FINDING}  |  {len(ASSETS)} asset(s)  |  {DR}", N4)

r4 = 3
th(ws4, r4, ["#", "Asset", "Type", "Endpoint / URL", "Cloud Project", "CVE", "Sensitive Data Exposed"]); r4 += 1

for i, a in enumerate(ASSETS, 1):
    rf = GREY if i % 2 == 0 else None
    td(ws4, r4, 1, i,           rf, ha="center")
    td(ws4, r4, 2, a["res"],    rf)
    td(ws4, r4, 3, RES_TYPE,    rf)
    td(ws4, r4, 4, a["ep"],     rf)
    td(ws4, r4, 5, a["prj"],    rf)
    td(ws4, r4, 6, a["cve"],    rf)
    td(ws4, r4, 7, a["data"],   rf)
    ws4.row_dimensions[r4].height = 28; r4 += 1

cw(ws4, [4, 36, 26, 46, 30, 20, 30])


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — DETAILS (Wiz source — audit trail)
# ════════════════════════════════════════════════════════════════════════════
ws5 = wb.create_sheet("Details")
N5 = 9
title(ws5, 1, "DETAILS", N5)
subtitle(ws5, 2, f"Wiz Source Record  |  {DR}", N5)

r5 = 3
det_hdrs = ["Wiz Issue ID", "Severity", "Status", "Created At", "Source Rule",
            "Resource Name", "Resource Type", "Cloud Project", "Wiz Issue URL"]
th(ws5, r5, det_hdrs)
ws5.freeze_panes = ws5["A4"]
r5 += 1

for i, a in enumerate(ASSETS, 1):
    rf = GREY if i % 2 == 0 else None
    for ci, val in enumerate([
        WIZ_ISSUE_ID, SEVERITY, STATUS, DR, RULE,
        a["res"], RES_TYPE, a["prj"], WIZ_URL
    ], 1):
        c = ws5.cell(r5, ci, val); sty(c, rf)
    ws5.row_dimensions[r5].height = 20; r5 += 1

cw(ws5, [38, 10, 12, 14, 56, 36, 26, 30, 60])


# ── Save ──────────────────────────────────────────────────────────────────────
# Final pass: full 'All Borders' on every sheet, merges intact. Must run after all
# content and merges are in place, immediately before save.
for sheet in wb.worksheets:
    all_borders(sheet)

if DEMO:
    # The shipped sample belongs to the repo, so resolve it relative to the skill
    # root (the parent of scripts/) rather than to wherever this was invoked from.
    skill_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir, out_name = os.path.join(skill_root, "assets"), "sample_report.xlsx"
else:
    # Real reports always go to Output/ in the CURRENT working directory.
    out_dir, out_name = "Output", "[EXAMPLE]_Finding_Report.xlsx"
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, out_name)
wb.save(out)
print("Saved:", os.path.abspath(out))
