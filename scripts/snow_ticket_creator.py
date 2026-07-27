"""
ServiceNow Incident Auto-Fill — SecOps Wiz Finding Reports
-----------------------------------------------------------
Data source:
  Reads ticket fields from  Output/snow_ticket_pending.json  (written by the
  report-building workflow).  Falls back to TICKET_DEFAULT if the file is missing.

Flow:
  1. Load ticket data from JSON (dynamic, per-report).
  2. Open isolated Edge, auto-detect your IdP/SSO login (no ENTER needed).
  3. Use in-page fetch() to resolve caller / group sys_ids via REST API.
  4. Navigate to new incident form.
  5. Scan all form fields → log exact IDs for checkbox & offering debugging.
  6. Inject fields instantly via g_form.setValue.
  7. Clear Affected User (auto-populated from Caller — must be blanked).
  8. Background watchdog auto-dismisses Major Incident popup.
  9. One ENTER after attaching file and submitting.

Log: Output/snow_ticket_log.txt
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeout


# ── Portable org config ───────────────────────────────────────────────────────
def _load_skill_config() -> dict:
    """Read skill_config.json from the skill root — the parent of scripts/, i.e. the
    directory holding SKILL.md (portable org settings).
    Missing/invalid file → {} so the script still runs on TICKET_DEFAULT/env vars."""
    cfg_path = Path(__file__).resolve().parent.parent / "skill_config.json"
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_CFG     = _load_skill_config()
_ANALYST = _CFG.get("analyst", {}) if isinstance(_CFG.get("analyst"), dict) else {}
_SNOW    = _CFG.get("servicenow", {}) if isinstance(_CFG.get("servicenow"), dict) else {}

# Force UTF-8 on Windows terminals so log symbols don't crash
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Paths & constants ─────────────────────────────────────────────────────────
# ServiceNow instance: env SNOW_INSTANCE_URL > skill_config.json (servicenow.instance_url) > placeholder.
INSTANCE         = (os.environ.get("SNOW_INSTANCE_URL")
                    or _SNOW.get("instance_url")
                    or "https://<your-org>.service-now.com")
NEW_INC_URL      = (
    f"{INSTANCE}/now/nav/ui/classic/params/target/"
    "incident.do%3Fsys_id%3D-1%26sysparm_query%3Dactive%3Dtrue"
    "%26sysparm_stack%3Dincident_list.do%3Fsysparm_query%3Dactive%3Dtrue"
)
PROFILE_DIR      = str(Path.home() / ".snow" / "browser-profile")
PENDING_JSON     = Path("Output") / "snow_ticket_pending.json"
RESULT_JSON      = Path("Output") / "snow_ticket_result.json"
LOG_PATH         = Path("Output") / "snow_ticket_log.txt"
DEFAULT_GROUP    = _SNOW.get("default_assignment_group") or "Vulnerability_Management"
LOGIN_TIMEOUT    = 300
LOGIN_POLL       = 3

SEVERITY_MAP = {
    "CRITICAL": {"impact": "2", "impact_label": "Group",      "urgency": "1", "urgency_label": "Interruption"},
    "HIGH":     {"impact": "3", "impact_label": "Individual", "urgency": "1", "urgency_label": "Interruption"},
    "MEDIUM":   {"impact": "3", "impact_label": "Individual", "urgency": "3", "urgency_label": "Service Request"},
    "LOW":      {"impact": "3", "impact_label": "Individual", "urgency": "3", "urgency_label": "Service Request"},
}

# Fallback only — normally written by the report workflow to snow_ticket_pending.json
TICKET_DEFAULT = {
    "severity":         "CRITICAL",
    "short_description": "SecOps Vuln | N Assets Impacted | Critical | <Finding Title> - Wiz",
    "caller_email":     _ANALYST.get("email", "you@example.com"),
    "caller_display":   _ANALYST.get("name", "Firstname Lastname"),
    "assignment_group": DEFAULT_GROUP,
    "category":         "security",
    "offering":         "Vulnerability Management",
    "type_of_assistance": "Service Request",
    "description":      "(No pending ticket data found — run the report workflow first.)",
}


# ── Logging ───────────────────────────────────────────────────────────────────
Path("Output").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_PATH, mode="w", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("snow")


# ── Load ticket data ──────────────────────────────────────────────────────────
def load_ticket() -> dict:
    if PENDING_JSON.exists():
        try:
            data = json.loads(PENDING_JSON.read_text(encoding="utf-8"))
            log.info("Loaded ticket data from %s", PENDING_JSON)
            return data
        except Exception as e:
            log.warning("Failed to read %s: %s — using default", PENDING_JSON, e)
    else:
        log.warning("%s not found — using TICKET_DEFAULT fallback", PENDING_JSON)
    return TICKET_DEFAULT.copy()


# ── In-page REST API ──────────────────────────────────────────────────────────
async def page_fetch(page, path: str, params: dict = None) -> dict | None:
    # Params are concatenated raw, not URL-encoded: the sysparm_query values are
    # pre-escaped by the callers (spaces as '+', per ServiceNow query syntax).
    # Encoding here would double-escape those, so leave it to the call sites.
    url = f"{INSTANCE}{path}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    script = """
        async (url) => {
            try {
                const r = await fetch(url, {
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'X-UserToken': window.g_ck || '',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                if (!r.ok) return { __status: r.status, __error: true };
                return await r.json();
            } catch(e) { return { __error: true, __msg: String(e) }; }
        }
    """
    try:
        res = await page.evaluate(script, url)
        if isinstance(res, dict) and res.get("__error"):
            log.warning("page_fetch %-45s → HTTP %s", path, res.get("__status", "?"))
            return None
        log.debug("page_fetch %-45s → ok", path)
        return res
    except Exception as e:
        log.warning("page_fetch %-45s → exception: %s", path, e)
        return None


async def lookup_sys_id(page, table: str, query: str, label: str) -> tuple[str | None, str]:
    """Return (sys_id, display_name). display_name is the record's real name from the
    table (authoritative — use it for the field's display so the Contact never shows a
    mislabelled name)."""
    data = await page_fetch(page, f"/api/now/table/{table}", {
        "sysparm_query":  query,
        "sysparm_fields": "sys_id,name,email",
        "sysparm_limit":  "1",
    })
    if data and data.get("result"):
        rec = data["result"][0]
        sid = rec.get("sys_id", "")
        name = rec.get("name", rec.get("email", ""))
        log.info("Lookup %-35s → %s  (%s)", label, sid, name)
        return sid, name
    log.warning("Lookup %-35s → not found  (query=%s)", label, query)
    return None, ""


async def lookup_user_groups(page, user_sid: str) -> list:
    """Return [(group_sys_id, group_name), ...] the user is an active member of.
    Used to derive the Assignment Group from the Assigned-To person: the rule is
    to assign the group the owner belongs to (if exactly one), NOT a forced default
    — setting a group the owner isn't in makes ServiceNow clear the Assigned To."""
    data = await page_fetch(page, "/api/now/table/sys_user_grmember", {
        "sysparm_query":  f"user={user_sid}",
        "sysparm_fields": "group.sys_id,group.name",
        "sysparm_limit":  "50",
    })
    groups = []
    if data and data.get("result"):
        for rec in data["result"]:
            gid = rec.get("group.sys_id") or ""
            gname = rec.get("group.name") or ""
            if gid:
                groups.append((gid, gname))
    log.info("Assignee group membership → %s", [g[1] for g in groups] or "none")
    return groups


# ── Login detection ───────────────────────────────────────────────────────────
async def wait_for_login(page) -> bool:
    log.info("Polling for login (max %ds)…", LOGIN_TIMEOUT)
    print(f"\n  Waiting for IdP/SSO login (log into the browser window):", flush=True)
    idp_host = (_SNOW.get("idp_login_host") or "").lower()
    for i in range(LOGIN_TIMEOUT // LOGIN_POLL):
        try:
            url = page.url
            # Must be on a real SNOW page — not an auth_redirect or an IdP/SSO URL
            lo = url.lower()
            on_snow = (
                "service-now.com" in url
                and "okta" not in lo
                and "auth_redirect" not in lo
                and "saml" not in lo
                and "microsoftonline" not in lo
                and "pingidentity" not in lo
                and (not idp_host or idp_host not in lo)
            )
            if on_snow:
                for sel in ["#gsft_nav", ".navpage-main", "#sn-appnavbar",
                            ".sn-polaris-layout", "[id='nav_home']"]:
                    if await page.locator(sel).count() > 0:
                        log.info("Login confirmed at real SNOW page — %s", url)
                        print("  Login detected — proceeding.", flush=True)
                        return True
        except Exception:
            pass
        if i % 5 == 0:
            elapsed = i * LOGIN_POLL
            print(f"  ... {elapsed}s elapsed, waiting for login ...", flush=True)
        await asyncio.sleep(LOGIN_POLL)
    log.warning("Login poll timed out after %ds", LOGIN_TIMEOUT)
    return False


# ── iframe ────────────────────────────────────────────────────────────────────
async def get_frame(page):
    try:
        await page.wait_for_selector("iframe#gsft_main", timeout=15000)
        frame = page.frame(name="gsft_main")
        if frame:
            log.info("Switched into gsft_main iframe")
            return frame
    except PWTimeout:
        pass
    log.warning("gsft_main not found — using main page")
    return page


# ── Form field scanner ────────────────────────────────────────────────────────
async def scan_form(frame) -> dict:
    """
    Scan the incident form and log all checkboxes and reference inputs.
    Used to identify the exact IDs for 'No Matching CI' and 'Offering'.
    """
    result = await frame.evaluate("""
        () => {
            const out = { checkboxes: [], ref_inputs: [] };

            // All checkboxes with their labels
            document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                const lbl = document.querySelector('label[for="' + cb.id + '"]');
                out.checkboxes.push({
                    id: cb.id,
                    name: cb.name,
                    checked: cb.checked,
                    label: lbl ? lbl.textContent.trim() : ''
                });
            });

            // Reference / text inputs — focus on ones with 'offering' or 'ci' in id/name
            document.querySelectorAll('input[type="text"], input:not([type])').forEach(inp => {
                const id   = (inp.id   || '').toLowerCase();
                const name = (inp.name || '').toLowerCase();
                const lbl  = document.querySelector('label[for="' + inp.id + '"]');
                const lblTxt = lbl ? lbl.textContent.trim() : '';
                if (id.includes('offer') || name.includes('offer') ||
                    id.includes('affec') || name.includes('affec') ||
                    lblTxt.toLowerCase().includes('offer') ||
                    lblTxt.toLowerCase().includes('affected')) {
                    out.ref_inputs.push({
                        id: inp.id, name: inp.name, label: lblTxt, value: inp.value
                    });
                }
            });

            return out;
        }
    """)
    log.info("── Form field scan ──")
    for cb in result.get("checkboxes", []):
        log.info("  CHECKBOX  id=%-45s name=%-40s label=%s", cb["id"], cb["name"], cb["label"])
    for inp in result.get("ref_inputs", []):
        log.info("  REF INPUT id=%-45s name=%-40s label=%s", inp["id"], inp["name"], inp["label"])
    return result


# ── Major Incident popup dismissal ────────────────────────────────────────────
async def dismiss_popup(page, frame, wait_secs: float = 5.0) -> bool:
    deadline = asyncio.get_event_loop().time() + wait_secs
    while asyncio.get_event_loop().time() < deadline:
        for target in [page, frame]:
            for sel in ["button:has-text('No')", "input[type='button'][value='No']",
                        "a.btn:has-text('No')", "[id*='major'] button:has-text('No')"]:
                try:
                    btn = target.locator(sel).first
                    if await btn.is_visible(timeout=250):
                        await btn.click()
                        log.info("Major Incident popup dismissed (No)")
                        return True
                except Exception:
                    pass
        await asyncio.sleep(0.3)
    return False


# ── g_form helpers ────────────────────────────────────────────────────────────
async def gf_set(frame, field: str, value, display: str = "") -> bool:
    # json.dumps, not repr: these values are interpolated into the page as JS
    # literals. Python's repr happens to be JS-compatible for the strings we send
    # (verified against quotes, newlines, backslashes, U+2028 and emoji), but
    # json.dumps is the escape actually defined for JS — no reliance on coincidence.
    display_js = f", {json.dumps(display)}" if display else ""
    # Coerce booleans properly for checkboxes
    val_js = json.dumps(value) if isinstance(value, str) else ("true" if value else "false")
    script = f"""
        (() => {{
            try {{
                if (typeof g_form === 'undefined') return 'no_gform';
                g_form.setValue({json.dumps(field)}, {val_js}{display_js});
                return 'ok';
            }} catch(e) {{ return 'err:' + e; }}
        }})()
    """
    try:
        r = await frame.evaluate(script)
        if r == "ok":
            log.info("g_form.setValue %-35s val=%-25s disp=%s", field, value, display)
            return True
        log.warning("g_form.setValue %-35s → %s", field, r)
        return False
    except Exception as e:
        log.warning("g_form.setValue %-35s exception: %s", field, e)
        return False


# ── Checkbox — smart find-by-label ────────────────────────────────────────────
async def tick_checkbox_by_label(frame, label_fragment: str) -> bool:
    """Find a checkbox whose visible label contains label_fragment and tick it."""
    script = f"""
        (() => {{
            const labels = Array.from(document.querySelectorAll('label'));
            const lbl = labels.find(l =>
                l.textContent.trim().toLowerCase().includes({json.dumps(label_fragment.lower())})
            );
            if (!lbl) return 'label_not_found';
            const forId = lbl.getAttribute('for');
            let cb = forId ? document.getElementById(forId) : null;
            if (!cb) cb = lbl.querySelector('input[type="checkbox"]');
            if (!cb) return 'checkbox_not_found';
            if (!cb.checked) {{ cb.click(); return 'clicked:' + cb.id + ':' + cb.name; }}
            return 'already_checked:' + cb.id;
        }})()
    """
    try:
        r = await frame.evaluate(script)
        if r.startswith("clicked") or r.startswith("already"):
            log.info("Checkbox '%s' → %s", label_fragment, r)
            return True
        log.warning("Checkbox '%s' → %s", label_fragment, r)
        return False
    except Exception as e:
        log.warning("Checkbox '%s' exception: %s", label_fragment, e)
        return False


# ── Offering — smart find-by-label ───────────────────────────────────────────
async def fill_offering_by_label(frame, value: str) -> bool:
    """Fill the Offering type-ahead field. ID confirmed from form scan."""
    # Confirmed via form scan: sys_display.incident.service_offering
    inp_id = "sys_display.incident.service_offering"

    # Verify it exists; if not, discover via label scan
    el_check = frame.locator(f"input[id='{inp_id}']").first
    if await el_check.count() == 0:
        inp_id = await frame.evaluate("""
            () => {
                const labels = Array.from(document.querySelectorAll('label'));
                const lbl = labels.find(l => l.textContent.trim().toLowerCase().includes('offering'));
                return lbl ? lbl.getAttribute('for') : null;
            }
        """)

    if inp_id:
        log.info("Offering input id found: %s", inp_id)
        el = frame.locator(f"input[id='{inp_id}']").first
        try:
            if await el.count() > 0 and await el.is_visible():
                await el.click(click_count=3)
                await el.fill("")
                await el.type(value, delay=40)
                await asyncio.sleep(1.5)
                for ac in [".ac_results li:first-child", "[id*='ac_option_0']",
                           ".typeahead li:first-child", "ul.ui-autocomplete li:first-child"]:
                    try:
                        sug = frame.locator(ac).first
                        if await sug.count() > 0 and await sug.is_visible():
                            await sug.click(timeout=3000)
                            log.info("Offering filled via type-ahead: %s", value)
                            return True
                    except Exception:
                        pass
                log.warning("Offering typed but no autocomplete suggestion clicked")
                return False
        except Exception as e:
            log.warning("Offering fill error: %s", e)
    else:
        log.warning("Offering label not found in form")

    # Last resort — try known name patterns directly
    for sel in ["input[name='incident.u_offering']", "input[name='incident.service_offering']",
                "input[id*='offering']", "input[name*='offering']"]:
        try:
            el = frame.locator(sel).first
            if await el.count() > 0 and await el.is_visible():
                await el.click(click_count=3)
                await el.fill("")
                await el.type(value, delay=40)
                await asyncio.sleep(1.5)
                for ac in [".ac_results li:first-child", "[id*='ac_option_0']"]:
                    try:
                        sug = frame.locator(ac).first
                        if await sug.count() > 0 and await sug.is_visible():
                            await sug.click(timeout=3000)
                            log.info("Offering filled via selector fallback: %s → %s", sel, value)
                            return True
                    except Exception:
                        pass
        except Exception:
            continue
    log.warning("Offering field not found by any method — fill manually")
    return False


# ── Choice dropdown — smart find-by-label (e.g. Type of Assistance) ───────────
async def set_choice_by_label(frame, label_fragment: str, option_text: str) -> bool:
    """Find a <select> by its visible label and pick the option whose text matches
    option_text. Sets the native value + fires change, and mirrors to g_form."""
    script = f"""
        (() => {{
            const frag = {json.dumps(label_fragment.lower())};
            const want = {json.dumps(option_text.lower())};
            const labels = Array.from(document.querySelectorAll('label'));
            let sel = null;
            const lbl = labels.find(l => l.textContent.trim().toLowerCase().includes(frag));
            if (lbl) {{
                const forId = lbl.getAttribute('for');
                if (forId) {{
                    const el = document.getElementById(forId);
                    if (el && el.tagName === 'SELECT') sel = el;
                    else if (el && el.querySelector) sel = el.querySelector('select');
                }}
                if (!sel) {{
                    const cont = lbl.closest('.form-group, tr, td, .sn-record-cell, .label-container') || lbl.parentElement;
                    if (cont) sel = cont.querySelector('select') ||
                                    (cont.parentElement && cont.parentElement.querySelector('select'));
                }}
            }}
            if (!sel) {{
                const selects = Array.from(document.querySelectorAll('select'));
                sel = selects.find(s => Array.from(s.options).some(o => o.text.trim().toLowerCase() === want));
            }}
            if (!sel) return 'select_not_found';
            let opt = Array.from(sel.options).find(o => o.text.trim().toLowerCase() === want)
                   || Array.from(sel.options).find(o => o.text.trim().toLowerCase().includes(want));
            if (!opt) return 'option_not_found:' + (sel.id||sel.name) + ':' +
                             Array.from(sel.options).map(o => o.text).join('|');
            sel.value = opt.value;
            sel.dispatchEvent(new Event('change', {{bubbles:true}}));
            try {{
                if (typeof g_form !== 'undefined') {{
                    const fname = (sel.name || sel.id || '').replace(/^incident\\./,'').replace(/^sys_display\\./,'');
                    if (fname) g_form.setValue(fname, opt.value);
                }}
            }} catch(e) {{}}
            return 'set:' + (sel.id||sel.name) + ':' + opt.text + '=' + opt.value;
        }})()
    """
    try:
        r = await frame.evaluate(script)
        if isinstance(r, str) and r.startswith("set:"):
            log.info("Choice '%s' → %s", label_fragment, r)
            return True
        log.warning("Choice '%s' → %s", label_fragment, r)
        return False
    except Exception as e:
        log.warning("Choice '%s' exception: %s", label_fragment, e)
        return False


# ── Type-ahead reference fallback ─────────────────────────────────────────────
async def typeahead(frame, display_id: str, value: str, label: str) -> bool:
    for sel in [f"input[id='{display_id}']", f"input[name='{display_id}']"]:
        try:
            el = frame.locator(sel).first
            if await el.count() == 0 or not await el.is_visible():
                continue
            await el.click(click_count=3)   # select-all without triple_click
            await el.fill("")
            await el.type(value, delay=50)
            await asyncio.sleep(2.0)
            for ac in [".ac_results li:first-child", "[id*='ac_option_0']",
                       ".typeahead .dropdown-item:first-child"]:
                try:
                    sug = frame.locator(ac).first
                    if await sug.count() > 0 and await sug.is_visible():
                        await sug.click(timeout=3000)
                        log.info("Type-ahead %-30s → '%s' selected", label, value)
                        return True
                except Exception:
                    continue
        except Exception as e:
            log.warning("Type-ahead %-30s error: %s", label, e)
    log.warning("Type-ahead %-30s → failed", label)
    return False


# ── DOM fallbacks ─────────────────────────────────────────────────────────────
async def dom_fill(frame, field: str, value: str) -> bool:
    for sel in [f"textarea[name='incident.{field}']", f"input[name='incident.{field}']",
                f"textarea[name='{field}']", f"input[name='{field}']"]:
        try:
            el = frame.locator(sel).first
            if await el.count() > 0 and await el.is_visible():
                await el.click()
                await el.fill(value)
                log.info("DOM fill %-30s → ok", field)
                return True
        except Exception:
            continue
    log.warning("DOM fill %-30s → not found", field)
    return False


# ── Main fill orchestrator ────────────────────────────────────────────────────
async def fill_ticket(page, data: dict):
    severity  = data.get("severity", "CRITICAL").upper()
    sev       = SEVERITY_MAP.get(severity, SEVERITY_MAP["CRITICAL"])
    log.info("severity=%s  impact=%s(%s)  urgency=%s(%s)",
             severity, sev["impact"], sev["impact_label"],
             sev["urgency"], sev["urgency_label"])

    # 1. Resolve sys_ids via in-page fetch (has session cookies)
    log.info("── sys_id lookups ──")
    caller_sid, caller_name = await lookup_sys_id(page, "sys_user",
                                     f"email={data['caller_email']}", "caller (email)")
    if not caller_sid:
        caller_sid, caller_name = await lookup_sys_id(page, "sys_user",
                                         f"nameLIKE{data['caller_display'].replace(' ', '+')}",
                                         "caller (name LIKE)")
    # Authoritative Contact display: the real name on the user record (resolved via the
    # caller's email), NOT the pending-JSON caller_display (which may be a different format
    # e.g. the Excel-author style "Lastname, Firstname"). Fall back to JSON only if unresolved.
    caller_display = caller_name or data.get("caller_display", "")

    group_sid, _ = await lookup_sys_id(page, "sys_user_group",
                                    f"name={data['assignment_group']}", "assignment_group (exact)")
    if not group_sid:
        group_sid, _ = await lookup_sys_id(page, "sys_user_group",
                                        f"nameLIKE{data['assignment_group'].replace('_', '+').replace(' ', '+')}",
                                        "assignment_group (LIKE)")

    # Assigned To — Technical Owner email (separate from Assignment Group)
    assigned_to_sid   = None
    assigned_to_email = data.get("assigned_to_email", "")
    assigned_to_name  = data.get("assigned_to_display", "")
    if assigned_to_email:
        assigned_to_sid, _ = await lookup_sys_id(
            page, "sys_user", f"email={assigned_to_email}", "assigned_to (email)"
        )
        if not assigned_to_sid and assigned_to_name:
            assigned_to_sid, _ = await lookup_sys_id(
                page, "sys_user",
                f"nameLIKE{assigned_to_name.replace(' ', '+')}",
                "assigned_to (name LIKE)",
            )

    # Affected User — the impacted application/product owner. Used when the owner cannot
    # be set as Assigned To (e.g. no ITIL access) but should still be recorded on the
    # incident. Looked up by email like the caller; falls back to name LIKE.
    affected_sid   = None
    affected_email = data.get("affected_user_email", "")
    affected_name  = data.get("affected_user_display", "")
    if affected_email:
        affected_sid, affected_lookup = await lookup_sys_id(
            page, "sys_user", f"email={affected_email}", "affected_user (email)")
        if not affected_sid and affected_name:
            affected_sid, affected_lookup = await lookup_sys_id(
                page, "sys_user",
                f"nameLIKE{affected_name.replace(' ', '+')}", "affected_user (name LIKE)")
        affected_name = affected_lookup or affected_name

    # Assignment Group rule: when a Technical Owner is
    # set, the Assignment Group MUST be a group the owner actually belongs to — never
    # a forced default. Setting a group the owner isn't in makes ServiceNow clear the
    # Assigned To (that is why it had to be re-entered manually). So:
    #   owner in exactly ONE group  → use that group
    #   owner in several / no groups → leave Assignment Group blank for manual pick
    #   NO owner                     → fall back to the provided/default group
    group_display = data.get("assignment_group", DEFAULT_GROUP)
    if assigned_to_sid:
        member_groups = await lookup_user_groups(page, assigned_to_sid)
        if len(member_groups) == 1:
            group_sid, group_display = member_groups[0]
            log.info("Assignment Group derived from assignee's single membership → %s", group_display)
        else:
            log.warning("Assignee is in %d group(s) %s — leaving Assignment Group blank for manual pick",
                        len(member_groups), [g[1] for g in member_groups])
            group_sid, group_display = None, ""

    # 2. Navigate to new incident form
    log.info("Navigating to new incident form…")
    try:
        await page.goto(NEW_INC_URL, wait_until="commit", timeout=60000)
    except Exception as e:
        log.warning("goto: %s", e)

    log.info("Waiting for form to render…")
    await asyncio.sleep(4)

    frame = await get_frame(page)
    await asyncio.sleep(1)

    # 3. Scan form to log exact field IDs (essential for debugging)
    await scan_form(frame)

    log.info("── Injecting fields ──")

    # Short description
    if not await gf_set(frame, "short_description", data["short_description"]):
        await dom_fill(frame, "short_description", data["short_description"])

    # Caller / Contact  (display = authoritative looked-up name, not the JSON label)
    if caller_sid:
        if not await gf_set(frame, "caller_id", caller_sid, caller_display):
            await typeahead(frame, "sys_display.incident.caller_id",
                            caller_display, "caller_id")
    else:
        log.warning("caller sys_id missing — type-ahead fallback")
        await typeahead(frame, "sys_display.incident.caller_id",
                        caller_display, "caller_id")

    # Affected User — auto-populated from caller. If an affected_user_email is provided
    # (e.g. the impacted app owner who lacks ITIL access and can't be Assigned To), set it
    # to that person; otherwise blank it (the default — it must not inherit the caller).
    await asyncio.sleep(0.5)
    if affected_email:
        if affected_sid:
            if not await gf_set(frame, "u_affected_user", affected_sid, affected_name or affected_email):
                await typeahead(frame, "sys_display.incident.u_affected_user",
                                affected_name or affected_email, "u_affected_user")
        else:
            log.warning("affected_user sys_id missing — type-ahead with email")
            await typeahead(frame, "sys_display.incident.u_affected_user",
                            affected_email, "u_affected_user")
    else:
        cleared = await gf_set(frame, "u_affected_user", "", "")
        if not cleared:
            # Try DOM clear on the display input
            for sel in ["input[id*='affected_user']", "input[name*='affected_user']",
                        "input[id='sys_display.incident.u_affected_user']"]:
                try:
                    el = frame.locator(sel).first
                    if await el.count() > 0 and await el.is_visible():
                        await el.click(click_count=3)
                        await el.fill("")
                        log.info("Affected User cleared via DOM (%s)", sel)
                        break
                except Exception:
                    continue

    # Category
    if not await gf_set(frame, "category", data.get("category", "security")):
        await dom_fill(frame, "category", data.get("category", "security"))

    # Impact — then watch for popup
    if not await gf_set(frame, "impact", sev["impact"]):
        await dom_fill(frame, "impact", sev["impact_label"])
    await dismiss_popup(page, frame, wait_secs=1.5)

    # Urgency — then watch for popup
    if not await gf_set(frame, "urgency", sev["urgency"]):
        await dom_fill(frame, "urgency", sev["urgency_label"])
    await dismiss_popup(page, frame, wait_secs=1.5)

    # Assignment Group (derived from the assignee's membership above; set BEFORE
    # Assigned To so the owner — a member — is not cleared). Blank ⇒ pick manually.
    if group_display:
        if group_sid:
            if not await gf_set(frame, "assignment_group", group_sid, group_display):
                await typeahead(frame, "sys_display.incident.assignment_group",
                                group_display, "assignment_group")
        else:
            log.warning("group sys_id missing — type-ahead fallback")
            await typeahead(frame, "sys_display.incident.assignment_group",
                            group_display, "assignment_group")
    else:
        log.info("Assignment Group left blank (assignee in multiple/zero groups) — pick manually")

    # Assigned To (Technical Owner — email-based user, not a group)
    if assigned_to_sid:
        if not await gf_set(frame, "assigned_to", assigned_to_sid, assigned_to_name or assigned_to_email):
            await typeahead(frame, "sys_display.incident.assigned_to",
                            assigned_to_name or assigned_to_email, "assigned_to")
    elif assigned_to_email:
        log.warning("assigned_to sys_id missing — type-ahead with email")
        await typeahead(frame, "sys_display.incident.assigned_to", assigned_to_email, "assigned_to")

    # No Matching Configuration Item — find by label text (not hardcoded field name)
    if not await tick_checkbox_by_label(frame, "No Matching Configuration Item"):
        if not await tick_checkbox_by_label(frame, "No Matching"):
            log.warning("'No Matching CI' checkbox not found — tick manually")

    # Offering — find by label text
    await fill_offering_by_label(frame, data.get("offering", "Vulnerability Management"))

    # Type of Assistance — choice dropdown beneath Offering (default: Service Request)
    toa = data.get("type_of_assistance", "Service Request")
    if toa:
        if not await set_choice_by_label(frame, "Type of Assistance", toa):
            log.warning("Type of Assistance not set automatically — select '%s' manually", toa)

    # Description (last — long text, no autocomplete risk)
    if not await gf_set(frame, "description", data["description"]):
        await dom_fill(frame, "description", data["description"])

    # Summary
    log.info("── Fill complete ──")
    print("\n" + "=" * 64)
    print("  Fields injected:")
    print(f"    Short Description  : {data['short_description'][:55]}…")
    print(f"    Caller / Contact   : {caller_display}  (sys_id: {caller_sid or '⚠ NOT FOUND'})")
    if affected_email:
        print(f"    Affected User      : {affected_name or affected_email}  (sys_id: {affected_sid or '⚠ NOT FOUND'})")
    else:
        print(f"    Affected User      : cleared")
    print(f"    Category           : {data.get('category')}")
    print(f"    Impact             : {sev['impact_label']}")
    print(f"    Urgency            : {sev['urgency_label']}")
    print(f"    Assignment Group   : {group_display or '⚠ left blank — pick manually'}  (sys_id: {group_sid or '—'})")
    if assigned_to_email:
        print(f"    Assigned To        : {assigned_to_name or assigned_to_email}  (sys_id: {assigned_to_sid or '⚠ NOT FOUND'})")
    print(f"    Offering           : {data.get('offering')}")
    print(f"    Type of Assistance : {data.get('type_of_assistance', 'Service Request')}")
    print(f"    Description        : {len(data['description'])} chars")
    print("=" * 64)
    if not caller_sid:
        print("  ⚠  Contact: fill manually")
    if not group_sid:
        print(f"  ⚠  Assignment Group: fill manually as '{DEFAULT_GROUP}'")
    print()
    print("  YOUR TURN:")
    print("  • Attach the vulnerability report Excel file")
    print("  • Verify any ⚠ fields above")
    print("  • Submit and note the INC number + URL")
    print(f"\n  Full log → {LOG_PATH.resolve()}")


# ── Entry point ───────────────────────────────────────────────────────────────
async def wait_for_submission(page, timeout_mins: int = 10) -> tuple[str, str]:
    """
    Poll until the user submits the incident form.
    Returns (inc_number, page_url) when detected, or ('', url) on timeout.
    Detection: URL shifts from sys_id=-1 (new form) to a real sys_id.
    """
    log.info("Waiting for form submission (up to %d min)…", timeout_mins)
    print(f"\n  Waiting for you to submit the ticket in the browser", end="", flush=True)
    deadline = asyncio.get_event_loop().time() + timeout_mins * 60
    while asyncio.get_event_loop().time() < deadline:
        try:
            url = page.url
            # A saved record has a real sys_id (32-char hex), not -1
            if ("incident.do" in url and
                    "sys_id%3D-1" not in url and
                    "sys_id=-1"   not in url and
                    "sysparm_action%3Dnew" not in url):
                # Extract INC number from the form
                inc = ""
                frame = page.frame(name="gsft_main") or page
                try:
                    inc = await frame.evaluate("""
                        () => {
                            for (const sel of [
                                '[id="sys_readonly.incident.number"]',
                                'input[name="incident.number"]',
                                '[id="incident.number"]',
                            ]) {
                                const el = document.querySelector(sel);
                                if (el) return (el.value || el.textContent || '').trim();
                            }
                            return '';
                        }
                    """) or ""
                except Exception:
                    pass
                print(" ✓")
                log.info("Submission detected — INC=%s  URL=%s", inc, url)
                return inc, url
        except Exception:
            pass
        print(".", end="", flush=True)
        await asyncio.sleep(3)
    print(" ✗ (timed out)")
    log.warning("Submission not detected within %d min", timeout_mins)
    return "", page.url


async def main():
    log.info("=" * 64)
    log.info("ServiceNow Auto-Fill  —  %s", datetime.now().strftime("%Y-%m-%d %H:%M"))
    log.info("=" * 64)

    data = load_ticket()
    log.info("Ticket: %s", data.get("short_description", "?"))

    Path(PROFILE_DIR).mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        context = await p.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            channel="msedge",
            headless=False,
            slow_mo=0,
            args=["--start-maximized"],
            no_viewport=True,
        )
        page = context.pages[0] if context.pages else await context.new_page()

        log.info("Opening ServiceNow…")
        try:
            await page.goto(INSTANCE, wait_until="commit", timeout=60000)
        except Exception as e:
            log.warning("Initial nav: %s", e)

        logged_in = await wait_for_login(page)
        if not logged_in:
            # Auto-detect failed — wait silently for the dashboard to appear
            log.warning("Auto-detect timed out — continuing to poll…")
            for _ in range(60):          # extra 3-minute grace period
                await asyncio.sleep(3)
                try:
                    if "service-now.com" in page.url and "okta" not in page.url.lower():
                        log.info("Resumed after grace period")
                        break
                except Exception:
                    pass

        await fill_ticket(page, data)

        # Wait for the user to attach the file and click Submit — fully automatic
        inc, final_url = await wait_for_submission(page, timeout_mins=10)

        # Persist the result IMMEDIATELY so the INC is never lost when the
        # browser window closes (Output/snow_ticket_result.json). Written on
        # both success and timeout so there is always a record to read back.
        try:
            RESULT_JSON.write_text(json.dumps({
                "inc": inc,
                "url": final_url,
                "short_description": data.get("short_description", ""),
                "capturedAt": datetime.now().isoformat(timespec="seconds"),
                "submitted": bool(inc),
            }, indent=2), encoding="utf-8")
            log.info("Result written to %s", RESULT_JSON)
        except Exception as e:
            log.warning("Could not write result file: %s", e)

        await asyncio.sleep(1)
        await context.close()

        print("\n" + "=" * 64)
        if inc:
            print(f"  Ticket submitted:  {inc}")
            print(f"  URL:               {final_url}")
            print(f"  Saved to:          {RESULT_JSON.resolve()}")
            log.info("DONE — INC=%s  URL=%s", inc, final_url)
        else:
            print("  Ticket status unclear — no submission detected in time.")
            print(f"  If you DID submit, read the INC from the browser and tell me;")
            print(f"  a stub was written to {RESULT_JSON.resolve()}")
            log.warning("DONE — submission not confirmed")
        print(f"  Full log → {LOG_PATH.resolve()}")
        print("=" * 64)


if __name__ == "__main__":
    asyncio.run(main())
