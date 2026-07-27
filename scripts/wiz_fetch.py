#!/usr/bin/env python3
"""
wiz_fetch.py — pull Wiz Issues via the Wiz GraphQL API so the wiz-finding-report
skill can build a report straight from a finding (no manual export/screenshot).

AUTH — three ways, resolved in this order for `list`/`get`:
  1. WIZ_API_TOKEN env var (a raw bearer token you pasted in) + WIZ_API_URL.
  2. A cached token captured by `login` (the default, recommended flow).
  3. Legacy OAuth2 client-credentials: WIZ_CLIENT_ID + WIZ_CLIENT_SECRET +
     WIZ_API_URL (+ optional WIZ_AUTH_URL).

  `login`  Opens your *installed* Edge/Chrome, you sign in via your org SSO + MFA,
           and the script captures the session bearer token AND the tenant
           GraphQL endpoint automatically off the first authenticated request,
           then caches them. No service account / admin provisioning needed.
           The browser profile persists under ~/.wiz so later logins are quick
           (often no re-typing). Requires `playwright` + a Chromium channel
           (msedge/chrome) — only this subcommand needs it; list/get are stdlib.

Token cache: ~/.wiz/token.json  {token, cookie, authMode, apiUrl, capturedAt, exp},
written 0600. Some tenants authenticate the GraphQL endpoint with a bearer token,
others with an httpOnly session cookie — `login` detects which and records it as
`authMode`. Session creds are short-lived; when one expires, re-run `login`.

TLS: requests verify certificates. If the certificate is rejected — the normal case
behind a TLS-inspecting proxy such as Zscaler — the request is retried once with
verification disabled and a warning on stderr. WIZ_VERIFY_SSL=1 fails instead of
falling back; WIZ_INSECURE_SSL=1 skips the verified attempt entirely.

Subcommands:
    login  Browser sign-in → capture + cache token & endpoint.
           --channel msedge|chrome   --portal-url <url>   --timeout <secs>
    list   List issues matching filters (for the "found N issues, pick one" step).
           --severity CRITICAL,HIGH   --status OPEN,IN_PROGRESS
           --search "text"            --project <projectId>   --first 25
    get    Fetch one issue in full, ready to map into the report.
           --id <issueId>   OR   --url "<wiz issue url>"
    status Show cached-token state (present? expired? when?) — no secrets printed.

Output: JSON to stdout. On error: JSON {"error": "..."} to stdout, exit 1.
The schema below targets Wiz `issuesV2`; if your tenant differs, adjust QUERY_*.
"""
import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def _load_skill_config():
    """Read skill_config.json from the skill root — the parent of scripts/, i.e. the
    directory holding SKILL.md (portable org settings).
    Missing/invalid file → {} so the script still runs and prompts for setup."""
    skill_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg_path = os.path.join(skill_root, "skill_config.json")
    try:
        with open(cfg_path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_CFG = _load_skill_config()
_WIZ_CFG = _CFG.get("wiz", {}) if isinstance(_CFG.get("wiz"), dict) else {}

DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
# Your organization's IdP-initiated SSO link to Wiz (Okta / Entra ID / Ping, etc.).
# Priority: --portal-url arg > WIZ_PORTAL_URL env > skill_config.json (wiz.portal_url).
# (A wrapped URL on the command line breaks the shell, so prefer config/env over --portal-url.)
DEFAULT_PORTAL_URL = _WIZ_CFG.get("portal_url", "")
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".wiz")
CACHE_FILE = os.path.join(CACHE_DIR, "token.json")
PROFILE_DIR = os.path.join(CACHE_DIR, "browser-profile")


def _fail(msg):
    print(json.dumps({"error": msg}, indent=2))
    sys.exit(1)


def _unverified_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_warned_insecure = [False]


def _urlopen(req, timeout):
    """Open `req`, verifying TLS, and fall back to unverified only if the
    certificate itself is rejected.

    Corporate TLS interception (e.g. Zscaler) injects a CA cert OpenSSL 3 refuses,
    which is why the fallback exists — but it is a fallback, not the default, so a
    clean network actually gets verification and you are told when it is skipped.

      WIZ_VERIFY_SSL=1   strict: fail on a bad certificate, never fall back.
      WIZ_INSECURE_SSL=1 skip verification from the start (no warning spam)."""
    if os.environ.get("WIZ_INSECURE_SSL"):
        return urllib.request.urlopen(req, timeout=timeout, context=_unverified_ctx())
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as e:
        cert_problem = isinstance(e.reason, ssl.SSLCertVerificationError)
        if not cert_problem or os.environ.get("WIZ_VERIFY_SSL"):
            raise
        if not _warned_insecure[0]:
            _warned_insecure[0] = True
            print("WARNING: TLS certificate verification failed (%s) — retrying with "
                  "verification DISABLED. This is expected behind a TLS-inspecting proxy. "
                  "Set WIZ_VERIFY_SSL=1 to fail instead, or WIZ_INSECURE_SSL=1 to skip the "
                  "verified attempt." % (getattr(e.reason, "reason", None) or e.reason),
                  file=sys.stderr)
        return urllib.request.urlopen(req, timeout=timeout, context=_unverified_ctx())


# --------------------------------------------------------------------------
# Token cache + JWT helpers
# --------------------------------------------------------------------------
def _read_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_cache(api_url, token=None, cookie=None):
    os.makedirs(CACHE_DIR, exist_ok=True)
    data = {
        "token": token,
        "cookie": cookie,
        "authMode": "bearer" if token else "cookie",
        "apiUrl": api_url,
        "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "exp": _jwt_exp(token) if token else None,
    }
    # Best-effort restrictive perms (no-op semantics on Windows, harmless).
    fd = os.open(CACHE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def _jwt_exp(token):
    """Return the `exp` epoch from a JWT, or None if it can't be parsed."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return claims.get("exp")
    except Exception:
        return None


def _is_expired(exp):
    # 60s safety margin so we don't hand off a token about to die mid-request.
    return bool(exp) and time.time() > (exp - 60)


def _token_from_storage(page):
    """Last-resort: scrape a JWT-looking access token from the page's
    local/session storage (used only if no request carried a bearer header)."""
    js = r"""
    () => {
      const out = [];
      const scan = (s) => {
        for (let i = 0; i < s.length; i++) {
          const v = s.getItem(s.key(i));
          if (!v) continue;
          if (v.split('.').length === 3 && v.length > 200) out.push(v);
          try {
            const o = JSON.parse(v);
            const t = o && (o.access_token || o.accessToken ||
                            (o.body && o.body.access_token));
            if (t) out.push(t);
          } catch (e) {}
        }
      };
      try { scan(localStorage); } catch (e) {}
      try { scan(sessionStorage); } catch (e) {}
      return out;
    }"""
    try:
        for v in (page.evaluate(js) or []):
            if _jwt_exp(v):  # parses as a JWT with an exp claim
                return v
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Auth resolution for list/get
# --------------------------------------------------------------------------
def get_token_client_creds(client_id, client_secret, auth_url):
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "wiz-api",
    }).encode()
    req = urllib.request.Request(auth_url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        _fail("Auth failed (HTTP %s): %s" % (e.code, e.read().decode()[:500]))
    except Exception as e:  # noqa
        _fail("Auth request error: %s" % e)
    tok = data.get("access_token")
    if not tok:
        _fail("Auth response had no access_token: %s" % json.dumps(data)[:300])
    return tok


def resolve_auth():
    """Return (auth_headers, api_url) using whichever auth path is available.
    auth_headers carries either an Authorization bearer or a Cookie header."""
    env_api = os.environ.get("WIZ_API_URL") or _WIZ_CFG.get("api_url") or None

    # 1. Explicit pasted token.
    env_tok = os.environ.get("WIZ_API_TOKEN")
    if env_tok:
        api = env_api or (_read_cache() or {}).get("apiUrl")
        if not api:
            _fail("WIZ_API_TOKEN is set but no API URL. Set WIZ_API_URL "
                  "(e.g. https://api.<region>.app.wiz.io/graphql), add wiz.api_url to "
                  "skill_config.json, or run `login` once.")
        return {"Authorization": "Bearer " + env_tok}, api

    # 2. Cached creds from `login` (bearer token or session cookie).
    cache = _read_cache()
    if cache and (cache.get("token") or cache.get("cookie")):
        api = env_api or cache.get("apiUrl")
        if not api:
            _fail("Cached creds have no API URL. Re-run `login`, or set WIZ_API_URL.")
        if cache.get("token"):
            if _is_expired(cache.get("exp")):
                _fail("Cached Wiz token has expired. Re-run: python scripts/wiz_fetch.py login")
            return {"Authorization": "Bearer " + cache["token"]}, api
        return {"Cookie": cache["cookie"]}, api

    # 3. Legacy client-credentials.
    cid = os.environ.get("WIZ_CLIENT_ID")
    secret = os.environ.get("WIZ_CLIENT_SECRET")
    if cid and secret and env_api:
        auth = os.environ.get("WIZ_AUTH_URL", DEFAULT_AUTH_URL)
        return {"Authorization": "Bearer " + get_token_client_creds(cid, secret, auth)}, env_api

    _fail("No Wiz credentials available. Sign in with: python scripts/wiz_fetch.py login "
          "(opens a browser). Alternatively set WIZ_API_TOKEN+WIZ_API_URL, or a "
          "service account's WIZ_CLIENT_ID/WIZ_CLIENT_SECRET/WIZ_API_URL.")


def gql(api_url, auth_headers, query, variables):
    payload = json.dumps({"query": query, "variables": variables}).encode()
    headers = {"Content-Type": "application/json"}
    headers.update(auth_headers)
    req = urllib.request.Request(api_url, data=payload, method="POST", headers=headers)
    try:
        with _urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:800]
        if e.code in (401, 403):
            _fail("GraphQL HTTP %s (token rejected/expired). Re-run `login`. %s" % (e.code, body))
        _fail("GraphQL HTTP %s: %s" % (e.code, body))
    except Exception as e:  # noqa
        _fail("GraphQL request error: %s" % e)
    if data.get("errors"):
        _fail("GraphQL errors: " + json.dumps(data["errors"])[:800])
    return data.get("data", {})


# --------------------------------------------------------------------------
# Browser sign-in (login)
# --------------------------------------------------------------------------
def cmd_login(args):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _fail("playwright is not installed. Install it with:\n"
              "  python -m pip install --user playwright\n"
              "Then re-run `login`. (No browser download needed — we drive your "
              "installed Edge/Chrome.)")

    portal = args.portal_url or os.environ.get("WIZ_PORTAL_URL") or DEFAULT_PORTAL_URL
    if not portal:
        _fail("No Wiz portal URL configured. Set your organization's IdP-initiated "
              "SSO link to Wiz one of these ways:\n"
              "  - add \"portal_url\" under \"wiz\" in skill_config.json (see "
              "skill_config.example.json), or\n"
              "  - set the WIZ_PORTAL_URL environment variable, or\n"
              "  - pass --portal-url \"<url>\" on the command line.\n"
              "Tip: in the Wiz console this is your SSO/login link (Okta / Entra ID / Ping).")
    captured = {"token": None, "api_url": None, "cookie": None}
    # Diagnostics so a timeout tells us *why* (did the dashboard even load?).
    diag = {"requests": 0, "bearer": 0, "graphql": 0, "wiz_hosts": set()}
    pending = []          # real GraphQL API requests awaiting header inspection
    first_gql = {"ts": None}

    def on_request(request):
        # Keep this light: NO Playwright method calls here (all_headers() inside
        # an event handler hits a reentrancy limit). Just classify and queue.
        try:
            url = request.url
            diag["requests"] += 1
            parts = urllib.parse.urlsplit(url)
            host, path = parts.netloc, parts.path
            if "wiz.io" in host:
                diag["wiz_hosts"].add(host)
            # A real GraphQL API call is a POST whose path ends with /graphql.
            # This excludes static bundles like /assets/graphql-<hash>.js.
            if request.method == "POST" and path.endswith("/graphql"):
                diag["graphql"] += 1
                if not captured["api_url"]:
                    captured["api_url"] = url.split("?", 1)[0]
                if first_gql["ts"] is None:
                    first_gql["ts"] = time.time()
                if not captured["token"]:
                    pending.append(request)
        except Exception:
            pass

    def _drain():
        # Read real headers from the MAIN thread, looking for the bearer token.
        if captured["token"]:
            pending.clear()
            return
        while pending:
            req = pending.pop(0)
            try:
                h = req.all_headers()
            except Exception:
                continue
            auth = h.get("authorization") or h.get("Authorization")
            if auth and auth.lower().startswith("bearer "):
                diag["bearer"] += 1
                captured["token"] = auth.split(" ", 1)[1].strip()
                pending.clear()
                return

    os.makedirs(PROFILE_DIR, exist_ok=True)
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())

    def _live_page(ctx):
        try:
            return ctx.pages[0] if ctx.pages else None
        except Exception:
            return None

    def _pump(ctx, until):
        """Wait until `until()` is true or the deadline, while letting the
        request listener fire. Returns 'ok' / 'closed' / 'timeout'."""
        while not until[0]() and time.time() < until[1]:
            pg = _live_page(ctx)
            if not pg:
                return "closed"
            try:
                pg.wait_for_timeout(1000)
            except Exception:
                time.sleep(1)
        return "ok" if until[0]() else "timeout"

    closed_early = False
    with sync_playwright() as p:
        try:
            ctx = p.chromium.launch_persistent_context(
                PROFILE_DIR, channel=args.channel, headless=False,
                args=["--no-first-run", "--no-default-browser-check"],
            )
        except Exception as e:  # noqa
            _fail("Could not launch '%s'. Try --channel chrome (or msedge). "
                  "Underlying error: %s" % (args.channel, e))
        # Capture across the whole context (new tabs/popups during SSO too).
        ctx.on("request", on_request)
        ctx.on("page", lambda pg: pg.on("request", on_request))
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(portal, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            pass  # SSO redirects can race the initial nav; the listener still fires.

        def done():
            _drain()  # inspect any queued GraphQL requests for a bearer token
            if captured["token"]:
                return True
            # Saw the real API but no bearer after a grace window → this tenant
            # authenticates the GraphQL endpoint with a session cookie instead.
            if (captured["api_url"] and first_gql["ts"]
                    and time.time() - first_gql["ts"] > 12):
                return True
            return False

        if interactive:
            # Proven pattern (your downloader): let the human drive the login,
            # then signal readiness with ENTER. No guessing when SSO finished.
            for line in ("", "=" * 64,
                         "A browser window opened. In it:",
                         "  1. Sign in with your organization's IdP / SSO (+ MFA).",
                         "  2. Wait for the Wiz dashboard to FULLY load.",
                         "  3. Return here and press ENTER.",
                         "=" * 64, ""):
                print(line, file=sys.stderr)
            try:
                input("Press ENTER once the Wiz dashboard is loaded... ")
            except EOFError:
                interactive = False
            # Reload the (now-authenticated) page to force GraphQL traffic we capture.
            live = _live_page(ctx)
            if live and not done():
                try:
                    live.reload(wait_until="domcontentloaded", timeout=60000)
                except Exception:
                    pass
            status = _pump(ctx, [done, time.time() + 90])
        else:
            print("Opening %s in %s — sign in via your IdP/SSO; capturing automatically "
                  "once the Wiz dashboard loads..." % (portal, args.channel),
                  file=sys.stderr)
            status = _pump(ctx, [done, time.time() + args.timeout])

        if status == "closed":
            closed_early = True

        # Last resort: scrape a JWT from browser storage if no request had one.
        if not captured["token"]:
            live = _live_page(ctx)
            if live:
                tok = _token_from_storage(live)
                if tok:
                    captured["token"] = tok
        # Cookie-auth fallback: some tenants authenticate the GraphQL API with a
        # session cookie rather than a bearer header. Grab cookies for that host.
        if not captured["token"] and captured["api_url"]:
            try:
                cookies = ctx.cookies(captured["api_url"])
                if cookies:
                    captured["cookie"] = "; ".join(
                        "%s=%s" % (c["name"], c["value"]) for c in cookies)
            except Exception:
                pass
        try:
            ctx.close()
        except Exception:
            pass

    # Fall back to a configured endpoint if we got a token but never saw /graphql.
    if captured["token"] and not captured["api_url"]:
        captured["api_url"] = os.environ.get("WIZ_API_URL")

    have_auth = bool(captured["api_url"] and (captured["token"] or captured["cookie"]))
    if not have_auth:
        hosts = ", ".join(sorted(diag["wiz_hosts"])) or "none"
        seen = ("Saw %d requests (%d to wiz.io hosts: %s; %d GraphQL; %d with a "
                "bearer token)." % (diag["requests"], len(diag["wiz_hosts"]),
                                     hosts, diag["graphql"], diag["bearer"]))
        if closed_early:
            _fail("The browser closed before sign-in completed. " + seen +
                  " If a window flashed and vanished, %s was already running and "
                  "handed off the URL — fully quit all %s windows (or use --channel "
                  "%s), then retry." % (args.channel, args.channel,
                                        "msedge" if args.channel == "chrome" else "chrome"))
        _fail("No usable Wiz credentials captured. " + seen +
              " Likely sign-in wasn't finished or the dashboard didn't load. Run "
              "in a real terminal so you can press ENTER once the Wiz dashboard is "
              "up, or (non-interactive) finish login before the --timeout elapses.")

    saved = _write_cache(captured["api_url"], token=captured["token"],
                         cookie=captured["cookie"])
    exp = saved.get("exp")
    out = {
        "status": "ok",
        "authMode": saved.get("authMode"),
        "apiUrl": saved["apiUrl"],
        "capturedAt": saved["capturedAt"],
        "expiresAt": (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(exp)) if exp else "unknown"),
        "cache": CACHE_FILE,
        "note": "Cached. list/get reuse this until it expires; re-run login after that.",
    }
    print(json.dumps(out, indent=2))


def cmd_status(args):
    cache = _read_cache()
    if not (cache and (cache.get("token") or cache.get("cookie"))):
        print(json.dumps({"loggedIn": False,
                          "note": "No cached creds. Run: python scripts/wiz_fetch.py login"}, indent=2))
        return
    exp = cache.get("exp")
    print(json.dumps({
        "loggedIn": True,
        "authMode": cache.get("authMode") or ("bearer" if cache.get("token") else "cookie"),
        "expired": _is_expired(exp),  # cookie mode has no JWT exp → false (re-login on 401)
        "apiUrl": cache.get("apiUrl"),
        "capturedAt": cache.get("capturedAt"),
        "expiresAt": (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(exp)) if exp else "unknown"),
    }, indent=2))


# --------------------------------------------------------------------------
# GraphQL queries
# --------------------------------------------------------------------------
# Compact list view for the selection step.
QUERY_LIST = """
query IssuesList($filterBy: IssueFilters, $first: Int, $orderBy: IssueOrder) {
  issuesV2(filterBy: $filterBy, first: $first, orderBy: $orderBy) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      severity
      status
      createdAt
      dueAt
      sourceRule { __typename ... on Control { id name } ... on CloudEventRule { id name } }
      entitySnapshot { id type name cloudPlatform region subscriptionName }
    }
  }
}
"""

# Full detail for one issue.
QUERY_GET = """
query IssueDetail($filterBy: IssueFilters, $first: Int) {
  issuesV2(filterBy: $filterBy, first: $first) {
    nodes {
      id
      severity
      status
      createdAt
      updatedAt
      dueAt
      resolvedAt
      description
      resolutionReason
      sourceRule {
        __typename
        ... on Control { id name resolutionRecommendation }
        ... on CloudEventRule { id name }
      }
      entitySnapshot {
        id
        type
        name
        nativeType
        cloudPlatform
        region
        subscriptionId
        subscriptionName
        subscriptionExternalId
        externalId
        providerId
        cloudProviderURL
        status
        tags
      }
      serviceTickets { externalId name url }
      notes { text }
    }
  }
}
"""


def _norm_list(csv):
    if not csv:
        return None
    return [s.strip().upper() for s in csv.split(",") if s.strip()]


def _bool_arg(v):
    s = str(v).strip().lower()
    if s in ("true", "t", "yes", "y", "1"):
        return True
    if s in ("false", "f", "no", "n", "0"):
        return False
    raise argparse.ArgumentTypeError("expected true or false, got %r" % v)


def cmd_list(args):
    auth_headers, api = resolve_auth()
    flt = {}
    sev = _norm_list(args.severity)
    sts = _norm_list(args.status)
    if sev:
        flt["severity"] = sev
    if sts:
        flt["status"] = sts
    if args.search:
        flt["search"] = args.search
    if args.project:
        flt["project"] = [args.project]
    if args.has_ticket is not None:
        flt["hasServiceTicket"] = args.has_ticket
    variables = {
        "filterBy": flt or None,
        "first": args.first,
        "orderBy": {"field": "SEVERITY", "direction": "DESC"},
    }
    data = gql(api, auth_headers, QUERY_LIST, variables)
    conn = data.get("issuesV2", {})
    out = {
        "totalCount": conn.get("totalCount"),
        "returned": len(conn.get("nodes", [])),
        "hasMore": conn.get("pageInfo", {}).get("hasNextPage"),
        "issues": [],
    }
    for n in conn.get("nodes", []):
        ent = n.get("entitySnapshot") or {}
        rule = n.get("sourceRule") or {}
        out["issues"].append({
            "id": n.get("id"),
            "severity": n.get("severity"),
            "status": n.get("status"),
            "createdAt": n.get("createdAt"),
            "dueAt": n.get("dueAt"),
            "rule": rule.get("name"),
            "resource": ent.get("name"),
            "resourceType": ent.get("type"),
            "cloud": ent.get("cloudPlatform"),
            "region": ent.get("region"),
            "subscription": ent.get("subscriptionName"),
        })
    print(json.dumps(out, indent=2))


_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _id_from_url(url):
    m = _UUID_RE.search(urllib.parse.unquote(url))
    return m.group(0) if m else None


def cmd_get(args):
    issue_id = args.id
    if not issue_id and args.url:
        issue_id = _id_from_url(args.url)
        if not issue_id:
            _fail("Could not find an issue UUID in the URL. Pass --id instead.")
    if not issue_id:
        _fail("Provide --id <issueId> or --url <wiz issue url>.")
    auth_headers, api = resolve_auth()
    variables = {"filterBy": {"id": [issue_id]}, "first": 1}
    data = gql(api, auth_headers, QUERY_GET, variables)
    nodes = data.get("issuesV2", {}).get("nodes", [])
    if not nodes:
        _fail("No issue found for id %s (check the id/scope)." % issue_id)
    print(json.dumps(nodes[0], indent=2))


def cmd_raw(args):
    """Run an arbitrary GraphQL query (advanced: schema introspection, evidence
    enrichment). Query from --query or --query-file; variables as JSON."""
    auth_headers, api = resolve_auth()
    query = args.query
    if args.query_file:
        with open(args.query_file, encoding="utf-8") as f:
            query = f.read()
    if not query:
        _fail("Provide --query \"...\" or --query-file <path>.")
    variables = {}
    if args.variables:
        try:
            variables = json.loads(args.variables)
        except Exception as e:  # noqa
            _fail("--variables must be valid JSON: %s" % e)
    print(json.dumps(gql(api, auth_headers, query, variables), indent=2))


def main():
    p = argparse.ArgumentParser(description="Fetch Wiz issues for the finding-report skill.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pli = sub.add_parser("login", help="Browser sign-in; capture + cache token & endpoint.")
    pli.add_argument("--channel", default="msedge", help="Browser channel: msedge (default) or chrome")
    pli.add_argument("--portal-url",
                     help="Your IdP-initiated SSO link to Wiz. Defaults to WIZ_PORTAL_URL, "
                          "else wiz.portal_url in skill_config.json.")
    pli.add_argument("--timeout", type=int, default=300, help="Seconds to wait for sign-in (default 300)")
    pli.set_defaults(func=cmd_login)

    ps = sub.add_parser("status", help="Show cached-token state (no secrets).")
    ps.set_defaults(func=cmd_status)

    pl = sub.add_parser("list", help="List issues matching filters.")
    pl.add_argument("--severity", help="CSV e.g. CRITICAL,HIGH")
    pl.add_argument("--status", help="CSV e.g. OPEN,IN_PROGRESS")
    pl.add_argument("--search", help="free-text search")
    pl.add_argument("--project", help="Wiz project id")
    pl.add_argument("--has-ticket", dest="has_ticket", type=_bool_arg, default=None,
                    help="Filter by whether a service ticket exists: true or false")
    pl.add_argument("--first", type=int, default=25)
    pl.set_defaults(func=cmd_list)

    pg = sub.add_parser("get", help="Fetch one issue in full.")
    pg.add_argument("--id", help="Wiz issue id (UUID)")
    pg.add_argument("--url", help="Wiz issue URL (id is parsed out)")
    pg.set_defaults(func=cmd_get)

    pr = sub.add_parser("raw", help="Run a raw GraphQL query (advanced).")
    pr.add_argument("--query", help="GraphQL query string")
    pr.add_argument("--query-file", dest="query_file", help="File containing the query")
    pr.add_argument("--variables", help="JSON variables object")
    pr.set_defaults(func=cmd_raw)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
