#!/usr/bin/env python3
"""tech404 - identify web technologies from their default 404 pages.

Sends requests for random non-existent paths and fingerprints the error
page bodies (falling back to Server / X-Powered-By headers) against the
stock 404 pages of common web servers and frameworks.

Three probes are issued per target:

  /<random>        plain 404 page (web server or framework default)
  /<random>.php    fronting servers proxy *.php to PHP-FPM, which answers
                   with the plain text "File not found."
  /<random>.aspx   IIS routes *.aspx through to ASP.NET, whose 404 page
                   differs from the IIS one

Usage:
  ./tech404.py http://10.10.10.5 [https://other.target ...]
  ./tech404.py site.local --json -k -t 15
  ./tech404.py -v http://10.10.10.5        full per-probe report

Standard library only (Python 3.7+).
"""

import argparse
import json
import random
import re
import ssl
import string
import urllib.error
import urllib.request

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) tech404/1.0"
MAX_BODY_BYTES = 1 << 20

# Bodies that are plain text rather than HTML.
PLAIN_TEXT_SIGNATURES = [
    ("PHP-FPM", "PHP handler (behind a web server)",
     lambda s: s == "File not found."),
    ("Gin", "Go web framework",
     lambda s: s == "404 page not found"),
    ("AIOHTTP", "Python framework / server",
     lambda s: s == "404: Not Found"),
    ("Fiber", "Go web framework",
     lambda s: re.fullmatch(r"Cannot [A-Z]+ \S+", s) is not None),
]

# HTML fingerprints; `version` is an optional regex searched in the body
# first, then the Server / X-Powered-By headers.
BODY_SIGNATURES = [
    {"name": "nginx", "category": "web server",
     "pattern": r"<center>\s*nginx",
     "version": r"nginx/([\w.\-+]+)"},
    {"name": "Apache httpd", "category": "web server",
     "pattern": r"<address>\s*Apache/",
     "version": r"Apache/([\d.]+(?:\s*\([^)]*\))?)"},
    {"name": "IIS", "category": "web server",
     "pattern": r"404 - File or directory not found",
     "version": r"Microsoft-IIS/([\d.]+)"},
    {"name": "Tomcat", "category": "Java web server",
     "pattern": r"<h1>HTTP Status 404|Apache Tomcat/",
     "version": r"Apache Tomcat/([^<]+)"},
    {"name": "Jetty", "category": "Java web server",
     "pattern": r"ServletHandler\$Default404Servlet|Powered by Eclipse Jetty",
     "version": r"[Jj]etty[\s(/]v?([\d][\w.\-]*)"},
    {"name": "Spring Boot", "category": "Java framework",
     "pattern": r"Whitelabel Error Page"},
    {"name": "ASP.NET", "category": "web framework (.NET)",
     "pattern": r"Server Error in '/[^']*' Application|The resource cannot be found\."},
    {"name": "Blazor", "category": "web framework (.NET)",
     "pattern": r"nothing at this address"},
    {"name": "Laravel", "category": "PHP framework",
     "pattern": r"border-r border-gray-400 tracking-wider"},
    {"name": "Symfony", "category": "PHP framework",
     "pattern": r"Oops! An Error Occurred|An Error Occurred: Not Found"},
    {"name": "Ruby on Rails", "category": "Ruby framework",
     "pattern": r"rails-default-error-page|The page you were looking for doesn"},
    {"name": "Sinatra", "category": "Ruby framework",
     "pattern": r"know this ditty"},
    {"name": "Express", "category": "Node.js framework",
     "pattern": r"<pre>\s*Cannot\s+[A-Z]+\s+\S+"},
    {"name": "NextJS", "category": "Node.js framework (React)",
     "pattern": r"next-error-h1|This page could not be found|__NEXT_DATA__"},
    {"name": "Flask", "category": "Python framework",
     "pattern": r"If you entered the URL manually please check your spelling and try again"},
    {"name": "Django", "category": "Python framework",
     "pattern": r"The requested resource was not found on this server"},
    {"name": "Django (DEBUG mode)", "category": "Python framework",
     "pattern": r"in your Django settings file"},
]

# Fingerprint/supplement via headers, used when the body is a custom page
# or to recover versions the body does not include.
HEADER_SIGNATURES = [
    ("nginx", "web server", "Server", r"nginx(?:/([\w.\-+]+))?"),
    ("Apache httpd", "web server", "Server", r"Apache(?:/([\d.]+))?"),
    ("IIS", "web server", "Server", r"Microsoft-IIS(?:/([\d.]+))?"),
    ("Tomcat", "Java web server", "Server", r"Tomcat(?:/([\d.]+))?"),
    ("Jetty", "Java web server", "Server", r"[Jj]etty(?:[\s(/]v?([\d][\w.\-]*))?"),
    ("Werkzeug", "Python WSGI server", "Server", r"Werkzeug(?:/([\d.]+))?"),
    ("PHP", "scripting language", "X-Powered-By", r"PHP(?:/([\d.\-]+))?"),
    ("Express", "Node.js framework", "X-Powered-By", r"Express"),
    ("ASP.NET", "web framework (.NET)", "X-Powered-By", r"ASP\.NET"),
    ("ASP.NET", "web framework (.NET)", "X-AspNet-Version", r"([\d.]+)"),
]

PROBE_EXTENSIONS = (".php", ".aspx")


def rand_token(length=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def fetch(url, timeout, insecure, user_agent):
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, headers={
        "User-Agent": user_agent,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(MAX_BODY_BYTES).decode("utf-8", "replace")
            return {"status": getattr(resp, "status", None) or resp.getcode(),
                    "headers": resp.headers, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": e.headers, "body": body, "error": None}
    except Exception as e:
        return {"status": None, "headers": {}, "body": "",
                "error": "{}: {}".format(type(e).__name__, e)}


def make_finding(technology, category, version, source, evidence):
    return {"technology": technology, "category": category,
            "version": version or "", "source": source, "evidence": evidence or ""}


def snippet(body, match, width=48):
    start = max(0, match.start() - width)
    end = min(len(body), match.end() + width)
    text = " ".join(body[start:end].split())
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(body) else ""
    return (prefix + text + suffix)[:120]


def search_version(regex, body, headers):
    for text in (body, headers.get("Server") or "", headers.get("X-Powered-By") or ""):
        m = re.search(regex, text, re.IGNORECASE)
        if m:
            groups = [g for g in m.groups() if g]
            if groups:
                return " ".join(groups)
    return ""


def match_fastapi(body):
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if isinstance(data, dict) and data.get("detail") == "Not Found":
        return make_finding("FastAPI / Starlette", "Python framework", "",
                            "404 body (JSON)", '{"detail": "Not Found"}')
    return None


def fingerprint(resp):
    body = resp["body"]
    headers = resp["headers"]
    findings = []

    stripped = body.strip()
    for name, category, predicate in PLAIN_TEXT_SIGNATURES:
        if predicate(stripped):
            findings.append(make_finding(name, category, "",
                                         "404 body (plain text)", stripped[:80]))

    fastapi = match_fastapi(body)
    if fastapi:
        findings.append(fastapi)

    for sig in BODY_SIGNATURES:
        m = re.search(sig["pattern"], body, re.IGNORECASE)
        if not m:
            continue
        version = ""
        if sig.get("version"):
            version = search_version(sig["version"], body, headers)
        findings.append(make_finding(sig["name"], sig["category"], version,
                                     "404 body", snippet(body, m)))

    for name, category, header, regex in HEADER_SIGNATURES:
        value = headers.get(header)
        if not value:
            continue
        m = re.search(regex, value, re.IGNORECASE)
        if not m:
            continue
        version = next((g for g in m.groups() if g), "")
        existing = next((f for f in findings if f["technology"] == name), None)
        if existing:
            if version and not existing["version"]:
                existing["version"] = version
                existing["source"] += " + {} header".format(header)
        else:
            findings.append(make_finding(name, category, version,
                                         "{} header (indirect)".format(header),
                                         value.strip()))
    return findings


def run_probe(base, ext, args):
    path = "/" + rand_token() + ext
    url = base.rstrip("/") + path
    return path, url, fetch(url, args.timeout, args.insecure, args.user_agent)


def scan_target(target, args):
    candidates = ([target] if "://" in target
                  else ["https://" + target, "http://" + target])
    base = None
    first = None
    last_error = None
    for cand in candidates:
        probe = run_probe(cand, "", args)
        if probe[2]["error"] is None:
            base, first = cand, probe
            break
        last_error = probe[2]["error"]
    if base is None:
        return {"target": target, "error": last_error}

    result = {"target": base, "probes": [], "technologies": []}
    seen = set()
    probes = [first] + [run_probe(base, ext, args) for ext in PROBE_EXTENSIONS]

    for path, url, resp in probes:
        entry = {"path": path, "url": url}
        if resp["error"]:
            entry["error"] = resp["error"]
            result["probes"].append(entry)
            continue
        entry["status"] = resp["status"]
        entry["server"] = resp["headers"].get("Server")
        entry["x_powered_by"] = resp["headers"].get("X-Powered-By")
        if resp["status"] != 404:
            entry["note"] = ("status {} (not 404) - the server may serve a "
                             "custom error page").format(resp["status"])
        entry["findings"] = fingerprint(resp)
        result["probes"].append(entry)
        for f in entry["findings"]:
            if f["technology"] not in seen:
                seen.add(f["technology"])
                result["technologies"].append(
                    (f["technology"] + " " + f["version"]).strip())
    return result


def print_report(result):
    bar = "=" * 72
    print()
    print(bar)
    print("Target: " + result["target"])
    print(bar)
    if result.get("error"):
        print("  error: " + result["error"])
        return
    for probe in result["probes"]:
        if "error" in probe:
            print("\n  GET {}  ->  error: {}".format(probe["path"], probe["error"]))
            continue
        print("\n  GET {}  ->  {}".format(probe["path"], probe["status"]))
        if probe.get("note"):
            print("      ! " + probe["note"])
        print("      Server header : " + (probe.get("server") or "-"))
        print("      X-Powered-By  : " + (probe.get("x_powered_by") or "-"))
        if not probe["findings"]:
            print("      (no fingerprint matched)")
        for f in probe["findings"]:
            label = f["technology"] + (" " + f["version"] if f["version"] else "")
            print("      [+] {}  ({})  [{}]".format(label, f["category"], f["source"]))
            if f["evidence"]:
                print("          evidence: " + f["evidence"])
    techs = ", ".join(result["technologies"]) or "none identified"
    print("\n  Technologies: " + techs)


def main():
    ap = argparse.ArgumentParser(
        description="Identify web technologies from their default 404 pages.")
    ap.add_argument("targets", nargs="+", metavar="URL",
                    help="target URL(s); scheme optional (https is tried first)")
    ap.add_argument("-j", "--json", action="store_true",
                    help="print machine-readable JSON instead of text")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the full per-probe report "
                         "(default: only the Technologies summary line)")
    ap.add_argument("-t", "--timeout", type=float, default=10.0,
                    help="per-request timeout in seconds (default: 10)")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="ignore TLS certificate errors")
    ap.add_argument("-A", "--user-agent", default=DEFAULT_UA,
                    help="User-Agent header (default: %(default)s)")
    args = ap.parse_args()

    results = [scan_target(t, args) for t in args.targets]
    if args.json:
        print(json.dumps(results, indent=2))
    elif not args.verbose:
        for r in results:
            if r.get("error"):
                line = "error: " + r["error"]
            else:
                line = "Technologies: " + (
                    ", ".join(r["technologies"]) or "none identified")
            if len(results) > 1:
                print("{}  ->  {}".format(r["target"], line))
            else:
                print(line)
    else:
        for r in results:
            print_report(r)
        print()


if __name__ == "__main__":
    main()
