#!/usr/bin/env python3
"""
del-git-repo.py
----------------------------
Find all forks of a deleted GitHub user's repos by scraping the
"forked from <username>/<repo>" text directly from each fork's GitHub page.

This is the most reliable method for deleted users because:
  - GitHub still renders "forked from userx/repo-y"
    on the fork's page even after the original is deleted
  - No API ancestry chain needed — one HTML check per candidate fork
  - Then we fetch the real tip SHA to find which forks are up to date

Usage:
    python3 del-git-repo.py <username> [--token TOKEN] [--all] [--json]
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("❌  pip install requests")

BASE = "https://api.github.com"
GITHUB_BASE = "https://github.com"
SEARCH_PAGE_SIZE = 100

FF_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)


FORK_RE = re.compile(
    r'forked from\s+<a[^>]+href="/([^/]+)/([^"]+)"',
    re.IGNORECASE,
)


# ── Session ───────────────────────────────────────────────────────────────────

def make_session(token: str | None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = FF_UA
    s.headers["Accept"] = "application/vnd.github+json"
    s.headers["X-GitHub-Api-Version"] = "2022-11-28"
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def rate_limit_wait(resp: requests.Response) -> None:
    remaining = int(resp.headers.get("X-RateLimit-Remaining", 10))
    if remaining < 5:
        reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait = max(reset_ts - int(time.time()), 1) + 2
        print(f"  ⏳ Rate limit low ({remaining} left). Sleeping {
              wait}s …", flush=True)
        time.sleep(wait)


def gh_get(session, url, params=None):
    resp = session.get(url, params=params or {})
    rate_limit_wait(resp)
    try:
        body = resp.json()
    except Exception:
        body = {}
    return resp.status_code, body


# ── Scrape "forked from" from the HTML page ───────────────────────────────────

def scrape_forked_from(session: requests.Session,
                       full_name: str) -> tuple[str, str] | None:
    """
    GET https://github.com/<full_name> and look for:
      forked from <a href="/<owner>/<repo>">

    Returns (owner, repo) or None.
    """
    url = f"{GITHUB_BASE}/{full_name}"
    # Use a plain Accept for HTML
    resp = session.get(url, headers={"Accept": "text/html"}, timeout=15)
    if resp.status_code != 200:
        return None
    m = FORK_RE.search(resp.text)
    if m:
        return m.group(1), m.group(2)
    return None


# ── Tip commit via Git refs API ───────────────────────────────────────────────

def get_tip_commit(session, full_name, branch):
    sha = None
    code, ref_data = gh_get(
        session, f"{BASE}/repos/{full_name}/git/refs/heads/{branch}"
    )
    if code == 200:
        if isinstance(ref_data, list):
            for r in ref_data:
                if r.get("ref") == f"refs/heads/{branch}":
                    sha = r.get("object", {}).get("sha")
                    break
        elif isinstance(ref_data, dict):
            sha = ref_data.get("object", {}).get("sha")

    if sha:
        code2, obj = gh_get(
            session, f"{BASE}/repos/{full_name}/git/commits/{sha}")
        if code2 == 200:
            date = (obj.get("committer", {}).get("date")
                    or obj.get("author",    {}).get("date"))
            msg = obj.get("message", "").split("\n")[0][:72]
            return {"sha": sha, "date": date, "message": msg}

    # fallback
    code, data = gh_get(session, f"{BASE}/repos/{full_name}/commits",
                        {"per_page": 1, "sha": branch})
    if code == 200 and isinstance(data, list) and data:
        c = data[0]
        sha = c.get("sha", "")
        date = (c.get("commit", {}).get("committer", {}).get("date")
                or c.get("commit", {}).get("author",    {}).get("date"))
        msg = c.get("commit", {}).get("message", "").split("\n")[0][:72]
        return {"sha": sha, "date": date, "message": msg}

    return {"sha": None, "date": None, "message": None}


def commits_behind_count(session, full_name, fork_sha, tip_sha):
    if not tip_sha or not fork_sha or tip_sha == fork_sha:
        return 0
    code, data = gh_get(
        session, f"{BASE}/repos/{full_name}/compare/{fork_sha}...{tip_sha}"
    )
    if code == 200:
        return data.get("ahead_by")
    return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_iso(iso):
    if not iso:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def fmt_dt(iso):
    if not iso:
        return "unknown"
    try:
        return datetime.fromisoformat(
            iso.replace("Z", "+00:00")
        ).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso or "unknown"


# ── Phase 1: discover repo names via search ───────────────────────────────────

def discover_repo_names(session, username):
    print(f"🔍 Searching GitHub for repos linked to '{username}' …")
    names = set()
    page = 1
    while True:
        code, data = gh_get(session, f"{BASE}/search/repositories", {
            "q":        f"{username} fork:true",
            "sort":     "updated",
            "order":    "desc",
            "per_page": SEARCH_PAGE_SIZE,
            "page":     page,
        })
        if code == 422:
            print("  ℹ️  Hit GitHub's 1 000-result search cap.")
            break
        if code != 200:
            print(f"  ⚠️  Search HTTP {code}.")
            break
        items = data.get("items", [])
        if page == 1:
            print(f"  → {data.get('total_count', '?')} total search hits.")
        for repo in items:
            if repo.get("fork"):
                names.add(repo["name"])
        if len(items) < SEARCH_PAGE_SIZE:
            break
        page += 1
        time.sleep(0.2)
    print(f"  → {len(names)} unique repo name(s) to investigate.\n")
    return names


# ── Phase 2: for each repo name, find + confirm forks via HTML scrape ─────────

def process_repo(session, username, repo_name, show_all):
    print(f"📦 [{repo_name}]")

    # Search for all forks of this repo name, newest-updated first
    raw_candidates = []
    page = 1
    while True:
        code, data = gh_get(session, f"{BASE}/search/repositories", {
            "q":        f"{repo_name} fork:true",
            "sort":     "updated",
            "order":    "desc",
            "per_page": SEARCH_PAGE_SIZE,
            "page":     page,
        })
        if code == 422 or code != 200:
            break
        for item in data.get("items", []):
            if item.get("fork") and item["name"].lower() == repo_name.lower():
                raw_candidates.append(item)
        if len(data.get("items", [])) < SEARCH_PAGE_SIZE:
            break
        page += 1
        time.sleep(0.2)

    if not raw_candidates:
        print(f"  ⚠️  No forks found in search. Skipping.\n")
        return None

    print(f"  → {len(raw_candidates)
                 } candidate(s). Scraping 'forked from' on each page …")

    # Scrape each fork's GitHub HTML page to confirm "forked from <username>/<repo>"
    confirmed = []
    for item in raw_candidates:
        full_name = item["full_name"]
        result = scrape_forked_from(session, full_name)
        if result:
            origin_owner, origin_repo = result
            if origin_owner.lower() == username.lower():
                # Accept regardless of repo name — the fork may have been renamed
                item["_origin_repo"] = origin_repo
                confirmed.append(item)
                print(f"    ✅ {full_name}  ← forked from {
                      origin_owner}/{origin_repo}")
            else:
                print(f"    ·  {full_name}  ← forked from {
                      origin_owner}/{origin_repo} (skip)")
        else:
            # No "forked from" found on page — could be the page changed or
            # the fork is so old GitHub stopped showing it. Skip.
            print(f"    ·  {full_name}  ← no 'forked from' found (skip)")
        time.sleep(0.3)   # polite delay between HTML page fetches

    if not confirmed:
        print(f"  ℹ️  No forks confirmed as 'forked from {
              username}/<repo>'.\n")
        return None

    print(f"\n  → {len(confirmed)} confirmed fork(s). Fetching tip commits …")

    # Fetch real tip commit for each confirmed fork
    enriched = []
    for item in confirmed:
        fn = item["full_name"]
        branch = item.get("default_branch", "main")
        tip = get_tip_commit(session, fn, branch)
        enriched.append({
            "full_name":   fn,
            "html_url":    item["html_url"],
            "branch":      branch,
            "stars":       item.get("stargazers_count", 0),
            "forks":       item.get("forks_count", 0),
            "updated_at":  item.get("updated_at"),
            "tip_sha":     tip["sha"],
            "tip_date":    tip["date"],
            "tip_message": tip["message"],
            "_tip_dt":     parse_iso(tip["date"]),
        })
        time.sleep(0.15)

    # Sort by real commit date (newest first)
    enriched.sort(key=lambda r: r["_tip_dt"], reverse=True)

    global_sha = enriched[0]["tip_sha"]
    global_date = enriched[0]["tip_date"]
    sha_short = (global_sha or "?")[:12]

    # Classify
    up_to_date, behind, unknown = [], [], []
    for fork in enriched:
        sha = fork["tip_sha"]
        if sha is None:
            fork["status"] = "unknown"
            fork["commits_behind"] = None
            unknown.append(fork)
        elif sha == global_sha:
            fork["status"] = "up_to_date"
            fork["commits_behind"] = 0
            up_to_date.append(fork)
        else:
            n = commits_behind_count(
                session, fork["full_name"], sha, global_sha)
            fork["status"] = "behind"
            fork["commits_behind"] = n
            behind.append(fork)
        time.sleep(0.1)

    # Print
    print(f"\n  🌐 Global tip SHA  : {sha_short}")
    print(f"  🌐 Global tip date : {fmt_dt(global_date)}")
    print(f"  ✅ Up to date      : {len(up_to_date)}")
    print(f"  ⬇️  Behind          : {len(behind)}")
    if unknown:
        print(f"  ❓ Unknown         : {len(unknown)}")
    print()

    if up_to_date:
        print(f"  ── UP-TO-DATE FORKS {'─'*38}")
        for i, f in enumerate(up_to_date, 1):
            sha_s = (f["tip_sha"] or "?")[:12]
            print(f"  {i}. 🟰 {f['full_name']}")
            print(f"       SHA        : {sha_s}")
            print(f"       Commit date: {fmt_dt(f['tip_date'])}")
            print(f"       Message    : {f['tip_message'] or '—'}")
            print(f"       Stars ⭐{f['stars']}   Forks 🍴{f['forks']}")
            print(f"       URL        : {f['html_url']}")
    else:
        print(f"  ❌ No up-to-date forks found.")

    if show_all and behind:
        print(f"\n  ── BEHIND FORKS {'─'*43}")
        for f in behind:
            sha_s = (f["tip_sha"] or "?")[:12]
            n = f["commits_behind"]
            n_str = f"{
                n} commit(s) behind" if n is not None else "? commits behind"
            print(f"  ⬇️  {f['full_name']}")
            print(f"       SHA        : {sha_s}  ({n_str})")
            print(f"       Commit date: {fmt_dt(f['tip_date'])}")
            print(f"       URL        : {f['html_url']}")

    print()

    for f in enriched:
        f.pop("_tip_dt", None)

    # Collect the real original repo names from the "forked from" scrape
    # (may differ from repo_name if the fork was renamed)
    origin_repos = list({c.get("_origin_repo", repo_name) for c in confirmed})
    original = f"{username}/{', '.join(origin_repos)}"

    return {
        "original_repo":    original,
        "searched_name":    repo_name,
        "global_tip_sha":   global_sha,
        "global_tip_date":  global_date,
        "up_to_date_forks": up_to_date,
        "behind_forks":     behind if show_all else [],
        "unknown_forks":    unknown,
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Find forks of a deleted GitHub user using 'forked from' page scraping."
    )
    ap.add_argument("username",      help="Deleted GitHub username")
    ap.add_argument("--token", "-t", default=None,
                    help="GitHub PAT (recommended – 5 000 req/h vs 60/h)")
    ap.add_argument("--json",  "-j", action="store_true", dest="output_json")
    ap.add_argument("--all",   "-a", action="store_true",
                    help="Show behind forks too with commit distance")
    args = ap.parse_args()

    session = make_session(args.token)

    code, _ = gh_get(session, f"{BASE}/users/{args.username}")
    if code == 404:
        print(f"✅ '{args.username}' does not exist on GitHub (deleted).\n")
    elif code == 200:
        print(f"ℹ️  '{args.username}' still exists on GitHub.\n")
    else:
        print(f"⚠️  GitHub returned HTTP {code} for user lookup.\n")

    repo_names = discover_repo_names(session, args.username)
    if not repo_names:
        print("❌ No repo names found.")
        sys.exit(1)

    all_results = []
    for name in sorted(repo_names):
        result = process_repo(session, args.username, name, args.all)
        if result:
            all_results.append(result)

    print("=" * 60)
    total_utd = sum(len(r["up_to_date_forks"]) for r in all_results)
    print(f"Summary : {len(all_results)} repo(s) | {
          total_utd} up-to-date fork(s)")
    print(f"User    : '{args.username}'")
    print("=" * 60)

    if args.output_json:
        print("\n── JSON ──")
        print(json.dumps(all_results, indent=2, default=str))


if __name__ == "__main__":
    main()
