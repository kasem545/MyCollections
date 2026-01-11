#!/usr/bin/env python3
import argparse
import os
import re
import sys
from typing import Set, Tuple
import requests

# ---- CONFIG: set repo once ----
OWNER = "OWNER" # CHANGE ME
REPO  = "REPO" # CHANGE ME
# --------------------------------

BLOB_LINK_RE = re.compile(
    r'href="(/[^/]+/[^/]+/blob/([0-9a-f]{7,40})/([^"#?]+))"'
)

def die(msg: str, code: int = 1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def pr_files_url(pr: int) -> str:
    return f"https://github.com/{OWNER}/{REPO}/pull/{pr}/files"

def raw_url(sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{sha}/{path}"

def parse_range(s: str) -> Tuple[int, int]:
    m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", s)
    if not m:
        die(f"Invalid range '{s}'. Use like 520-525.")
    a, b = int(m.group(1)), int(m.group(2))
    return (a, b) if a <= b else (b, a)

def read_pr_file(path: str) -> Set[int]:
    if not os.path.isfile(path):
        die(f"PR file not found: {path}")

    prs = set()
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.isdigit():
                die(f"Invalid PR number in {path}:{lineno} -> '{line}'")
            prs.add(int(line))
    return prs

def unique_name(base: str, used: Set[str]) -> str:
    if base not in used and not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    i = 2
    while True:
        cand = f"{root}_{i}{ext}"
        if cand not in used and not os.path.exists(cand):
            return cand
        i += 1

def fetch_files(session: requests.Session, pr: int, timeout: int):
    url = pr_files_url(pr)
    print(f"[*] Fetching PR #{pr}")
    r = session.get(url, timeout=timeout)
    if r.status_code != 200:
        print(f"[!] PR #{pr}: HTTP {r.status_code}", file=sys.stderr)
        return set()
    return {(sha, path) for _, sha, path in BLOB_LINK_RE.findall(r.text)}

def main():
    ap = argparse.ArgumentParser(
        description="Download files changed in GitHub PR(s) using PR numbers only."
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pr", type=int, help="Single PR number")
    src.add_argument("--range", dest="pr_range", help="PR range like 520-525")
    src.add_argument("--pr-file", help="File with PR numbers (one per line)")

    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                    help="GitHub token (or env GITHUB_TOKEN)")
    ap.add_argument("--timeout", type=int, default=30)

    ap.add_argument("--conflict", choices=["rename", "overwrite", "skip"],
                    default="rename", help="Filename collision handling")
    ap.add_argument("--dry-run", action="store_true")

    args = ap.parse_args()

    # ---- build PR set ----
    prs: Set[int] = set()

    if args.pr is not None:
        prs.add(args.pr)
    elif args.pr_range:
        a, b = parse_range(args.pr_range)
        prs.update(range(a, b + 1))
    else:
        prs = read_pr_file(args.pr_file)

    prs = sorted(prs)
    if not prs:
        die("No PRs to process")

    headers = {
        "User-Agent": "pr-files-downloader/3.0",
        "Accept": "text/html",
    }
    if args.token:
        headers["Authorization"] = f"token {args.token}"

    session = requests.Session()
    session.headers.update(headers)

    used_names: Set[str] = set()
    total_found = total_dl = 0

    for pr in prs:
        files = fetch_files(session, pr, args.timeout)
        if not files:
            continue

        print(f"[*] PR #{pr}: {len(files)} file(s)")
        total_found += len(files)

        for sha, path in sorted(files):
            base = os.path.basename(path)
            dest = base

            if dest in used_names or os.path.exists(dest):
                if args.conflict == "skip":
                    print(f"[=] SKIP {base}")
                    continue
                elif args.conflict == "rename":
                    dest = unique_name(base, used_names)

            url = raw_url(sha, path)
            print(f"[+] {url} -> {dest}")

            if args.dry_run:
                used_names.add(dest)
                continue

            r = session.get(url, timeout=args.timeout)
            if r.status_code != 200:
                print(f"[!] Failed: {url}", file=sys.stderr)
                continue

            with open(dest, "wb") as f:
                f.write(r.content)

            used_names.add(dest)
            total_dl += 1

    print(f"[*] Done. Found {total_found} file(s). Downloaded {total_dl}.")

if __name__ == "__main__":
    try:
        import requests  # noqa
    except ImportError:
        die("Missing dependency: requests (pip install requests)")
    main()

