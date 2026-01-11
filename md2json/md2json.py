#!/usr/bin/env python3
import json, re, sys

try:
    import yaml  # python3 -m pip install pyyaml
except ImportError:
    print("Missing dependency: pyyaml (install: python3 -m pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*(?:\n|$)", re.DOTALL)

def ensure_nl(s: str) -> str:
    return s if s.endswith("\n") else s + "\n"

def extract_frontmatter(text: str) -> str:
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("No YAML front-matter at file start (expected '---').")
    return m.group(1)

def convert(md_text: str) -> dict:
    yml = extract_frontmatter(md_text)
    data = yaml.safe_load(yml) or {}
    if not isinstance(data, dict) or "functions" not in data or not isinstance(data["functions"], dict):
        raise ValueError("Front-matter must contain 'functions:' mapping.")

    out = {"functions": {}}
    for func, entries in data["functions"].items():
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ValueError(f"functions.{func} must be a list.")
        arr = []
        for i, ent in enumerate(entries):
            if not isinstance(ent, dict) or "code" not in ent or not isinstance(ent["code"], str):
                raise ValueError(f"functions.{func}[{i}] must have string field 'code'.")
            desc = ent.get("description", "")
            if desc is None:
                desc = ""
            if not isinstance(desc, str):
                raise ValueError(f"functions.{func}[{i}].description must be a string.")
            arr.append({"description": desc, "code": ensure_nl(ent["code"])})
        out["functions"][str(func)] = arr

    return out

def main() -> int:
    md = sys.stdin.read()
    try:
        obj = convert(md)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(obj, indent=2, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
