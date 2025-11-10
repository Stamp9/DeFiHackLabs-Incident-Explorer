#!/usr/bin/env python3
"""
Build/Update rootcause_data.json from local Markdown RCA files.

Input discovery (KISS):
- Looks for Markdown files under ./root/** whose folder name likely contains
  Root Cause content (e.g., 'DeFi Hacks Analysis - Root Cause Analysis',
  or any directory under ./root). It will simply walk ./root and parse *.md.

Output:
- rootcause_data.json at repo root with entries keyed by project title/name.
- Each entry contains: type, date (YYYY-MM-DD), rootCause, images, optional Lost.

Merge behavior (add-on, not overwrite):
- If rootcause_data.json exists, entries are merged by key (title/name).
- New non-empty fields overwrite old ones. Images are merged uniquely.
"""

import os
import re
import json
from typing import Dict, Any, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_ROOT = os.path.join(REPO_ROOT, "root")
OUT_PATH = os.path.join(REPO_ROOT, "rootcause_data.json")


def _format_date(date_str: str) -> str:
    if not date_str:
        return ""
    s = date_str.strip()
    if len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    # Already formatted like YYYY-MM-DD
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return s
    # Try to normalize YYYY.MM.DD
    if re.match(r"^\d{4}\.\d{2}\.\d{2}$", s):
        parts = s.split(".")
        return f"{parts[0]}-{parts[1]}-{parts[2]}"
    return s


def _extract_images(md_content: str, md_file_path: str) -> List[str]:
    images: List[str] = []
    for m in re.finditer(r"!\[[^\]]*\]\(([^)]+)\)", md_content):
        p = m.group(1).strip()
        if p.startswith("http://") or p.startswith("https://"):
            images.append(p)
            continue
        # Make a repository-relative path for local images
        md_dir = os.path.dirname(md_file_path)
        rel = os.path.relpath(os.path.join(md_dir, p), REPO_ROOT)
        images.append(os.path.normpath(rel))
    # De-duplicate preserving order
    seen = set()
    out = []
    for x in images:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _parse_md(md_path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return None

    # Title: prefer 'Title:' line, fallback to first H1 '# ...', then filename
    title = None
    m = re.search(r"^\s*Title:\s*([^\n]+)", content, re.IGNORECASE | re.MULTILINE)
    if m:
        title = m.group(1).strip()
    if not title:
        m = re.search(r"^\s*#\s+([^\n]+)", content, re.MULTILINE)
        if m:
            title = m.group(1).strip()
    if not title:
        title = os.path.splitext(os.path.basename(md_path))[0]

    # Type, Date
    typ = ""
    m = re.search(r"^\s*Type:\s*([^\n]+)", content, re.IGNORECASE | re.MULTILINE)
    if m:
        typ = m.group(1).strip()

    date = ""
    m = re.search(r"^\s*Date:\s*([^\n]+)", content, re.IGNORECASE | re.MULTILINE)
    if m:
        date = _format_date(m.group(1).strip())

    # Lost (free-form) — capture the rest of line; leave as-is
    lost = ""
    m = re.search(r"^\s*Lost:\s*([^\n]+)", content, re.IGNORECASE | re.MULTILINE)
    if m:
        lost = m.group(1).strip()

    # POC link (optional)
    poc = ""
    m = re.search(r"^\s*POC:\s*([^\n]+)", content, re.IGNORECASE | re.MULTILINE)
    if m:
        poc = m.group(1).strip()

    # Root cause: everything after 'Root cause:' (case-insensitive)
    root_cause = ""
    m = re.search(r"^\s*Root\s+[Cc]ause:\s*([\s\S]*?)\Z", content, re.MULTILINE)
    if m:
        root_cause = m.group(1).strip()

    images = _extract_images(content, md_path)

    return {
        "title": title,
        "type": typ,
        "date": date,
        "Lost": lost,  # keep label to align with UI expectations
        "pocLink": poc,
        "rootCause": root_cause,
        "images": images,
    }


def _iter_md_files(root_dir: str) -> List[str]:
    paths: List[str] = []
    if not os.path.isdir(root_dir):
        return paths
    for r, _, files in os.walk(root_dir):
        for f in files:
            if not f.lower().endswith(".md"):
                continue
            # Skip obvious non-RCA docs (tune as needed)
            if f.lower() in {"readme.md"}:
                continue
            paths.append(os.path.join(r, f))
    return paths


def build_rootcause() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    md_files = _iter_md_files(SCAN_ROOT)
    for md in md_files:
        data = _parse_md(md)
        if not data:
            continue
        key = data.get("title")
        if not key:
            continue
        out[key] = {
            "type": data.get("type", ""),
            "date": data.get("date", ""),
            "rootCause": data.get("rootCause", ""),
            "images": data.get("images", []),
        }
        # Include Lost if present
        if data.get("Lost"):
            out[key]["Lost"] = data["Lost"]
        # Optionally include POC link (unused by UI, but harmless)
        if data.get("pocLink"):
            out[key]["POC"] = data["pocLink"]
    return out


def merge_existing(new_data: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(OUT_PATH):
        return new_data
    try:
        with open(OUT_PATH, "r", encoding="utf-8") as f:
            existing = json.load(f)
    except Exception:
        existing = {}

    merged = dict(existing)
    for k, v in new_data.items():
        prev = merged.get(k, {})
        # For each field, prefer new non-empty; merge images uniquely
        out = dict(prev)
        for field in ("type", "date", "rootCause", "Lost", "POC"):
            nv = v.get(field)
            if isinstance(nv, str):
                if nv and nv.strip():
                    out[field] = nv
            elif nv is not None:
                out[field] = nv
        if "images" in v:
            imgs = list(dict.fromkeys((prev.get("images") or []) + (v.get("images") or [])))
            out["images"] = imgs
        merged[k] = out
    return merged


def main():
    if not os.path.isdir(SCAN_ROOT):
        raise SystemExit(
            f"Missing RCA markdown directory at {SCAN_ROOT}. Place RCA markdowns under ./root."
        )

    new_data = build_rootcause()
    merged = merge_existing(new_data)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    print(
        f"Parsed {len(new_data)} RCA entries; merged into {len(merged)} total at {OUT_PATH}"
    )


if __name__ == "__main__":
    main()

