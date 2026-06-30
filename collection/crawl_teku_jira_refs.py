#!/usr/bin/env python3
"""crawl_teku_jira_refs.py — Dedicated Teku Jira-reference PR crawler (T21).

Consensys/teku uses Jira for issue tracking and does NOT use GitHub labels
consistently — the existing `crawl_eth_past_fixes.py` body_keyword_only
strategy only returned 1 row for teku because it relied on label-based
filtering.

This script uses `gh search prs` (which IS indexed for Consensys/teku) to
find merged PRs that contain:
  - TEKU-NNNNN Jira refs in title or body (~97 PRs)
  - semantic-release `fix:` commits in title (~21 PRs)
  - General `Fix` commits in title (~21 PRs)
  - Java assertion errors in body (~4 PRs)
  - Security CHANGELOG mentions in body (~6 PRs)

All queries are deduplicated by PR number. The TEKU-NNNNN pattern is
extracted from title/body as the `issue_id`; for PRs without a Jira ref
the issue_id falls back to "PR#{number}".

Output:
    <out-dir>/teku.jira_refs.csv
    <out-dir>/teku.jira_refs.crawl_manifest.json

CSV schema matches `scripts/datasets/merge_crawl_csvs.py` (old-schema with
`source` column — merge_crawl_csvs.py normalises to source_platform).

Usage:
    uv run python3 benchmarks/scripts/crawl_teku_jira_refs.py \\
        --out-dir C:\\tmp\\teku_jira
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TEKU_REPO = "Consensys/teku"

# Queries for `gh search prs --repo Consensys/teku --merged`.
# Each tuple is (search_string, limit).
TEKU_QUERIES: list[tuple[str, int]] = [
    ("TEKU- in:title,body", 500),       # Jira refs: ~97 PRs
    ("fix: in:title", 500),             # semantic-release fix commits: ~21 PRs
    ("Fix in:title", 500),              # General fixes: ~21 PRs
    ("assertion in:body", 500),         # Java assertion errors: ~4 PRs
    ("CHANGELOG security in:body", 500),# Security changelog mentions: ~6 PRs
]

# Pattern for extracting TEKU-NNNNN from title or body.
TEKU_JIRA_RE = re.compile(r"\bTEKU-(\d+)\b", re.IGNORECASE)

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)


def gh_json(args: list[str], timeout: int = 120):
    """Run `gh` and return parsed JSON, or None on error."""
    try:
        result = subprocess.run(
            ["gh", *args],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  [warn] gh failed: {e}", file=sys.stderr)
        return None
    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:300]
        print(f"  [warn] gh exit {result.returncode}: {msg}", file=sys.stderr)
        return None
    body = result.stdout.strip()
    if not body:
        return []
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        print(f"  [warn] gh output not JSON: {e}", file=sys.stderr)
        return None


def extract_jira_id(title: str, body: str) -> str | None:
    """Return the first TEKU-NNNNN found in title then body, or None."""
    for text in (title, body):
        m = TEKU_JIRA_RE.search(text)
        if m:
            return f"TEKU-{m.group(1)}"
    return None


def crawl_teku_jira_refs(max_results: int = 500) -> list[dict]:
    """Run all TEKU_QUERIES against Consensys/teku and return deduplicated rows."""
    seen: set[int] = set()
    rows: list[dict] = []

    for i, (query_str, limit) in enumerate(TEKU_QUERIES):
        if i > 0:
            time.sleep(2)  # search API rate-limit guard

        print(
            f"  [T21] teku query {i+1}/{len(TEKU_QUERIES)}: {query_str!r}",
            file=sys.stderr,
        )
        chunk = gh_json([
            "search", "prs",
            "--repo", TEKU_REPO,
            "--merged",
            "--json", "number,title,body,url,closedAt",
            "--limit", str(limit),
            query_str,
        ])
        if not isinstance(chunk, list):
            print(
                f"  [T21] query {query_str!r} returned no results",
                file=sys.stderr,
            )
            continue

        new_in_query = 0
        for item in chunk:
            num = item.get("number")
            if num is None or num in seen:
                continue
            seen.add(num)
            title = (item.get("title") or "").strip()
            body = (item.get("body") or "").strip()
            if not title and not body:
                continue

            jira_id = extract_jira_id(title, body)
            issue_id = jira_id if jira_id else f"PR#{num}"

            rows.append({
                "source": "teku",
                "contest": "jira_reference",
                "issue_id": issue_id,
                "severity": "Unrated",
                "title": title,
                "description": body,
                "source_url": (item.get("url") or "").strip(),
                "introduced_in_commit": "",
            })
            new_in_query += 1

        print(
            f"  [T21] query {query_str!r} => {len(chunk)} returned, "
            f"{new_in_query} new (running total: {len(rows)})",
            file=sys.stderr,
        )

    print(
        f"  [T21] teku jira refs: {len(rows)} unique PRs from "
        f"{len(TEKU_QUERIES)} queries",
        file=sys.stderr,
    )
    return rows


def write_csv(rows: list[dict], out_path: Path) -> int:
    """Write rows to out_path in canonical column order. Returns row count."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})
            n += 1
    return n


def write_manifest(
    out_path: Path,
    *,
    n_rows: int,
    n_queries: int,
) -> None:
    """Write a provenance manifest JSON next to the CSV."""
    gh_version = ""
    try:
        v = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if v.returncode == 0:
            gh_version = v.stdout.strip().splitlines()[0]
    except Exception:
        pass

    manifest = {
        "client": "teku",
        "repo": TEKU_REPO,
        "n_rows": n_rows,
        "n_queries": n_queries,
        "queries": [q for q, _ in TEKU_QUERIES],
        "sources": [
            f"https://github.com/{TEKU_REPO}/pulls (gh search prs)",
        ],
        "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version": gh_version,
        "script": "benchmarks/scripts/crawl_teku_jira_refs.py",
        "task": "T21",
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--out-dir",
        default="C:\\tmp\\teku_jira",
        help="Output directory for teku.jira_refs.csv + manifest.",
    )
    p.add_argument(
        "--max-results", type=int, default=500,
        help="Per-query --limit for gh search prs (default 500).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Run queries but do not write output files.",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    print(f"[T21] crawling teku Jira-reference PRs on {TEKU_REPO}...", file=sys.stderr)
    rows = crawl_teku_jira_refs(max_results=args.max_results)

    if args.dry_run:
        print(f"[T21] dry-run: {len(rows)} rows found, not written", file=sys.stderr)
        return 0

    csv_path = out_dir / "teku.jira_refs.csv"
    manifest_path = out_dir / "teku.jira_refs.crawl_manifest.json"

    n = write_csv(rows, csv_path)
    write_manifest(manifest_path, n_rows=n, n_queries=len(TEKU_QUERIES))

    print(f"[T21] wrote {n} rows -> {csv_path}", file=sys.stderr)
    print(f"[T21] manifest -> {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
