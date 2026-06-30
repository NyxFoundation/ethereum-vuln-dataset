#!/usr/bin/env python3
"""merge_cve.py — Merge CVE CSV files into train.parquet.

Reads all <client>.cve.csv from the cve/ subfolder, normalizes columns to
match train.parquet schema, deduplicates on (source_platform, issue_id),
and appends new rows.

Usage:
    uv run python3 scripts/datasets/merge_cve.py \
        --cve-dir dataset/ethereum_past_fixes/cve \
        --parquet dataset/ethereum_past_fixes/train.parquet \
        --out dataset/ethereum_past_fixes/train.parquet
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("Run: uv add pandas pyarrow")

REQUIRED_PARQUET_COLS = [
    "id", "source_platform", "contest", "issue_id", "severity",
    "title", "description", "source_url", "introduced_in_commit",
    "domain", "scraped_at", "stride", "cwe_top25",
]


def make_id(source_platform: str, issue_id: str) -> str:
    return hashlib.md5(f"{source_platform}:{issue_id}".encode()).hexdigest()[:16]


def load_cve_csvs(cve_dir: Path) -> list[dict]:
    rows = []
    now = datetime.now(timezone.utc).isoformat()
    for csv_path in sorted(cve_dir.glob("*.cve.csv")):
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                source_platform = row.get("source", "").strip()
                issue_id = row.get("issue_id", "").strip()
                if not source_platform or not issue_id:
                    continue
                rows.append({
                    "id": make_id(source_platform, issue_id),
                    "source_platform": source_platform,
                    "contest": row.get("contest", "nvd").strip(),
                    "issue_id": issue_id,
                    "severity": row.get("severity", "Info").strip() or "Info",
                    "title": row.get("title", "").strip(),
                    "description": row.get("description", "").strip(),
                    "source_url": row.get("source_url", "").strip(),
                    "introduced_in_commit": row.get("introduced_in_commit", "").strip(),
                    "domain": "ethereum",
                    "scraped_at": now,
                    "stride": "Other",
                    "cwe_top25": "N/A",
                })
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cve-dir", default="dataset/ethereum_past_fixes/cve", type=Path)
    p.add_argument("--parquet", default="dataset/ethereum_past_fixes/train.parquet", type=Path)
    p.add_argument("--out", default="dataset/ethereum_past_fixes/train.parquet", type=Path)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    cve_rows = load_cve_csvs(args.cve_dir)
    print(f"[merge_cve] loaded {len(cve_rows)} CVE rows from {args.cve_dir}", file=sys.stderr)

    df = pd.read_parquet(args.parquet)
    print(f"[merge_cve] existing parquet: {len(df)} rows", file=sys.stderr)

    existing_ids = set(df["id"].tolist())
    new_rows = [r for r in cve_rows if r["id"] not in existing_ids]
    print(f"[merge_cve] new (deduplicated): {len(new_rows)} rows", file=sys.stderr)

    if not new_rows:
        print("[merge_cve] nothing to add — parquet unchanged", file=sys.stderr)
        return 0

    if args.dry_run:
        print(f"[dry-run] would add {len(new_rows)} rows; skipping write", file=sys.stderr)
        return 0

    new_df = pd.DataFrame(new_rows)[REQUIRED_PARQUET_COLS]
    merged = pd.concat([df, new_df], ignore_index=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    merged.to_parquet(args.out, index=False)
    print(f"[merge_cve] wrote {args.out} ({len(merged)} rows, +{len(new_rows)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
