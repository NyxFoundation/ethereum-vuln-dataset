#!/usr/bin/env python3
"""Compare this corpus with the public MineBlockVuln ESEC/FSE 2022 database.

The external SQLite database is not vendored (it is approximately 1.5 GiB).
Download it from the URL documented by VPRLab/BlkVulnDataset, then run:

    UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/compare_mineblockvuln.py \
      --mineblock-db /path/to/BlkVulnDataset.db
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import sqlite3
from pathlib import Path

import pandas as pd


GETH_REF_RE = re.compile(
    r"github\.com/ethereum/go-ethereum/(pull|issues)/(\d+)", re.IGNORECASE
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
TYPE_NAMES = {
    1: "Race Condition",
    2: "Check/Validation",
    3: "Resource Leak",
    4: "Transaction Related",
    5: "Deadlock",
    6: "Go Panic",
    7: "Block Related",
    8: "Denial-of-Service",
    9: "Peer/Node Related",
    10: "Sanity Check",
    11: "Overflow",
    12: "Wallet Key/Password",
    13: "Uninitialized Read",
    14: "RPC Related",
    15: "Out-of-Bound",
    16: "Off-by-One",
    17: "Segfault",
    18: "Memory Pool",
    19: "Nil Pointer Dereference",
    20: "Database Corruption",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_ref(kind: str, number: str | int) -> str:
    normalized = "pull" if str(kind).lower() == "pull" else "issues"
    return f"{normalized}/{int(number)}"


def refs_from_text(value: str) -> set[str]:
    return {canonical_ref(kind, number) for kind, number in GETH_REF_RE.findall(value)}


def parse_legacy_commits(value: str) -> set[str]:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return set()
    if isinstance(parsed, str):
        parsed = {parsed}
    return {str(item).lower() for item in parsed if SHA_RE.match(str(item))}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mineblock-db", required=True, type=Path)
    parser.add_argument(
        "--current",
        type=Path,
        default=Path("data/ethereum_vulns.parquet"),
    )
    parser.add_argument(
        "--raw",
        type=Path,
        default=Path("data/raw/train.classified.parquet"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/paper/tables"),
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(f"file:{args.mineblock_db}?mode=ro", uri=True) as connection:
        legacy = pd.read_sql_query(
            "SELECT REPO, NUMBER, URL, COMMITS, MODULES, TITLE "
            "FROM VULN_ISSUES WHERE REPO = 'ethereum/go-ethereum'",
            connection,
        )
        typed = pd.read_sql_query(
            "SELECT REPO, NUMBER, TITLE, TYPE, COMMITS "
            "FROM TOP20_VULN_ISSUES WHERE REPO = 'ethereum/go-ethereum'",
            connection,
        )

    current_all = pd.read_parquet(args.current)
    current = current_all[current_all["source_platform"].eq("geth")].copy()
    provenance_columns = ["source_url", "evidence", "title", "description"]
    current["provenance_blob"] = (
        current[provenance_columns].fillna("").astype(str).agg(" ".join, axis=1)
    )
    current["refs"] = current["provenance_blob"].map(refs_from_text)
    all_current_blob = (
        current_all[provenance_columns].fillna("").astype(str).agg(" ".join, axis=1)
    )
    all_current_refs = set().union(*all_current_blob.map(refs_from_text))

    raw_all = pd.read_parquet(args.raw)
    raw = raw_all[raw_all["source_platform"].eq("geth")].copy()
    raw_provenance_columns = [
        column
        for column in ["source_url", "evidence", "title", "description"]
        if column in raw.columns
    ]
    raw["provenance_blob"] = (
        raw[raw_provenance_columns].fillna("").astype(str).agg(" ".join, axis=1)
    )
    raw["refs"] = raw["provenance_blob"].map(refs_from_text)
    all_raw_blob = (
        raw_all[raw_provenance_columns].fillna("").astype(str).agg(" ".join, axis=1)
    )
    all_raw_refs = set().union(*all_raw_blob.map(refs_from_text))
    legacy["ref"] = legacy.apply(
        lambda row: canonical_ref(
            "pull" if "/pull/" in str(row["URL"]) else "issues",
            row["NUMBER"],
        ),
        axis=1,
    )
    legacy["commit_set"] = legacy["COMMITS"].fillna("{}").map(parse_legacy_commits)

    legacy_refs = set(legacy["ref"])
    current_refs = set().union(*current["refs"]) if len(current) else set()
    raw_refs = set().union(*raw["refs"]) if len(raw) else set()
    shared_refs = legacy_refs & current_refs
    shared_raw_refs = legacy_refs & raw_refs
    collected_but_not_curated = shared_raw_refs - shared_refs
    absent_from_collection = legacy_refs - raw_refs
    legacy_commits = set().union(*legacy["commit_set"]) if len(legacy) else set()
    current_commits = {
        value.lower()
        for value in current["fix_commit"].fillna("").astype(str)
        if SHA_RE.match(value)
    }
    shared_commits = legacy_commits & current_commits

    summary = [
        ("mineblock_db_sha256", sha256(args.mineblock_db), "", ""),
        ("mineblock_public_geth_vuln_issues", len(legacy), "rows", "VULN_ISSUES"),
        (
            "mineblock_paper_final_geth_vuln_issues",
            365,
            "rows",
            "Table 2 after final invalid-code exclusion",
        ),
        ("mineblock_geth_top20_typed_issues", len(typed), "rows", "TOP20_VULN_ISSUES"),
        ("current_geth_rows", len(current), "rows", "current curated Parquet"),
        ("raw_geth_rows", len(raw), "rows", "raw classified Parquet"),
        ("mineblock_unique_issue_pr_refs", len(legacy_refs), "refs", ""),
        ("current_unique_geth_issue_pr_refs", len(current_refs), "refs", ""),
        ("raw_unique_geth_issue_pr_refs", len(raw_refs), "refs", ""),
        ("shared_issue_pr_refs", len(shared_refs), "refs", "exact URL identity"),
        (
            "shared_issue_pr_refs_any_current_client",
            len(legacy_refs & all_current_refs),
            "refs",
            "sensitivity: Geth refs found anywhere in the curated corpus",
        ),
        (
            "shared_raw_issue_pr_refs",
            len(shared_raw_refs),
            "refs",
            "MineBlockVuln refs found before the current curation gate",
        ),
        (
            "shared_raw_issue_pr_refs_any_client",
            len(legacy_refs & all_raw_refs),
            "refs",
            "sensitivity: Geth refs found anywhere in the raw corpus",
        ),
        (
            "legacy_refs_collected_but_not_curated",
            len(collected_but_not_curated),
            "refs",
            "present in raw snapshot but absent from curated snapshot",
        ),
        (
            "legacy_refs_absent_from_collection",
            len(absent_from_collection),
            "refs",
            "not found in the raw snapshot",
        ),
        (
            "legacy_issue_pr_ref_recall",
            round(len(shared_refs) / len(legacy_refs), 6),
            "fraction",
            "shared / MineBlockVuln refs",
        ),
        (
            "current_issue_pr_ref_overlap",
            round(len(shared_refs) / len(current_refs), 6) if current_refs else 0,
            "fraction",
            "shared / current refs",
        ),
        (
            "raw_legacy_issue_pr_ref_recall",
            round(len(shared_raw_refs) / len(legacy_refs), 6),
            "fraction",
            "shared raw / MineBlockVuln refs",
        ),
        ("mineblock_unique_fix_commits", len(legacy_commits), "commits", ""),
        ("current_geth_unique_fix_commits", len(current_commits), "commits", ""),
        ("shared_fix_commits", len(shared_commits), "commits", "exact SHA identity"),
        (
            "legacy_fix_commit_recall",
            round(len(shared_commits) / len(legacy_commits), 6),
            "fraction",
            "shared / MineBlockVuln commits",
        ),
        (
            "current_fix_commit_overlap",
            round(len(shared_commits) / len(current_commits), 6)
            if current_commits
            else 0,
            "fraction",
            "shared / current Geth fix commits",
        ),
    ]
    pd.DataFrame(
        summary, columns=["metric", "value", "unit", "definition"]
    ).to_csv(args.output_dir / "mineblock_overlap_summary.csv", index=False)

    legacy["current_recall_status"] = legacy["ref"].map(
        lambda ref: (
            "curated_match"
            if ref in shared_refs
            else "raw_only"
            if ref in collected_but_not_curated
            else "not_collected"
        )
    )
    legacy[
        ["ref", "current_recall_status", "TITLE", "URL", "MODULES", "COMMITS"]
    ].sort_values(["current_recall_status", "ref"]).to_csv(
        args.output_dir / "mineblock_recall_decomposition.csv", index=False
    )

    typed["type_name"] = typed["TYPE"].map(TYPE_NAMES)
    type_counts = (
        typed.groupby(["TYPE", "type_name"], dropna=False)
        .size()
        .reset_index(name="mineblock_geth_issues")
        .sort_values("TYPE")
    )
    type_counts.to_csv(args.output_dir / "mineblock_type_counts.csv", index=False)

    current_by_ref: dict[str, list[dict]] = {}
    for row in current.to_dict("records"):
        for ref in row["refs"]:
            current_by_ref.setdefault(ref, []).append(row)

    overlap_rows: list[dict] = []
    for row in legacy[legacy["ref"].isin(shared_refs)].to_dict("records"):
        matches = current_by_ref[row["ref"]]
        overlap_rows.append(
            {
                "ref": row["ref"],
                "mineblock_title": row["TITLE"],
                "current_rows": len(matches),
                "current_ids": "|".join(sorted({str(item["id"]) for item in matches})),
                "current_titles": " | ".join(
                    sorted({str(item["title"]) for item in matches})
                ),
                "current_root_causes": "|".join(
                    sorted({str(item["root_cause"]) for item in matches})
                ),
                "current_labels": "|".join(
                    sorted({str(item["label"]) for item in matches})
                ),
            }
        )
    pd.DataFrame(overlap_rows).sort_values("ref").to_csv(
        args.output_dir / "mineblock_overlap_rows.csv", index=False
    )

    typed["ref"] = typed["NUMBER"].map(lambda number: canonical_ref("issues", number))
    # MineBlockVuln's NUMBER does not retain pull-vs-issue in TOP20; match either.
    crosswalk_rows: list[dict] = []
    for row in typed.to_dict("records"):
        candidate_refs = {
            canonical_ref("issues", row["NUMBER"]),
            canonical_ref("pull", row["NUMBER"]),
        }
        matches = [
            item
            for ref in candidate_refs
            for item in current_by_ref.get(ref, [])
        ]
        for item in matches:
            crosswalk_rows.append(
                {
                    "mineblock_type": int(row["TYPE"]),
                    "mineblock_type_name": TYPE_NAMES.get(int(row["TYPE"]), "Unknown"),
                    "current_root_cause": item["root_cause"],
                    "current_label": item["label"],
                    "ref": next(ref for ref in candidate_refs if ref in current_by_ref),
                }
            )
    crosswalk = pd.DataFrame(crosswalk_rows)
    if not crosswalk.empty:
        crosswalk = (
            crosswalk.groupby(
                [
                    "mineblock_type",
                    "mineblock_type_name",
                    "current_root_cause",
                    "current_label",
                ]
            )
            .size()
            .reset_index(name="matched_current_rows")
            .sort_values(
                ["mineblock_type", "matched_current_rows"],
                ascending=[True, False],
            )
        )
    crosswalk.to_csv(args.output_dir / "mineblock_type_crosswalk.csv", index=False)

    print(
        "MineBlockVuln comparison:",
        f"{len(shared_refs)}/{len(legacy_refs)} issue/PR refs,",
        f"{len(shared_commits)}/{len(legacy_commits)} commits shared",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
