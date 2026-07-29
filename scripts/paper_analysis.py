#!/usr/bin/env python3
"""Generate publication-analysis tables from one frozen curated snapshot.

Run from the repository root:

    UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/paper_analysis.py

The outputs under ``docs/paper/tables`` are intentionally small CSV files so
that every number cited by the paper-facing documentation is reviewable in git.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd


RATED = {"critical", "high", "medium", "low"}
ADVISORY_ID_RE = re.compile(
    r"CVE-\d{4}-\d{4,7}"
    r"|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|RUSTSEC-\d{4}-\d{4}",
    re.IGNORECASE,
)
CVE_GHSA_RE = re.compile(r"CVE-|GHSA-")
PROVENANCE_FIELDS = [
    "title",
    "description",
    "issue_id",
    "contest",
    "source_url",
    "evidence",
]

# MITRE's 2025 CWE Top 25, archived 2025-12-15.
# https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
CWE_TOP_25_2025 = {
    "CWE-79",
    "CWE-89",
    "CWE-352",
    "CWE-862",
    "CWE-787",
    "CWE-22",
    "CWE-416",
    "CWE-125",
    "CWE-78",
    "CWE-94",
    "CWE-120",
    "CWE-434",
    "CWE-476",
    "CWE-121",
    "CWE-502",
    "CWE-122",
    "CWE-863",
    "CWE-20",
    "CWE-284",
    "CWE-200",
    "CWE-306",
    "CWE-918",
    "CWE-77",
    "CWE-639",
    "CWE-770",
}


def pct(count: int, denominator: int) -> float:
    return round(100.0 * count / denominator, 3) if denominator else 0.0


def metric(name: str, count: int, denominator: int, definition: str) -> dict:
    return {
        "metric": name,
        "count": int(count),
        "denominator": int(denominator),
        "percent": pct(int(count), int(denominator)),
        "definition": definition,
    }


def write_counts(series: pd.Series, path: Path, column: str) -> None:
    out = series.rename_axis(column).reset_index(name="count")
    out["percent"] = (100.0 * out["count"] / out["count"].sum()).round(3)
    out.to_csv(path, index=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/ethereum_vulns.parquet"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/paper/tables"),
    )
    args = parser.parse_args()

    df = pd.read_parquet(args.input)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    n = len(df)

    title_description = (
        df["title"].fillna("").astype(str)
        + " "
        + df["description"].fillna("").astype(str)
    )
    provenance_blob = df[PROVENANCE_FIELDS].fillna("").astype(str).agg(" ".join, axis=1)

    rated = df["severity"].fillna("").str.lower().isin(RATED)
    # Reproduces the narrow definition used by scripts/make_figures.py.
    narrow_cve_ghsa = title_description.str.contains(CVE_GHSA_RE)
    # Publication-facing definition: recognized IDs in any provenance field.
    any_advisory_id = provenance_blob.str.contains(ADVISORY_ID_RE)
    narrow_neither = ~(rated | narrow_cve_ghsa)
    broad_neither = ~(rated | any_advisory_id)

    cwe = df["cwe_top25"].fillna("N/A").astype(str)
    cwe_known = cwe.ne("N/A")
    cwe_top25 = cwe.isin(CWE_TOP_25_2025)
    cwe_known_not_top25 = cwe_known & ~cwe_top25

    fix_commit = df["fix_commit"].fillna("").astype(str).str.len().gt(0)
    post_code = ~df["post_fix_code"].fillna("[]").astype(str).isin({"", "[]", "nan"})
    source_upstream = df["severity_source"].eq("upstream-cvss")
    upstream_rated = source_upstream & rated
    upstream_unrated = source_upstream & ~rated

    rows = [
        metric("rows", n, n, "all curated rows in the frozen Parquet snapshot"),
        metric(
            "authority_A",
            df["authority_tier"].eq("A_authoritative").sum(),
            n,
            "authority_tier == A_authoritative",
        ),
        metric(
            "authority_A_or_B",
            df["authority_tier"].isin({"A_authoritative", "B_corroborated"}).sum(),
            n,
            "the essential slice",
        ),
        metric("rated_severity", rated.sum(), n, "Critical/High/Medium/Low"),
        metric(
            "cve_ghsa_in_title_or_description",
            narrow_cve_ghsa.sum(),
            n,
            "case-sensitive CVE-/GHSA- token; reproduces make_figures.py",
        ),
        metric(
            "recognized_advisory_id_any_provenance",
            any_advisory_id.sum(),
            n,
            "case-insensitive CVE/GHSA/RUSTSEC ID in title, description, issue_id, "
            "contest, source_url, or evidence",
        ),
        metric(
            "neither_rated_nor_narrow_cve_ghsa",
            narrow_neither.sum(),
            n,
            "no rated severity and no case-sensitive CVE-/GHSA- in title/description",
        ),
        metric(
            "neither_rated_nor_any_advisory_id",
            broad_neither.sum(),
            n,
            "no rated severity and no recognized advisory ID in any provenance field",
        ),
        metric("fix_commit_present", fix_commit.sum(), n, "non-empty fix_commit"),
        metric("post_fix_code_present", post_code.sum(), n, "non-empty post_fix_code JSON"),
        metric("cwe_present", cwe_known.sum(), n, "cwe_top25 != N/A"),
        metric(
            "cwe_in_2025_top25",
            cwe_top25.sum(),
            n,
            "cwe_top25 value is a member of MITRE's 2025 CWE Top 25",
        ),
        metric(
            "cwe_present_but_not_2025_top25",
            cwe_known_not_top25.sum(),
            cwe_known.sum(),
            "known CWE value outside MITRE's 2025 Top 25; denominator is CWE-known rows",
        ),
        metric(
            "severity_source_upstream_cvss",
            source_upstream.sum(),
            n,
            "severity_source == upstream-cvss",
        ),
        metric(
            "upstream_cvss_with_rated_severity",
            upstream_rated.sum(),
            source_upstream.sum(),
            "upstream-cvss rows with Critical/High/Medium/Low; denominator is all "
            "upstream-cvss rows",
        ),
        metric(
            "upstream_cvss_without_rated_severity",
            upstream_unrated.sum(),
            source_upstream.sum(),
            "upstream-cvss rows with Info/Unrated; denominator is all upstream-cvss rows",
        ),
    ]
    pd.DataFrame(rows).to_csv(args.output_dir / "snapshot_metrics.csv", index=False)

    write_counts(
        df["authority_tier"].value_counts(),
        args.output_dir / "authority_tier_counts.csv",
        "authority_tier",
    )
    write_counts(
        df["root_cause"].value_counts(),
        args.output_dir / "root_cause_counts.csv",
        "root_cause",
    )
    write_counts(
        df["attack_path"].value_counts(),
        args.output_dir / "attack_path_counts.csv",
        "attack_path",
    )

    cwe_counts = cwe[cwe_known].value_counts().rename_axis("cwe").reset_index(name="count")
    cwe_counts["percent_of_cwe_known"] = (
        100.0 * cwe_counts["count"] / cwe_known.sum()
    ).round(3)
    cwe_counts["in_2025_top25"] = cwe_counts["cwe"].isin(CWE_TOP_25_2025)
    cwe_counts.to_csv(args.output_dir / "cwe_counts.csv", index=False)

    provenance = pd.crosstab(
        df["severity_source"],
        rated.map({True: "rated", False: "info_or_unrated"}),
    )
    provenance = provenance.rename_axis("severity_source").reset_index()
    provenance["total"] = provenance.get("rated", 0) + provenance.get("info_or_unrated", 0)
    provenance.to_csv(args.output_dir / "severity_source_by_rating.csv", index=False)

    print(f"wrote publication tables to {args.output_dir} (n={n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
