#!/usr/bin/env python3
"""Generate publication-analysis tables from one frozen curated snapshot.

Run from the repository root:

    UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/paper_analysis.py

The outputs under ``docs/paper/tables`` are intentionally small CSV files so
that every number cited by the paper-facing documentation is reviewable in git.
"""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path

import numpy as np
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
LANGUAGE = {
    "geth": "Go",
    "erigon": "Go",
    "prysm": "Go",
    "nethermind": "C#",
    "besu": "Java",
    "teku": "Java",
    "reth": "Rust",
    "lighthouse": "Rust",
    "grandine": "Rust",
    "nimbus": "Nim",
    "lodestar": "TypeScript",
}
POPULATIONS = {
    "A_only": {"A_authoritative"},
    "A_or_B": {"A_authoritative", "B_corroborated"},
    "all_tiers": {"A_authoritative", "B_corroborated", "C_candidate"},
}
BIAS_DIMENSIONS = [
    "root_cause",
    "attack_path",
    "label",
    "source_platform",
    "layer",
    "language",
]
DEPENDENCY_NAME_RE = re.compile(
    r"golang\.org/x|openssl|netty|log4j|spring|jackson|protobuf|fastify"
    r"|axios|urllib3|jinja2|pillow|nbconvert|ipython|fonttools|undici"
    r"|jose4j|assertj|libp2p|rust-yamux|snakeyaml|tuweni|quic-go"
    r"|node-forge|micromatch|electron|grafana|jwt-go|gorilla/websocket",
    re.IGNORECASE,
)
DEPENDENCY_ACTION_RE = re.compile(
    r"\b(?:bump|upgrade|update|deps?|dependabot|dependency|dependencies|library"
    r"|package|crate|cargo|rustsec)\b",
    re.IGNORECASE,
)
TOOLING_RE = re.compile(
    r"(?:^|[/\s])(?:docs?|ncli|test_report|ci|\.github)(?:[/\s:]|$)"
    r"|integration test|cargo deny|trivy warning|vulnerability testdata",
    re.IGNORECASE,
)
CLIENT_NAMES = {
    "geth": ("geth", "go-ethereum", "go ethereum"),
    "erigon": ("erigon",),
    "nethermind": ("nethermind",),
    "besu": ("besu",),
    "reth": ("reth",),
    "prysm": ("prysm",),
    "lighthouse": ("lighthouse",),
    "teku": ("teku",),
    "nimbus": ("nimbus",),
    "lodestar": ("lodestar",),
    "grandine": ("grandine",),
    "consensus-specs": ("consensus specs", "consensus-specs"),
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


def benjamini_hochberg(p_values: pd.Series) -> pd.Series:
    """Return monotone Benjamini-Hochberg adjusted p-values."""
    if p_values.empty:
        return p_values.astype(float)
    values = p_values.to_numpy(dtype=float)
    order = np.argsort(values)
    ranked = values[order]
    adjusted = ranked * len(values) / np.arange(1, len(values) + 1)
    adjusted = np.minimum.accumulate(adjusted[::-1])[::-1]
    result = np.empty_like(adjusted)
    result[order] = np.minimum(adjusted, 1.0)
    return pd.Series(result, index=p_values.index)


def cramers_v(frame: pd.DataFrame, category: str, outcome: str) -> tuple[float, float]:
    """Compute Pearson chi-square and bias-uncorrected Cramér's V."""
    table = pd.crosstab(frame[category], frame[outcome]).to_numpy(dtype=float)
    if table.size == 0 or table.shape[0] < 2 or table.shape[1] < 2:
        return 0.0, 0.0
    expected = np.outer(table.sum(axis=1), table.sum(axis=0)) / table.sum()
    valid = expected > 0
    chi_square = float((((table - expected) ** 2) / expected)[valid].sum())
    denominator = table.sum() * min(table.shape[0] - 1, table.shape[1] - 1)
    value = math.sqrt(chi_square / denominator) if denominator else 0.0
    return chi_square, value


def advisory_bias_tables(df: pd.DataFrame, output_dir: Path) -> None:
    """Write advisory prevalence and category-level selection-bias estimates."""
    prevalence_rows: list[dict] = []
    global_rows: list[dict] = []
    category_rows: list[dict] = []

    for population, tiers in POPULATIONS.items():
        subset = df[df["authority_tier"].isin(tiers)].copy()
        n = len(subset)
        n_advisory = int(subset["advisory_id_present"].sum())
        prevalence_rows.append(
            {
                "population": population,
                "rows": n,
                "advisory_id_rows": n_advisory,
                "advisory_percent": pct(n_advisory, n),
            }
        )

        for dimension in BIAS_DIMENSIONS:
            working = subset[
                subset[dimension].fillna("").astype(str).str.len().gt(0)
            ].copy()
            chi_square, effect = cramers_v(
                working, dimension, "advisory_id_present"
            )
            global_rows.append(
                {
                    "population": population,
                    "dimension": dimension,
                    "rows": len(working),
                    "categories": working[dimension].nunique(),
                    "chi_square": round(chi_square, 6),
                    "cramers_v": round(effect, 6),
                    "note": (
                        "descriptive only: authority tier is partly defined by "
                        "advisory evidence"
                        if population == "A_only"
                        else ""
                    ),
                }
            )

            total_advisory = int(working["advisory_id_present"].sum())
            total_non_advisory = len(working) - total_advisory
            for value, group in working.groupby(dimension, dropna=False):
                group_n = len(group)
                if group_n < 20:
                    continue
                a = int(group["advisory_id_present"].sum())
                b = group_n - a
                c = total_advisory - a
                d = total_non_advisory - b
                # Haldane-Anscombe correction keeps zero-cell estimates finite.
                ac, bc, cc, dc = (x + 0.5 for x in (a, b, c, d))
                log_or = math.log((ac * dc) / (bc * cc))
                standard_error = math.sqrt(1 / ac + 1 / bc + 1 / cc + 1 / dc)
                z = log_or / standard_error
                p_value = math.erfc(abs(z) / math.sqrt(2))
                category_rows.append(
                    {
                        "population": population,
                        "dimension": dimension,
                        "category": value,
                        "rows": group_n,
                        "advisory_rows": a,
                        "advisory_percent": pct(a, group_n),
                        "odds_ratio": round(math.exp(log_or), 6),
                        "ci95_low": round(math.exp(log_or - 1.96 * standard_error), 6),
                        "ci95_high": round(math.exp(log_or + 1.96 * standard_error), 6),
                        "p_value": p_value,
                    }
                )

    prevalence = pd.DataFrame(prevalence_rows)
    prevalence.to_csv(output_dir / "advisory_prevalence.csv", index=False)
    pd.DataFrame(global_rows).to_csv(
        output_dir / "advisory_bias_global.csv", index=False
    )

    categories = pd.DataFrame(category_rows)
    categories["q_value_bh"] = categories.groupby(
        ["population", "dimension"], group_keys=False
    )["p_value"].transform(benjamini_hochberg)
    categories.sort_values(
        ["population", "dimension", "q_value_bh", "odds_ratio"],
        ascending=[True, True, True, False],
        inplace=True,
    )
    categories["p_value"] = categories["p_value"].map(lambda x: f"{x:.8g}")
    categories["q_value_bh"] = categories["q_value_bh"].map(lambda x: f"{x:.8g}")
    categories.to_csv(output_dir / "advisory_bias_categories.csv", index=False)


def advisory_scope_suggestion(row: pd.Series) -> tuple[str, str]:
    """Conservative triage suggestion for the manual advisory review queue."""
    title = str(row.get("title") or "")
    description = str(row.get("description") or "")
    issue_id = str(row.get("issue_id") or "")
    source_url = str(row.get("source_url") or "")
    text = f"{title} {description}"

    if DEPENDENCY_NAME_RE.search(text):
        return "dependency_or_tooling", "known dependency name in title/description"
    if DEPENDENCY_ACTION_RE.search(title) and (
        re.search(r"\b(?:version|security|vulnerab|CVE|GHSA|RUSTSEC)\b", title, re.I)
        or TOOLING_RE.search(text)
    ):
        return "dependency_or_tooling", "dependency action plus security/version signal"
    if TOOLING_RE.search(title):
        return "dependency_or_tooling", "documentation/CI/test tooling signal"
    if issue_id.upper().startswith("RUSTSEC-"):
        return "dependency_or_tooling", "RustSec identifier"

    platform = str(row.get("source_platform") or "")
    names = CLIENT_NAMES.get(platform, ())
    if any(name.lower() in text.lower() for name in names):
        return "client_implementation", "client product named in title/description"
    if "/security/advisories/GHSA-" in source_url:
        return "client_implementation", "client-repository GitHub Security Advisory"
    if str(row.get("severity_source") or "") == "bounty-graded":
        return "client_implementation", "bounty-graded provenance"
    return "needs_manual_review", "insufficient high-precision scope evidence"


def write_advisory_review_queue(df: pd.DataFrame, output_dir: Path) -> None:
    review = df[df["advisory_id_present"]].copy()
    suggestions = review.apply(advisory_scope_suggestion, axis=1)
    review["suggested_scope"] = [value[0] for value in suggestions]
    review["suggestion_reason"] = [value[1] for value in suggestions]
    review["description_excerpt"] = (
        review["description"].fillna("").astype(str).str.replace(r"\s+", " ", regex=True).str[:500]
    )
    review["reviewed_scope"] = ""
    review["review_notes"] = ""
    columns = [
        "id",
        "source_platform",
        "issue_id",
        "title",
        "description_excerpt",
        "source_url",
        "authority_tier",
        "severity",
        "severity_source",
        "label",
        "root_cause",
        "attack_path",
        "suggested_scope",
        "suggestion_reason",
        "reviewed_scope",
        "review_notes",
    ]
    review[columns].sort_values(
        ["suggested_scope", "source_platform", "issue_id"]
    ).to_csv(output_dir / "advisory_review_queue.csv", index=False)


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
    df["advisory_id_present"] = any_advisory_id
    df["language"] = df["source_platform"].map(LANGUAGE)

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
    advisory_bias_tables(df, args.output_dir)
    write_advisory_review_queue(df, args.output_dir)

    print(f"wrote publication tables to {args.output_dir} (n={n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
