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

# Manual corrections after reviewing all 172 advisory-linked rows in the frozen
# snapshot. Rows not listed retain the conservative automated suggestion:
# dependency_or_tooling stays dependency/tooling and client_implementation stays
# direct client implementation. Every needs_manual_review row is resolved here.
SCOPE_OVERRIDES = {
    # Automated client-name matching hid dependency/tooling work.
    "fc384bdaf55405d0": ("dependency_or_tooling", "Netty CVE dependency update"),
    "c4abc462e912553e": ("dependency_or_tooling", "secp256k1 dependency update"),
    "d9d15b02a9ffb53b": ("dependency_or_tooling", "gnark-crypto dependency update"),
    "geth:ghsa-advisory:GHSA-m6gx-rhvj-fh52": (
        "dependency_or_tooling",
        "upstream Go CVE",
    ),
    "eb5202427514a50d": ("dependency_or_tooling", "zeroize_derive dependency update"),
    "a4bfb41590b1a159": ("dependency_or_tooling", "elliptic dependency update"),
    "52a0b74179ac2fb5": (
        "dependency_or_tooling",
        "client-side guard around bigint-buffer dependency vulnerability",
    ),
    "lodestar:scope-networking:PR#8927": (
        "dependency_or_tooling",
        "AJV development-dependency update",
    ),
    "nimbus:consensus:PR#6805": (
        "dependency_or_tooling",
        "documentation-only reference removal",
    ),
    "3c83a22575420ffe": (
        "dependency_or_tooling",
        "golang.org/x/crypto CVE dependency update",
    ),
    "9b6f7f93db170dd0": ("dependency_or_tooling", "generic dependency update"),
    # The NVD name match is a different Nethermind product, not the Ethereum client.
    "ea812e5ad2a3da8e": (
        "other_product",
        "Nethermind Juno is a Starknet client, outside the Ethereum-client scope",
    ),
    # Resolution of the nine formerly ambiguous rows.
    "39f552132567e254": (
        "direct_client_implementation",
        "Erigon client crypto validation fix",
    ),
    "erigon:erigontech-erigon:PR#5450": (
        "direct_client_implementation",
        "Erigon regression test for a client vulnerability",
    ),
    "7c5ea587d2623255": ("dependency_or_tooling", "pion/dtls dependency update"),
    "f4dd3dfb89c70b7d": (
        "dependency_or_tooling",
        "golang.org/x/crypto vulnerability",
    ),
    "d77e6d7be5ad3831": ("dependency_or_tooling", "upstream Go crypto vulnerability"),
    "17e86a513438dd82": (
        "dependency_or_tooling",
        "upstream SSH protocol/library vulnerability",
    ),
    "016e9b48cc0d0faa": ("dependency_or_tooling", "ignored hyper dependency advisory"),
    "7aa58e560f5daf20": ("dependency_or_tooling", "axum dependency update"),
    "b9328bbd0a612628": ("dependency_or_tooling", "protobuf CVE dependency update"),
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
    def reviewed(row: pd.Series) -> tuple[str, str]:
        if row["id"] in SCOPE_OVERRIDES:
            return SCOPE_OVERRIDES[row["id"]]
        if row["suggested_scope"] == "dependency_or_tooling":
            return "dependency_or_tooling", "confirmed by dependency/tooling title evidence"
        if row["suggested_scope"] == "client_implementation":
            return "direct_client_implementation", "confirmed client implementation record"
        raise ValueError(f"unresolved advisory scope: {row['id']}")

    resolutions = review.apply(reviewed, axis=1)
    review["reviewed_scope"] = resolutions.map(lambda item: item[0])
    review["review_notes"] = resolutions.map(lambda item: item[1])
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


def reviewed_scope_tables(df: pd.DataFrame, output_dir: Path) -> None:
    """Compare manually reviewed advisory scope with records carrying no ID."""
    advisory = df[df["advisory_id_present"]].copy()
    suggestions = advisory.apply(advisory_scope_suggestion, axis=1)
    advisory["suggested_scope"] = suggestions.map(lambda item: item[0])

    def scope(row: pd.Series) -> str:
        if row["id"] in SCOPE_OVERRIDES:
            return SCOPE_OVERRIDES[row["id"]][0]
        return {
            "dependency_or_tooling": "dependency_or_tooling",
            "client_implementation": "direct_client_implementation",
        }[row["suggested_scope"]]

    advisory["reviewed_scope"] = advisory.apply(scope, axis=1)
    counts = (
        advisory["reviewed_scope"]
        .value_counts()
        .rename_axis("reviewed_scope")
        .reset_index(name="rows")
    )
    counts["percent_of_advisory_linked"] = (
        100 * counts["rows"] / len(advisory)
    ).round(3)
    counts.to_csv(output_dir / "reviewed_advisory_scope_counts.csv", index=False)

    by_client = pd.crosstab(advisory["source_platform"], advisory["reviewed_scope"])
    by_client["total"] = by_client.sum(axis=1)
    by_client.rename_axis("source_platform").reset_index().to_csv(
        output_dir / "reviewed_advisory_scope_by_client.csv", index=False
    )

    identifier_rows: list[dict] = []
    for _, row in advisory.iterrows():
        blob = " ".join(str(row.get(field) or "") for field in PROVENANCE_FIELDS)
        for identifier in sorted(
            {match.group(0).upper() for match in ADVISORY_ID_RE.finditer(blob)}
        ):
            identifier_rows.append(
                {
                    "advisory_id": identifier,
                    "reviewed_scope": row["reviewed_scope"],
                    "source_platform": row["source_platform"],
                    "record_id": row["id"],
                }
            )
    identifiers = pd.DataFrame(identifier_rows)
    scope_counts = identifiers.groupby("advisory_id")["reviewed_scope"].nunique()
    identifiers["appears_in_multiple_scopes"] = identifiers["advisory_id"].map(
        scope_counts.gt(1)
    )
    identifiers.to_csv(
        output_dir / "reviewed_advisory_identifiers.csv", index=False
    )

    comparison = df.copy()
    comparison["comparison_group"] = "no_recognized_advisory_id"
    scope_by_id = advisory.set_index("id")["reviewed_scope"]
    advisory_rows = comparison["id"].isin(scope_by_id.index)
    comparison.loc[advisory_rows, "comparison_group"] = comparison.loc[
        advisory_rows, "id"
    ].map(scope_by_id)
    comparison["comparison_group"] = comparison["comparison_group"].replace(
        {"direct_client_implementation": "direct_client_advisory"}
    )
    cwe_rows: list[dict] = []
    for group, group_frame in comparison.groupby("comparison_group"):
        cwe = group_frame["cwe_top25"].fillna("N/A").astype(str)
        known = cwe.ne("N/A")
        top25 = cwe.isin(CWE_TOP_25_2025)
        cwe_rows.append(
            {
                "comparison_group": group,
                "rows": len(group_frame),
                "cwe_known_rows": int(known.sum()),
                "cwe_known_percent": pct(int(known.sum()), len(group_frame)),
                "top25_rows": int(top25.sum()),
                "top25_percent_of_all": pct(int(top25.sum()), len(group_frame)),
                "top25_percent_of_cwe_known": pct(
                    int(top25.sum()), int(known.sum())
                ),
            }
        )
    pd.DataFrame(cwe_rows).to_csv(
        output_dir / "reviewed_scope_cwe_coverage.csv", index=False
    )
    comparison = comparison[
        comparison["comparison_group"].isin(
            {"direct_client_advisory", "no_recognized_advisory_id"}
        )
    ]

    rows: list[dict] = []
    for population, tiers in POPULATIONS.items():
        population_frame = comparison[comparison["authority_tier"].isin(tiers)].copy()
        direct = population_frame["comparison_group"].eq("direct_client_advisory")
        no_id = population_frame["comparison_group"].eq("no_recognized_advisory_id")
        for dimension in [
            "root_cause",
            "attack_path",
            "label",
            "source_platform",
            "layer",
        ]:
            for category in population_frame[dimension].dropna().unique():
                member = population_frame[dimension].eq(category)
                a = int((direct & member).sum())
                b = int((direct & ~member).sum())
                c = int((no_id & member).sum())
                d = int((no_id & ~member).sum())
                if a + c < 20:
                    continue
                ac, bc, cc, dc = (value + 0.5 for value in (a, b, c, d))
                log_or = math.log((ac * dc) / (bc * cc))
                standard_error = math.sqrt(1 / ac + 1 / bc + 1 / cc + 1 / dc)
                p_value = math.erfc(abs(log_or / standard_error) / math.sqrt(2))
                rows.append(
                    {
                        "population": population,
                        "dimension": dimension,
                        "category": category,
                        "direct_advisory_rows": a,
                        "direct_advisory_denominator": int(direct.sum()),
                        "direct_advisory_percent": pct(a, int(direct.sum())),
                        "no_id_rows": c,
                        "no_id_denominator": int(no_id.sum()),
                        "no_id_percent": pct(c, int(no_id.sum())),
                        "odds_ratio": round(math.exp(log_or), 6),
                        "ci95_low": round(math.exp(log_or - 1.96 * standard_error), 6),
                        "ci95_high": round(math.exp(log_or + 1.96 * standard_error), 6),
                        "p_value": p_value,
                    }
                )
    out = pd.DataFrame(rows)
    out["q_value_bh"] = out.groupby(
        ["population", "dimension"], group_keys=False
    )["p_value"].transform(benjamini_hochberg)
    out.sort_values(
        ["population", "dimension", "q_value_bh", "odds_ratio"], inplace=True
    )
    out["p_value"] = out["p_value"].map(lambda value: f"{value:.8g}")
    out["q_value_bh"] = out["q_value_bh"].map(lambda value: f"{value:.8g}")
    out.to_csv(output_dir / "direct_advisory_vs_no_id.csv", index=False)


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
            "unrated_severity",
            (~rated).sum(),
            n,
            "severity is Info or Unrated; this is not an advisory-linkage measure",
        ),
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
        metric(
            "recognized_advisory_id_and_rated",
            (rated & any_advisory_id).sum(),
            n,
            "recognized advisory ID present and severity is rated",
        ),
        metric(
            "recognized_advisory_id_only",
            ((~rated) & any_advisory_id).sum(),
            n,
            "recognized advisory ID present but severity is Info or Unrated",
        ),
        metric(
            "rated_only_without_recognized_advisory_id",
            (rated & ~any_advisory_id).sum(),
            n,
            "rated severity but no recognized advisory ID in any provenance field",
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
    reviewed_scope_tables(df, args.output_dir)

    print(f"wrote publication tables to {args.output_dir} (n={n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
