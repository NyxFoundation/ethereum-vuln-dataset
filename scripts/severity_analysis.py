#!/usr/bin/env python3
"""Generate EF bug-bounty severity analysis tables from the frozen snapshot.

Only ``bounty-graded`` and ``llm-estimated`` rows share the EF-bounty impact
model. ``upstream-cvss`` and ``unassessed`` rows are excluded. Analysis is
two-stage: bounty eligibility first, then Critical/High versus Medium/Low among
eligible rows.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


EF_SOURCES = {"bounty-graded", "llm-estimated"}
ELIGIBLE_TIERS = {"Critical", "High", "Medium", "Low"}
SEVERE_TIERS = {"Critical", "High"}
DIMENSIONS = [
    "source_platform",
    "layer",
    "authority_tier",
    "attack_path",
    "root_cause",
    "label",
]


def pct(count: int, denominator: int) -> float:
    return round(100 * count / denominator, 3) if denominator else 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", type=Path, default=Path("data/ethereum_vulns.parquet")
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("docs/paper/tables")
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.input)
    ef = df[df["severity_source"].isin(EF_SOURCES)].copy()
    ef["bounty_eligible"] = ef["severity_estimated"].isin(ELIGIBLE_TIERS)
    ef["critical_or_high"] = ef["severity_estimated"].isin(SEVERE_TIERS)

    summary = [
        ("snapshot_rows", len(df), len(df), "all frozen snapshot records"),
        (
            "ef_comparable_rows",
            len(ef),
            len(df),
            "severity_source is bounty-graded or llm-estimated",
        ),
        (
            "excluded_upstream_cvss",
            int(df["severity_source"].eq("upstream-cvss").sum()),
            len(df),
            "not comparable with the EF-bounty scale",
        ),
        (
            "excluded_unassessed",
            int(df["severity_source"].eq("unassessed").sum()),
            len(df),
            "no severity assessment",
        ),
        (
            "ef_bounty_eligible",
            int(ef["bounty_eligible"].sum()),
            len(ef),
            "Critical/High/Medium/Low among EF-comparable rows",
        ),
        (
            "ef_not_eligible",
            int((~ef["bounty_eligible"]).sum()),
            len(ef),
            "not-eligible is a scope decision, not a Low tier",
        ),
        (
            "ef_critical_or_high",
            int(ef["critical_or_high"].sum()),
            int(ef["bounty_eligible"].sum()),
            "Critical/High among bounty-eligible EF-comparable rows",
        ),
    ]
    summary_frame = pd.DataFrame(
        summary, columns=["metric", "count", "denominator", "definition"]
    )
    summary_frame["percent"] = summary_frame.apply(
        lambda row: pct(int(row["count"]), int(row["denominator"])), axis=1
    )
    summary_frame.to_csv(args.output_dir / "ef_severity_population.csv", index=False)

    tier_rows: list[dict] = []
    populations = {
        "bounty_graded": ef[ef["severity_source"].eq("bounty-graded")],
        "llm_estimated": ef[ef["severity_source"].eq("llm-estimated")],
        "combined_ef": ef,
    }
    tier_order = ["Critical", "High", "Medium", "Low", "not-eligible"]
    for population, frame in populations.items():
        counts = frame["severity_estimated"].value_counts()
        for tier in tier_order:
            count = int(counts.get(tier, 0))
            tier_rows.append(
                {
                    "population": population,
                    "tier": tier,
                    "rows": count,
                    "denominator": len(frame),
                    "percent": pct(count, len(frame)),
                }
            )
    pd.DataFrame(tier_rows).to_csv(
        args.output_dir / "ef_severity_tier_counts.csv", index=False
    )

    dimension_rows: list[dict] = []
    for population, frame in {
        "combined_ef": ef,
        "llm_only": ef[ef["severity_source"].eq("llm-estimated")],
    }.items():
        eligible = frame[frame["bounty_eligible"]]
        for dimension in DIMENSIONS:
            for category, group in eligible.groupby(dimension, dropna=False):
                severe = int(group["critical_or_high"].sum())
                dimension_rows.append(
                    {
                        "population": population,
                        "dimension": dimension,
                        "category": category,
                        "eligible_rows": len(group),
                        "critical_or_high_rows": severe,
                        "critical_or_high_percent": pct(severe, len(group)),
                    }
                )
    pd.DataFrame(dimension_rows).to_csv(
        args.output_dir / "ef_severity_by_dimension.csv", index=False
    )

    llm = ef[ef["severity_source"].eq("llm-estimated")].copy()
    llm_high = llm[llm["severity_estimated"].eq("High")]
    decomposition_rows: list[dict] = []
    for dimension in ["impact_type", "reachability", "blast_radius"]:
        for category, count in llm_high[dimension].value_counts(dropna=False).items():
            decomposition_rows.append(
                {
                    "dimension": dimension,
                    "category": category,
                    "high_rows": int(count),
                    "high_denominator": len(llm_high),
                    "percent": pct(int(count), len(llm_high)),
                }
            )
    pd.DataFrame(decomposition_rows).to_csv(
        args.output_dir / "ef_severity_high_decomposition.csv", index=False
    )

    client_rows: list[dict] = []
    for source, frame in {
        "bounty_graded": ef[ef["severity_source"].eq("bounty-graded")],
        "llm_estimated": llm,
    }.items():
        eligible = frame[frame["bounty_eligible"]]
        for client, group in eligible.groupby("source_platform"):
            severe = int(group["critical_or_high"].sum())
            client_rows.append(
                {
                    "severity_source": source,
                    "source_platform": client,
                    "eligible_rows": len(group),
                    "critical_or_high_rows": severe,
                    "critical_or_high_percent": pct(severe, len(group)),
                }
            )
    pd.DataFrame(client_rows).to_csv(
        args.output_dir / "ef_severity_client_diagnostic.csv", index=False
    )

    queue_columns = [
        "id",
        "source_platform",
        "title",
        "source_url",
        "authority_tier",
        "severity_estimated",
        "severity_source",
        "impact_type",
        "reachability",
        "blast_radius",
        "root_cause",
        "attack_path",
        "label",
        "severity_why",
    ]
    ef[ef["critical_or_high"]][queue_columns].sort_values(
        ["severity_estimated", "severity_source", "source_platform", "id"]
    ).to_csv(args.output_dir / "ef_severity_high_review_queue.csv", index=False)

    print(
        "EF severity analysis:",
        f"{len(ef)} comparable,",
        f"{int(ef['bounty_eligible'].sum())} eligible,",
        f"{int(ef['critical_or_high'].sum())} Critical/High",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
