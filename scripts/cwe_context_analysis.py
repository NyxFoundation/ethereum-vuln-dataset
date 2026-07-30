#!/usr/bin/env python3
"""Compare generic CWE coverage with Ethereum-specific context axes."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:
    from scripts.paper_analysis import CWE_TOP_25_2025
except ModuleNotFoundError:  # Direct execution puts scripts/ on sys.path.
    from paper_analysis import CWE_TOP_25_2025


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
    df["cwe_known"] = df["cwe_top25"].fillna("N/A").ne("N/A")
    df["cwe_2025_top25"] = df["cwe_top25"].isin(CWE_TOP_25_2025)
    df["root_cause_known"] = df["root_cause"].fillna("other").ne("other")
    df["protocol_label_known"] = df["label"].fillna("other").ne("other")
    df["confirmed_bounty_severe"] = (
        df["severity_source"].eq("bounty-graded")
        & df["severity_estimated"].isin(["Critical", "High"])
    )

    populations = {
        "all_snapshot": df,
        "authority_A_or_B": df[df["authority_tier"].isin(
            ["A_authoritative", "B_corroborated"]
        )],
        "bounty_graded": df[df["severity_source"].eq("bounty-graded")],
        "confirmed_bounty_critical_or_high": df[df["confirmed_bounty_severe"]],
        "llm_estimated": df[df["severity_source"].eq("llm-estimated")],
    }
    coverage_rows: list[dict] = []
    for population, frame in populations.items():
        no_cwe = ~frame["cwe_known"]
        metrics = {
            "cwe_known": (frame["cwe_known"], len(frame)),
            "cwe_2025_top25": (frame["cwe_2025_top25"], len(frame)),
            "root_cause_known": (frame["root_cause_known"], len(frame)),
            "protocol_label_known": (frame["protocol_label_known"], len(frame)),
            "no_cwe_but_root_cause_known": (
                no_cwe & frame["root_cause_known"],
                int(no_cwe.sum()),
            ),
            "no_cwe_but_protocol_label_known": (
                no_cwe & frame["protocol_label_known"],
                int(no_cwe.sum()),
            ),
            "no_cwe_but_both_context_axes_known": (
                no_cwe
                & frame["root_cause_known"]
                & frame["protocol_label_known"],
                int(no_cwe.sum()),
            ),
        }
        for metric, (mask, denominator) in metrics.items():
            count = int(mask.sum())
            coverage_rows.append(
                {
                    "population": population,
                    "metric": metric,
                    "rows": count,
                    "denominator": denominator,
                    "percent": pct(count, denominator),
                }
            )
    pd.DataFrame(coverage_rows).to_csv(
        args.output_dir / "cwe_context_coverage.csv", index=False
    )

    root_rows: list[dict] = []
    for root_cause, frame in df.groupby("root_cause", dropna=False):
        known = int(frame["cwe_known"].sum())
        top25 = int(frame["cwe_2025_top25"].sum())
        root_rows.append(
            {
                "root_cause": root_cause,
                "rows": len(frame),
                "cwe_known_rows": known,
                "cwe_known_percent": pct(known, len(frame)),
                "cwe_2025_top25_rows": top25,
                "cwe_2025_top25_percent": pct(top25, len(frame)),
                "distinct_cwe_labels": int(
                    frame.loc[frame["cwe_known"], "cwe_top25"].nunique()
                ),
            }
        )
    pd.DataFrame(root_rows).sort_values(
        ["rows", "root_cause"], ascending=[False, True]
    ).to_csv(args.output_dir / "cwe_root_cause_coverage.csv", index=False)

    multiplicity_rows: list[dict] = []
    for cwe, frame in df[df["cwe_known"]].groupby("cwe_top25"):
        multiplicity_rows.append(
            {
                "cwe": cwe,
                "rows": len(frame),
                "in_2025_top25": cwe in CWE_TOP_25_2025,
                "distinct_root_causes": int(frame["root_cause"].nunique()),
                "distinct_protocol_labels": int(frame["label"].nunique()),
                "leading_root_cause": frame["root_cause"].value_counts().index[0],
                "leading_root_cause_rows": int(
                    frame["root_cause"].value_counts().iloc[0]
                ),
            }
        )
    pd.DataFrame(multiplicity_rows).sort_values(
        ["rows", "cwe"], ascending=[False, True]
    ).to_csv(args.output_dir / "cwe_semantic_multiplicity.csv", index=False)

    severe_columns = [
        "id",
        "source_platform",
        "severity_estimated",
        "cwe_top25",
        "cwe_known",
        "cwe_2025_top25",
        "root_cause",
        "label",
        "attack_path",
        "title",
        "source_url",
    ]
    df[df["confirmed_bounty_severe"]][severe_columns].sort_values(
        ["severity_estimated", "source_platform", "id"]
    ).to_csv(args.output_dir / "bounty_severe_cwe_audit.csv", index=False)

    print(
        "CWE context analysis:",
        f"{int(df['cwe_known'].sum())}/{len(df)} CWE-known,",
        f"{int(df['cwe_2025_top25'].sum())} in 2025 Top 25,",
        f"{int(df.loc[df['confirmed_bounty_severe'], 'cwe_known'].sum())}/"
        f"{int(df['confirmed_bounty_severe'].sum())} severe CWE-known",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
