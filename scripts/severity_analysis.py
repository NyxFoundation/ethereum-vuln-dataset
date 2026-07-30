#!/usr/bin/env python3
"""Generate provenance-aware EF bug-bounty severity analysis tables.

The original LLM estimates are retained for reproducibility.  A conservative
review layer reclassifies every LLM-estimated High as ``tier-uncertain``:

* ``client_specific`` estimates used an unversioned client-share prior, so the
  >33% EF threshold is not established at the fix date;
* ``spec_level`` says that code implements a shared rule, but does not prove
  that every implementation had the defect or that >33% of the network was
  affected.

The former High estimates remain a candidate queue.  They are never combined
with bounty-graded Critical/High records as if they were confirmed tiers.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


EF_SOURCES = {"bounty-graded", "llm-estimated"}
ELIGIBLE_TIERS = {"Critical", "High", "Medium", "Low"}
SEVERE_TIERS = {"Critical", "High"}
UNCERTAIN_TIER = "tier-uncertain"
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


def apply_high_review(ef: pd.DataFrame) -> pd.DataFrame:
    """Add a traceable analysis label without overwriting source estimates."""
    reviewed = ef.copy()
    reviewed["severity_analysis_label"] = reviewed["severity_estimated"]
    reviewed["severity_review_status"] = "unreviewed_estimate"
    reviewed["severity_review_reason"] = (
        "Original LLM estimate retained; this row was not part of the High audit."
    )

    bounty = reviewed["severity_source"].eq("bounty-graded")
    reviewed.loc[bounty, "severity_review_status"] = "confirmed_bounty_grade"
    reviewed.loc[bounty, "severity_review_reason"] = (
        "Published bounty grade; no LLM correction applied."
    )

    high = reviewed["severity_source"].eq("llm-estimated") & reviewed[
        "severity_estimated"
    ].eq("High")
    client_specific = high & reviewed["blast_radius"].eq("client_specific")
    spec_level = high & reviewed["blast_radius"].eq("spec_level")
    other = high & ~(client_specific | spec_level)

    reviewed.loc[high, "severity_analysis_label"] = UNCERTAIN_TIER
    reviewed.loc[high, "severity_review_status"] = "threshold_unverified"
    reviewed.loc[client_specific, "severity_review_reason"] = (
        "Exact High removed: the estimator used an unversioned static client-share "
        "prior, so >33% affected at the fix date is not evidenced."
    )
    reviewed.loc[spec_level, "severity_review_reason"] = (
        "Exact High removed: implementing a shared specification rule does not prove "
        "that other clients shared the defect or that >33% of the network was affected."
    )
    reviewed.loc[other, "severity_review_reason"] = (
        "Exact High removed: the record does not independently establish the EF >33% "
        "impact threshold."
    )

    # A build produced by the revised estimator states threshold dependence directly,
    # so the blast_radius proxy above is superseded: any tier that holds only above a
    # deployment share the corpus cannot evidence is tier-uncertain, at every tier
    # rather than only at High. The frozen snapshot predates the column, so this is a
    # no-op there and the proxy rule still applies.
    if "severity_certainty" in reviewed.columns:
        dependent = reviewed["severity_source"].eq("llm-estimated") & reviewed[
            "severity_certainty"
        ].eq("share_dependent")
        reviewed.loc[dependent, "severity_analysis_label"] = UNCERTAIN_TIER
        reviewed.loc[dependent, "severity_review_status"] = "threshold_share_dependent"
        required = reviewed.get("severity_required_client_share")
        reviewed.loc[dependent, "severity_review_reason"] = (
            "Exact tier removed: it holds only where the affected client's deployment "
            "share at the fix date reaches "
            + (required[dependent].astype(str) if required is not None else "the EF threshold")
            + ", which this corpus does not evidence."
        )

        # A `bounded` tier is one the share arithmetic cannot reduce, so it would enter
        # the analysis as an exact tier. Every such row in practice rests on a
        # `client_conditional_reach` of `all_nodes`, and that is precisely the assessment
        # that failed source review: all three reviewable `all_nodes` judgements were
        # over-permissive (see paper/client_conditional_severity.md section 6). The tier
        # is kept -- the arithmetic really does hold *if* the reach is right -- but the
        # status names the dependency so it cannot be quoted as confirmed unnoticed.
        if "client_conditional_reach" in reviewed.columns:
            unreviewed = (
                reviewed["severity_source"].eq("llm-estimated")
                & reviewed["severity_certainty"].eq("bounded")
                & reviewed["client_conditional_reach"].eq("all_nodes")
            )
            reviewed.loc[unreviewed, "severity_review_status"] = (
                "bounded_on_unreviewed_reach"
            )
            reviewed.loc[unreviewed, "severity_review_reason"] = (
                "Tier survives the share bound, but only because reach was assessed as "
                "all_nodes, the judgement that was over-permissive on every reviewable "
                "case. Validate the reach before treating this as an exact tier."
            )
    return reviewed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", type=Path, default=Path("data/ethereum_vulns.parquet")
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("docs/paper/tables")
    )
    parser.add_argument(
        "--severity-csv",
        type=Path,
        default=None,
        help=(
            "optional re-estimation overlay joined by id. Supplies the columns the frozen "
            "snapshot predates (severity_certainty, client_conditional_reach, "
            "severity_required_client_share) so the certainty rules above can act. Without "
            "it the blast_radius proxy applies and the checked-in tables are reproduced."
        ),
    )
    parser.add_argument(
        "--overlay-out-dir",
        type=Path,
        default=None,
        help="write overlay-derived tables here instead of over the snapshot ones",
    )
    args = parser.parse_args()
    if args.severity_csv and not args.overlay_out_dir:
        # An overlay changes every count, so it must not silently overwrite the tables the
        # frozen snapshot generates and the paper cites.
        raise SystemExit(
            "--severity-csv changes every count; pass --overlay-out-dir to say where the "
            "overlay tables go rather than overwriting the snapshot tables"
        )
    out_dir = args.overlay_out_dir or args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.input)
    if args.severity_csv and args.severity_csv.exists():
        overlay = pd.read_csv(args.severity_csv, dtype=str).drop_duplicates("id")
        carry = [
            c for c in ("severity_estimated", "severity_source", "impact_type",
                        "blast_radius", "client_conditional_reach", "severity_certainty",
                        "severity_required_client_share")
            if c in overlay.columns
        ]
        before = len(df)
        df = df.drop(columns=[c for c in carry if c in df.columns]).merge(
            overlay[["id"] + carry], on="id", how="left"
        )
        assert len(df) == before, "overlay join must not change row count"
        df["severity_estimated"] = df["severity_estimated"].map(
            lambda x: str(x).capitalize() if pd.notna(x) and str(x) else x
        )
        covered = df["severity_certainty"].notna().sum() if "severity_certainty" in df else 0
        print(f"overlay {args.severity_csv}: {covered}/{len(df)} rows carry a certainty")

    ef = apply_high_review(df[df["severity_source"].isin(EF_SOURCES)].copy())
    ef["original_bounty_eligible"] = ef["severity_estimated"].isin(ELIGIBLE_TIERS)
    ef["original_critical_or_high"] = ef["severity_estimated"].isin(SEVERE_TIERS)
    ef["confirmed_critical_or_high"] = (
        ef["severity_source"].eq("bounty-graded")
        & ef["severity_analysis_label"].isin(SEVERE_TIERS)
    )
    ef["llm_high_candidate"] = (
        ef["severity_source"].eq("llm-estimated")
        & ef["severity_analysis_label"].eq(UNCERTAIN_TIER)
    )

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
            "original_ef_bounty_eligible",
            int(ef["original_bounty_eligible"].sum()),
            len(ef),
            "Critical/High/Medium/Low before the High audit",
        ),
        (
            "ef_not_eligible",
            int(ef["severity_estimated"].eq("not-eligible").sum()),
            len(ef),
            "not-eligible is a scope decision, not a Low tier",
        ),
        (
            "original_ef_critical_or_high",
            int(ef["original_critical_or_high"].sum()),
            int(ef["original_bounty_eligible"].sum()),
            "pre-audit Critical/High; includes unverified LLM High",
        ),
        (
            "confirmed_bounty_critical_or_high",
            int(ef["confirmed_critical_or_high"].sum()),
            int(ef["severity_source"].eq("bounty-graded").sum()),
            "published bounty grades only",
        ),
        (
            "llm_high_candidates_tier_uncertain",
            int(ef["llm_high_candidate"].sum()),
            int(ef["severity_source"].eq("llm-estimated").sum()),
            "original LLM High removed from exact-tier analysis",
        ),
    ]
    summary_frame = pd.DataFrame(
        summary, columns=["metric", "count", "denominator", "definition"]
    )
    summary_frame["percent"] = summary_frame.apply(
        lambda row: pct(int(row["count"]), int(row["denominator"])), axis=1
    )
    summary_frame.to_csv(out_dir / "ef_severity_population.csv", index=False)

    tier_rows: list[dict] = []
    populations = {
        "bounty_graded": ef[ef["severity_source"].eq("bounty-graded")],
        "llm_estimated": ef[ef["severity_source"].eq("llm-estimated")],
        "combined_ef": ef,
    }
    tier_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "not-eligible",
        UNCERTAIN_TIER,
    ]
    for population, frame in populations.items():
        counts = frame["severity_analysis_label"].value_counts()
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
        out_dir / "ef_severity_tier_counts.csv", index=False
    )

    dimension_rows: list[dict] = []
    for population, frame in {
        "combined_ef": ef,
        "llm_only": ef[ef["severity_source"].eq("llm-estimated")],
    }.items():
        eligible = frame[frame["original_bounty_eligible"]]
        for dimension in DIMENSIONS:
            for category, group in eligible.groupby(dimension, dropna=False):
                confirmed = int(group["confirmed_critical_or_high"].sum())
                candidates = int(group["llm_high_candidate"].sum())
                dimension_rows.append(
                    {
                        "population": population,
                        "dimension": dimension,
                        "category": category,
                        "eligible_rows": len(group),
                        "confirmed_critical_or_high_rows": confirmed,
                        "llm_high_candidate_rows": candidates,
                        "candidate_percent": pct(candidates, len(group)),
                    }
                )
    pd.DataFrame(dimension_rows).to_csv(
        out_dir / "ef_severity_by_dimension.csv", index=False
    )

    llm = ef[ef["severity_source"].eq("llm-estimated")].copy()
    llm_high = llm[llm["llm_high_candidate"]]
    decomposition_rows: list[dict] = []
    for dimension in ["impact_type", "reachability", "blast_radius"]:
        for category, count in llm_high[dimension].value_counts(dropna=False).items():
            decomposition_rows.append(
                {
                    "dimension": dimension,
                    "category": category,
                    "candidate_rows": int(count),
                    "candidate_denominator": len(llm_high),
                    "percent": pct(int(count), len(llm_high)),
                }
            )
    pd.DataFrame(decomposition_rows).to_csv(
        out_dir / "ef_severity_high_decomposition.csv", index=False
    )

    client_rows: list[dict] = []
    for source, frame in {
        "bounty_graded": ef[ef["severity_source"].eq("bounty-graded")],
        "llm_estimated": llm,
    }.items():
        eligible = frame[frame["original_bounty_eligible"]]
        for client, group in eligible.groupby("source_platform"):
            confirmed = int(group["confirmed_critical_or_high"].sum())
            candidates = int(group["llm_high_candidate"].sum())
            client_rows.append(
                {
                    "severity_source": source,
                    "source_platform": client,
                    "eligible_rows": len(group),
                    "confirmed_critical_or_high_rows": confirmed,
                    "llm_high_candidate_rows": candidates,
                    "candidate_percent": pct(candidates, len(group)),
                }
            )
    pd.DataFrame(client_rows).to_csv(
        out_dir / "ef_severity_client_diagnostic.csv", index=False
    )

    queue_columns = [
        "id",
        "source_platform",
        "title",
        "source_url",
        "authority_tier",
        "severity_estimated",
        "severity_analysis_label",
        "severity_review_status",
        "severity_review_reason",
        "severity_source",
        "impact_type",
        "reachability",
        "blast_radius",
        "root_cause",
        "attack_path",
        "label",
        "severity_why",
    ]
    ef[ef["confirmed_critical_or_high"] | ef["llm_high_candidate"]][
        queue_columns
    ].sort_values(
        ["severity_estimated", "severity_source", "source_platform", "id"]
    ).to_csv(out_dir / "ef_severity_high_review_queue.csv", index=False)

    print(
        "EF severity analysis:",
        f"{len(ef)} comparable,",
        f"{int(ef['original_bounty_eligible'].sum())} originally eligible,",
        f"{int(ef['confirmed_critical_or_high'].sum())} confirmed Critical/High,",
        f"{int(ef['llm_high_candidate'].sum())} tier-uncertain candidates",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
