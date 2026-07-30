#!/usr/bin/env python3
"""Client-conditional severity: separate the two factors behind an EF network share.

The EF bug-bounty tiers are stated as a fraction of the *network* affected by a
single remote message or transaction.  A record's estimated tier therefore
combines two independent quantities:

    affected_network_share = affected_client_share x client_conditional_reach

``affected_client_share`` is historical deployment data that is not present in a
diff, an issue, or an advisory.  ``client_conditional_reach`` -- of the operators
running the affected client, what fraction can the attacker actually affect --
*is* assessable from the fix, because it is determined by default configuration,
node role, platform, and whether the input is attacker-supplied.

This script never guesses the first factor.  It inverts the threshold instead:

    required_client_share(tier) = ef_threshold(tier) / client_conditional_reach

which yields three share-independent verdicts per record and tier:

* ``excluded``  -- even the most favourable share and reach fall below the
  threshold, so the tier is arithmetically impossible without new evidence;
* ``share_dependent`` -- the tier needs a client share of at least the printed
  value at the fix date, which must be sourced separately;
* ``supported`` -- the threshold is met even at the least favourable share and
  reach in the band.

Outputs (all under ``docs/paper/tables``):

* ``client_conditional_reach_bands.csv``    the reach vocabulary
* ``client_conditional_frontier.csv``       per client x tier minimum reach
* ``client_conditional_candidate_bounds.csv`` the tier-uncertain queue, bounded
* ``client_conditional_summary.csv``        headline counts
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


# --------------------------------------------------------------------------
# EF bug-bounty thresholds expressed as a fraction of the network affected by a
# single remote message or transaction.  Critical also has non-share criteria
# (create/finalize infinite ETH, steal or burn ETH from all EOAs) that this
# arithmetic deliberately does not model; the 0.50 entry is the validator
# slashing form of Critical, which is the only share-shaped one.
EF_THRESHOLD = {
    "Critical": 0.50,
    "High": 0.33,
    "Medium": 0.05,
    "Low": 0.0001,
}

# --------------------------------------------------------------------------
# Client-conditional reach vocabulary.  These bands describe the fraction of the
# operators running the affected client that a single attacker-supplied input can
# affect.  They are assessable from the fix itself, which is the whole point of
# the split.
REACH_BANDS = {
    "all_nodes": {
        "low": 0.90,
        "high": 1.00,
        "definition": (
            "Any node running this client on its default configuration processes "
            "the attacker-supplied input on the affected path."
        ),
    },
    "default_role_subset": {
        "low": 0.25,
        "high": 0.75,
        "definition": (
            "Only one common node role or default-adjacent mode is affected: "
            "validating vs non-validating, archive vs pruned, snap vs full sync, "
            "or an endpoint that is enabled by default but not always exposed."
        ),
    },
    "narrow_config": {
        "low": 0.01,
        "high": 0.25,
        "definition": (
            "A non-default flag, an unusual platform (for example a 32-bit host), "
            "an opt-in feature, or an operator-specific deployment shape is "
            "required."
        ),
    },
    "operator_self_only": {
        "low": 0.0,
        "high": 0.01,
        "definition": (
            "Only the operator's own node is affected through local action; no "
            "attacker-supplied remote input crosses to other operators."
        ),
    },
    "unknown": {
        "low": 0.0,
        "high": 1.00,
        "definition": (
            "Not assessed. Used so an unreviewed row widens its bound instead of "
            "silently assuming full reach."
        ),
    },
}

# --------------------------------------------------------------------------
# Deployment-share bands.  These are the prose tiers already hard-coded in
# collection/estimate_severity.py, made numeric so the inversion is auditable.
# They are NOT a sourced measurement: no observation date, no crawler, no
# citation.  Every table generated here reports the required share so a reader
# can substitute a sourced series; nothing downstream may present these bands as
# measured deployment data.
SHARE_BANDS = {
    "geth": ("execution", 0.45, 0.55),
    "nethermind": ("execution", 0.20, 0.30),
    "erigon": ("execution", 0.10, 0.20),
    "besu": ("execution", 0.00, 0.10),
    "reth": ("execution", 0.00, 0.10),
    "prysm": ("consensus", 0.30, 0.40),
    "lighthouse": ("consensus", 0.30, 0.40),
    "teku": ("consensus", 0.10, 0.15),
    "nimbus": ("consensus", 0.00, 0.10),
    "lodestar": ("consensus", 0.00, 0.05),
    "grandine": ("consensus", 0.00, 0.05),
}
SHARE_BANDS_PROVENANCE = (
    "unsourced prose tiers inherited from collection/estimate_severity.py; "
    "no observation date"
)


# Reach values established by the source reviews in liveness_candidate_audit.md, used
# to score the model's reach assessment. Only rows whose audit text states a
# configuration, platform, endpoint, or lifecycle restriction are listed: an audit that
# faulted a record's *trigger* or *impact* evidence says nothing about how many of the
# client's operators the code path covers, and reach must not be lowered for it.
REVIEWED_REACH = {
    # "an observed OOM ... explicitly noting a possible 32-bit-host condition"
    "b1c9a13d15ccd608": ("narrow_config", "OOM conditioned on a 32-bit host"),
    # "proves the panic but not unauthenticated public network reachability"
    "geth:ethereum-go-ethereum:PR#24946": (
        "narrow_config",
        "Engine API is an authenticated CL-to-EL endpoint, not the public network",
    ),
    # "cache/finalizer lifecycle behavior rather than an evidenced attacker trigger"
    "eceadd9c7892558a": (
        "operator_self_only",
        "local cache and finalizer lifecycle; no attacker input crosses operators",
    ),
    # "panic only once Verkle is activated"
    "9d281cd7385d8958": ("narrow_config", "requires Verkle activation"),
    # "a broad storage redesign", diff absent at a requested slot
    "lighthouse:networking:PR#4652": (
        "narrow_config",
        "hierarchical state diffs are part of an opt-in storage redesign",
    ),
    # "many parallel HTTP state requests" against an endpoint the operator exposes
    "lighthouse:networking:PR#4879": (
        "default_role_subset",
        "HTTP state endpoint exposure is an operator choice",
    ),
    # "explicitly basic, non-tested PeerDAS early-request feature"
    "lighthouse:networking:PR#5569": ("narrow_config", "unreleased PeerDAS feature"),
    # PeerDAS getBlobs race
    "6fad56ffd2f16be8": ("narrow_config", "unreleased PeerDAS feature"),
}


def score_reach_against_review(bounds: pd.DataFrame) -> pd.DataFrame:
    """Compare the model's reach with the source-reviewed reach, where one exists.

    This is the validity check the reframing needs: it moved the unmeasurable factor
    (historical deployment share) onto a measurable one (reach), so the measurement has
    to be scored against human source review rather than trusted.
    """
    rows = []
    for row_id, (reviewed, why) in REVIEWED_REACH.items():
        match = bounds[bounds["id"].eq(row_id)]
        if match.empty:
            continue
        record = match.iloc[0]
        model = str(record["client_conditional_reach"])
        rank = list(REACH_BANDS)  # ordered most to least permissive
        direction = "agree"
        if model != reviewed:
            direction = (
                "model_more_permissive"
                if rank.index(model) < rank.index(reviewed)
                else "model_more_restrictive"
            )
        rows.append(
            {
                "id": row_id,
                "client": record["client"],
                "model_reach": model,
                "reviewed_reach": reviewed,
                "direction": direction,
                "model_high_verdict": record["high_verdict"],
                "review_basis": why,
            }
        )
    return pd.DataFrame(rows).sort_values(["direction", "id"])


def required_reach(threshold: float, share: float) -> float | None:
    """Minimum client-conditional reach that meets ``threshold`` at ``share``."""
    if share <= 0:
        return None
    return threshold / share


def verdict(threshold: float, lo: float, hi: float) -> str:
    """Compare an evidenced affected-network-share interval with a threshold."""
    if hi < threshold:
        return "excluded"
    if lo >= threshold:
        return "supported"
    return "share_dependent"


def build_reach_band_table() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "reach_band": name,
                "reach_low": band["low"],
                "reach_high": band["high"],
                "definition": band["definition"],
            }
            for name, band in REACH_BANDS.items()
        ]
    )


def build_frontier() -> pd.DataFrame:
    """Per client x tier, the reach a client-specific defect must achieve.

    This table needs no LLM output and no record.  It is pure arithmetic over the
    EF thresholds and the share bands, and it establishes which tiers a
    client-specific defect can reach at all.
    """
    rows = []
    for client, (layer, share_lo, share_hi) in sorted(SHARE_BANDS.items()):
        for tier, threshold in EF_THRESHOLD.items():
            at_hi = required_reach(threshold, share_hi)
            at_lo = required_reach(threshold, share_lo)
            feasible = at_hi is not None and at_hi <= 1.0
            rows.append(
                {
                    "client": client,
                    "layer": layer,
                    "share_low": share_lo,
                    "share_high": share_hi,
                    "tier": tier,
                    "ef_network_threshold": threshold,
                    "min_reach_at_share_high": (
                        round(at_hi, 4) if at_hi is not None else ""
                    ),
                    "min_reach_at_share_low": (
                        round(at_lo, 4) if at_lo is not None else ""
                    ),
                    "client_specific_tier_feasible": feasible,
                    "share_bands_provenance": SHARE_BANDS_PROVENANCE,
                }
            )
    return pd.DataFrame(rows)


def bound_candidates(queue: pd.DataFrame) -> pd.DataFrame:
    """Bound each tier-uncertain candidate, using an assessed reach when present.

    ``client_conditional_reach`` is absent from the frozen snapshot: the estimator
    that produced those rows never asked for it.  A row without one is bounded with
    ``reach=unknown`` (0.0 to 1.0), the most favourable possible assumption, so a
    tier that is still ``excluded`` is excluded by arithmetic alone, independent of
    any source review.  Pass ``--severity-csv`` to join a re-estimation that does
    carry the axis; those rows then bound with their assessed band.

    ``blast_radius`` decides which share enters the upper bound:

    * ``client_specific`` -- only the fixing client's share;
    * ``spec_level`` -- up to the whole network, because a shared rule *may* be
      wrong in every implementation.  The evidenced *lower* bound is still only
      the fixing client's share, since no row enumerates which other clients
      actually contained the defect.
    """
    rows = []
    for record in queue.to_dict("records"):
        client = str(record.get("source_platform") or "").lower()
        layer, share_lo, share_hi = SHARE_BANDS.get(client, ("unknown", 0.0, 1.0))
        blast = str(record.get("blast_radius") or "") or "unspecified"

        reach_name = str(record.get("client_conditional_reach") or "").strip()
        if reach_name not in REACH_BANDS:
            reach_name = "unknown"
        reach_lo = REACH_BANDS[reach_name]["low"]
        reach_hi = REACH_BANDS[reach_name]["high"]

        # Upper bound on the affected network share.
        if blast == "spec_level":
            bound_share_hi = 1.0
            enumerated = "no_client_set_enumerated"
        else:
            bound_share_hi = share_hi
            enumerated = "fixing_client_only"

        affected_hi = bound_share_hi * reach_hi
        # Lower end stays on the fixing client's share even for spec_level, because
        # no row enumerates which other implementations held the shared-rule defect.
        affected_lo = share_lo * reach_lo

        high_at_hi = required_reach(EF_THRESHOLD["High"], share_hi)
        high_at_lo = required_reach(EF_THRESHOLD["High"], share_lo)
        rows.append(
            {
                "id": record["id"],
                "client": client,
                "layer": layer,
                "impact_type": record.get("impact_type", ""),
                "blast_radius": blast,
                "reachability": record.get("reachability", ""),
                "severity_estimated": record.get("severity_estimated", ""),
                "severity_analysis_label": record.get("severity_analysis_label", ""),
                "client_conditional_reach": reach_name,
                "affected_share_low": round(affected_lo, 6),
                "affected_share_high": round(affected_hi, 6),
                "spec_level_client_set": enumerated,
                # Share-independent requirement for a client-specific reading.
                "client_specific_min_reach_for_high_at_share_high": (
                    round(high_at_hi, 4) if high_at_hi is not None else ""
                ),
                "client_specific_min_reach_for_high_at_share_low": (
                    round(high_at_lo, 4) if high_at_lo is not None else ""
                ),
                "client_specific_high_feasible": (
                    high_at_hi is not None and high_at_hi <= 1.0
                ),
                "high_verdict": verdict(EF_THRESHOLD["High"], affected_lo, affected_hi),
                "medium_verdict": verdict(
                    EF_THRESHOLD["Medium"], affected_lo, affected_hi
                ),
            }
        )
    return pd.DataFrame(rows)


def build_reach_distribution(bounds: pd.DataFrame) -> pd.DataFrame:
    """Reach x blast radius x High verdict, once a re-estimation supplies reach.

    This is the table that shows whether the assessed reach actually moves records
    off ``share_dependent``, rather than only widening the bound.
    """
    grouped = (
        bounds.groupby(
            ["client_conditional_reach", "blast_radius", "high_verdict"], dropna=False
        )
        .size()
        .reset_index(name="records")
        .sort_values(["records", "client_conditional_reach"], ascending=[False, True])
    )
    return grouped


def build_summary(frontier: pd.DataFrame, bounds: pd.DataFrame) -> pd.DataFrame:
    high = frontier[frontier["tier"].eq("High")]
    feasible = high[high["client_specific_tier_feasible"]]
    infeasible = high[~high["client_specific_tier_feasible"]]
    medium = frontier[frontier["tier"].eq("Medium")]

    cs = bounds[bounds["blast_radius"].eq("client_specific")]
    spec = bounds[bounds["blast_radius"].eq("spec_level")]
    cs_needs_most = cs[
        pd.to_numeric(
            cs["client_specific_min_reach_for_high_at_share_high"], errors="coerce"
        )
        > 0.5
    ]
    cs_infeasible_low = cs[
        pd.to_numeric(
            cs["client_specific_min_reach_for_high_at_share_low"], errors="coerce"
        )
        > 1.0
    ]

    rows = [
        ("clients_in_share_table", len(SHARE_BANDS)),
        ("clients_where_client_specific_high_is_feasible", len(feasible)),
        ("clients_where_client_specific_high_is_arithmetically_excluded", len(infeasible)),
        (
            "clients_where_client_specific_medium_is_arithmetically_excluded",
            int((~medium["client_specific_tier_feasible"]).sum()),
        ),
        ("tier_uncertain_candidates", len(bounds)),
        ("candidates_client_specific", len(cs)),
        ("candidates_spec_level", len(spec)),
        (
            "client_specific_candidates_needing_reach_above_50pct_at_share_high",
            len(cs_needs_most),
        ),
        (
            "client_specific_candidates_infeasible_at_share_low",
            len(cs_infeasible_low),
        ),
        (
            "candidates_with_assessed_client_conditional_reach",
            int((bounds["client_conditional_reach"] != "unknown").sum()),
        ),
        # The point of assessing reach: a candidate whose High is arithmetically
        # excluded is resolved, not uncertain, and needs no source review to rule the
        # tier out. Everything else still needs a sourced deployment share.
        ("high_excluded_arithmetically", int(bounds["high_verdict"].eq("excluded").sum())),
        ("high_share_dependent", int(bounds["high_verdict"].eq("share_dependent").sum())),
        ("high_supported_at_any_plausible_share",
         int(bounds["high_verdict"].eq("supported").sum())),
    ]
    return pd.DataFrame(rows, columns=["measure", "value"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--queue",
        type=Path,
        default=Path("docs/paper/tables/ef_severity_high_review_queue.csv"),
    )
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    ap.add_argument(
        "--severity-csv",
        type=Path,
        default=None,
        help=(
            "optional re-estimation carrying client_conditional_reach, joined as an "
            "overlay by id. The frozen snapshot is never modified: rows the overlay "
            "does not cover keep reach=unknown."
        ),
    )
    args = ap.parse_args()

    queue = pd.read_csv(args.queue)
    uncertain = queue[queue["severity_analysis_label"].eq("tier-uncertain")].copy()

    if args.severity_csv and args.severity_csv.exists():
        overlay = pd.read_csv(args.severity_csv).drop_duplicates("id")
        cols = [c for c in ("id", "client_conditional_reach") if c in overlay.columns]
        if "client_conditional_reach" not in cols:
            raise SystemExit(
                f"{args.severity_csv} has no client_conditional_reach column; it "
                "predates the revised prompt."
            )
        before = len(uncertain)
        uncertain = uncertain.merge(overlay[cols], on="id", how="left")
        assert len(uncertain) == before, "overlay join must not change row count"
        covered = uncertain["client_conditional_reach"].isin(REACH_BANDS).sum()
        print(
            f"overlay {args.severity_csv}: {covered}/{before} candidates carry an "
            f"assessed client_conditional_reach"
        )

    reach_bands = build_reach_band_table()
    frontier = build_frontier()
    bounds = bound_candidates(uncertain)
    distribution = build_reach_distribution(bounds)
    reach_review = score_reach_against_review(bounds)
    summary = build_summary(frontier, bounds)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    reach_bands.to_csv(args.out_dir / "client_conditional_reach_bands.csv", index=False)
    frontier.to_csv(args.out_dir / "client_conditional_frontier.csv", index=False)
    bounds.sort_values(["client", "blast_radius", "id"]).to_csv(
        args.out_dir / "client_conditional_candidate_bounds.csv", index=False
    )
    distribution.to_csv(
        args.out_dir / "client_conditional_reach_distribution.csv", index=False
    )
    if not reach_review.empty:
        reach_review.to_csv(
            args.out_dir / "client_conditional_reach_vs_review.csv", index=False
        )
    summary.to_csv(args.out_dir / "client_conditional_summary.csv", index=False)

    print(f"tier-uncertain candidates: {len(bounds)}")
    print("\n=== client-specific High frontier ===")
    high = frontier[frontier["tier"].eq("High")]
    for row in high.to_dict("records"):
        state = "feasible" if row["client_specific_tier_feasible"] else "EXCLUDED"
        print(
            f"  {row['client']:11s} share {row['share_low']:.2f}-{row['share_high']:.2f}"
            f"  min reach {row['min_reach_at_share_high'] or 'n/a'}"
            f" (at share low: {row['min_reach_at_share_low'] or 'n/a'})  {state}"
        )
    if not reach_review.empty:
        print("\n=== model reach vs source-reviewed reach ===")
        print(reach_review[
            ["id", "model_reach", "reviewed_reach", "direction", "model_high_verdict"]
        ].to_string(index=False))
        print("  " + reach_review["direction"].value_counts().to_string().replace("\n", "\n  "))
    print("\n=== summary ===")
    for row in summary.to_dict("records"):
        print(f"  {row['measure']}: {row['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
