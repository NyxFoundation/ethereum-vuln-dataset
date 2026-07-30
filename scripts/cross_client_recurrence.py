#!/usr/bin/env python3
r"""Stage 7: does a defect surface recur across independent implementations?

The paper's novelty claim is cross-implementation analysis, so the question is whether
a fix in one client indicates variants in another. Two things must be said up front
about what this corpus can and cannot answer.

**Direction needs a date the snapshot lacks.** ``fix_commit`` is a SHA and
``scraped_at`` is crawl time, so precedence is not testable from the Parquet file alone.
``scripts/resolve_fix_dates.py`` recovers a committer and author date for all 1,959 rows
that have a fix commit, from the bare clones the crawler already maintains; pass the
resulting overlay via ``--fix-dates`` and section 4 orders each multi-client anchor in
time. Without it, everything here is co-occurrence only.

**An anchor must be readable from the record.** A record states its shared-spec surface
by naming an EIP, a consensus-spec function, or an opcode. Prose alone does so on 8.1%
of rows, so the captured ``post_fix_code`` is scanned too: a spec function appears in the
code that implements it whether or not the author mentioned it.

Two things make that scan trustworthy rather than merely larger. Spec function names are
**enumerated**, because a generic ``(process|get|is)_\w+`` pattern is dominated by
language idiom -- its most frequent corpus hits are ``is_empty``, ``is_none`` and
``is_some``. And matching is **naming-convention agnostic**: the specs are snake_case and
Rust and Nim keep it, but Java and TypeScript write ``processAttestation`` and Go writes
``ProcessAttestation``, so a snake_case-only match would decide which *languages* are
able to appear in a cross-client result at all.

The primary analysis therefore uses the dataset's own normalised coordinates
(``label`` x ``root_cause``) and asks a contrast question with an internal control: do
surfaces defined by a *shared specification* show more cross-client spread than
surfaces that are each client's own business? A raw cross-client rate would be
uninterpretable -- with eleven clients, any large cluster spans several by chance -- so
the comparison is stratified by cluster size and tested by permutation.

Outputs under ``docs/paper/tables``:

* ``cross_client_cluster_spread.csv``      per (layer, label, root_cause) cluster
* ``cross_client_surface_comparison.csv``  spec-anchored vs client-local, by size
* ``cross_client_permutation_test.csv``    the stratified permutation result
* ``cross_client_spec_anchors.csv``        explicit anchors and their client spread
* ``cross_client_anchor_precedence.csv``   multi-client anchors ordered in time
* ``cross_client_anchor_first_mover.csv``  which client is first, across anchors
* ``cross_client_recurrence_summary.csv``  headline counts
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------
# Which protocol surfaces are defined by a specification every client must follow,
# and which are each implementation's own business. This is the internal control: if
# cross-client recurrence is driven by shared specification, it should concentrate in
# the first group. Assignments follow the Ethereum specs rather than intuition --
# JSON-RPC and the Engine API are specified, while transaction-pool policy explicitly
# is not, and a client's database, CLI, and metrics are nobody else's contract.
SPEC_ANCHORED_LABELS = {
    "evm", "opcodes", "gas", "precompiles", "state-trie", "transactions",
    "block-processing", "fork-choice", "serialization", "crypto",
    "kzg-commitments", "blobs", "data-availability-sampling", "engine-api",
    "p2p-interface", "light-client", "validator", "withdrawals", "deposits",
    "rlp", "bls", "deposit-contract", "fork-transition", "weak-subjectivity",
    "beacon-chain:attestation", "beacon-chain:block-processing",
    "beacon-chain:slashing", "beacon-chain:execution-payload",
    "beacon-chain:sync-committee", "beacon-chain:epoch-processing",
    "beacon-chain:state-transition", "beacon-chain:fork-choice",
}

# A deliberately narrow reading, used only to check that the result below is not an
# artifact of where the broad set draws its line: consensus-critical state transition
# and execution semantics, where every client must produce a bit-identical result.
NARROW_SPEC_ANCHORED_LABELS = {
    "evm", "opcodes", "gas", "precompiles", "state-trie", "block-processing",
    "fork-choice", "serialization", "rlp", "transactions",
    "beacon-chain:block-processing", "beacon-chain:epoch-processing",
    "beacon-chain:state-transition", "beacon-chain:fork-choice",
    "beacon-chain:attestation", "beacon-chain:execution-payload",
}
CLIENT_LOCAL_LABELS = {
    "rpc",  # JSON-RPC is specified, but these rows are server-implementation defects
    "database", "cli", "build-ci", "test", "metrics-observability",
    "txpool",  # mempool policy is deliberately unspecified
    "builder", "p2p", "sync", "logging", "keystore", "docs",
}


def classify_surface(label: str, narrow: bool = False) -> str:
    if narrow:
        if label in NARROW_SPEC_ANCHORED_LABELS:
            return "spec_anchored"
        return "client_local" if label != "other" else "unclassified"
    if label in SPEC_ANCHORED_LABELS or label.startswith("beacon-chain:"):
        return "spec_anchored"
    if label in CLIENT_LOCAL_LABELS:
        return "client_local"
    return "unclassified"


# --------------------------------------------------------------------------
# Explicit specification anchors. A record that names one of these states its shared
# surface directly, so co-occurrence across clients is much closer to "the same spec
# text" than a taxonomy match is.
#
# Consensus-spec function names are enumerated rather than pattern-matched. A generic
# `(process|get|is|compute)_\w+` pattern looks attractive but is dominated by language
# idiom -- across the corpus its most frequent hits are `is_empty`, `is_none`, `is_some`
# and `get_state`, which are Rust Option methods and ordinary accessors, not spec
# surfaces.
CONSENSUS_SPEC_FUNCTIONS = (
    # phase0 state transition
    "process_slots", "process_slot", "process_block", "process_epoch",
    "process_block_header", "process_randao", "process_eth1_data",
    "process_operations", "process_proposer_slashing", "process_attester_slashing",
    "process_attestation", "process_deposit", "process_voluntary_exit",
    "process_justification_and_finalization", "process_rewards_and_penalties",
    "process_registry_updates", "process_slashings", "process_eth1_data_reset",
    "process_effective_balance_updates", "process_slashings_reset",
    "process_randao_mixes_reset", "process_historical_roots_update",
    "process_participation_record_updates",
    # altair and later
    "process_sync_aggregate", "process_participation_flag_updates",
    "process_sync_committee_updates", "process_inactivity_updates",
    "process_execution_payload", "process_withdrawals",
    "process_bls_to_execution_change", "process_deposit_request",
    "process_withdrawal_request", "process_consolidation_request",
    "process_pending_deposits", "process_pending_consolidations",
    "process_execution_requests",
    # accessors
    "get_current_epoch", "get_previous_epoch", "get_block_root",
    "get_block_root_at_slot", "get_randao_mix", "get_active_validator_indices",
    "get_validator_churn_limit", "get_seed", "get_committee_count_per_slot",
    "get_beacon_committee", "get_beacon_proposer_index", "get_total_balance",
    "get_total_active_balance", "get_domain", "get_indexed_attestation",
    "get_attesting_indices", "get_next_sync_committee", "get_sync_committee_indices",
    "get_unslashed_participating_indices", "get_flag_index_deltas",
    "get_inactivity_penalty_deltas", "get_eligible_validator_indices",
    "get_finality_delay", "get_expected_withdrawals", "get_balance_churn_limit",
    "get_activation_exit_churn_limit", "get_consolidation_churn_limit",
    "get_pending_balance_to_withdraw", "get_base_reward",
    "get_base_reward_per_increment", "get_proposer_reward",
    "get_attestation_participation_flag_indices",
    # fork choice
    "get_head", "get_ancestor", "get_weight", "get_checkpoint_block",
    "get_voting_source", "get_filtered_block_tree", "get_proposer_score",
    "on_block", "on_attestation", "on_tick", "on_attester_slashing",
    # predicates
    "is_active_validator", "is_eligible_for_activation",
    "is_eligible_for_activation_queue", "is_slashable_validator",
    "is_slashable_attestation_data", "is_valid_indexed_attestation",
    "is_valid_merkle_branch", "is_aggregator", "is_sync_committee_aggregator",
    "is_merge_transition_complete", "is_merge_transition_block",
    "is_execution_block", "is_valid_genesis_state", "is_previous_epoch_justified",
    "is_optimistic_candidate_block", "is_fully_withdrawable_validator",
    "is_partially_withdrawable_validator", "is_valid_deposit_signature",
    "is_compounding_validator",
    # signature checks
    "verify_block_signature", "verify_deposit_signature",
    "verify_sync_committee_signature", "verify_merkle_branch",
    # helpers
    "compute_epoch_at_slot", "compute_start_slot_at_epoch", "compute_shuffled_index",
    "compute_proposer_index", "compute_committee", "compute_activation_exit_epoch",
    "compute_fork_digest", "compute_domain", "compute_signing_root",
    "compute_subscribed_subnets", "compute_timestamp_at_slot",
    "compute_sync_committee_period", "compute_weak_subjectivity_period",
    "compute_exit_epoch_and_update_churn",
    "compute_consolidation_epoch_and_update_churn",
)


def _naming_convention_agnostic(name: str) -> str:
    """Match a spec name across the conventions the eleven clients actually use.

    The specs are written in snake_case and Rust and Nim keep it, but Java and
    TypeScript render `process_attestation` as `processAttestation` and Go as
    `ProcessAttestation`. Matching snake_case alone would make an anchor findable only
    in some languages, which for a cross-client analysis is not a coverage gap but a
    bias: it decides which implementations are *able* to appear at all.
    """
    return r"\b" + r"_?".join(re.escape(part) for part in name.split("_")) + r"\b"


CONSENSUS_FN_RE = re.compile(
    "|".join(f"({_naming_convention_agnostic(name)})" for name in CONSENSUS_SPEC_FUNCTIONS),
    re.IGNORECASE,
)

ANCHOR_PATTERNS = {
    "eip": re.compile(r"\bEIP[-\s]?(\d{1,4})\b", re.IGNORECASE),
    "opcode": re.compile(
        r"\b(MULMOD|ADDMOD|EXP|SHL|SHR|SAR|CALLDATACOPY|RETURNDATACOPY|EXTCODECOPY"
        r"|CREATE2|SELFDESTRUCT|DELEGATECALL|STATICCALL|BLOBHASH|MCOPY|TSTORE|TLOAD"
        r"|BLOCKHASH|CODECOPY|SSTORE|SLOAD)\b"
    ),
    "fork": re.compile(
        r"\b(Homestead|Byzantium|Constantinople|Istanbul|Berlin|London|Paris"
        r"|Shanghai|Capella|Deneb|Electra|Fulu|Pectra|Prague|Osaka|Verkle"
        r"|Kintsugi|Kiln|Altair|Bellatrix|Merge)\b"
    ),
}


def extract_anchors(text: str) -> list[str]:
    """Return normalised ``kind:value`` anchors named in a record's own text or code."""
    text = text or ""
    found = []
    for kind, pattern in ANCHOR_PATTERNS.items():
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            found.append(f"{kind}:{value.lower()}")
    # Report the canonical snake_case spec name whatever convention the client used, so
    # a Java and a Rust record land on the same anchor.
    for match in CONSENSUS_FN_RE.finditer(text):
        if match.lastindex is None:  # alternation always captures; guard for clarity
            continue
        canonical = CONSENSUS_SPEC_FUNCTIONS[match.lastindex - 1]
        found.append(f"consensus_fn:{canonical}")
    return sorted(set(found))


def anchor_source_text(data: pd.DataFrame, code_chars: int = 20000) -> pd.Series:
    """Text an anchor may be named in: the record's prose plus its post-fix code.

    Prose alone names an anchor on 8.1% of records. The captured post-fix code names one
    on far more, because a spec function or opcode appears in the code that implements
    it whether or not the author mentioned it in the title.
    """
    return (
        data["title"].fillna("").astype(str)
        + " "
        + data["description"].fillna("").astype(str).str.slice(0, 4000)
        + " "
        + data["post_fix_code"].fillna("").astype(str).str.slice(0, code_chars)
    )


def build_clusters(data: pd.DataFrame) -> pd.DataFrame:
    """One row per (layer, label, root_cause) cluster with its client spread."""
    grouped = data.groupby(["layer", "label", "root_cause"], dropna=False)
    rows = []
    for (layer, label, root_cause), frame in grouped:
        clients = sorted(frame["source_platform"].dropna().unique())
        rows.append(
            {
                "layer": layer,
                "label": label,
                "root_cause": root_cause,
                "surface": classify_surface(str(label)),
                "surface_narrow": classify_surface(str(label), narrow=True),
                "records": len(frame),
                "clients": len(clients),
                "spans_multiple_clients": len(clients) >= 2,
                "client_list": ";".join(clients),
            }
        )
    return pd.DataFrame(rows).sort_values(
        ["records", "clients"], ascending=False
    )


SIZE_BUCKETS = [(2, 3), (4, 7), (8, 15), (16, 10**9)]


def size_bucket(n: int) -> str | None:
    for low, high in SIZE_BUCKETS:
        if low <= n <= high:
            return f"{low}-{high}" if high < 10**9 else f"{low}+"
    return None  # singleton clusters cannot span clients; excluded, not counted as 0


def compare_surfaces(clusters: pd.DataFrame) -> pd.DataFrame:
    """Cross-client rate for each surface class, stratified by cluster size.

    Singleton clusters are dropped rather than scored: one record cannot span two
    clients, so including them would measure cluster-size distribution instead of
    recurrence.
    """
    usable = clusters[clusters["records"] >= 2].copy()
    usable["size_bucket"] = usable["records"].map(size_bucket)
    rows = []
    for (bucket, surface), frame in usable.groupby(["size_bucket", "surface"]):
        spans = int(frame["spans_multiple_clients"].sum())
        rows.append(
            {
                "size_bucket": bucket,
                "surface": surface,
                "clusters": len(frame),
                "spanning_multiple_clients": spans,
                "spanning_pct": round(100 * spans / len(frame), 1),
                "mean_clients": round(float(frame["clients"].mean()), 2),
                "records": int(frame["records"].sum()),
            }
        )
    order = {f"{lo}-{hi}" if hi < 10**9 else f"{lo}+": i
             for i, (lo, hi) in enumerate(SIZE_BUCKETS)}
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values(
        ["size_bucket", "surface"], key=lambda s: s.map(order) if s.name == "size_bucket" else s
    )


def stratified_permutation_test(
    clusters: pd.DataFrame,
    iterations: int = 20000,
    seed: int = 20260730,
    surface_column: str = "surface",
) -> pd.DataFrame:
    """Test whether spec-anchored surfaces spread across more clients than local ones.

    The statistic is the difference in mean client count, pooled over size strata so a
    surface class cannot win by having larger clusters. The null shuffles the surface
    label *within* each stratum, which is the assumption being tested: that a cluster's
    client spread is unrelated to whether its surface is specified.
    """
    usable = clusters[
        clusters["records"].ge(2) & clusters[surface_column].ne("unclassified")
    ].copy()
    usable["size_bucket"] = usable["records"].map(size_bucket)
    if usable.empty or usable[surface_column].nunique() < 2:
        return pd.DataFrame()

    def statistic(surface: pd.Series) -> float:
        total = 0.0
        weight = 0
        for _, frame in usable.groupby("size_bucket"):
            local = surface.loc[frame.index]
            spec = frame.loc[local.eq("spec_anchored"), "clients"]
            own = frame.loc[local.eq("client_local"), "clients"]
            if spec.empty or own.empty:
                continue
            total += len(frame) * (spec.mean() - own.mean())
            weight += len(frame)
        return total / weight if weight else float("nan")

    observed = statistic(usable[surface_column])
    rng = np.random.default_rng(seed)
    draws = np.empty(iterations)
    for i in range(iterations):
        shuffled = usable.groupby("size_bucket")[surface_column].transform(
            lambda s: pd.Series(rng.permutation(s.to_numpy()), index=s.index)
        )
        draws[i] = statistic(shuffled)
    finite = draws[np.isfinite(draws)]
    # two-sided, with the conventional +1 correction so p is never exactly zero
    p_value = (int((np.abs(finite) >= abs(observed)).sum()) + 1) / (len(finite) + 1)
    return pd.DataFrame(
        [
            {
                "surface_definition": surface_column,
                "statistic": "stratified difference in mean clients per cluster",
                "observed": round(float(observed), 4),
                "null_mean": round(float(finite.mean()), 4),
                "null_sd": round(float(finite.std(ddof=1)), 4),
                "iterations": len(finite),
                "p_value_two_sided": round(float(p_value), 6),
                "seed": seed,
            }
        ]
    )


def anchor_spread(data: pd.DataFrame, per_row: pd.Series) -> pd.DataFrame:
    """Client spread for every explicitly named specification anchor."""
    rows = []
    for idx, anchors in per_row.items():
        for anchor in anchors:
            rows.append({"anchor": anchor, "id": data.at[idx, "id"],
                         "client": data.at[idx, "source_platform"],
                         "layer": data.at[idx, "layer"],
                         "label": data.at[idx, "label"]})
    if not rows:
        return pd.DataFrame()
    long = pd.DataFrame(rows)
    grouped = long.groupby("anchor")
    out = pd.DataFrame(
        {
            "records": grouped["id"].nunique(),
            "clients": grouped["client"].nunique(),
            "client_list": grouped["client"].apply(lambda s: ";".join(sorted(set(s)))),
            "labels": grouped["label"].apply(lambda s: ";".join(sorted(set(s.astype(str))))),
        }
    ).reset_index()
    out["kind"] = out["anchor"].str.split(":").str[0]
    return out.sort_values(["clients", "records"], ascending=False)


def anchor_precedence(
    data: pd.DataFrame, anchors: pd.DataFrame, dates: pd.DataFrame, per_row: pd.Series
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Order each multi-client anchor in time and report who was first.

    This is the directional question, and it is only answerable once ``fix_commit`` has
    a date (see scripts/resolve_fix_dates.py). Fork-name anchors are excluded: they mark
    a release cycle, so "who shipped Electra first" is not a statement about defects.

    Author date is used rather than committer date because squash-merges and rebases
    rewrite the latter, which would reorder clients by their maintainers' merge
    workflows instead of by when the patch was written.
    """
    if anchors.empty or dates.empty:
        return pd.DataFrame(), pd.DataFrame()

    stamped = dates[dates["fix_author_date"].notna() & dates["fix_author_date"].ne("")]
    when = dict(zip(stamped["id"], stamped["fix_author_date"]))

    rows = []
    for idx, found in per_row.items():
        row_id = data.at[idx, "id"]
        stamp = when.get(row_id)
        if not stamp:
            continue
        for anchor in found:
            if anchor.startswith("fork:"):
                continue
            rows.append(
                {
                    "anchor": anchor,
                    "id": row_id,
                    "client": data.at[idx, "source_platform"],
                    "author_date": stamp,
                }
            )
    if not rows:
        return pd.DataFrame(), pd.DataFrame()

    long = pd.DataFrame(rows)
    long["date"] = pd.to_datetime(long["author_date"], utc=True, format="ISO8601")

    ordered = []
    for anchor, frame in long.groupby("anchor"):
        if frame["client"].nunique() < 2:
            continue
        frame = frame.sort_values("date")
        first, last = frame.iloc[0], frame.iloc[-1]
        ordered.append(
            {
                "anchor": anchor,
                "records": len(frame),
                "clients": frame["client"].nunique(),
                "first_client": first["client"],
                "first_date": first["date"].date().isoformat(),
                "last_client": last["client"],
                "last_date": last["date"].date().isoformat(),
                "span_days": int((last["date"] - first["date"]).days),
                "client_order": ";".join(frame["client"].tolist()),
            }
        )
    if not ordered:
        return pd.DataFrame(), pd.DataFrame()

    detail = pd.DataFrame(ordered).sort_values(["clients", "span_days"], ascending=False)
    leaders = (
        detail.groupby("first_client")
        .agg(times_first=("anchor", "count"),
             median_span_days=("span_days", "median"))
        .reset_index()
        .sort_values("times_first", ascending=False)
    )

    # Raw first-mover counts are not evidence of leadership: a client that appears in
    # more anchors gets more chances to be first. Normalise by each client's share of
    # all positions across the multi-client anchors, so a ratio near 1 means "first as
    # often as it shows up at all" -- that is, no information beyond volume.
    positions = detail["client_order"].str.split(";").explode()
    position_share = positions.value_counts()
    position_counts = pd.DataFrame(
        {"first_client": position_share.index, "positions": position_share.to_numpy()}
    )
    leaders = leaders.merge(position_counts, on="first_client", how="left")
    leaders["position_share_pct"] = (
        100 * leaders["positions"] / int(position_share.sum())
    ).round(1)
    leaders["first_share_pct"] = (
        100 * leaders["times_first"] / int(leaders["times_first"].sum())
    ).round(1)
    leaders["first_to_position_ratio"] = (
        leaders["first_share_pct"] / leaders["position_share_pct"]
    ).round(2)
    return detail, leaders.sort_values("times_first", ascending=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path,
                    default=Path("data/ethereum_vulns.parquet"))
    ap.add_argument("--fix-dates", type=Path, default=Path("data/fix_dates.csv"),
                    help="overlay from scripts/resolve_fix_dates.py; enables the "
                         "precedence analysis, which is otherwise skipped")
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    ap.add_argument("--iterations", type=int, default=20000)
    args = ap.parse_args()

    data = pd.read_parquet(args.inp)
    clusters = build_clusters(data)
    comparison = compare_surfaces(clusters)
    permutation = pd.concat(
        [
            stratified_permutation_test(
                clusters, iterations=args.iterations, surface_column=column
            )
            for column in ("surface", "surface_narrow")
        ],
        ignore_index=True,
    )
    # Extraction scans up to 20k characters per row against a large alternation, so it
    # runs once here and every consumer reuses the result.
    anchors_per_row = anchor_source_text(data).map(extract_anchors)
    anchors = anchor_spread(data, anchors_per_row)
    dates = (
        pd.read_csv(args.fix_dates, dtype=str)
        if args.fix_dates.exists()
        else pd.DataFrame()
    )
    precedence, leaders = anchor_precedence(data, anchors, dates, anchors_per_row)

    usable = clusters[clusters["records"] >= 2]
    anchored = anchors[anchors["clients"] >= 2] if not anchors.empty else anchors
    anchor_rows = 0
    if not anchors.empty:
        anchor_rows = int(anchors_per_row.map(bool).sum())

    summary = pd.DataFrame(
        [
            ("records", len(data)),
            ("clusters_label_x_root_cause", len(clusters)),
            ("clusters_with_at_least_two_records", len(usable)),
            ("clusters_spanning_multiple_clients", int(usable["spans_multiple_clients"].sum())),
            ("records_in_multi_client_clusters",
             int(usable.loc[usable["spans_multiple_clients"], "records"].sum())),
            ("spec_anchored_clusters",
             int(usable["surface"].eq("spec_anchored").sum())),
            ("client_local_clusters", int(usable["surface"].eq("client_local").sum())),
            ("unclassified_clusters", int(usable["surface"].eq("unclassified").sum())),
            ("records_naming_an_explicit_spec_anchor", anchor_rows),
            ("records_naming_an_anchor_pct", round(100 * anchor_rows / len(data), 1)),
            ("distinct_explicit_anchors", len(anchors)),
            ("explicit_anchors_in_two_or_more_clients", len(anchored)),
            ("fix_dates_resolved", int(dates["fix_author_date"].ne("").sum())
             if not dates.empty else 0),
            ("non_fork_anchors_with_dates_in_two_or_more_clients", len(precedence)),
            # A span of years means both clients merely touched a long-lived surface at
            # some point; propagation would show up as a short one.
            ("multi_client_anchors_span_90_days_or_less",
             int(precedence["span_days"].le(90).sum()) if not precedence.empty else 0),
            ("multi_client_anchors_span_over_2_years",
             int(precedence["span_days"].gt(730).sum()) if not precedence.empty else 0),
            ("median_span_days_across_anchors",
             int(precedence["span_days"].median()) if not precedence.empty else 0),
            ("most_times_first_by_any_single_client",
             int(leaders["times_first"].max()) if not leaders.empty else 0),
            # After controlling for how often each client appears at all, a leader would
            # show a ratio well above 1 on a non-trivial number of anchors.
            ("clients_first_more_often_than_volume_predicts",
             int((leaders["first_to_position_ratio"] > 1.2).sum())
             if not leaders.empty else 0),
            ("largest_volume_client_first_to_position_ratio",
             float(leaders.sort_values("positions", ascending=False)
                   .iloc[0]["first_to_position_ratio"])
             if not leaders.empty else 0.0),
            ("distinct_clients_appearing_first",
             int(len(leaders)) if not leaders.empty else 0),
        ],
        columns=["measure", "value"],
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    clusters.to_csv(args.out_dir / "cross_client_cluster_spread.csv", index=False)
    comparison.to_csv(args.out_dir / "cross_client_surface_comparison.csv", index=False)
    if not permutation.empty:
        permutation.to_csv(args.out_dir / "cross_client_permutation_test.csv", index=False)
    if not anchors.empty:
        anchors.to_csv(args.out_dir / "cross_client_spec_anchors.csv", index=False)
    if not precedence.empty:
        precedence.to_csv(
            args.out_dir / "cross_client_anchor_precedence.csv", index=False
        )
        leaders.to_csv(
            args.out_dir / "cross_client_anchor_first_mover.csv", index=False
        )
    summary.to_csv(args.out_dir / "cross_client_recurrence_summary.csv", index=False)

    print("=== cross-client spread by surface class, stratified by cluster size ===")
    print(comparison.to_string(index=False))
    if not permutation.empty:
        print("\n=== stratified permutation test ===")
        print(permutation.to_string(index=False))
    if not anchors.empty:
        print("\n=== explicit specification anchors in the most clients ===")
        print(anchors.head(12)[["anchor", "kind", "records", "clients"]].to_string(index=False))
    if not precedence.empty:
        print("\n=== multi-client anchors ordered in time (author date) ===")
        print(precedence[["anchor", "clients", "first_client", "first_date",
                          "last_client", "last_date", "span_days"]].to_string(index=False))
        print("\n=== which client is first, across anchors ===")
        print(leaders.to_string(index=False))
    print("\n=== summary ===")
    for row in summary.to_dict("records"):
        print(f"  {row['measure']}: {row['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
