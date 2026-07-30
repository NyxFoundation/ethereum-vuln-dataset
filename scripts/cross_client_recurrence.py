#!/usr/bin/env python3
"""Stage 7: does a defect surface recur across independent implementations?

The paper's novelty claim is cross-implementation analysis, so the question is whether
a fix in one client indicates variants in another. Two things must be said up front
about what this corpus can and cannot answer.

**It cannot test direction.** There is no fix date in the snapshot -- ``fix_commit`` is
a SHA and ``scraped_at`` is crawl time -- so "a fix in client A precedes variants in
client B" is not measurable here. Everything below measures *co-occurrence*, never
precedence, and the word "predicts" must not be used for it.

**Explicit specification anchors are sparse.** Naming an EIP, a consensus-spec
function, an opcode, or a fork is the only way a record states its shared-spec surface
directly, and fewer than one row in ten does. Section 2 reports that as a finding about
description quality rather than working around it.

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
ANCHOR_PATTERNS = {
    "eip": re.compile(r"\bEIP[-\s]?(\d{1,4})\b", re.IGNORECASE),
    "consensus_fn": re.compile(
        r"\b((?:process|compute|verify|is|get)_[a-z][a-z0-9_]{3,})\b"
    ),
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
    """Return normalised ``kind:value`` anchors named in a record's own text."""
    found = []
    for kind, pattern in ANCHOR_PATTERNS.items():
        for match in pattern.findall(text or ""):
            value = match if isinstance(match, str) else match[0]
            found.append(f"{kind}:{value.lower()}")
    return sorted(set(found))


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


def anchor_spread(data: pd.DataFrame) -> pd.DataFrame:
    """Client spread for every explicitly named specification anchor."""
    text = (
        data["title"].fillna("").astype(str)
        + " "
        + data["description"].fillna("").astype(str).str.slice(0, 4000)
    )
    rows = []
    for idx, anchors in text.map(extract_anchors).items():
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path,
                    default=Path("data/ethereum_vulns.parquet"))
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
    anchors = anchor_spread(data)

    usable = clusters[clusters["records"] >= 2]
    anchored = anchors[anchors["clients"] >= 2] if not anchors.empty else anchors
    anchor_rows = 0
    if not anchors.empty:
        text = (data["title"].fillna("").astype(str) + " "
                + data["description"].fillna("").astype(str).str.slice(0, 4000))
        anchor_rows = int(text.map(lambda t: bool(extract_anchors(t))).sum())

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
            ("fix_dates_available", 0),  # no date column: precedence is not testable
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
    summary.to_csv(args.out_dir / "cross_client_recurrence_summary.csv", index=False)

    print("=== cross-client spread by surface class, stratified by cluster size ===")
    print(comparison.to_string(index=False))
    if not permutation.empty:
        print("\n=== stratified permutation test ===")
        print(permutation.to_string(index=False))
    if not anchors.empty:
        print("\n=== explicit specification anchors in the most clients ===")
        print(anchors.head(12)[["anchor", "kind", "records", "clients"]].to_string(index=False))
    print("\n=== summary ===")
    for row in summary.to_dict("records"):
        print(f"  {row['measure']}: {row['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
