#!/usr/bin/env python3
"""Population estimates from the classified commit sample.

The curated corpus cannot state a population rate: it was assembled by keyword search, so
asking it what share of security fixes are silent is circular — the sample was selected by
the presence of the language whose absence defines "silent". This estimates the same
quantities from a probability sample, where every commit had a known chance of selection
and the answer therefore carries an interval.

**Unequal inclusion probabilities are handled, not ignored.** The sample was drawn per
client at a fraction of about 0.489%, but Erigon forked from Geth and Prysm carries part of
its history, so 10,423 commits sit in two or three clients at once. Such a commit had two or
three independent chances of being drawn, so its inclusion probability is
``1 - Π(1 - f_c)`` over the clients holding it, not ``f_c``. Weighting by ``1/π`` corrects
it exactly; treating every draw alike would over-weight early execution-layer history by
about a factor of three.

Intervals come from a stratified bootstrap rather than a closed form, because the estimator
is a ratio of weighted sums and the strata differ by two orders of magnitude in size.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def inclusion_probability(clients_sharing: int, fraction: float) -> float:
    """Chance a commit held by ``clients_sharing`` clients is drawn at least once."""
    return 1.0 - (1.0 - fraction) ** max(int(clients_sharing), 1)


def weighted_share(hit: np.ndarray, weight: np.ndarray) -> float:
    total = weight.sum()
    return float((hit * weight).sum() / total) if total else 0.0


def bootstrap_interval(
    hit: np.ndarray, weight: np.ndarray, strata: np.ndarray,
    iterations: int = 4000, seed: int = 20260801,
) -> tuple[float, float]:
    """Percentile interval from resampling within strata, preserving the design."""
    if len(hit) == 0:
        return (0.0, 0.0)
    rng = np.random.default_rng(seed)
    index_by_stratum = [np.flatnonzero(strata == s) for s in np.unique(strata)]
    draws = np.empty(iterations)
    for i in range(iterations):
        picked = np.concatenate([
            idx[rng.integers(0, len(idx), len(idx))] for idx in index_by_stratum if len(idx)
        ])
        draws[i] = weighted_share(hit[picked], weight[picked])
    return (float(np.percentile(draws, 2.5)), float(np.percentile(draws, 97.5)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", type=Path, default=Path("data/commit_sample_labels.csv"))
    ap.add_argument("--frame", type=Path, default=Path("data/commit_frame.parquet"))
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    ap.add_argument("--iterations", type=int, default=4000)
    args = ap.parse_args()

    labels = pd.read_csv(args.labels)
    frame = pd.read_parquet(args.frame)

    # One commit, one row: two shas were drawn twice under different clients.
    labels = labels.drop_duplicates("sha", keep="first")
    labels = labels[labels["classified"]].copy()

    sharing = frame.set_index("sha")["clients_sharing"].to_dict()
    fractions = (
        frame.groupby("client").size().rename("stratum")
        .to_frame().join(labels.groupby("client").size().rename("drawn"))
    )
    fractions["fraction"] = fractions["drawn"].fillna(0) / fractions["stratum"]
    frac_by_client = fractions["fraction"].to_dict()

    labels["clients_sharing"] = labels["sha"].map(sharing).fillna(1).astype(int)
    labels["pi"] = [
        inclusion_probability(k, frac_by_client.get(c, 0.0))
        for k, c in zip(labels["clients_sharing"], labels["client"])
    ]
    labels["hw"] = np.where(labels["pi"] > 0, 1.0 / labels["pi"], 0.0)

    hit = labels["security_relevant"].eq(True).to_numpy()
    weight = labels["hw"].to_numpy()
    strata = labels["client"].to_numpy()

    rows = []
    share = weighted_share(hit, weight)
    lo, hi = bootstrap_interval(hit, weight, strata, args.iterations)
    rows.append({
        "quantity": "security_relevant_share_of_all_commits",
        "population": "all non-merge commits in eleven clients",
        "n_classified": int(len(labels)),
        "n_hits": int(hit.sum()),
        "estimate_pct": round(100 * share, 2),
        "ci_low_pct": round(100 * lo, 2),
        "ci_high_pct": round(100 * hi, 2),
        "implied_population_count": int(round(share * len(frame))),
    })

    fixes = labels[hit]
    for name, mask in (
        ("silent", fixes["disclosure"].eq("silent")),
        ("implied_fix", fixes["disclosure"].eq("implied_fix")),
        ("explicit_security", fixes["disclosure"].eq("explicit_security")),
    ):
        sub_hit = mask.to_numpy()
        sub_w = fixes["hw"].to_numpy()
        est = weighted_share(sub_hit, sub_w)
        clo, chi = bootstrap_interval(sub_hit, sub_w, fixes["client"].to_numpy(), args.iterations)
        rows.append({
            "quantity": f"{name}_share_of_security_relevant_fixes",
            "population": "security-relevant fixes",
            "n_classified": int(len(fixes)),
            "n_hits": int(sub_hit.sum()),
            "estimate_pct": round(100 * est, 2),
            "ci_low_pct": round(100 * clo, 2),
            "ci_high_pct": round(100 * chi, 2),
            "implied_population_count": int(round(est * share * len(frame))),
        })

    estimates = pd.DataFrame(rows)

    per_client = []
    for client, group in labels.groupby("client"):
        g_hit = group["security_relevant"].eq(True).to_numpy()
        g_w = group["hw"].to_numpy()
        est = weighted_share(g_hit, g_w)
        clo, chi = bootstrap_interval(g_hit, g_w, np.zeros(len(group)), args.iterations)
        per_client.append({
            "client": client,
            "n_classified": len(group),
            "n_hits": int(g_hit.sum()),
            "estimate_pct": round(100 * est, 2),
            "ci_low_pct": round(100 * clo, 2),
            "ci_high_pct": round(100 * chi, 2),
            "ci_width_pp": round(100 * (chi - clo), 2),
        })
    per_client = pd.DataFrame(per_client).sort_values("n_classified", ascending=False)

    classes = (
        fixes.groupby("defect_class")
        .apply(lambda g: pd.Series({
            "n": len(g),
            "share_of_fixes_pct": round(100 * g["hw"].sum() / fixes["hw"].sum(), 2),
        }), include_groups=False)
        .reset_index()
        .sort_values("share_of_fixes_pct", ascending=False)
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    estimates.to_csv(args.out_dir / "commit_sample_estimates.csv", index=False)
    per_client.to_csv(args.out_dir / "commit_sample_by_client.csv", index=False)
    classes.to_csv(args.out_dir / "commit_sample_defect_classes.csv", index=False)

    print("=== population estimates (95% stratified bootstrap) ===")
    print(estimates[["quantity", "n_classified", "n_hits", "estimate_pct",
                     "ci_low_pct", "ci_high_pct"]].to_string(index=False))
    print("\n=== by client ===")
    print(per_client.to_string(index=False))
    print("\n=== defect classes among security-relevant fixes ===")
    print(classes.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
