#!/usr/bin/env python3
"""Draw a stratified probability sample from the commit frame.

The curated corpus was assembled by keyword search, so it cannot answer the question the
paper most wants to answer. "What fraction of security-relevant fixes are silent?" is
circular when computed on a corpus that was *found* by looking for non-silent language —
the 88.2% figure in ``snapshot_audit.md`` measures the collector, not the population. A
probability sample breaks that circularity: every commit in the history has a known,
non-zero chance of selection, so the estimate carries a confidence interval and means what
it says.

Design:

* **Population** — every non-merge commit in the eleven client clones (613,820), which is
  the frame ``build_commit_frame.py`` produced.
* **Strata** — client. Collection intensity in the curated corpus already varies tenfold
  across clients (prysm 0.092%, nimbus 0.943%), so client is the axis most likely to carry
  a design effect.
* **Allocation** — proportional to stratum size, which minimises variance for the overall
  rate. The cost is that small clients get few draws: per-client rates from this sample
  carry wide intervals and must be reported with them, or the sample re-drawn with equal
  allocation if per-client rates are the target.
* **Seed** — fixed, so the drawn sample is reproducible and the estimate is auditable.

Weights are written out even though proportional allocation makes them near-uniform: an
estimate from a stratified sample is a weighted one, and carrying the weight makes that
explicit rather than assumed.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval — behaves at the small proportions expected here.

    The normal approximation is unusable near a 2% rate with modest n: it can put the
    lower bound below zero.
    """
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--frame", type=Path, default=Path("data/commit_frame.parquet"))
    ap.add_argument("--n", type=int, default=3000, help="total sample size")
    ap.add_argument("--seed", type=int, default=20260731)
    ap.add_argument("--out", type=Path, default=Path("data/commit_sample.csv"))
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    args = ap.parse_args()

    frame = pd.read_parquet(args.frame)
    total = len(frame)
    rng = np.random.default_rng(args.seed)

    draws = []
    design = []
    for client, group in frame.groupby("client"):
        # Largest-remainder allocation, so the parts sum to exactly n rather than to
        # n plus or minus a few from independent rounding.
        exact = args.n * len(group) / total
        design.append({"client": client, "stratum_size": len(group), "exact_allocation": exact})
    design = pd.DataFrame(design)
    design["take"] = np.floor(design["exact_allocation"]).astype(int)
    shortfall = args.n - int(design["take"].sum())
    if shortfall > 0:
        order = (design["exact_allocation"] - design["take"]).sort_values(ascending=False)
        design.loc[order.index[:shortfall], "take"] += 1

    for row in design.to_dict("records"):
        group = frame[frame["client"].eq(row["client"])]
        take = min(int(row["take"]), len(group))
        picked = group.iloc[rng.choice(len(group), size=take, replace=False)].copy()
        # Inverse selection probability: what each drawn commit stands for.
        picked["stratum_size"] = len(group)
        picked["stratum_drawn"] = take
        picked["weight"] = len(group) / take if take else 0.0
        draws.append(picked)

    sample = pd.concat(draws, ignore_index=True).sort_values(["client", "author_date"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    sample[["sha", "client", "author_date", "year", "subject",
            "stratum_size", "stratum_drawn", "weight"]].to_csv(args.out, index=False)

    design["drawn"] = design["client"].map(sample["client"].value_counts())
    design["sampling_fraction_pct"] = (
        100 * design["drawn"] / design["stratum_size"]
    ).round(4)
    design = design[["client", "stratum_size", "drawn", "sampling_fraction_pct"]]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    design.sort_values("stratum_size", ascending=False).to_csv(
        args.out_dir / "commit_sample_design.csv", index=False
    )

    print(f"drew {len(sample):,} of {total:,} commits (seed {args.seed})")
    print(design.sort_values("stratum_size", ascending=False).to_string(index=False))
    print("\nprecision this buys on the overall rate, if the true rate is:")
    for p in (0.01, 0.02, 0.05):
        lo, hi = wilson_interval(int(round(p * len(sample))), len(sample))
        print(f"  {100*p:4.1f}%  ->  95% CI [{100*lo:.2f}%, {100*hi:.2f}%]  (+/-{100*(hi-lo)/2:.2f}pp)")
    smallest = design.sort_values("stratum_size").iloc[0]
    lo, hi = wilson_interval(int(round(0.02 * smallest["drawn"])), int(smallest["drawn"]))
    print(f"\nper-client, the smallest stratum ({smallest['client']}, n={int(smallest['drawn'])}) "
          f"gives [{100*lo:.1f}%, {100*hi:.1f}%] at a true 2% — report per-client rates with "
          f"their intervals or re-draw with equal allocation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
