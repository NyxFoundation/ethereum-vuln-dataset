#!/usr/bin/env python3
"""Resolve each ``fix_commit`` to a committer date from the local bare clones.

[`docs/paper/cross_client_recurrence.md`](../docs/paper/cross_client_recurrence.md)
found that the single highest-value addition to the corpus is a fix date: without one,
"a fix in client A precedes variants in client B" is not testable, so cross-client
analysis is stuck at co-occurrence. The dates already exist in the clones that
``collection/local_diffs.py`` maintains under ``scratchpad_crawl/repos``, so this needs
no GitHub API traffic and no new annotation.

Both dates are recorded because they answer different questions. The **committer**
date is when the fix entered the branch, which is what precedence between clients is
about. The **author** date is when the patch was written, which survives rebases and
cherry-picks and is therefore the one to prefer when a maintainer's merge workflow
rewrites committer dates. They disagree often enough that a precedence analysis must
say which it used.

The output is an overlay keyed by ``id``, not a rebuild of the frozen snapshot:

* ``data/fix_dates.csv``                     id, sha, author and committer dates
* ``docs/paper/tables/fix_date_coverage.csv`` per-client coverage and date span
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pandas as pd


REPO_DIR = Path("scratchpad_crawl/repos")
# Git's own separator; %x1f is the ASCII unit separator, which cannot occur in a date.
GIT_FORMAT = "%H%x1f%aI%x1f%cI"


def resolve_batch(repo: Path, shas: list[str]) -> dict[str, tuple[str, str]]:
    """Return ``{input_sha: (author_date, committer_date)}`` for shas git recognises.

    ``git cat-file --batch-check``-style bulk lookup is not available for formatted
    output, so this uses one ``show`` invocation per batch of revisions. Unknown or
    unreachable objects make git exit non-zero while still printing the ones it did
    resolve, so the return value is parsed rather than gated on the exit code.

    ``fix_commit`` is not always a full object name -- 36 Prysm rows carry a 7-character
    abbreviation -- and git answers those with the *expanded* oid. Keying the result by
    what git printed would therefore silently drop every abbreviated row, so resolved
    oids are also indexed by prefix and matched back to the input.
    """
    if not repo.exists() or not shas:
        return {}
    by_oid: dict[str, tuple[str, str]] = {}
    # One process per chunk keeps the argv well inside limits on every platform.
    for start in range(0, len(shas), 200):
        chunk = shas[start:start + 200]
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", "-s", f"--format={GIT_FORMAT}", *chunk],
            capture_output=True,
            text=True,
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\x1f")
            if len(parts) == 3 and len(parts[0]) == 40:
                by_oid[parts[0]] = (parts[1], parts[2])

    resolved: dict[str, tuple[str, str]] = {}
    for sha in shas:
        if sha in by_oid:
            resolved[sha] = by_oid[sha]
            continue
        matches = [oid for oid in by_oid if oid.startswith(sha)]
        # An ambiguous prefix would attach the wrong date, so leave it unresolved.
        if len(matches) == 1:
            resolved[sha] = by_oid[matches[0]]
    return resolved


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path,
                    default=Path("data/ethereum_vulns.parquet"))
    ap.add_argument("--repo-dir", type=Path, default=REPO_DIR)
    ap.add_argument("--out", type=Path, default=Path("data/fix_dates.csv"))
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    args = ap.parse_args()

    data = pd.read_parquet(args.inp)
    have = data[data["fix_commit"].notna() & data["fix_commit"].ne("")].copy()
    have["fix_commit"] = have["fix_commit"].astype(str)

    rows = []
    for client, frame in have.groupby("source_platform"):
        repo = args.repo_dir / f"{client}.git"
        shas = sorted(set(frame["fix_commit"]))
        resolved = resolve_batch(repo, shas)
        print(f"[dates] {client:11s} {len(resolved)}/{len(shas)} shas resolved",
              flush=True)
        for record in frame.to_dict("records"):
            dates = resolved.get(record["fix_commit"])
            rows.append(
                {
                    "id": record["id"],
                    "source_platform": client,
                    "fix_commit": record["fix_commit"],
                    "fix_author_date": dates[0] if dates else "",
                    "fix_committer_date": dates[1] if dates else "",
                }
            )

    out = pd.DataFrame(rows)
    resolved_mask = out["fix_committer_date"].ne("")
    out.to_csv(args.out, index=False)

    stamped = out[resolved_mask].copy()
    stamped["committer_year"] = stamped["fix_committer_date"].str.slice(0, 4)
    # A rebase or squash-merge moves the committer date without moving the author date;
    # counting the disagreement tells a reader which field to trust for precedence.
    stamped["dates_differ"] = (
        stamped["fix_author_date"].str.slice(0, 10)
        != stamped["fix_committer_date"].str.slice(0, 10)
    )
    coverage = (
        stamped.groupby("source_platform")
        .agg(
            rows_with_fix_commit=("id", "count"),
            earliest=("fix_committer_date", "min"),
            latest=("fix_committer_date", "max"),
            author_committer_day_differs=("dates_differ", "sum"),
        )
        .reset_index()
    )
    coverage["rows_requested"] = coverage["source_platform"].map(
        have["source_platform"].value_counts()
    )
    coverage["resolved_pct"] = (
        100 * coverage["rows_with_fix_commit"] / coverage["rows_requested"]
    ).round(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    coverage.to_csv(args.out_dir / "fix_date_coverage.csv", index=False)

    print(f"\nwrote {args.out}")
    print(coverage.to_string(index=False))
    print(f"\nresolved {int(resolved_mask.sum())}/{len(out)} rows "
          f"({100 * resolved_mask.mean():.1f}%)")
    if resolved_mask.any():
        print(f"date span: {stamped['fix_committer_date'].min()[:10]} .. "
              f"{stamped['fix_committer_date'].max()[:10]}")
        print(f"author/committer day differs on "
              f"{int(stamped['dates_differ'].sum())} rows "
              f"({100 * stamped['dates_differ'].mean():.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
