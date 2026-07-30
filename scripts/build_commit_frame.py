#!/usr/bin/env python3
"""Enumerate every commit in the eleven client clones as a sampling frame.

The corpus holds 1,957 distinct fix commits against a history of 613,820 non-merge
commits — 0.31%. Raising that by filtering is not viable: measured against the
MineBlockVuln labelled set, message mining tops out at 45.4% recall while selecting a
quarter of all history, an added-guard diff filter reaches 56.1% recall at 39%, and their
optimistic union would leave 389,076 commits to classify — about 400 hours of model time
(``tables/silent_fix_message_mining_ceiling.csv``).

That failure is not incidental. A silent fix is by definition a fix whose message does not
announce it, so a message-derived selector cannot find one; and the diff-shape medians of
known vulnerability commits are nearly identical to ordinary ones (2 files vs 1, 15 added
lines vs 10). The signal is not concentrated enough for needle-hunting at a 1.3% base rate.

What *is* affordable is a probability sample: 3,012 commits estimate a 2% rate to within
±0.5 percentage points at 95% confidence, in about three hours of model time. That is a
better instrument for the question anyway. The existing corpus is a convenience sample with
documented selection bias, so it cannot state a population rate at all; a probability sample
can, and it can also measure what the convenience sample over- and under-represents.

This script builds the frame that any such design needs. It is local-only — no API calls —
and deliberately stores just enough to sample and stratify from. Diff statistics are left
for the sampled rows, since computing them for 720k commits costs far more than the sample
does.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pandas as pd


REPO_DIR = Path("scratchpad_crawl/repos")
# %x1f separates fields and %x1e separates records: both are ASCII separators that cannot
# appear in a subject line, unlike the newlines and tabs a commit message may contain.
GIT_FORMAT = "%H%x1f%aI%x1f%s%x1e"


def enumerate_client(repo: Path) -> pd.DataFrame:
    """Every non-merge commit reachable from any ref, as sha / author date / subject.

    Merges are excluded because they carry no diff of their own; a squash-merge workflow
    still leaves the substantive commit on the branch.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "--all", "--no-merges", f"--format={GIT_FORMAT}"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    rows = []
    for record in proc.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split("\x1f")
        if len(parts) != 3:
            continue
        sha, authored, subject = parts
        rows.append({"sha": sha.strip(), "author_date": authored, "subject": subject})
    return pd.DataFrame(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-dir", type=Path, default=REPO_DIR)
    ap.add_argument("--out", type=Path, default=Path("data/commit_frame.parquet"))
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    args = ap.parse_args()

    frames = []
    for repo in sorted(args.repo_dir.glob("*.git")):
        client = repo.name[: -len(".git")]
        frame = enumerate_client(repo)
        frame["client"] = client
        print(f"[frame] {client:11s} {len(frame):7,d} non-merge commits", flush=True)
        frames.append(frame)

    if not frames:
        raise SystemExit(f"no clones under {args.repo_dir}")

    frame = pd.concat(frames, ignore_index=True)
    frame["year"] = frame["author_date"].str.slice(0, 4)
    # A handful of commits carry a broken author timestamp (Nethermind has one at the
    # Unix epoch), so year is kept as recorded and flagged rather than silently repaired.
    frame["date_implausible"] = frame["year"].lt("2013") | frame["year"].gt("2027")
    if frame["date_implausible"].any():
        print(f"[frame] {int(frame['date_implausible'].sum())} commits have an implausible "
              f"author date and are flagged, not corrected", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(args.out, index=False)

    corpus = Path("data/ethereum_vulns.parquet")
    known: set[str] = set()
    if corpus.exists():
        known = set(pd.read_parquet(corpus)["fix_commit"].dropna().astype(str))
    covered = int(frame["sha"].isin(known).sum())

    coverage = pd.DataFrame(
        [
            {
                "client": client,
                "commits": len(group),
                "earliest": group["author_date"].min()[:10],
                "latest": group["author_date"].max()[:10],
                "in_curated_corpus": int(group["sha"].isin(known).sum()),
            }
            for client, group in frame.groupby("client")
        ]
    )
    coverage["corpus_coverage_pct"] = (
        100 * coverage["in_curated_corpus"] / coverage["commits"]
    ).round(3)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    coverage.sort_values("commits", ascending=False).to_csv(
        args.out_dir / "commit_frame_coverage.csv", index=False
    )

    print(f"\nwrote {args.out}: {len(frame):,} commits across {frame['client'].nunique()} clients")
    print(f"curated corpus covers {covered:,} of them ({100 * covered / len(frame):.3f}%)")
    print(coverage.sort_values("commits", ascending=False).to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
