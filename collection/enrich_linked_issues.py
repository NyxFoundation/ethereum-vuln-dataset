#!/usr/bin/env python3
"""enrich_linked_issues.py — [C5] linked-issue / fuzzer-report signal.

A stealth PR is often terse ("fix edge case") while the *issue it closes*
describes the real impact — a crash, panic, consensus divergence, or a fuzzer
report. This adds a second independent signal: for each candidate PR, resolve
the issues it closes and score their title+body for vuln language and known
fuzzer reporters. Writes a sidecar CSV consumed by the curation as
`linked_issue_signal`, which `count_signals()` already reads to promote a row
into the corroborated tier.

Output: <out>  (CSV: source_url, linked_issue_signal, evidence)

Usage:
    uv run python collection/enrich_linked_issues.py \
        --in data/ethereum_vulns.parquet --out scratchpad_crawl/supp/linked_issues.csv \
        --tier C_candidate --limit 400
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd

CLIENT_REPOS: dict[str, str] = {
    "geth": "ethereum/go-ethereum", "nethermind": "NethermindEth/nethermind",
    "besu": "hyperledger/besu", "erigon": "erigontech/erigon",
    "reth": "paradigmxyz/reth", "lighthouse": "sigp/lighthouse",
    "lodestar": "ChainSafe/lodestar", "nimbus": "status-im/nimbus-eth2",
    "prysm": "prysmaticlabs/prysm", "teku": "Consensys/teku",
    "grandine": "grandinetech/grandine",
}

# Impact language in a linked issue = the vuln the terse PR hides.
IMPACT_RE = re.compile(
    r"\b(?:crash|panic|segfault|deadlock|hang|freeze|out.of.memory|oom"
    r"|consensus (?:fail|split|diverg)|chain split|invalid block|stuck|halt"
    r"|reorg|non.?determin|assertion|overflow|underflow|use.after.free"
    r"|denial.of.service|dos|infinite loop|unbounded|exhaust)\b",
    re.IGNORECASE,
)
# Known fuzzers / security reporters — a report from these is high-signal.
FUZZER_RE = re.compile(
    r"\b(?:oss.?fuzz|clusterfuzz|guido vranken|gvranken|fuzz(?:ing|er|z)?"
    r"|nosy|go-?fuzz|libfuzzer|honggfuzz|afl|differential (?:test|fuzz))\b",
    re.IGNORECASE,
)
PR_NUM_RE = re.compile(r"PR#?(\d+)|/pull/(\d+)", re.IGNORECASE)
# Only ~13% of client PRs use formal `Closes #N`, so calling the API blindly is
# wasteful. Pre-filter to PRs that reference an issue inline — same yield, far
# fewer calls.
INLINE_REF_RE = re.compile(
    r"#\d{2,}|closes?\s+#|fixes?\s+#|resolves?\s+#|issue\s+\d", re.IGNORECASE)


def _pr_number(row) -> str | None:
    for field in (str(row.get("issue_id", "")), str(row.get("source_url", ""))):
        m = PR_NUM_RE.search(field)
        if m:
            return m.group(1) or m.group(2)
    return None


def _linked_issues(repo: str, pr: str) -> list[dict]:
    try:
        r = subprocess.run(
            ["gh", "pr", "view", pr, "--repo", repo,
             "--json", "closingIssuesReferences"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    try:
        return json.loads(r.stdout).get("closingIssuesReferences") or []
    except json.JSONDecodeError:
        return []


def _score_issue(issue: dict) -> str:
    blob = (issue.get("title") or "") + " " + (issue.get("body") or "")
    hits = []
    if FUZZER_RE.search(blob):
        hits.append("fuzzer")
    if IMPACT_RE.search(blob):
        hits.append("impact")
    return ",".join(hits)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--in", dest="inp", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--tier", default="C_candidate",
                   help="only enrich rows in this authority_tier (or 'all')")
    p.add_argument("--limit", type=int, default=400)
    p.add_argument("--sleep", type=float, default=0.7)
    p.add_argument("--require-inline-ref", action="store_true",
                   help="only call the API for PRs that reference an issue inline")
    a = p.parse_args()

    df = pd.read_parquet(a.inp)
    if a.tier != "all" and "authority_tier" in df.columns:
        df = df[df["authority_tier"] == a.tier]
    # only PR-backed rows can have linked issues
    df = df[df.apply(lambda r: _pr_number(r) is not None, axis=1)]
    if a.require_inline_ref:
        blob = df["title"].fillna("") + " " + df["description"].fillna("")
        df = df[blob.str.contains(INLINE_REF_RE)]
    if a.limit:
        df = df.head(a.limit)
    print(f"[enrich] {len(df)} candidate PRs (tier={a.tier})", file=sys.stderr)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    n_signal = 0
    with a.out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["source_url", "linked_issue_signal", "evidence"])
        for i, (_, row) in enumerate(df.iterrows()):
            repo = CLIENT_REPOS.get(row["source_platform"])
            pr = _pr_number(row)
            if not repo or not pr:
                continue
            ev = []
            for iss in _linked_issues(repo, pr):
                s = _score_issue(iss)
                if s:
                    ev.append(f"#{iss.get('number')}:{s}")
            sig = "1" if ev else ""
            if ev:
                n_signal += 1
            w.writerow([row["source_url"], sig, ";".join(ev)])
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(df)}] {n_signal} with signal", file=sys.stderr)
            time.sleep(a.sleep)
    print(f"[enrich] done — {n_signal}/{len(df)} PRs have a linked-issue signal "
          f"-> {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
