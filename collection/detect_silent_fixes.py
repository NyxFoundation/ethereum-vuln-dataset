#!/usr/bin/env python3
"""detect_silent_fixes.py — code-diff silent-fix detection.

Silent (a.k.a. stealth) security fixes deliberately carry uninformative commit
messages, so message-based detection fails on exactly the fixes we care about.
The security-patch-identification literature (Sabetta & Bezzi, ESEM 2018;
VulFixMiner, Zhou et al. ASE 2021; GraphSPD, S&P 2023; SPI, Zhou et al.) shows
that the *code change* remains discriminative: a security patch tends to **add
guard/validation conditionals**, add error/overflow handling, and be small and
localized — features that survive a silent message.

This computes a language-agnostic feature vector from a PR/commit diff and a
`silent_fix_score` in [0,1]. It is a metadata/regex approximation of the
learned models above (no CodeBERT / code-property-graph), chosen so it runs
across all 11 clients (Go, Rust, Java, Nim, JS/TS) from GitHub diffs alone.

    ⚠ VALIDATED NEGATIVE (2026-07-02). On two labelled samples the score did
    NOT separate known-real fixes from ordinary changes: with broad guard
    patterns the ranking *inverted* (A-tier 0.20 < noise 0.40) because generic
    `if`/`len`/`index` fire on every diff; tightening to high-precision guards
    collapsed both to ≈0 (A-tier 0.14 vs noise 0.18). This reproduces exactly
    why the cited work uses learned code embeddings / code-property-graphs
    rather than surface patterns. **This module is therefore experimental and
    is NOT wired into the curation gate** — it must not silently degrade the
    dataset. Kept for reference and as the harness for a future model-based
    detector (feed diffs to CodeBERT/StarEncoder and learn the weights). The
    working, deterministic branch of the same research (patch backlinking:
    advisory → fixed commit/version) is implemented in crawl_osv.py instead.

Discriminative features (net = added-line hits − removed-line hits, so we
reward checks *introduced* by the patch, per the added-condition intuition):
  guard_added        if/require/assert/guard, null|nil|bounds|len checks     0.40
  overflow_safe      checked_/saturating_/try_into/addExact/SafeMath          0.30
  error_handling     recover/try-catch/except/return err/Result/?            0.20
  sensitive_file     changed path in a security-sensitive subsystem           0.20
  small_localized    additions ≤ 60 and changed_files ≤ 5 (surgical)          0.15
  test_added         a test/fuzz/regression file touched                      0.10
(score is the capped sum; silent_fix_signal = score ≥ 0.5)

Output (sidecar, merged by curation as `silent_fix_signal`):
    <out>  CSV: source_url, silent_fix_score, silent_fix_signal, features

Usage:
    uv run python collection/detect_silent_fixes.py \
        --in data/ethereum_vulns.parquet --out scratchpad_crawl/supp/silent_fix.csv \
        --tier C_candidate --limit 400
"""
from __future__ import annotations

import argparse
import csv
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

PR_NUM_RE = re.compile(r"/pull/(\d+)")
COMMIT_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.IGNORECASE)

# --- feature regexes (matched on added/removed code lines) ------------------
# HIGH-PRECISION only: generic `if`/`len`/`index` appear in every diff and are
# non-discriminative (they invert the ranking). We keep patterns that a security
# fix specifically introduces: explicit nil/None/empty guards, bounds/range
# validation, and length preconditions.
GUARD_RE = re.compile(
    r"[!=]=\s*(?:nil|null|none)\b|\bis_(?:some|none|null|nil)\(\)"
    r"|\.is_empty\(\)|out.of.(?:bounds|range)|\bbounds check|index out of"
    r"|if\s+[^\n]{0,40}\blen\([^\n]{0,20}\)\s*[<>=]|>=\s*len\(|<\s*0\b"
    r"|\brequire\(|\bassert(?:_eq|_ne|!|\()|\bpanic\b.{0,20}recover"
    r"|ensure!|\bguard\s+let|MerkleProof|verify_(?:proof|signature|merkle)",
    re.IGNORECASE,
)
OVERFLOW_SAFE_RE = re.compile(
    r"\bchecked_(?:add|sub|mul|div|rem)|\bsaturating_|\boverflowing_"
    r"|\btry_(?:into|from)\b|addExact|subtractExact|multiplyExact|SafeMath"
    r"|\bcheckedAdd|Math\.(?:addExact|floorDiv)|safe_(?:add|sub|mul)",
    re.IGNORECASE,
)
# Replacing a panicking/aborting path with graceful handling — a classic silent
# DoS fix. We reward net-added recover/error-return and net-REMOVED unwrap/panic.
ERROR_HANDLING_RE = re.compile(
    r"\brecover\(\)|\.map_err\(|return\s+(?:nil,\s*)?err\b|\bResult<"
    r"|catch\s*\(|\.ok_or\(|ok_or_else|\?\s*$",
    re.IGNORECASE,
)
# Net-REMOVED unsafe constructs (unwrap/expect/panic!) => hardening.
UNSAFE_REMOVED_RE = re.compile(
    r"\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|assert!\(|\bunsafe\b",
    re.IGNORECASE,
)
SENSITIVE_FILE_RE = re.compile(
    r"fork.?choice|state.?transition|epoch|consensus|finality|reorg|slashing"
    r"|attestation|sync.?committee|blob|kzg|bls|blst|discv5|gossip|req.?resp"
    r"|/p2p/|devp2p|rlpx|/evm|opcode|precompile|trie|tx.?pool|mempool"
    r"|signature|merkle|/ssz|/rlp|secp256|ecrecover|snap.?sync|downloader",
    re.IGNORECASE,
)
TEST_FILE_RE = re.compile(r"test|fuzz|spec\.|_spec|regression|testdata|crasher",
                          re.IGNORECASE)


def _pr_number(row) -> str | None:
    m = PR_NUM_RE.search(str(row.get("source_url", "")))
    if m:
        return m.group(1)
    m = re.search(r"PR#?(\d+)", str(row.get("issue_id", "")))
    return m.group(1) if m else None


def _commit_sha(row) -> str | None:
    m = COMMIT_RE.search(str(row.get("source_url", "")))
    return m.group(1) if m else None


def _fetch_diff(repo: str, pr: str | None, sha: str | None) -> str | None:
    """Return unified diff text, or None on failure."""
    try:
        if pr:
            cmd = ["gh", "pr", "diff", pr, "--repo", repo]
        elif sha:
            cmd = ["gh", "api", f"/repos/{repo}/commits/{sha}",
                   "--jq", ".files[] | .patch // empty"]
        else:
            return None
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                           encoding="utf-8", errors="replace")
        return r.stdout if r.returncode == 0 and r.stdout.strip() else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def score_diff(diff: str) -> tuple[float, dict]:
    """Compute the silent-fix feature vector + score from a unified diff."""
    added, removed, files = [], [], set()
    add_loc = 0
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            m = re.search(r"[ab]/(.+)$", line)
            if m:
                files.add(m.group(1))
            continue
        if line.startswith("+"):
            added.append(line[1:]); add_loc += 1
        elif line.startswith("-"):
            removed.append(line[1:])
    add_txt, rem_txt = "\n".join(added), "\n".join(removed)
    paths = "\n".join(files)

    def net(rx: re.Pattern) -> int:
        return len(rx.findall(add_txt)) - len(rx.findall(rem_txt))

    feats = {
        "guard_added": net(GUARD_RE) > 0,
        "overflow_safe": net(OVERFLOW_SAFE_RE) > 0,
        "error_handling": net(ERROR_HANDLING_RE) > 0,
        "unsafe_removed": net(UNSAFE_REMOVED_RE) > 0,   # more unsafe removed than added
        "sensitive_file": bool(SENSITIVE_FILE_RE.search(paths)),
        "small_localized": 0 < add_loc <= 60 and 0 < len(files) <= 5,
        "test_added": bool(TEST_FILE_RE.search(paths)),
    }
    weights = {"guard_added": 0.45, "overflow_safe": 0.35, "error_handling": 0.20,
               "unsafe_removed": 0.25, "sensitive_file": 0.15, "small_localized": 0.10,
               "test_added": 0.10}
    # A code-change feature (not just file/size) must fire — sensitive_file or a
    # small diff alone is not a security patch.
    code_feats = ("guard_added", "overflow_safe", "error_handling", "unsafe_removed")
    if not any(feats[k] for k in code_feats):
        return 0.0, feats
    score = min(1.0, sum(w for k, w in weights.items() if feats[k]))
    return score, feats


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--in", dest="inp", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--tier", default="C_candidate")
    p.add_argument("--limit", type=int, default=400)
    p.add_argument("--sleep", type=float, default=0.5)
    a = p.parse_args()

    df = pd.read_parquet(a.inp)
    if a.tier != "all" and "authority_tier" in df.columns:
        df = df[df["authority_tier"] == a.tier]
    df = df[df.apply(lambda r: _pr_number(r) or _commit_sha(r), axis=1).astype(bool)]
    if a.limit:
        df = df.head(a.limit)
    print(f"[silent-fix] scoring {len(df)} diffs (tier={a.tier})", file=sys.stderr)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    n_sig = 0
    with a.out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["source_url", "silent_fix_score", "silent_fix_signal", "features"])
        for i, (_, row) in enumerate(df.iterrows()):
            repo = CLIENT_REPOS.get(row["source_platform"])
            if not repo:
                continue
            diff = _fetch_diff(repo, _pr_number(row), _commit_sha(row))
            if diff is None:
                w.writerow([row["source_url"], "", "", "nodiff"]); continue
            score, feats = score_diff(diff)
            sig = "1" if score >= 0.5 else ""
            if sig:
                n_sig += 1
            w.writerow([row["source_url"], f"{score:.2f}", sig,
                        ",".join(k for k, v in feats.items() if v)])
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(df)}] {n_sig} silent-fix signals", file=sys.stderr)
            time.sleep(a.sleep)
    print(f"[silent-fix] done — {n_sig}/{len(df)} scored ≥0.5 -> {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
