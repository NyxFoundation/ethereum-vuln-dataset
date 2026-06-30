#!/usr/bin/env python3
"""build_security_dataset.py — turn the raw past-fix crawl into a curated
*security-only* Ethereum vulnerability dataset.

The raw crawl (one row per merged PR / commit / advisory / release note across
the 11 clients) is high recall but noisy: only ~half the rows are actually
security fixes, and release-note boilerplate inflates severity. This script
applies the collection methodology and emits a curated table where every row is
a genuine security fix, each annotated with a relevance score and a confidence
tier so a consumer can threshold further.

Three stages, run in order (the order matters):

  T1  Drop release-note / urgency boilerplate.
      Nimbus release notes carry an "Urgency guidelines" template
      ("critical update required for Nimbus") that an earlier severity regex
      mis-read as 97 Critical findings — 95 of them bogus. These are not fixes;
      they are dropped outright. Severity from a release header is never trusted.

  T7  Score security relevance (0.0-1.0) from CVE/GHSA ids, severity, and a
      weighted keyword match over title + description. Runs AFTER T1 so the
      bogus release-note severities can't score themselves to 1.0.

  GATE  Mark a row security_relevant when ANY independent signal fires:
        a CVE/GHSA id, a rated severity, a security keyword, an LLM STRIDE
        category, or an LLM CWE-Top-25 label. The curated output keeps only
        these rows. A `confidence` tier (high/medium/low) records how strong the
        evidence is so downstream users can take the high-confidence slice.

Deterministic and offline: same input parquet -> same output. No network, no
API key. (Re-collecting the raw parquet is a separate, network-bound step under
collection/.)

Usage::

    uv run python pipeline/build_security_dataset.py \
        --in  data/raw/train.classified.parquet \
        --out data/ethereum_vulns.parquet

    # inspect the effect without writing anything
    uv run python pipeline/build_security_dataset.py --in data/raw/train.classified.parquet --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

# --- T1: release-note / urgency boilerplate (not a fix) --------------------
BOILERPLATE_RE = re.compile(
    r"critical update required"
    r"|urgency guidelines"
    r"|high-urgency"
    r"|update is (?:strongly )?recommended for all"
    r"|this is a (?:low|medium|high)-urgency release",
    re.IGNORECASE,
)

# --- T7: weighted security keywords ---------------------------------------
# Identifiers are decisive on their own.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)

# Strong: words that almost always mean a security defect. Includes the
# protocol-specific failure modes that generic CWE wordlists miss.
STRONG_RE = re.compile(
    r"\b(?:"
    r"vulnerabilit(?:y|ies)|exploit|RCE|remote code exec(?:ution)?|arbitrary code"
    r"|use.after.free|UAF|double.free|heap (?:overflow|corruption|spray)"
    r"|stack (?:overflow|smash|corruption)|integer (?:overflow|underflow)|buffer overflow"
    r"|out.of.bounds|OOB|null pointer deref|segfault|memory (?:corruption|safety)|unsound(?:ness)?"
    r"|injection|deserializ|privilege escal|auth(?:entication)? bypass|access control"
    r"|denial.of.service|DoS|OOM|resource exhaustion"
    r"|consensus (?:failure|split|diverg)|finality (?:reversion|stall)|chain split"
    r"|equivocation|long.range attack|eclipse attack|timing attack|replay attack"
    r"|validator (?:slashing|key leak)|invalid block accept|state (?:divergence|corruption)"
    r")\b",
    re.IGNORECASE,
)

# Moderate: bug-class words that are often, but not always, security relevant.
MODERATE_RE = re.compile(
    r"\b(?:"
    r"panic|crash|hang|deadlock|livelock|race condition|data race|TOCTOU"
    r"|memory leak|goroutine leak|fd leak|infinite loop|unbounded|amplification"
    r"|reorg|nonce|underflow|assertion|invariant|divergence|malformed|untrusted"
    r"|security|unsafe|sanitiz|validate|overflow"
    r")\b",
    re.IGNORECASE,
)

HIGH_SEV = frozenset({"critical", "high"})
RATED_SEV = frozenset({"critical", "high", "medium", "low"})


def score_row(title: str, description: str, severity: str) -> float:
    """Security-relevance score in [0.0, 1.0]. See module docstring."""
    t, d = title or "", description or ""
    s = (severity or "").lower()
    combined = t + " " + d
    if CVE_RE.search(combined):
        return 1.0
    if s in HIGH_SEV:
        return 1.0
    if STRONG_RE.search(t):
        return 0.9
    if STRONG_RE.search(d):
        return 0.8
    if MODERATE_RE.search(t):
        return 0.5
    if MODERATE_RE.search(d):
        return 0.3
    return 0.0


def confidence_tier(row) -> str:
    """high / medium / low evidence that the row is a real vulnerability fix."""
    t, d = str(row["title"] or ""), str(row["description"] or "")
    s = str(row["severity"] or "").lower()
    if CVE_RE.search(t + " " + d) or s in HIGH_SEV or STRONG_RE.search(t):
        return "high"
    if row["cwe_top25"] not in ("", "N/A", None) or s == "medium" or row["security_score"] >= 0.5:
        return "medium"
    return "low"


def build(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    n_raw = len(df)
    for col in ("title", "description", "severity", "stride", "cwe_top25", "source_platform"):
        if col not in df.columns:
            df[col] = ""
    blob = df["title"].fillna("").astype(str) + " " + df["description"].fillna("").astype(str)

    # T1
    t1_mask = blob.str.contains(BOILERPLATE_RE)
    t1_dropped = df[t1_mask]
    df = df[~t1_mask].copy()

    # T7
    df["security_score"] = [
        score_row(t, d, s)
        for t, d, s in zip(df["title"].fillna(""), df["description"].fillna(""), df["severity"].fillna(""))
    ]

    # GATE — union of independent signals
    has_id = (df["title"].fillna("") + " " + df["description"].fillna("")).str.contains(CVE_RE)
    has_sev = df["severity"].fillna("").str.lower().isin(RATED_SEV)
    has_kw = df["security_score"] >= 0.5
    has_stride = ~df["stride"].fillna("Other").isin(["Other"])
    has_cwe = ~df["cwe_top25"].fillna("N/A").isin(["N/A"])
    df["security_relevant"] = has_id | has_sev | has_kw | has_stride | has_cwe

    sec = df[df["security_relevant"]].copy()
    sec["confidence"] = sec.apply(confidence_tier, axis=1)
    sec = sec.drop(columns=["security_relevant"])

    report = {
        "raw_rows": int(n_raw),
        "t1_boilerplate_dropped": int(len(t1_dropped)),
        "t1_dropped_by_source": {k: int(v) for k, v in t1_dropped["source_platform"].value_counts().items()},
        "after_t1": int(len(df)),
        "security_rows": int(len(sec)),
        "low_signal_dropped": int(len(df) - len(sec)),
        "by_confidence": {k: int(v) for k, v in sec["confidence"].value_counts().items()},
        "by_source": {k: int(v) for k, v in sec["source_platform"].value_counts().items()},
        "by_severity": {k: int(v) for k, v in sec["severity"].value_counts().items()},
        "by_score": {str(k): int(v) for k, v in sec["security_score"].round(1).value_counts().sort_index().items()},
        "residual_boilerplate_fp": int(
            (sec["title"].fillna("") + " " + sec["description"].fillna("")).str.contains(BOILERPLATE_RE).sum()
        ),
    }
    return sec, report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True, type=Path)
    ap.add_argument("--out", dest="out", type=Path)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    df = pd.read_parquet(a.inp)
    sec, report = build(df)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    assert report["residual_boilerplate_fp"] == 0, "T1 leak: boilerplate survived into the security set"

    if a.dry_run:
        return 0
    if not a.out:
        ap.error("--out is required unless --dry-run")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    sec.to_parquet(a.out, index=False)
    print(f"\nwrote {len(sec)} rows -> {a.out}")

    manifest_path = a.manifest or a.out.with_name("manifest.json")
    manifest = {
        "domain": "ethereum",
        "n_rows": int(len(sec)),
        "schema": list(sec.columns),
        "build": report,
        "source": "11 Ethereum execution + consensus clients (past security fixes)",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote manifest -> {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
