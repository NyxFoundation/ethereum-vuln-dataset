#!/usr/bin/env python3
"""train_silent_fix_classifier.py — learned silent-fix detector (method 1).

Faithful, torch-free instantiation of the security-patch-classification line of
silent-fix research (Sabetta & Bezzi, ESEM 2018: represent the patch as a
*document* and train a supervised classifier; the deep-embedding successors —
VulFixMiner ASE'21, GraphSPD S&P'23 — swap bag-of-words for CodeBERT/CPG but
keep the same supervised-on-code-change setup). Regex proxies failed to
discriminate (see detect_silent_fixes.py, validated negative); a *learned*
weighting of diff tokens is the method the research actually endorses.

Pipeline:
  1. Weak labels from the dataset itself:
       positive = confirmed security fix (advisory/CVE/GHSA id or rated severity)
       negative = dep-bump / docs / CI meta-work (never a client vuln)
  2. Fetch each item's code diff (cached on disk; re-runs are free).
  3. TF-IDF over the diff's changed lines (1–2 grams, code tokens).
  4. Logistic regression, stratified 5-fold CV, report ROC-AUC + PR-AUC.
  5. Persist model + metrics. Only worth wiring into curation if AUC beats the
     tier baseline (regex ≈ 0.5, i.e. no better than chance).

Usage:
    uv run python collection/train_silent_fix_classifier.py \
        --in data/ethereum_vulns.parquet --raw data/raw/train.classified.parquet \
        --cache scratchpad_crawl/diff_cache.json --per-class 150
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

CLIENT_REPOS: dict[str, str] = {
    "geth": "ethereum/go-ethereum", "nethermind": "NethermindEth/nethermind",
    "besu": "hyperledger/besu", "erigon": "erigontech/erigon",
    "reth": "paradigmxyz/reth", "lighthouse": "sigp/lighthouse",
    "lodestar": "ChainSafe/lodestar", "nimbus": "status-im/nimbus-eth2",
    "prysm": "prysmaticlabs/prysm", "teku": "Consensys/teku",
    "grandine": "grandinetech/grandine",
}
PR_RE = re.compile(r"/pull/(\d+)")
SHA_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.IGNORECASE)
NOISE_TITLE_RE = re.compile(
    r"\b(?:bump|chore\(deps|dependabot|renovate|docs?:|readme|changelog|typo"
    r"|lint|ci:|workflow|github actions|codeql|rename|comment|cleanup"
    r"|refactor|reword|polish|cosmetic|formatting|gofmt|clippy)\b", re.IGNORECASE)


def _ident(row):
    u = str(row.get("source_url", ""))
    m = PR_RE.search(u)
    if m:
        return ("pr", m.group(1))
    m = SHA_RE.search(u)
    if m:
        return ("sha", m.group(1))
    return None


def _fetch_diff(repo, kind, ident):
    try:
        if kind == "pr":
            cmd = ["gh", "pr", "diff", ident, "--repo", repo]
        else:
            cmd = ["gh", "api", f"/repos/{repo}/commits/{ident}",
                   "--jq", ".files[] | .patch // empty"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                           encoding="utf-8", errors="replace")
        return r.stdout if r.returncode == 0 and r.stdout.strip() else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _diff_to_doc(diff: str) -> str:
    """Reduce a unified diff to its changed code lines (Sabetta&Bezzi doc)."""
    out = []
    for ln in diff.splitlines():
        if ln[:1] in "+-" and not ln.startswith(("+++", "---")):
            out.append(ln[1:])
        elif ln.startswith("diff --git"):
            out.append(ln.split()[-1])          # keep the path token
    return "\n".join(out)[:20000]


def build_labels(cur: pd.DataFrame, raw: pd.DataFrame, per_class: int):
    rated = {"critical", "high", "medium", "low"}
    idrx = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-", re.I)
    blob = cur["title"].fillna("") + " " + cur["description"].fillna("")
    pos = cur[(cur["severity"].str.lower().isin(rated) | blob.str.contains(idrx))
              & cur["source_url"].str.contains(r"/pull/|/commit/", na=False)]
    rblob = raw["title"].fillna("")
    neg = raw[rblob.str.contains(NOISE_TITLE_RE)
              & raw["source_url"].str.contains(r"/pull/|/commit/", na=False)
              & ~(raw["title"].fillna("") + " " + raw["description"].fillna("")).str.contains(idrx)]
    pos = pos.head(per_class)
    neg = neg.head(per_class)
    items = [(r, 1) for _, r in pos.iterrows()] + [(r, 0) for _, r in neg.iterrows()]
    return items


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True, type=Path)
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--cache", default=Path("scratchpad_crawl/diff_cache.json"), type=Path)
    ap.add_argument("--per-class", type=int, default=150)
    ap.add_argument("--sleep", type=float, default=0.35)
    ap.add_argument("--model-out", type=Path)
    ap.add_argument("--apply-tier", help="score rows of this authority_tier and exit")
    ap.add_argument("--apply-out", type=Path)
    ap.add_argument("--apply-limit", type=int, default=250)
    a = ap.parse_args()

    cur = pd.read_parquet(a.inp)

    # ---- apply mode: score rows with a previously saved model ----------------
    if a.apply_tier:
        import csv
        import pickle
        model = pickle.loads(Path(a.model_out or "scratchpad_crawl/silent_fix_model.pkl").read_bytes())
        cache = json.loads(a.cache.read_text()) if a.cache.exists() else {}
        tier_mask = (cur["authority_tier"].notna() if a.apply_tier == "all"
                     else cur["authority_tier"] == a.apply_tier)
        sub = cur[tier_mask
                  & cur["source_url"].str.contains(r"/pull/|/commit/", na=False)].head(a.apply_limit)
        rows = []
        for _, row in sub.iterrows():
            url = str(row["source_url"])
            diff = cache.get(url)
            if diff is None:
                ident = _ident(row); repo = CLIENT_REPOS.get(row["source_platform"])
                diff = _fetch_diff(repo, *ident) if (ident and repo) else None
                cache[url] = diff or ""
                time.sleep(a.sleep)
            if not diff:
                continue
            prob = float(model.predict_proba([_diff_to_doc(diff)])[0, 1])
            rows.append((url, prob, row["title"][:70]))
        a.cache.write_text(json.dumps(cache))
        rows.sort(key=lambda x: -x[1])
        if a.apply_out:
            with a.apply_out.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh); w.writerow(["source_url", "silent_fix_prob"])
                for u, p, _ in rows:
                    w.writerow([u, f"{p:.3f}"])
        hi = sum(1 for _, p, _ in rows if p >= 0.5)
        print(f"[apply] scored {len(rows)} {a.apply_tier} rows; {hi} at prob>=0.5")
        print("\n-- highest silent-fix prob --")
        for u, p, t in rows[:12]:
            print(f"  {p:.2f}  {t}")
        print("\n-- lowest silent-fix prob --")
        for u, p, t in rows[-8:]:
            print(f"  {p:.2f}  {t}")
        return 0
    raw = pd.read_parquet(a.raw)
    items = build_labels(cur, raw, a.per_class)
    print(f"[train] labeled items: {sum(y for _,y in items)} pos / "
          f"{sum(1 for _,y in items if not y)} neg", file=sys.stderr)

    cache = {}
    if a.cache.exists():
        cache = json.loads(a.cache.read_text())
    docs, ys = [], []
    fetched = 0
    for row, y in items:
        url = str(row["source_url"])
        if url in cache:
            diff = cache[url]
        else:
            ident = _ident(row)
            repo = CLIENT_REPOS.get(row["source_platform"])
            diff = _fetch_diff(repo, *ident) if (ident and repo) else None
            cache[url] = diff or ""
            fetched += 1
            if fetched % 25 == 0:
                print(f"  fetched {fetched} diffs…", file=sys.stderr)
                a.cache.parent.mkdir(parents=True, exist_ok=True)
                a.cache.write_text(json.dumps(cache))
            time.sleep(a.sleep)
        if diff:
            docs.append(_diff_to_doc(diff)); ys.append(y)
    a.cache.parent.mkdir(parents=True, exist_ok=True)
    a.cache.write_text(json.dumps(cache))
    print(f"[train] usable diffs: {len(docs)} "
          f"({sum(ys)} pos / {len(ys)-sum(ys)} neg)", file=sys.stderr)

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import cross_val_predict, StratifiedKFold
    from sklearn.metrics import roc_auc_score, average_precision_score, classification_report

    X, yv = docs, np.array(ys)
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]{1,}",
                                  ngram_range=(1, 2), min_df=2, max_features=20000,
                                  sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0)),
    ])
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    proba = cross_val_predict(pipe, X, yv, cv=cv, method="predict_proba")[:, 1]
    auc = roc_auc_score(yv, proba)
    ap_ = average_precision_score(yv, proba)
    print("\n================ silent-fix classifier (5-fold CV) ================")
    print(f"  ROC-AUC : {auc:.3f}   (regex baseline ≈ 0.50 = chance)")
    print(f"  PR-AUC  : {ap_:.3f}   (positive prevalence {yv.mean():.2f})")
    print(classification_report(yv, (proba >= 0.5).astype(int),
                                target_names=["non-fix", "silent-fix"], digits=3))
    verdict = ("BEATS baseline — worth wiring into curation" if auc >= 0.75
               else "NOT better than baseline — do not ship" if auc < 0.65
               else "marginal — needs more data / deep embeddings")
    print(f"  VERDICT : {verdict}")

    if a.model_out and auc >= 0.75:
        import pickle
        pipe.fit(X, yv)
        a.model_out.write_bytes(pickle.dumps(pipe))
        print(f"  saved model -> {a.model_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
