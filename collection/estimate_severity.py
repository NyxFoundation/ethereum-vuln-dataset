#!/usr/bin/env python3
"""estimate_severity.py — LLM severity estimation against the EF bug-bounty model.

Severity in the bounty is NETWORK-SCALE IMPACT x REMOTE REACHABILITY (a single
packet / on-chain tx). Asking an LLM for "Critical?" directly over-rates. Instead
we DECOMPOSE into the bounty's own axes and let a deterministic guardrail cap the
tier, then CALIBRATE against the 143 rows the bounty actually graded.

Per row the LLM emits:
  impact_type   chain_split | liveness_dos | value_integrity | validator_slashing
                | local_only | none
  reachability  remote_single_message_or_tx | remote_needs_conditions | local_internal
  blast_radius  spec_level (all clients / whole network) | client_specific | subset
  severity_est  Critical | High | Medium | Low | not-eligible
  confidence, why

Guardrails (applied after the LLM):
  * local_internal reachability OR impact_type in {local_only, none}  -> not-eligible
  * client_specific bug is capped by that client's network share tier
  * spec_level chain_split / value_integrity can reach High/Critical

--validate : run on the bounty-graded rows and report agreement (exact / ±1 tier)
--apply    : write severity_estimated + rationale for all rows (severity_source
             = 'bounty-graded' where a real grade exists, else 'llm-estimated')
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import llm_classify_fixes as llm  # noqa: E402
import local_diffs as ld  # noqa: E402

# rough, historical network-share tiers — only to bound blast radius for a
# client-specific bug (a spec-level bug affects the whole network regardless).
SHARE = {
    "geth": "DOMINANT execution client (~45-55% of execution nodes)",
    "nethermind": "MAJOR execution client (~20-30%)",
    "erigon": "MODERATE execution client (~10-20%)",
    "besu": "MINOR execution client (<10%)",
    "reth": "MINOR (growing) execution client (<10%)",
    "prysm": "MAJOR consensus client (~30-40%)",
    "lighthouse": "MAJOR consensus client (~30-40%)",
    "teku": "MODERATE consensus client (~10-15%)",
    "nimbus": "MINOR consensus client (<10%)",
    "lodestar": "MINOR consensus client (<5%)",
    "grandine": "MINOR consensus client (<5%)",
}
TIER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "not-eligible": 0, "": 0}
DEF = """EF bug-bounty severity = network-scale impact reachable by a SINGLE network packet or on-chain transaction:
- Critical: create/finalize infinite ETH; steal or burn ETH from all EOAs; take down the ENTIRE network with one tx; slash >50% of validators.
- High: chain split affecting >33% of the network; bring down >33% with one tx; slash >33% of validators.
- Medium: split >5%; bring down >5%; slash >1%.
- Low: split/down >0.01% by a single packet/tx.
- not-eligible: only locally/internally triggerable (needs local access, not a single remote packet/tx), or no network impact (tooling / test / CLI / metrics / dependency hygiene)."""


def build_prompt(r, diff):
    share = SHARE.get(r["source_platform"], "a client")
    return f"""Triage this Ethereum client fix for the Ethereum Foundation bug bounty.

{DEF}

Reason step by step, then map to a tier USING THE DEFINITION ABOVE (do not inflate):
1. impact_type: what could an attacker actually achieve?
   {{chain_split, liveness_dos, value_integrity, validator_slashing, local_only, none}}
2. reachability: {{remote_single_message_or_tx, remote_needs_conditions, local_internal}}
3. blast_radius: is the defect in SHARED spec logic or CLIENT-SPECIFIC?
   {{spec_level, client_specific, subset}}
   IMPORTANT: EVM opcodes/precompiles/gas rules, consensus state-transition,
   fork-choice, attestation/slashing rules, and SSZ/RLP consensus encoding are
   SPEC-LEVEL — every client must produce the identical result, so a divergence
   or crash there can split or stall the WHOLE network (High/Critical), not just
   this client. Only genuinely client-local code (this client's DB, RPC server,
   CLI, sync internals) is client_specific.
   This client is: {share}.
4. severity_est: Critical | High | Medium | Low | not-eligible.

Context — area: {r.get('label')} · root_cause: {r.get('root_cause')} · attack_path: {r.get('attack_path')}
Title: {str(r.get('title') or '')[:200]}
Description: {str(r.get('description') or '')[:600]}
Code diff (truncated):
{(diff or '(no diff)')[:2800]}

Output ONLY one JSON object on the last line:
{{"impact_type":"...","reachability":"...","blast_radius":"...","severity_est":"...","confidence":0.0,"why":"<one sentence>"}}"""


def guardrail(o, client):
    est = str(o.get("severity_est", "")).lower()
    if o.get("reachability") == "local_internal" or o.get("impact_type") in ("local_only", "none"):
        return "not-eligible"
    # client-specific liveness DoS on a minor client can't reach >33% -> cap High->Medium
    if o.get("blast_radius") == "client_specific" and est in ("critical", "high"):
        if o.get("impact_type") in ("liveness_dos",) and "MINOR" in SHARE.get(client, ""):
            return "medium"
    return est or "not-eligible"


def classify(row):
    r, diff = row
    try:
        out = llm._call_llm(build_prompt(r, diff))
        m = re.search(r"\{[^{}]*\"severity_est\"[^{}]*\}", out, re.S)
        o = json.loads(m.group(0)) if m else {}
    except Exception as e:
        o = {"error": str(e)}
    o["severity_final"] = guardrail(o, r["source_platform"]) if "error" not in o else ""
    return r["id"], o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=Path("data/ethereum_vulns.parquet"), type=Path)
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out", default=Path("data/severity_est.csv"), type=Path)
    ap.add_argument("--cache", default=Path("scratchpad_crawl/diff_cache.json"), type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=6)
    import os
    ap.add_argument("--engine", default="openai"); ap.add_argument("--model", default="")
    ap.add_argument("--base-url", default="https://ollama.com/v1")
    ap.add_argument("--api-key-env", default="OLLAMA_API_KEY")
    a = ap.parse_args()
    llm.ENGINE.update(engine=a.engine, model=a.model or "gemma4:31b", base_url=a.base_url,
                      api_key=os.environ.get(a.api_key_env, ""))

    d = pd.read_parquet(a.inp)
    dcache = json.loads(a.cache.read_text()) if a.cache.exists() else {}
    sev = d.severity.str.lower()
    sub = d[sev.isin(["critical", "high", "medium", "low"])] if a.validate else d
    if a.limit:
        sub = sub.head(a.limit)
    rows = []
    for r in sub.to_dict("records"):
        diff = ld.get_diff_cached(str(r["source_url"]), r["source_platform"], dcache) \
            if r["source_platform"] in ld.CLIENT_REPOS else None
        rows.append((r, diff))
    print(f"[severity] {len(rows)} rows (validate={a.validate})", file=sys.stderr)
    res = {}
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for rid, o in ex.map(classify, rows):
            res[rid] = o
    a.cache.write_text(json.dumps(dcache))

    if a.validate:
        exact = within1 = neel = tot = 0
        conf = {}
        for r in sub.to_dict("records"):
            o = res.get(r["id"], {}); pred = str(o.get("severity_final", "")).lower()
            true = r["severity"].lower()
            if pred in ("", "error") or "error" in o:
                continue
            tot += 1
            gp, gt = TIER.get(pred, 0), TIER.get(true, 0)
            if pred == "not-eligible":
                neel += 1
            if gp == gt:
                exact += 1
            if abs(gp - gt) <= 1:
                within1 += 1
            conf[(true, pred)] = conf.get((true, pred), 0) + 1
        print(f"\n=== validation vs bounty grades (n={tot}) ===")
        print(f"  exact-tier agreement : {exact}/{tot} ({100*exact/tot:.0f}%)")
        print(f"  within +/-1 tier      : {within1}/{tot} ({100*within1/tot:.0f}%)")
        print(f"  predicted not-eligible: {neel} (should be ~0 — graded rows ARE reachable)")
        print("  confusion (true -> pred):")
        for (t, p), c in sorted(conf.items(), key=lambda x: -x[1])[:12]:
            print(f"    {t:9s} -> {p:12s} {c}")
    if a.apply:
        import csv
        real = {r["id"]: r["severity"] for r in d.to_dict("records")}
        with a.out.open("w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["id", "severity_estimated", "severity_source",
                                            "impact_type", "reachability", "blast_radius", "severity_why"])
            for rid, o in res.items():
                graded = real.get(rid, "Unrated").lower() in ("critical", "high", "medium", "low")
                w.writerow([rid, real[rid] if graded else o.get("severity_final", ""),
                            "bounty-graded" if graded else "llm-estimated",
                            o.get("impact_type", ""), o.get("reachability", ""),
                            o.get("blast_radius", ""), str(o.get("why", ""))[:200]])
        print(f"wrote {a.out}")


if __name__ == "__main__":
    raise SystemExit(main())
