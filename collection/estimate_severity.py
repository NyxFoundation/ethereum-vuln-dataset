#!/usr/bin/env python3
"""estimate_severity.py — LLM severity estimation against the EF bug-bounty model.

Severity in the bounty is NETWORK-SCALE IMPACT x REMOTE REACHABILITY (a single
packet / on-chain tx). Asking an LLM for "Critical?" directly over-rates, because
the tier depends on a quantity that is not in the diff:

    affected_network_share = affected_client_share x client_conditional_reach

The first factor is historical deployment data. The second — of the operators
running THIS client, what fraction can the attacker actually affect — is decided
by default configuration, node role, platform, and whether the triggering input is
attacker-supplied, so it IS assessable from the fix.

We therefore ask the LLM only for the assessable factor and never for a network
percentage. The prompt deliberately does NOT state this client's deployment
share: an earlier revision did, which made the resulting tier a restatement of a
hard-coded prior (see docs/paper/ef_severity_analysis.md). A deterministic
post-step then bounds the affected network share and caps the tier, and CALIBRATES
against rows classified as client-code bounty grades. In the current snapshot,
60 rows are marked ``bounty-graded``; rated upstream-CVSS rows are a separate
population.

Per row the LLM emits:
  impact_type   chain_split | liveness_dos | value_integrity | validator_slashing
                | local_only | none
  reachability  remote_single_message_or_tx | remote_needs_conditions | local_internal
  blast_radius  spec_level (all clients / whole network) | client_specific | subset
  client_conditional_reach
                all_nodes | default_role_subset | narrow_config
                | operator_self_only        (share of THIS client's operators)
  severity_est  Critical | High | Medium | Low | not-eligible
  confidence, why

Guardrails (applied after the LLM):
  * local_internal reachability OR impact_type in {local_only, none}  -> not-eligible
  * the affected network share is bounded as an interval from blast_radius,
    client_conditional_reach, and a numeric share band, then the tier is capped by
    the interval's upper end
  * a tier that the interval's lower end does not reach is marked
    ``share_dependent``: it holds only if the client's deployment share at the fix
    date is at least ``severity_required_client_share``, which this file does not
    claim to know
  * value_integrity is exempt from the share cap, because "create/finalize
    infinite ETH" and "steal or burn ETH from all EOAs" are not share criteria

--validate : run on the bounty-graded rows and report agreement (exact / ±1 tier)
--apply    : write severity_estimated + rationale for all rows (severity_source
             = 'bounty-graded' where a real grade exists, else 'llm-estimated')

The share bands here are the *only* place deployment share enters. They are
unsourced prose tiers with no observation date; downstream analysis must report
``severity_required_client_share`` rather than presenting a tier that depends on
them as measured. ``scripts/client_conditional_severity.py`` generates the
share-independent frontier tables from the same numbers.
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

# Numeric deployment-share bands, as (low, high) fractions of that layer's nodes.
# These are the ONLY place deployment share enters, they are never shown to the
# LLM, and they are unsourced: the prose tiers were inherited from an earlier
# revision and carry no observation date or citation. Downstream code must report
# the required share rather than presenting these as measured deployment data.
SHARE_BANDS = {
    "geth": (0.45, 0.55),
    "nethermind": (0.20, 0.30),
    "erigon": (0.10, 0.20),
    "besu": (0.00, 0.10),
    "reth": (0.00, 0.10),
    "prysm": (0.30, 0.40),
    "lighthouse": (0.30, 0.40),
    "teku": (0.10, 0.15),
    "nimbus": (0.00, 0.10),
    "lodestar": (0.00, 0.05),
    "grandine": (0.00, 0.05),
}

# Fraction of THIS client's operators that a single attacker-supplied input can
# affect. Assessable from the fix, which is why the LLM is asked for this and not
# for a network percentage.
REACH_BANDS = {
    "all_nodes": (0.90, 1.00),
    "default_role_subset": (0.25, 0.75),
    "narrow_config": (0.01, 0.25),
    "operator_self_only": (0.00, 0.01),
    "unknown": (0.00, 1.00),
}

# EF tiers as a fraction of the network affected. Critical's 0.50 is its validator
# slashing form; its value-integrity forms are not share-shaped and are exempted
# from the cap below.
EF_THRESHOLD = [("critical", 0.50), ("high", 0.33), ("medium", 0.05), ("low", 0.0001)]

TIER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "not-eligible": 0, "": 0}

# The severity cache is keyed by row id, so it must also be keyed by prompt: a v1
# entry has no client_conditional_reach and would silently reintroduce the
# share-prior labels this revision removed. Bump this whenever build_prompt or the
# guardrail changes meaning. Old entries are left in place so the frozen snapshot
# stays reproducible.
PROMPT_VERSION = "v2-client-conditional-reach"


def cache_key(row_id: str) -> str:
    return f"{row_id}@{PROMPT_VERSION}"
DEF = """EF bug-bounty severity = network-scale impact reachable by a SINGLE network packet or on-chain transaction:
- Critical: create/finalize infinite ETH; steal or burn ETH from all EOAs; take down the ENTIRE network with one tx; slash >50% of validators.
- High: chain split affecting >33% of the network; bring down >33% with one tx; slash >33% of validators.
- Medium: split >5%; bring down >5%; slash >1%.
- Low: split/down >0.01% by a single packet/tx.
- not-eligible: only locally/internally triggerable (needs local access, not a single remote packet/tx), or no network impact (tooling / test / CLI / metrics / dependency hygiene)."""


def build_prompt(r, diff):
    return f"""Triage this Ethereum client fix for the Ethereum Foundation bug bounty.

{DEF}

Reason step by step and answer the five questions below. Do NOT estimate what
fraction of the whole Ethereum network is affected: you are not told this client's
deployment share, and guessing it is how these labels get inflated. Question 4 asks
only about operators of THIS client, which the fix itself tells you.
1. impact_type: what could an attacker actually achieve?
   {{chain_split, liveness_dos, value_integrity, validator_slashing, local_only, none}}
2. reachability: {{remote_single_message_or_tx, remote_needs_conditions, local_internal}}
3. blast_radius: is the defect in SHARED spec logic or CLIENT-SPECIFIC?
   {{spec_level, client_specific, subset}}
   IMPORTANT: EVM opcodes/precompiles/gas rules, consensus state-transition,
   fork-choice, attestation/slashing rules, and SSZ/RLP consensus encoding are
   SPEC-LEVEL — every client must produce the identical result, so a divergence
   or crash there can split or stall the WHOLE network, not just this client.
   Only genuinely client-local code (this client's DB, RPC server, CLI, sync
   internals) is client_specific.
4. client_conditional_reach: of the operators ALREADY RUNNING THIS CLIENT, what
   fraction can the attacker affect with this defect?
   {{all_nodes, default_role_subset, narrow_config, operator_self_only}}
   - all_nodes: any node on the DEFAULT configuration processes the
     attacker-supplied input on the affected path.
   - default_role_subset: one common role or default-adjacent mode only —
     validating vs non-validating, archive vs pruned, snap vs full sync, or a
     default-on endpoint that is not always exposed.
   - narrow_config: needs a non-default flag, an unusual platform (for example a
     32-bit host), an opt-in or unreleased feature, or a specific deployment shape.
   - operator_self_only: only the operator's own node, through local action; no
     attacker-supplied input crosses to other operators.
   Judge this from the diff and description — guards, config gates, feature flags,
   platform assumptions, and which code path consumes the untrusted input. If the
   fix touches an unreleased fork or feature, that is narrow_config.
5. severity_est: Critical | High | Medium | Low | not-eligible, for the case where
   this client were the ENTIRE network. A later deterministic step rescales this by
   deployment share, so do not discount for the client being small or popular.

Context — area: {r.get('label')} · root_cause: {r.get('root_cause')} · attack_path: {r.get('attack_path')}
Title: {str(r.get('title') or '')[:200]}
Description: {str(r.get('description') or '')[:600]}
Code diff (truncated):
{(diff or '(no diff)')[:2800]}

Output ONLY one JSON object on the last line:
{{"impact_type":"...","reachability":"...","blast_radius":"...","client_conditional_reach":"...","severity_est":"...","confidence":0.0,"why":"<one sentence>"}}"""


def affected_share_bounds(o, client):
    """Bound the affected network share as an interval.

    Lower end uses only the fixing client's share, because no LLM output enumerates
    which *other* implementations actually contained a shared-rule defect. Upper end
    opens to the whole network for ``spec_level``, which is exactly why a spec-level
    estimate cannot be read as an exact tier.
    """
    reach_lo, reach_hi = REACH_BANDS.get(
        str(o.get("client_conditional_reach") or "unknown"), REACH_BANDS["unknown"])
    share_lo, share_hi = SHARE_BANDS.get(client, (0.0, 1.0))
    if o.get("blast_radius") == "spec_level":
        share_hi = 1.0
    return share_lo * reach_lo, share_hi * reach_hi


def max_tier(share_hi):
    for tier, threshold in EF_THRESHOLD:
        if share_hi >= threshold:
            return tier
    return "not-eligible"


def required_client_share(tier, o):
    """Minimum deployment share at which ``tier`` holds, given the assessed reach.

    Deliberately client-independent: this is the share a reader must establish from
    a sourced series, not one this file supplies.
    """
    threshold = dict(EF_THRESHOLD).get(tier)
    if threshold is None:
        return None
    _, reach_hi = REACH_BANDS.get(
        str(o.get("client_conditional_reach") or "unknown"), REACH_BANDS["unknown"])
    if reach_hi <= 0:
        return None
    return round(min(threshold / reach_hi, 1.0), 4)


def guardrail(o, client):
    """Cap the LLM tier by the bounded affected share; report share dependence.

    Returns ``(tier, certainty, required_share)``. ``certainty`` is ``bounded`` when
    even the interval's lower end reaches the tier, ``share_dependent`` when the
    tier holds only above ``required_share``, and ``out_of_scope`` for the
    eligibility guardrail.
    """
    est = str(o.get("severity_est", "")).lower()
    if o.get("reachability") == "local_internal" or o.get("impact_type") in ("local_only", "none"):
        return "not-eligible", "out_of_scope", None
    if not est:
        return "not-eligible", "no_estimate", None

    # "Infinite ETH" and "steal from all EOAs" are not network-share criteria.
    if o.get("impact_type") == "value_integrity":
        return est, "share_exempt", None

    lo, hi = affected_share_bounds(o, client)
    capped = est if TIER.get(est, 0) <= TIER[max_tier(hi)] else max_tier(hi)
    if capped == "not-eligible":
        return "not-eligible", "below_lowest_threshold", None
    certainty = "bounded" if lo >= dict(EF_THRESHOLD).get(capped, 0.0) else "share_dependent"
    return capped, certainty, required_client_share(capped, o)


DEP_RE = re.compile(
    r"upgrade|update|bump|dependab|netty|log4j|spring|jackson|guava|protobuf"
    r"|golang\.org/x|rustsec|jsonparser|libp2p|discv5|openssl|zlib|\bcrate\b",
    re.IGNORECASE)


def is_dependency(r) -> bool:
    """Upstream dependency / tooling CVE — carries CVSS, not EF-bounty severity."""
    if DEP_RE.search(str(r.get("title") or "")):
        return True
    return bool(re.search(r"CHANGELOG|/releases/|nvd\.nist\.gov|rustsec",
                          str(r.get("source_url") or "")))


def classify(row, retries=1):
    r, diff = row
    o = {}
    for _ in range(retries + 1):
        try:
            out = llm._call_llm(build_prompt(r, diff))
            m = re.search(r"\{[^{}]*\"severity_est\"[^{}]*\}", out, re.S)
            o = json.loads(m.group(0)) if m else {}
        except Exception as e:
            o = {"error": str(e)}
        if o.get("severity_est"):            # got a usable answer
            break
    # A truncated JSON response must stay unassessed rather than collapse to
    # not-eligible; see the concurrency note in docs/severity_labeling.md.
    if o.get("severity_est"):
        tier, certainty, required = guardrail(o, r["source_platform"])
    else:
        tier, certainty, required = "", "no_estimate", None
    o["severity_final"] = tier
    o["severity_certainty"] = certainty
    o["severity_required_client_share"] = "" if required is None else f"{required:g}"
    o["prompt_version"] = PROMPT_VERSION
    return r["id"], o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=Path("data/ethereum_vulns.parquet"), type=Path)
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out", default=Path("data/severity_est.csv"), type=Path)
    ap.add_argument("--cache", default=Path("scratchpad_crawl/diff_cache.json"), type=Path)
    ap.add_argument("--sev-cache", default=Path("scratchpad_crawl/severity_cache.json"), type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--allow-partial", action="store_true",
                    help="let --apply write rows with no current-prompt estimate as unassessed")
    ap.add_argument("--only-ids", type=Path, default=None,
                    help="newline-separated row ids to estimate; lets a prompt bump "
                         "refresh the analysed queue before the full corpus")
    import os
    ap.add_argument("--engine", default="openai"); ap.add_argument("--model", default="")
    ap.add_argument("--base-url", default="https://ollama.com/v1")
    ap.add_argument("--api-key-env", default="OLLAMA_API_KEY")
    a = ap.parse_args()
    llm.ENGINE.update(engine=a.engine, model=a.model or "gemma4:31b", base_url=a.base_url,
                      api_key=os.environ.get(a.api_key_env, ""))

    d = pd.read_parquet(a.inp)
    dcache = json.loads(a.cache.read_text()) if a.cache.exists() else {}
    scache = json.loads(a.sev_cache.read_text()) if a.sev_cache.exists() else {}
    sev = d.severity.str.lower()
    graded = sev.isin(["critical", "high", "medium", "low"])
    dep = d.apply(is_dependency, axis=1)

    if a.validate:
        sub = d[graded & ~dep]                       # calibrate on client-code grades only
    else:                                            # --apply: estimate client-code UNRATED rows
        sub = d[~dep & ~graded & d.source_platform.isin(ld.CLIENT_REPOS)]
    if a.only_ids:
        wanted = {ln.strip() for ln in a.only_ids.read_text().splitlines() if ln.strip()}
        sub = sub[sub["id"].isin(wanted)]
        print(f"[severity] --only-ids: {len(wanted)} requested, {len(sub)} in this population",
              file=sys.stderr)
    if a.limit:
        sub = sub.head(a.limit)

    todo = [r for r in sub.to_dict("records") if cache_key(r["id"]) not in scache]
    print(f"[severity] {len(sub)} target rows, {len(todo)} to run "
          f"({len(sub)-len(todo)} cached at {PROMPT_VERSION})  validate={a.validate}",
          file=sys.stderr)
    rows = [(r, ld.get_diff_cached(str(r["source_url"]), r["source_platform"], dcache))
            for r in todo]
    done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for rid, o in ex.map(classify, rows):
            scache[cache_key(rid)] = o; done += 1
            if done % 25 == 0:
                a.sev_cache.write_text(json.dumps(scache)); a.cache.write_text(json.dumps(dcache))
                print(f"  [severity] {done}/{len(todo)}", file=sys.stderr)
    a.sev_cache.write_text(json.dumps(scache)); a.cache.write_text(json.dumps(dcache))
    res = {r["id"]: scache.get(cache_key(r["id"]), {}) for r in sub.to_dict("records")}

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
        # The graded rows are the only place the reach axis can be checked against a
        # published tier, so report its distribution and how often the tier survives
        # without assuming a deployment share.
        reach, cert = {}, {}
        for r in sub.to_dict("records"):
            o = res.get(r["id"], {})
            if not o.get("severity_final"):
                continue
            k = o.get("client_conditional_reach") or "(absent)"
            reach[k] = reach.get(k, 0) + 1
            c = o.get("severity_certainty") or "(absent)"
            cert[c] = cert.get(c, 0) + 1
        print("  client_conditional_reach:")
        for k, c in sorted(reach.items(), key=lambda x: -x[1]):
            print(f"    {k:20s} {c}")
        print("  tier certainty:")
        for k, c in sorted(cert.items(), key=lambda x: -x[1]):
            print(f"    {k:20s} {c}")
    if a.apply:
        import csv
        # A prompt bump empties the cache for every row. Writing the estimate file
        # anyway would silently downgrade 1,500+ rows to `unassessed`, so require
        # the operator to opt into a partial file.
        target = d[~dep & ~graded & d.source_platform.isin(ld.CLIENT_REPOS)]
        missing = [r["id"] for r in target.to_dict("records")
                   if not scache.get(cache_key(r["id"]), {}).get("severity_final")]
        if missing and not a.allow_partial:
            print(f"[severity] refusing to write {a.out}: {len(missing)}/{len(target)} "
                  f"client-code rows have no {PROMPT_VERSION} estimate. Finish the run, "
                  f"or pass --allow-partial to write them as unassessed.", file=sys.stderr)
            return 1
        if missing:
            print(f"[severity] WARNING: partial file — {len(missing)}/{len(target)} rows "
                  f"unassessed at {PROMPT_VERSION}", file=sys.stderr)
        n_est = n_bg = n_dep = 0
        with a.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh); w.writerow(["id", "severity_estimated", "severity_source",
                                            "impact_type", "reachability", "blast_radius",
                                            "client_conditional_reach", "severity_certainty",
                                            "severity_required_client_share", "severity_why"])
            for r in d.to_dict("records"):
                rid = r["id"]; g = str(r["severity"]).lower() in ("critical", "high", "medium", "low")
                dpp = is_dependency(r); o = scache.get(cache_key(rid), {})
                if g and not dpp:                    # real client bug, graded by the bounty
                    src, est = "bounty-graded", r["severity"]; n_bg += 1
                elif dpp:                            # upstream dependency CVE -> keep CVSS, out of scope
                    src, est = "upstream-cvss", (r["severity"] if g else "not-eligible"); n_dep += 1
                elif o.get("severity_final"):        # client-code, LLM-estimated
                    src, est = "llm-estimated", o["severity_final"]; n_est += 1
                else:
                    src, est = "unassessed", ""
                w.writerow([rid, est, src, o.get("impact_type", ""), o.get("reachability", ""),
                            o.get("blast_radius", ""), o.get("client_conditional_reach", ""),
                            o.get("severity_certainty", ""),
                            o.get("severity_required_client_share", ""),
                            str(o.get("why", ""))[:200]])
        print(f"wrote {a.out} — bounty-graded {n_bg}, llm-estimated {n_est}, upstream-cvss {n_dep}")


if __name__ == "__main__":
    raise SystemExit(main())
