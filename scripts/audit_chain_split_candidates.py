#!/usr/bin/env python3
"""Audit the 21 LLM High rows whose inferred impact was ``chain_split``.

This is a source-evidence audit, not a new severity estimator.  The decisions
below distinguish a concrete defect in consensus-sensitive code from
hardening, feature work, operational recovery, and mismatched source linkage.
None of those decisions independently proves the EF High threshold (>33%).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


DECISIONS = {
    "511d306991f1f534": (
        "consensus_sensitive_defect",
        "predeployment",
        "The source and diff add two missing EIP-7928 validity checks; this is a "
        "concrete conformance defect, but the description identifies a devnet spec.",
    ),
    "5106a70e2cbfc8ad": (
        "availability_defect_not_chain_split",
        "testnet_or_predeployment",
        "The source directly reports a blob-receipt encoding panic on blob testnets. "
        "That supports an availability defect, not the inferred chain-split outcome.",
    ),
    "ab4b3b42313daaa5": (
        "preventive_hardening_no_realized_failure",
        "latent_future_condition",
        "The overflow occurs only once the Ethash DAG exceeds a 32-bit index. The "
        "source establishes a latent deterministic limit, not a remote malicious block.",
    ),
    "cd61542cfa31ee40": (
        "consensus_sensitive_defect",
        "deployment_unclear",
        "Differential fuzzing found stack-trie crashes and a missing small-root commit. "
        "The defect is concrete, but a remotely constructible mainnet path is not shown.",
    ),
    "fef6b529d2c24653": (
        "consensus_sensitive_defect",
        "deployed_code",
        "The diff corrects an EVM memory-gas overflow boundary. Consensus sensitivity "
        "is direct; practical reachability and affected network share are not shown.",
    ),
    "441cd590285ea8e0": (
        "preventive_hardening_no_realized_failure",
        "testnet",
        "The author calls the overflow theoretical and says it should not affect "
        "Medalla or other testnets. The change is defensive checked arithmetic.",
    ),
    "62e8f286767d785e": (
        "operational_or_nonconsensus_change",
        "deployed_code",
        "The change lets Lighthouse recover after an execution-client consensus "
        "failure and requires restart. It does not fix a Lighthouse-originated split.",
    ),
    "d985fecc6f7d7397": (
        "feature_or_predeployment_change",
        "predeployment",
        "This is Merge optimistic-verification feature implementation with assorted "
        "error-handling changes, not source evidence of one exploited vulnerability.",
    ),
    "lighthouse:networking:PR#1009": (
        "preventive_hardening_no_realized_failure",
        "predeployment",
        "The PR broadly introduces checked arithmetic and linting. It does not identify "
        "a concrete reachable overflow with a demonstrated divergent result.",
    ),
    "lighthouse:networking:PR#3749": (
        "consensus_sensitive_defect",
        "predeployment",
        "The source identifies two concrete Capella logic defects in payload defaults "
        "and epoch-boundary payload attributes, but they were fixed as fork work.",
    ),
    "lighthouse:networking:PR#457": (
        "consensus_sensitive_defect",
        "pre_mainnet",
        "Balance verification compared against the wrong amount. This is a concrete "
        "state-transition defect, but the record predates deployed Ethereum consensus.",
    ),
    "lighthouse:networking:PR#4877": (
        "operational_or_nonconsensus_change",
        "deployed_code",
        "The source changes the attestation-rewards calculation/API after an inactivity "
        "leak; it does not change canonical consensus state transition.",
    ),
    "lighthouse:networking:PR#5037": (
        "operational_or_nonconsensus_change",
        "deployed_code",
        "This PR deletes a temporary workaround after a separate specification and "
        "implementation patch. The deletion is not the underlying vulnerability fix.",
    ),
    "lighthouse:networking:PR#5764": (
        "consensus_sensitive_defect",
        "predeployment",
        "Production verification code switches the indexed-attestation map key to a "
        "tree-hash root to prevent collisions. The defect is concrete but Electra-era.",
    ),
    "lighthouse:networking:PR#5772": (
        "consensus_sensitive_defect",
        "predeployment",
        "The PR fixes overflow and ordering in PeerDAS custody-column computation. "
        "This is concrete spec logic but part of predeployment spec-test work.",
    ),
    "lighthouse:networking:PR#8496": (
        "consensus_sensitive_defect",
        "deployment_unclear",
        "A failing test and code diff directly establish incorrect BLS infinity-state "
        "tracking. Acceptance of an invalid consensus message is not demonstrated.",
    ),
    "lighthouse:networking:PR#9177": (
        "operational_or_nonconsensus_change",
        "deployed_code",
        "The PR moves proposer-reorg configuration from CLI defaults to specification "
        "values. It is local configuration alignment, not a remote chain-split fix.",
    ),
    "lighthouse:networking:PR#9233": (
        "feature_or_predeployment_change",
        "predeployment",
        "The change avoids zero hashes in post-Gloas forkchoiceUpdated calls and adds "
        "mock-EL assertions. It is future-fork conformance work.",
    ),
    "lighthouse:sigp-lighthouse:ISSUE#1773": (
        "source_linkage_insufficient",
        "deployment_unclear",
        "The issue describes a protocol timing attack, but the captured code change is "
        "an unrelated compression error conversion. This row cannot support the claim.",
    ),
    "3d74c0f53be49bec": (
        "consensus_sensitive_defect",
        "deployment_unclear",
        "The diff fixes a hard-coded EVM zero-padding direction in UInt256 overloads. "
        "A consensus-sensitive defect is plausible; an exercised opcode path is absent.",
    ),
    "prysm:prysmaticlabs-prysm:ISSUE#9098": (
        "preventive_hardening_no_realized_failure",
        "deployment_unclear",
        "The report explicitly describes the zero random coefficient as negligible "
        "probability and defense in depth; no fix diff or realized forgery is present.",
    ),
}


def pct(count: int, denominator: int) -> float:
    return round(100 * count / denominator, 3) if denominator else 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", type=Path, default=Path("data/ethereum_vulns.parquet")
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("docs/paper/tables")
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.input)
    candidates = df[
        df["severity_source"].eq("llm-estimated")
        & df["severity_estimated"].eq("High")
        & df["impact_type"].eq("chain_split")
    ].copy()
    actual = set(candidates["id"])
    expected = set(DECISIONS)
    if actual != expected:
        raise ValueError(
            f"Audit decisions do not match candidate set; "
            f"missing={sorted(actual - expected)}, extra={sorted(expected - actual)}"
        )

    candidates["audit_verdict"] = candidates["id"].map(
        lambda row_id: DECISIONS[row_id][0]
    )
    candidates["deployment_context"] = candidates["id"].map(
        lambda row_id: DECISIONS[row_id][1]
    )
    candidates["audit_reason"] = candidates["id"].map(
        lambda row_id: DECISIONS[row_id][2]
    )
    candidates["confirmed_chain_split"] = False
    candidates["severity_analysis_label"] = "tier-uncertain"
    candidates["audit_basis"] = (
        "upstream title/description plus captured pre/post-fix code"
    )

    columns = [
        "id",
        "source_platform",
        "title",
        "source_url",
        "authority_tier",
        "severity_estimated",
        "severity_analysis_label",
        "impact_type",
        "audit_verdict",
        "deployment_context",
        "confirmed_chain_split",
        "audit_reason",
        "audit_basis",
        "root_cause",
        "attack_path",
        "label",
    ]
    candidates[columns].sort_values(
        ["audit_verdict", "source_platform", "id"]
    ).to_csv(args.output_dir / "chain_split_candidate_audit.csv", index=False)

    summary_rows: list[dict] = []
    for verdict, frame in candidates.groupby("audit_verdict"):
        summary_rows.append(
            {
                "audit_verdict": verdict,
                "rows": len(frame),
                "denominator": len(candidates),
                "percent": pct(len(frame), len(candidates)),
                "confirmed_chain_split_rows": int(
                    frame["confirmed_chain_split"].sum()
                ),
            }
        )
    pd.DataFrame(summary_rows).sort_values(
        ["rows", "audit_verdict"], ascending=[False, True]
    ).to_csv(args.output_dir / "chain_split_audit_summary.csv", index=False)

    print(
        "Chain-split candidate audit:",
        f"{len(candidates)} reviewed,",
        f"{int(candidates['audit_verdict'].eq('consensus_sensitive_defect').sum())} "
        "consensus-sensitive defects,",
        f"{int(candidates['confirmed_chain_split'].sum())} confirmed chain splits",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
