#!/usr/bin/env python3
"""Triage 89 LLM High liveness candidates and audit the five labelled ``test``."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

import pandas as pd


AVAILABILITY_RE = re.compile(
    r"panic|crash|oom|out.of.memory|denial.of.service|\bdos\b|deadlock|hang"
    r"|memory exhaustion",
    re.IGNORECASE,
)
REMOTE_RE = re.compile(
    r"malicious|malformed|crafted|remote|peer|packet|message|request",
    re.IGNORECASE,
)

TEST_DECISIONS = {
    "61ef89e2ab534b32": (
        "remote_dos_logic_defect_no_crash_evidence",
        "duplicate_fix",
        "transactions",
        "The production slice calculation in transaction-announcement DoS prevention "
        "is wrong, but the source does not report a panic, crash, or node takedown. "
        "This is the PR-form duplicate of the commit record.",
    ),
    "7dce34f9c4b9981e": (
        "remote_dos_logic_defect_no_crash_evidence",
        "duplicate_fix",
        "transactions",
        "The production slice calculation in transaction-announcement DoS prevention "
        "is wrong, but the source does not report a panic, crash, or node takedown. "
        "This is the commit-form duplicate of the PR record.",
    ),
    "b1c9a13d15ccd608": (
        "conditional_availability_incident",
        "unique_fix",
        "block-processing",
        "The source links the code to an observed OOM during reorg log collection, "
        "while explicitly noting a possible 32-bit-host condition. A single malicious "
        "message or transaction is not established.",
    ),
    "eceadd9c7892558a": (
        "local_lifecycle_availability_defect",
        "unique_fix",
        "block-processing",
        "The source reports crashes caused by freeing Ethash memory while still in use. "
        "The defect is concrete, but it is cache/finalizer lifecycle behavior rather "
        "than an evidenced remote attacker trigger.",
    ),
    "geth:ethereum-go-ethereum:PR#24946": (
        "invalid_internal_api_input_panic",
        "unique_fix",
        "engine-api",
        "The diff adds a length check preventing a panic on invalid Engine API "
        "logsBloom input. The source proves the panic but not unauthenticated public "
        "network reachability or the EF >33% threshold.",
    ),
}


def pct(count: int, denominator: int) -> float:
    return round(100 * count / denominator, 3) if denominator else 0.0


def diff_fingerprint(row: pd.Series) -> str:
    pre = str(row.get("pre_fix_code") or "")
    post = str(row.get("post_fix_code") or "")
    if pre.strip() in {"", "[]"} and post.strip() in {"", "[]"}:
        return ""
    return hashlib.sha256(f"{pre}\n{post}".encode()).hexdigest()


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
        & df["impact_type"].eq("liveness_dos")
    ].copy()
    if len(candidates) != 89:
        raise ValueError(f"Expected 89 liveness candidates, found {len(candidates)}")

    source_text = (
        candidates["title"].fillna("") + " " + candidates["description"].fillna("")
    )
    candidates["source_has_availability_term"] = source_text.str.contains(
        AVAILABILITY_RE
    )
    candidates["source_has_remote_trigger_term"] = source_text.str.contains(
        REMOTE_RE
    )
    candidates["evidence_screen"] = "neither_term"
    candidates.loc[
        candidates["source_has_availability_term"],
        "evidence_screen",
    ] = "availability_term_only"
    candidates.loc[
        candidates["source_has_remote_trigger_term"],
        "evidence_screen",
    ] = "remote_term_only"
    candidates.loc[
        candidates["source_has_availability_term"]
        & candidates["source_has_remote_trigger_term"],
        "evidence_screen",
    ] = "both_terms"

    candidates["diff_fingerprint"] = candidates.apply(diff_fingerprint, axis=1)
    fingerprint_counts = candidates["diff_fingerprint"].value_counts()
    duplicate_fingerprints = set(
        fingerprint_counts[
            fingerprint_counts.index.to_series().ne("") & fingerprint_counts.gt(1)
        ].index
    )
    candidates["exact_diff_duplicate"] = candidates["diff_fingerprint"].isin(
        duplicate_fingerprints
    )
    candidates["duplicate_group"] = candidates["diff_fingerprint"].map(
        lambda value: f"diff-{value[:12]}" if value in duplicate_fingerprints else ""
    )
    candidates["needs_source_review"] = True
    candidates["severity_analysis_label"] = "tier-uncertain"

    triage_columns = [
        "id",
        "source_platform",
        "title",
        "source_url",
        "authority_tier",
        "severity_estimated",
        "severity_analysis_label",
        "blast_radius",
        "source_has_availability_term",
        "source_has_remote_trigger_term",
        "evidence_screen",
        "exact_diff_duplicate",
        "duplicate_group",
        "needs_source_review",
        "root_cause",
        "attack_path",
        "label",
        "severity_why",
    ]
    candidates[triage_columns].sort_values(
        ["evidence_screen", "source_platform", "id"]
    ).to_csv(args.output_dir / "liveness_candidate_triage.csv", index=False)

    test_rows = candidates[candidates["label"].eq("test")].copy()
    actual = set(test_rows["id"])
    expected = set(TEST_DECISIONS)
    if actual != expected:
        raise ValueError(
            f"Test-label decisions mismatch; "
            f"missing={sorted(actual - expected)}, extra={sorted(expected - actual)}"
        )
    test_rows["audit_verdict"] = test_rows["id"].map(
        lambda row_id: TEST_DECISIONS[row_id][0]
    )
    test_rows["fix_uniqueness"] = test_rows["id"].map(
        lambda row_id: TEST_DECISIONS[row_id][1]
    )
    test_rows["reviewed_protocol_label"] = test_rows["id"].map(
        lambda row_id: TEST_DECISIONS[row_id][2]
    )
    test_rows["audit_reason"] = test_rows["id"].map(
        lambda row_id: TEST_DECISIONS[row_id][3]
    )
    test_rows["confirmed_high"] = False
    test_rows[
        [
            "id",
            "source_platform",
            "title",
            "source_url",
            "severity_estimated",
            "severity_analysis_label",
            "audit_verdict",
            "fix_uniqueness",
            "label",
            "reviewed_protocol_label",
            "confirmed_high",
            "audit_reason",
            "exact_diff_duplicate",
            "duplicate_group",
            "root_cause",
            "attack_path",
        ]
    ].sort_values(["audit_verdict", "id"]).to_csv(
        args.output_dir / "liveness_test_label_audit.csv", index=False
    )

    exact_duplicate_rows = int(candidates["exact_diff_duplicate"].sum())
    duplicate_groups = len(duplicate_fingerprints)
    distinct_artifacts = len(candidates) - (exact_duplicate_rows - duplicate_groups)
    summary = [
        (
            "candidate_rows",
            len(candidates),
            len(candidates),
            "original LLM High liveness rows",
        ),
        (
            "distinct_diff_artifacts",
            distinct_artifacts,
            len(candidates),
            "candidate rows after collapsing two exact-diff duplicate pairs",
        ),
        (
            "source_has_availability_term",
            int(candidates["source_has_availability_term"].sum()),
            len(candidates),
            "keyword screen only; not proof of availability impact",
        ),
        (
            "source_has_remote_trigger_term",
            int(candidates["source_has_remote_trigger_term"].sum()),
            len(candidates),
            "keyword screen only; not proof of reachability",
        ),
        (
            "source_has_both_term_classes",
            int(
                (
                    candidates["source_has_availability_term"]
                    & candidates["source_has_remote_trigger_term"]
                ).sum()
            ),
            len(candidates),
            "contains both availability and remote-trigger vocabulary",
        ),
        (
            "client_specific",
            int(candidates["blast_radius"].eq("client_specific").sum()),
            len(candidates),
            "exact High still requires dated client-share evidence",
        ),
        (
            "spec_level",
            int(candidates["blast_radius"].eq("spec_level").sum()),
            len(candidates),
            "shared-rule label does not establish shared implementation defect",
        ),
        (
            "geth_rows",
            int(candidates["source_platform"].eq("geth").sum()),
            len(candidates),
            "candidate concentration is confounded by the prompt's client-share prior",
        ),
        (
            "lighthouse_rows",
            int(candidates["source_platform"].eq("lighthouse").sum()),
            len(candidates),
            "candidate concentration is confounded by the prompt's client-share prior",
        ),
        (
            "authority_B",
            int(candidates["authority_tier"].eq("B_corroborated").sum()),
            len(candidates),
            "source-backed fix record, not a confirmed severity grade",
        ),
        (
            "authority_C",
            int(candidates["authority_tier"].eq("C_candidate").sum()),
            len(candidates),
            "candidate-quality evidence",
        ),
        (
            "test_label_rows",
            len(test_rows),
            len(candidates),
            "first manually audited stratum; four distinct fixes",
        ),
        (
            "test_label_confirmed_high",
            int(test_rows["confirmed_high"].sum()),
            len(test_rows),
            "none establish the EF >33% threshold",
        ),
    ]
    summary_frame = pd.DataFrame(
        summary, columns=["metric", "rows", "denominator", "definition"]
    )
    summary_frame["percent"] = summary_frame.apply(
        lambda row: pct(int(row["rows"]), int(row["denominator"])), axis=1
    )
    summary_frame.to_csv(
        args.output_dir / "liveness_candidate_summary.csv", index=False
    )

    print(
        "Liveness candidate audit:",
        f"{len(candidates)} rows / {distinct_artifacts} distinct diff artifacts,",
        f"{len(test_rows)} test-labelled rows audited,",
        f"{int(test_rows['confirmed_high'].sum())} confirmed High",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
