"""Quality gates for the curated ethereum-vuln-dataset.

These assert the properties that make the corpus "vulnerabilities only": the
build is reproducible, the release-note boilerplate is gone, and every row
carries a security signal.
"""
import json
import re
from pathlib import Path

import pandas as pd
import pytest
from scripts.paper_analysis import ADVISORY_ID_RE, PROVENANCE_FIELDS, RATED

ROOT = Path(__file__).resolve().parents[1]
CURATED = ROOT / "data" / "ethereum_vulns.parquet"
RAW = ROOT / "data" / "raw" / "train.classified.parquet"
MANIFEST = ROOT / "data" / "manifest.json"
ADVISORY_REVIEW = ROOT / "docs" / "paper" / "tables" / "advisory_review_queue.csv"
ADVISORY_COMPARISON = (
    ROOT / "docs" / "paper" / "tables" / "direct_advisory_vs_no_id.csv"
)
MINEBLOCK_AXES = ROOT / "docs" / "paper" / "tables" / "mineblock_type_axes.csv"
MINEBLOCK_ALIGNMENT = (
    ROOT / "docs" / "paper" / "tables" / "mineblock_taxonomy_alignment.csv"
)
EF_SEVERITY_POPULATION = (
    ROOT / "docs" / "paper" / "tables" / "ef_severity_population.csv"
)
EF_SEVERITY_TIERS = (
    ROOT / "docs" / "paper" / "tables" / "ef_severity_tier_counts.csv"
)
EF_SEVERITY_HIGH_QUEUE = (
    ROOT / "docs" / "paper" / "tables" / "ef_severity_high_review_queue.csv"
)
CWE_CONTEXT_COVERAGE = (
    ROOT / "docs" / "paper" / "tables" / "cwe_context_coverage.csv"
)
CWE_ROOT_CAUSE_COVERAGE = (
    ROOT / "docs" / "paper" / "tables" / "cwe_root_cause_coverage.csv"
)
BOUNTY_SEVERE_CWE_AUDIT = (
    ROOT / "docs" / "paper" / "tables" / "bounty_severe_cwe_audit.csv"
)
CHAIN_SPLIT_AUDIT = (
    ROOT / "docs" / "paper" / "tables" / "chain_split_candidate_audit.csv"
)
CHAIN_SPLIT_SUMMARY = (
    ROOT / "docs" / "paper" / "tables" / "chain_split_audit_summary.csv"
)

BOILERPLATE = re.compile(r"critical update required|urgency guidelines|high-urgency", re.I)
REQUIRED_COLS = {
    "id", "source_platform", "severity", "title", "description",
    "source_url", "stride", "cwe_top25", "security_score", "confidence",
}


@pytest.fixture(scope="module")
def df():
    return pd.read_parquet(CURATED)


def test_schema(df):
    assert REQUIRED_COLS <= set(df.columns), REQUIRED_COLS - set(df.columns)


def test_nonempty(df):
    assert len(df) > 1000


def test_no_release_boilerplate(df):
    """T1: the phantom-Nimbus-critical class must not survive."""
    blob = df["title"].fillna("") + " " + df["description"].fillna("")
    assert int(blob.str.contains(BOILERPLATE).sum()) == 0


def test_every_row_has_a_security_signal(df):
    """GATE: no row without at least one independent security signal."""
    has_sev = df["severity"].fillna("").str.lower().isin({"critical", "high", "medium", "low"})
    has_kw = df["security_score"] >= 0.5
    has_stride = ~df["stride"].fillna("Other").isin(["Other"])
    has_cwe = ~df["cwe_top25"].fillna("N/A").isin(["N/A"])
    blob = df["title"].fillna("") + " " + df["description"].fillna("")
    has_id = blob.str.contains(r"CVE-\d{4}-\d{4,7}|GHSA-", case=False, regex=True)
    # fix-verb × crash-class impact in the title (recall-expansion gate signal)
    fiximpact = re.compile(
        r"\b(?:fix|fixes|fixed|prevent|avoid|guard|handle|resolve|correct|patch)\w*"
        r"\b[^.\n]{0,40}\b(?:crash|panic|segfault|deadlock|hang|freeze|oom"
        r"|out.of.memory|overflow|underflow|data race|race condition|reorg"
        r"|non.?determin|infinite loop|use.after.free|null (?:pointer|deref))\b"
        r"|\b(?:crash|panic|segfault|deadlock|hang|oom|overflow|underflow|reorg"
        r"|race condition)\b[^.\n]{0,25}"
        r"\b(?:fix|fixed|prevent|avoid|guard against|resolved|patch)\w*\b", re.I)
    has_fiximpact = df["title"].fillna("").str.contains(fiximpact)
    if "silent_fix_prob" in df.columns:
        has_silentfix = pd.to_numeric(df["silent_fix_prob"], errors="coerce").fillna(0) >= 0.70
    else:
        has_silentfix = pd.Series(False, index=df.index)
    assert bool((has_sev | has_kw | has_stride | has_cwe | has_id | has_fiximpact
                 | has_silentfix).all())


def test_confidence_values(df):
    assert set(df["confidence"].unique()) <= {"high", "medium", "low"}


def test_score_range(df):
    assert df["security_score"].between(0.0, 1.0).all()


def test_curated_is_subset_of_raw(df):
    raw = pd.read_parquet(RAW)
    assert len(df) < len(raw)
    assert set(df["id"]) <= set(raw["id"])


def test_manifest_distributions_match_curated_snapshot(df):
    """Prevent a previous build's distributions from surviving a row update."""
    manifest = json.loads(MANIFEST.read_text())
    build = manifest["build"]

    def counts(column):
        return {
            str(key): int(value)
            for key, value in df[column].value_counts().items()
        }

    assert manifest["n_rows"] == len(df)
    assert build["security_rows"] == len(df)
    assert build["by_confidence"] == counts("confidence")
    assert build["by_authority_tier"] == counts("authority_tier")
    assert build["by_n_signals"] == counts("n_signals")
    assert build["by_source"] == counts("source_platform")
    assert build["by_severity"] == counts("severity")
    assert build["by_score"] == counts("security_score")
    assert build["by_severity_source"] == counts("severity_source")


def test_canonical_public_evidence_partition(df):
    """The four publication categories must be mutually exclusive and exhaustive."""
    advisory = (
        df[PROVENANCE_FIELDS]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
        .str.contains(ADVISORY_ID_RE)
    )
    rated = df["severity"].fillna("").str.lower().isin(RATED)
    partition = [
        advisory & rated,
        advisory & ~rated,
        ~advisory & rated,
        ~advisory & ~rated,
    ]
    assert sum(int(mask.sum()) for mask in partition) == len(df)
    assert [int(mask.sum()) for mask in partition] == [52, 120, 91, 1962]


def test_advisory_scope_review_is_complete():
    review = pd.read_csv(ADVISORY_REVIEW)
    assert len(review) == 172
    assert review["reviewed_scope"].notna().all()
    assert review["review_notes"].notna().all()
    assert review["reviewed_scope"].value_counts().to_dict() == {
        "dependency_or_tooling": 135,
        "direct_client_implementation": 36,
        "other_product": 1,
    }


def test_advisory_comparison_denominators():
    comparison = pd.read_csv(ADVISORY_COMPARISON)
    denominators = (
        comparison[
            [
                "population",
                "direct_advisory_denominator",
                "no_id_denominator",
            ]
        ]
        .drop_duplicates()
        .set_index("population")
    )
    assert denominators.loc["A_or_B"].to_dict() == {
        "direct_advisory_denominator": 36,
        "no_id_denominator": 1656,
    }
    assert denominators.loc["all_tiers"].to_dict() == {
        "direct_advisory_denominator": 36,
        "no_id_denominator": 2053,
    }


def test_mineblock_semantic_axes_and_alignment():
    axes = pd.read_csv(MINEBLOCK_AXES).set_index("semantic_axis")
    assert int(axes["mineblock_geth_issues"].sum()) == 212
    assert axes["mineblock_geth_issues"].to_dict() == {
        "root_cause": 109,
        "subsystem_or_object": 53,
        "symptom_or_impact": 50,
    }

    alignment = pd.read_csv(MINEBLOCK_ALIGNMENT).set_index("mineblock_type_name")
    assert int(alignment.loc["Go Panic", "matched_current_rows"]) == 23
    assert int(alignment.loc["Go Panic", "distinct_current_root_causes"]) == 6
    assert float(alignment.loc["Overflow", "expected_root_cause_percent"]) == 80.0


def test_ef_severity_population_and_tiers():
    population = pd.read_csv(EF_SEVERITY_POPULATION).set_index("metric")
    assert int(population.loc["ef_comparable_rows", "count"]) == 1612
    assert int(population.loc["excluded_upstream_cvss", "count"]) == 612
    assert int(population.loc["original_ef_bounty_eligible", "count"]) == 592
    assert int(population.loc["ef_not_eligible", "count"]) == 1020
    assert int(population.loc["original_ef_critical_or_high", "count"]) == 128
    assert int(
        population.loc["confirmed_bounty_critical_or_high", "count"]
    ) == 18
    assert int(
        population.loc["llm_high_candidates_tier_uncertain", "count"]
    ) == 110

    tiers = pd.read_csv(EF_SEVERITY_TIERS).set_index(["population", "tier"])
    assert int(tiers.loc[("llm_estimated", "Critical"), "rows"]) == 0
    assert int(tiers.loc[("llm_estimated", "High"), "rows"]) == 0
    assert int(tiers.loc[("llm_estimated", "tier-uncertain"), "rows"]) == 110
    assert int(tiers.loc[("bounty_graded", "Critical"), "rows"]) == 2
    assert int(tiers.loc[("bounty_graded", "High"), "rows"]) == 16


def test_ef_high_queue_provenance_and_client_prior_diagnostic():
    queue = pd.read_csv(EF_SEVERITY_HIGH_QUEUE)
    assert len(queue) == 128
    assert set(queue["severity_source"]) == {"bounty-graded", "llm-estimated"}
    assert not queue["severity_source"].eq("upstream-cvss").any()

    llm_high = queue[queue["severity_source"].eq("llm-estimated")]
    assert len(llm_high) == 110
    assert llm_high["severity_estimated"].eq("High").all()
    assert llm_high["severity_analysis_label"].eq("tier-uncertain").all()
    assert llm_high["severity_review_status"].eq("threshold_unverified").all()
    assert llm_high["severity_review_reason"].notna().all()
    assert llm_high["blast_radius"].value_counts().to_dict() == {
        "client_specific": 55,
        "spec_level": 55,
    }
    assert int(llm_high["source_platform"].isin(["geth", "lighthouse"]).sum()) == 107


def test_cwe_context_complementarity_and_severe_audit():
    coverage = pd.read_csv(CWE_CONTEXT_COVERAGE).set_index(
        ["population", "metric"]
    )
    assert int(coverage.loc[("all_snapshot", "cwe_known"), "rows"]) == 396
    assert int(
        coverage.loc[("all_snapshot", "cwe_2025_top25"), "rows"]
    ) == 130
    assert int(
        coverage.loc[
            ("all_snapshot", "no_cwe_but_both_context_axes_known"), "rows"
        ]
    ) == 1541
    assert int(
        coverage.loc[
            ("all_snapshot", "no_cwe_but_both_context_axes_known"),
            "denominator",
        ]
    ) == 1829

    severe = pd.read_csv(BOUNTY_SEVERE_CWE_AUDIT)
    assert len(severe) == 18
    assert int(severe["cwe_known"].sum()) == 3
    assert int(severe["cwe_2025_top25"].sum()) == 0

    roots = pd.read_csv(CWE_ROOT_CAUSE_COVERAGE).set_index("root_cause")
    assert roots.loc["consensus_divergence"].to_dict() == {
        "rows": 174,
        "cwe_known_rows": 2,
        "cwe_known_percent": 1.149,
        "cwe_2025_top25_rows": 1,
        "cwe_2025_top25_percent": 0.575,
        "distinct_cwe_labels": 2,
    }
    assert int(roots.loc["incorrect_gas_accounting", "cwe_known_rows"]) == 0


def test_chain_split_candidate_source_audit_is_complete():
    audit = pd.read_csv(CHAIN_SPLIT_AUDIT)
    assert len(audit) == 21
    assert audit["id"].nunique() == 21
    assert audit["severity_estimated"].eq("High").all()
    assert audit["severity_analysis_label"].eq("tier-uncertain").all()
    assert not audit["confirmed_chain_split"].any()
    assert audit["audit_reason"].notna().all()
    assert audit["audit_verdict"].value_counts().to_dict() == {
        "consensus_sensitive_defect": 9,
        "operational_or_nonconsensus_change": 4,
        "preventive_hardening_no_realized_failure": 4,
        "feature_or_predeployment_change": 2,
        "availability_defect_not_chain_split": 1,
        "source_linkage_insufficient": 1,
    }

    summary = pd.read_csv(CHAIN_SPLIT_SUMMARY).set_index("audit_verdict")
    assert int(summary["rows"].sum()) == 21
    assert int(summary["confirmed_chain_split_rows"].sum()) == 0
