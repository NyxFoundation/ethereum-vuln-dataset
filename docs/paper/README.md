# Paper analysis workspace

This directory contains the incremental, reproducible analysis for the
`ethereum-vuln-dataset` paper.

All current counts use the definitions in
[`../DATA_SNAPSHOT.md`](../DATA_SNAPSHOT.md).

The working thesis is:

> CVE-, CWE-, and smart-contract-centred security views do not fully represent
> the consensus, availability, and cross-implementation failure modes found in
> Ethereum clients.

A second result has emerged from testing it, and it now runs through the severity
chain: **a label is only as strong as the thing that produced it.** The corpus's
`bounty-graded` provenance turned out to be assigned by exclusion rather than by
evidence, and the EF severity tiers turned out to depend on a quantity no repository
artifact contains. Stages 4c and 4d are where that is traced and repaired.

## Analysis stages

1. [`snapshot_audit.md`](snapshot_audit.md) freezes the current dataset and
   resolves definition and documentation mismatches before hypothesis testing.
2. [`advisory_bias_preliminary.md`](advisory_bias_preliminary.md) runs the
   first advisory-selection analysis and identifies dependency/tooling
   contamination that must be reviewed before interpreting protocol labels.
3. [`advisory_scope_review.md`](advisory_scope_review.md) resolves that scope
   contamination and reruns direct-client versus no-ID comparisons.
4. [`ef_severity_analysis.md`](ef_severity_analysis.md) audits the
   EF-bounty `severity_estimated` population without mixing upstream CVSS. It
   retains the 110 original LLM High labels as a traceable `tier-uncertain`
   candidate queue. **Its exact-tier population is superseded — read stage 4d
   first.**
   1. [`chain_split_candidate_audit.md`](chain_split_candidate_audit.md)
      source-reviews all 21 inferred chain-split candidates: nine are concrete
      consensus-sensitive defects, none establishes a chain split.
   2. [`liveness_candidate_audit.md`](liveness_candidate_audit.md) screens all 89
      liveness candidates and source-reviews 15 of them across three strata, with
      zero confirmed High.
   3. [`client_conditional_severity.md`](client_conditional_severity.md)
      restates the tier as deployment share × client-conditional reach, so the
      assessable factor comes from the fix and each record reports the deployment
      share its tier would require. A client-local defect cannot reach High for 8
      of 11 clients at any reach; measuring reach rules 30 of the 110 candidates
      out of High arithmetically. Scoring that measurement against source review
      finds exclusions confirmed and full-coverage assessments over-permissive.
   4. [`bounty_graded_population_audit.md`](bounty_graded_population_audit.md)
      traces the `bounty-graded` label itself: 45 of the 60 rows inherited a
      severity from a ten-keyword crawler heuristic, so the confirmed
      Critical/High sample is **8, not 18**, and exact-tier inference has 13
      usable rows. Two independent models corroborate the split.
5. [`cwe_context_comparison.md`](cwe_context_comparison.md) measures how much
   Ethereum root-cause and protocol-location context remains when generic CWE
   metadata is absent.
6. Prior-work comparison: replicate and extend MineBlockVuln (ESEC/FSE 2022)
   across eleven Ethereum clients and six implementation languages. See
   [`mineblock_replication.md`](mineblock_replication.md).
7. Cross-client recurrence: cluster fixes by specification anchor and measure
   whether a fix in one implementation predicts variants in another.

## Reproduce the checked-in tables

From the repository root:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/paper_analysis.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/severity_analysis.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/audit_chain_split_candidates.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/audit_liveness_candidates.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/client_conditional_severity.py \
  --severity-csv data/severity_est_v2.csv
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/audit_bounty_graded_population.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/cwe_context_analysis.py
git diff --exit-code docs/paper/tables
```

The generated CSV files are deliberately checked in. A paper claim should cite
a generated table, identify its population and denominator, and state whether
the underlying label is authoritative, heuristic, or LLM-derived.

`data/severity_est_v2.csv` is a re-estimation overlay, checked in because the
`client_conditional_*` tables are generated from it. It covers only the rows the paper
analysis consumes, so its other rows read `unassessed`; the frozen Parquet snapshot is
never rebuilt from it. See
[`../severity_labeling.md`](../severity_labeling.md) for how to regenerate it.

## Claim status

All statements in this directory use one of these states:

- **Observation** — directly computed from the frozen snapshot.
- **Interpretation** — a plausible explanation of an observation.
- **Hypothesis** — requires a statistical test, external comparison, or manual
  validation.
- **Do not claim yet** — contradicted by the current snapshot or not supported
  by its provenance.
