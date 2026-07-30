# Paper analysis workspace

This directory contains the incremental, reproducible analysis for the
`ethereum-vuln-dataset` paper.

All current counts use the definitions in
[`../DATA_SNAPSHOT.md`](../DATA_SNAPSHOT.md).

The working thesis is:

> CVE-, CWE-, and smart-contract-centred security views do not fully represent
> the consensus, availability, and cross-implementation failure modes found in
> Ethereum clients.

## Analysis stages

1. [`snapshot_audit.md`](snapshot_audit.md) freezes the current dataset and
   resolves definition and documentation mismatches before hypothesis testing.
2. [`advisory_bias_preliminary.md`](advisory_bias_preliminary.md) runs the
   first advisory-selection analysis and identifies dependency/tooling
   contamination that must be reviewed before interpreting protocol labels.
3. [`advisory_scope_review.md`](advisory_scope_review.md) resolves that scope
   contamination and reruns direct-client versus no-ID comparisons.
4. [`ef_severity_analysis.md`](ef_severity_analysis.md) audits the
   EF-bounty `severity_estimated` population without mixing upstream CVSS. Its
   primary exact-tier result uses 60 bounty grades; 110 original LLM High
   labels are retained as a traceable `tier-uncertain` candidate queue.
   [`chain_split_candidate_audit.md`](chain_split_candidate_audit.md) then
   source-reviews all 21 inferred chain-split candidates.
   [`liveness_candidate_audit.md`](liveness_candidate_audit.md) screens all 89
   liveness candidates and source-reviews the first five suspicious
   `label=test` rows.
   [`client_conditional_severity.md`](client_conditional_severity.md) then
   restates the tier as deployment share × client-conditional reach, so the
   assessable factor comes from the fix and each record reports the deployment
   share its tier would require.
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
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/client_conditional_severity.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/cwe_context_analysis.py
git diff --exit-code docs/paper/tables
```

The generated CSV files are deliberately checked in. A paper claim should cite
a generated table, identify its population and denominator, and state whether
the underlying label is authoritative, heuristic, or LLM-derived.

## Claim status

All statements in this directory use one of these states:

- **Observation** — directly computed from the frozen snapshot.
- **Interpretation** — a plausible explanation of an observation.
- **Hypothesis** — requires a statistical test, external comparison, or manual
  validation.
- **Do not claim yet** — contradicted by the current snapshot or not supported
  by its provenance.
