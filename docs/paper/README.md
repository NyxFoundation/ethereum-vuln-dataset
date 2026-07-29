# Paper analysis workspace

This directory contains the incremental, reproducible analysis for the
`ethereum-vuln-dataset` paper.

The working thesis is:

> CVE-, CWE-, and smart-contract-centred security views do not fully represent
> the consensus, availability, and cross-implementation failure modes found in
> Ethereum clients.

## Analysis stages

1. [`snapshot_audit.md`](snapshot_audit.md) freezes the current dataset and
   resolves definition and documentation mismatches before hypothesis testing.
2. Advisory-selection bias: compare advisory-linked and non-advisory records
   across protocol area, root cause, attack path, client, language, and layer.
3. CWE comparison: test how much protocol context adds beyond generic weakness
   labels when explaining network impact.
4. Prior-work comparison: replicate and extend MineBlockVuln (ESEC/FSE 2022)
   across eleven Ethereum clients and six implementation languages.
5. Cross-client recurrence: cluster fixes by specification anchor and measure
   whether a fix in one implementation predicts variants in another.

## Reproduce the checked-in tables

From the repository root:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/paper_analysis.py
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
