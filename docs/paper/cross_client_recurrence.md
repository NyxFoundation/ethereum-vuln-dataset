# RQ4: does a defect surface recur across independent implementations?

## Question

The corpus's stated novelty is cross-implementation coverage — eleven clients, six
languages — so the analysis that justifies it is whether a defect in one
implementation indicates variants in another. This document reports what the frozen
snapshot can and cannot establish about that, and the primary result is negative.

## 1. Two limits fixed before measuring

**Precedence is not testable.** The snapshot has no fix date. `fix_commit` is a SHA,
`introduced_in_commit` is its parent, and `scraped_at` is crawl time. So "a fix in
client A precedes variants in client B" cannot be evaluated here at all. Everything
below measures **co-occurrence**, and the word "predicts" must not be attached to it.

**Records rarely name their specification surface.** Naming an EIP, a consensus-spec
function, an opcode, or a fork is the only way a record states the shared surface it
sits on. Only 181 of 2,225 records (8.1%) name any of them.

## 2. The apparent result, and why it is an artifact

Clustering by the dataset's normalised coordinates — `layer` × `label` × `root_cause` —
gives 362 clusters, 252 of which hold at least two records. Of those, **211 span two or
more clients, covering 1,993 records (89.6% of the corpus)**.

Taken at face value that is overwhelming cross-client recurrence. It is not a result.
With eleven clients and 45 protocol labels, a cluster of any size spans several clients
by construction, so the number measures cluster size rather than recurrence.

The way to tell the two apart is an internal control: surfaces defined by a
specification every client must implement identically (EVM, opcodes, gas, state trie,
fork choice, SSZ/RLP, beacon-chain state transition) versus surfaces that are each
implementation's own business (its database, CLI, metrics, build, and transaction-pool
policy, which is deliberately unspecified). If recurrence is driven by shared
specification, it must concentrate in the first group.

Stratified by cluster size, it does not:

| Cluster size | Surface | Clusters | Spanning ≥2 clients | Mean clients |
|---|---|---:|---:|---:|
| 2–3 | client-local | 30 | 83.3% | 2.00 |
| 2–3 | spec-anchored | 71 | 60.6% | 1.65 |
| 4–7 | client-local | 26 | 88.5% | 2.54 |
| 4–7 | spec-anchored | 36 | 91.7% | 2.83 |
| 8–15 | client-local | 18 | 100% | 3.39 |
| 8–15 | spec-anchored | 32 | 93.8% | 3.44 |
| 16+ | client-local | 12 | 100% | 4.42 |
| 16+ | spec-anchored | 18 | 100% | 4.50 |

Within every stratum the two classes are indistinguishable, and in the smallest
stratum the spec-anchored surfaces spread *less*. A permutation test that shuffles the
surface class within size strata — 5,000 iterations, seed 20260730 — confirms it:

| Surface definition | Observed Δ mean clients | Null mean | Null SD | p (two-sided) |
|---|---:|---:|---:|---:|
| broad | −0.051 | −0.001 | 0.107 | **0.63** |
| narrow (consensus-critical only) | +0.048 | −0.001 | 0.108 | **0.64** |

The observed statistic changes sign between two defensible readings of "specified",
which is what a quantity sitting at zero looks like.

**Do not claim.** Cross-client co-occurrence in this taxonomy is not evidence of
specification-driven recurrence. The 89.6% figure must not appear as a finding: it is
what cluster size and a coarse label vocabulary produce on their own.

**Interpretation.** This is a limit of the *unit*, not of the corpus. `label` ×
`root_cause` is too coarse to identify "the same defect": two clients having a
`missing_input_validation` fix in `p2p-interface` is not a shared bug. The dataset's
two-coordinate description is a retrieval and comparison aid — the contribution
claimed in [`cwe_context_comparison.md`](cwe_context_comparison.md) — and this result
marks where that aid stops being sufficient.

## 3. What explicit anchors do support

Anchors a record names itself are much closer to "the same specification text". There
are 130 distinct ones across the 181 records that name any, and 31 appear in two or
more clients — but 12 of those 31 are fork names, which mark a release cycle rather
than a defect surface: `electra` in seven clients means seven clients did Electra work,
not that they shared a bug.

Excluding forks leaves **19 anchors present in two or more independent
implementations**, and these are concrete:

| Anchor | Records | Clients |
|---|---:|---|
| EIP-4844 | 5 | erigon, geth, lighthouse, reth |
| EIP-1559 | 3 | erigon, geth, reth |
| EIP-7732 | 3 | lodestar, nimbus, teku |
| `DELEGATECALL` | 4 | besu, nethermind |
| EIP-7928 | 3 | besu, erigon |
| `SHR` | 3 | besu, erigon |
| `process_attestation` | 2 | lighthouse, nimbus |
| `process_epoch` | 2 | lighthouse, nimbus |
| `get_beacon_proposer_index` | 2 | lighthouse, nimbus |
| `process_rewards_and_penalties` | 2 | lighthouse, nimbus |
| `CREATE2` | 2 | besu, geth |
| … 8 more | | |

EIP-4844 is the strongest case: five records across four clients spanning both the
execution and consensus layers. These 19 anchors are the defensible output of this
stage — a **candidate variant set for manual pairing**, not a measured recurrence rate.
Nineteen anchors over 2,225 records is far too thin to estimate how often defects
recur.

## 4. Defensible claim

> Cross-client co-occurrence measured on a normalised protocol-and-cause taxonomy is
> explained by cluster size alone: surfaces bound by a shared specification spread
> across no more clients than surfaces that are each implementation's own business
> (stratified permutation p = 0.63, and the effect changes sign under a narrower
> reading of "specified"). Recurrence analysis therefore needs an anchor at
> specification-text granularity, which only 8.1% of records supply, yielding 19
> explicitly anchored candidate variant sets across independent implementations.

The contribution is the demonstration that the coarse unit fails, plus a concrete,
small candidate set — not a recurrence rate.

## 5. What would make this answerable

1. **Fix dates.** Resolving `fix_commit` to a committer date for the 1,959 rows that
   have one would make precedence testable and is the single highest-value addition.
   It needs ~1,959 GitHub API lookups, not new annotation.
2. **Specification-text anchors on more records.** Extraction currently relies on the
   record naming an EIP, spec function, or opcode. Diff-derived anchors — the opcode
   constant, precompile address, or spec function a hunk touches — would raise coverage
   well beyond 8.1% without asking humans for labels.
3. **Manual pairing of the 19 anchored candidate sets.** For each, decide whether the
   records describe the same defect, independent defects on a shared surface, or
   ordinary parallel feature work. That converts a candidate list into a measured rate
   with a stated denominator.
4. Only then is the directional question — does a fix in one implementation indicate
   variants in another — worth testing.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/cross_client_recurrence.py \
  --iterations 5000
git diff --exit-code docs/paper/tables
```

The permutation test is seeded, so the checked-in tables are byte-reproducible at a
given iteration count.

## Generated evidence

- [`tables/cross_client_cluster_spread.csv`](tables/cross_client_cluster_spread.csv)
- [`tables/cross_client_surface_comparison.csv`](tables/cross_client_surface_comparison.csv)
- [`tables/cross_client_permutation_test.csv`](tables/cross_client_permutation_test.csv)
- [`tables/cross_client_spec_anchors.csv`](tables/cross_client_spec_anchors.csv)
- [`tables/cross_client_recurrence_summary.csv`](tables/cross_client_recurrence_summary.csv)
