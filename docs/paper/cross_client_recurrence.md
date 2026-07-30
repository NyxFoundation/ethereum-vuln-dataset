# RQ4: does a defect surface recur across independent implementations?

## Question

The corpus's stated novelty is cross-implementation coverage — eleven clients, six
languages — so the analysis that justifies it is whether a defect in one
implementation indicates variants in another. Two negative results follow: the
normalised taxonomy is too coarse to detect specification-driven recurrence at all, and
once fix dates are recovered, the explicitly anchored cases show no propagation either.

## 1. One limit fixed, one removed

**Records rarely name their specification surface.** Naming an EIP, a consensus-spec
function, or an opcode is the only way a record states the shared surface it sits on.
Only 181 of 2,225 records (8.1%) name any of them, fork names included.

**Precedence is testable after all.** The Parquet snapshot has no fix date —
`fix_commit` is a SHA, `scraped_at` is crawl time — which initially made "a fix in
client A precedes variants in client B" unanswerable. The dates were already on disk:
[`scripts/resolve_fix_dates.py`](../../scripts/resolve_fix_dates.py) reads the bare
clones the crawler maintains and recovers author and committer dates for **1,959/1,959
rows (100%)** that carry a fix commit, spanning 2014-07-14 to 2026-06-30, with no
GitHub API traffic. Section 4 uses them.

The analysis prefers the **author** date. Squash-merges and rebases rewrite committer
dates, so ordering clients by committer date would rank them by their maintainers' merge
workflows rather than by when the patch was written; the two disagree on the day for 130
rows (6.6%).

## 2. The apparent recurrence, and why it is an artifact

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

## 3. Explicit anchors, and what fork names are not

Anchors a record names itself are much closer to "the same specification text". There
are 130 distinct ones across the 181 records that name any, and 31 appear in two or
more clients — but 12 of those 31 are fork names, which mark a release cycle rather
than a defect surface: `electra` in seven clients means seven clients did Electra work,
not that they shared a bug. Fork anchors are excluded from everything below.

That leaves **18 dated anchors present in two or more independent implementations** —
EIP-4844 across erigon, geth, lighthouse and reth, spanning both layers; EIP-1559 across
three execution clients; `DELEGATECALL` and `CREATE2` across besu, geth and nethermind;
`process_attestation`, `process_epoch` and `get_beacon_proposer_index` across lighthouse
and nimbus.

## 4. With dates, there is still no propagation

Ordering each of the 18 anchors by author date
([`tables/cross_client_anchor_precedence.csv`](tables/cross_client_anchor_precedence.csv)):

| Measure | Value |
|---|---:|
| Median span between first and last client | **1,051 days** (2.9 years) |
| Anchors spanning over 2 years | **10 / 18** |
| Anchors spanning ≤ 90 days | 4 / 18 |
| Distinct clients appearing first | **8** |
| Most times first by any single client | **4** (lighthouse, nimbus) |

Two things rule out the propagation reading.

**No client leads.** If a dominant implementation's fixes indicated latent variants
elsewhere, one client would appear first repeatedly. Instead eight different clients take
the first position across 18 anchors, and the maximum is four — lighthouse and nimbus,
not the largest execution client. Geth is first twice.

**The gaps are too long to be propagation.** `CREATE2` spans 2,848 days between Geth
and Besu; `get_total_active_balance` spans 2,097 days; EIP-1559 spans 1,602. At that
scale "both clients touched this surface" is close to guaranteed for any long-lived
specification, and says nothing about one fix indicating another.

The four short-span anchors do not rescue it, because they are the opposite phenomenon:
EIP-7732 (54 days), EIP-7928 (48), EIP-8037 (17) and `get_head` (2) are all
current-fork development, where several clients implement a new EIP concurrently by
design. That is coordinated engineering, not variant discovery.

**Do not claim.** Neither long nor short spans support "a fix in one implementation
predicts variants in another". Long spans are independent work on a durable surface;
short spans are simultaneous implementation of new specification text.

## 5. Defensible claim

> Cross-client co-occurrence measured on a normalised protocol-and-cause taxonomy is
> explained by cluster size alone: surfaces bound by a shared specification spread
> across no more clients than surfaces that are each implementation's own business
> (stratified permutation p = 0.63, with the effect changing sign under a narrower
> reading of "specified"). Recovering fix dates for all 1,959 rows with a fix commit
> makes precedence testable and does not rescue the claim either: across the 18
> explicitly anchored multi-client cases, eight different clients appear first, no
> client leads more than four times, and the median gap between first and last is 2.9
> years. Cross-implementation recurrence is not demonstrated by this corpus at either
> granularity.

The contribution is a demonstration that both candidate units fail, and a dated,
per-anchor candidate list for anyone who wants to attempt the pairing manually.

## 6. What would make this answerable

1. **Specification-text anchors on more records.** Extraction currently relies on the
   record naming an EIP, spec function, or opcode, which 8.1% do. Diff-derived anchors —
   the opcode constant, precompile address, or spec function a hunk touches — would raise
   coverage substantially without asking humans for labels, and would let the precedence
   analysis run on hundreds of anchors instead of 18.
2. **Manual pairing of the 18 dated anchor sets.** For each, decide whether the records
   describe the same defect, independent defects on a shared surface, or ordinary
   parallel feature work. Only that converts the candidate list into a measured rate
   with a stated denominator.
3. **A propagation-shaped hypothesis.** If variant propagation exists it should appear
   as a short-span, same-defect pair *outside* a shared fork-development window. That is
   a testable prediction, and the dated table is what it should be tested against.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/resolve_fix_dates.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/cross_client_recurrence.py \
  --iterations 5000
git diff --exit-code docs/paper/tables
```

`resolve_fix_dates.py` needs the bare clones under `scratchpad_crawl/repos`; without
them the precedence tables are skipped and the rest still generates. The permutation
test is seeded, so the checked-in tables are byte-reproducible at a given iteration
count.

## Generated evidence

- [`tables/cross_client_cluster_spread.csv`](tables/cross_client_cluster_spread.csv)
- [`tables/cross_client_surface_comparison.csv`](tables/cross_client_surface_comparison.csv)
- [`tables/cross_client_permutation_test.csv`](tables/cross_client_permutation_test.csv)
- [`tables/cross_client_spec_anchors.csv`](tables/cross_client_spec_anchors.csv)
- [`tables/cross_client_anchor_precedence.csv`](tables/cross_client_anchor_precedence.csv)
- [`tables/cross_client_anchor_first_mover.csv`](tables/cross_client_anchor_first_mover.csv)
- [`tables/cross_client_recurrence_summary.csv`](tables/cross_client_recurrence_summary.csv)
- [`tables/fix_date_coverage.csv`](tables/fix_date_coverage.csv)
