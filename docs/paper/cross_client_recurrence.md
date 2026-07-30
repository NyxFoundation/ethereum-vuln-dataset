# RQ4: does a defect surface recur across independent implementations?

## Question

The corpus's stated novelty is cross-implementation coverage — eleven clients, six
languages — so the analysis that justifies it is whether a defect in one
implementation indicates variants in another. Two negative results follow: the
normalised taxonomy is too coarse to detect specification-driven recurrence at all, and
once fix dates are recovered, the explicitly anchored cases show no propagation either.

## 1. One limit fixed, one removed

**An anchor has to be readable off the record.** A record states its shared surface by
naming an EIP, a consensus-spec function, or an opcode. Prose alone does so on 181 of
2,225 rows (8.1%), so the captured `post_fix_code` is scanned as well: a spec function
appears in the code that implements it whether or not the author mentioned it. That
raises coverage to **438 rows (19.7%)** and multi-client anchors from 31 to 114.

Two choices make that scan trustworthy rather than merely larger, and both changed the
result. Spec function names are **enumerated** from the consensus specs rather than
pattern-matched, because a generic `(process|get|is)_\w+` pattern is dominated by
language idiom — its most frequent hits across this corpus are `is_empty` (38),
`is_none` (23) and `is_some` (20), which are Rust `Option` methods, not spec surfaces.
And matching is **naming-convention agnostic**: the specs are snake_case and Rust and Nim
keep it, but Java and TypeScript write `processAttestation` and Go writes
`ProcessAttestation`. A snake_case-only match is not merely incomplete — it decides which
*languages* are able to appear in a cross-client result at all, and under it Teku and
Prysm never surfaced. After the fix all eleven clients do.

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
are 187 distinct ones across the 438 records that name any, and 114 appear in two or more
clients:

| Anchor kind | In ≥2 clients |
|---|---:|
| consensus-spec function | 63 |
| EIP | 22 |
| fork name | 20 |
| opcode | 9 |

The 20 fork names are excluded from everything below. A fork marks a release cycle, not a
defect surface: `electra` appearing in seven clients means seven clients did Electra work,
not that they shared a bug. Of the 94 non-fork multi-client anchors, two have no dated
record on one side, leaving 92 for the precedence analysis.

That leaves **92 dated anchors present in two or more independent implementations** —
EIP-4844 spanning both layers, EIP-1559 across three execution clients, `DELEGATECALL`
and `CREATE2` across besu, geth and nethermind, and the consensus state-transition
functions (`process_attestation`, `process_epoch`, `get_beacon_proposer_index`,
`compute_epoch_at_slot`) across the consensus clients.

## 4. With dates, there is still no propagation

Ordering each of the 92 anchors by author date
([`tables/cross_client_anchor_precedence.csv`](tables/cross_client_anchor_precedence.csv)):

| Measure | Value |
|---|---:|
| Median span between first and last client | **1,688 days** (4.6 years) |
| Anchors spanning over 2 years | **72 / 92** |
| Anchors spanning ≤ 90 days | 4 / 92 |
| Distinct clients appearing first | **11** (all of them) |
| Most times first by any single client | 29 (nimbus) |

Two things rule out the propagation reading.

**No client leads once volume is controlled.** Raw first-mover counts are not evidence:
a client appearing in more anchors gets more chances to be first. Normalising by each
client's share of all positions across the 92 anchors
([`tables/cross_client_anchor_first_mover.csv`](tables/cross_client_anchor_first_mover.csv)):

| Client | Positions | Position share | First share | Ratio |
|---|---:|---:|---:|---:|
| nimbus | 190 | 24.9% | 31.5% | 1.27 |
| lodestar | **292** | **38.2%** | 22.8% | **0.60** |
| lighthouse | 91 | 11.9% | 14.1% | 1.18 |
| teku | 48 | 6.3% | 5.4% | 0.86 |
| erigon | 47 | 6.2% | 5.4% | 0.87 |
| besu | 24 | 3.1% | 3.3% | 1.06 |
| grandine | 21 | 2.7% | 2.2% | 0.81 |
| reth | 17 | 2.2% | 5.4% | 2.45 |
| geth | 16 | 2.1% | 6.5% | 3.10 |
| nethermind | 12 | 1.6% | 1.1% | 0.69 |
| prysm | 6 | 0.8% | 2.2% | 2.75 |

Nimbus's 29 first positions track its 24.9% share of positions, and the client holding
the *most* positions — lodestar, at 38.2% — is first **less** often than its share
predicts. The three ratios above 2 (geth, reth, prysm) rest on 16, 17 and 6 positions,
which is noise. No client is first more often than simply showing up explains.

**The gaps are too long to be propagation.** The median span between first and last
client is 4.6 years and 72 of 92 anchors exceed two years. At that scale "both clients
touched this surface" is close to guaranteed for any long-lived specification and says
nothing about one fix indicating another.

The four short-span anchors do not rescue it, because they are the opposite phenomenon:
EIP-7732 (54 days), EIP-7928 (48), EIP-8037 (17) and `get_head` (2) are all
current-fork development, where several clients implement new specification text
concurrently by design. That is coordinated engineering, not variant discovery.

**Do not claim.** Neither long nor short spans support "a fix in one implementation
predicts variants in another". Long spans are independent work on a durable surface;
short spans are simultaneous implementation of new specification text.

## 5. Defensible claim

> Cross-client co-occurrence measured on a normalised protocol-and-cause taxonomy is
> explained by cluster size alone: surfaces bound by a shared specification spread
> across no more clients than surfaces that are each implementation's own business
> (stratified permutation p = 0.63, with the effect changing sign under a narrower
> reading of "specified"). Recovering fix dates for all 1,959 rows with a fix commit
> makes precedence testable and does not rescue the claim either: across the 92
> explicitly anchored multi-client cases, all eleven clients appear first, first-mover
> counts are proportional to each client's share of positions — the highest-volume
> client is first *less* often than its share predicts — and the median gap between
> first and last is 4.6 years. Cross-implementation recurrence is not demonstrated by
> this corpus at either granularity.

The contribution is a demonstration that both candidate units fail, and a dated,
per-anchor candidate list for anyone who wants to attempt the pairing manually.

## 6. What would make this answerable

1. **Anchors on the remaining 80% of records.** Scanning post-fix code took coverage from
   8.1% to 19.7%; the rest needs anchors the code does not name literally — the precompile
   address or gas-schedule constant a hunk touches, or the SSZ container it serialises.
2. **Manual pairing of the 92 dated anchor sets.** For each, decide whether the records
   describe the same defect, independent defects on a shared surface, or ordinary
   parallel feature work. Only that converts the candidate list into a measured rate
   with a stated denominator. At 92 anchors this is now a feasible review, which it was
   not at 18.
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
