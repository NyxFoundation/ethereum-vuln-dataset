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
2,225 rows (8.1%). Reading the captured `post_fix_code` too raises coverage to **337 rows
(15.1%)**, but only for one anchor kind, and getting there took three corrections that
each changed the result.

*Enumerate spec functions, do not pattern-match them.* A generic `(process|get|is)_\w+`
pattern is dominated by language idiom: its most frequent hits across this corpus are
`is_empty` (38), `is_none` (23) and `is_some` (20) — Rust `Option` methods, not spec
surfaces. The ~120 real consensus-spec function names are listed instead.

*Match across naming conventions.* The specs are snake_case and Rust and Nim keep it,
but Java and TypeScript write `processAttestation` and Go writes `ProcessAttestation`. A
snake_case-only match is not merely incomplete — it decides which *languages* can appear
in a cross-client result at all, and under it Teku and Prysm never surfaced.

*Read EIPs from prose only.* Scanning code for every anchor kind looked like a free
doubling of coverage. Reviewing the shortest-span anchors record by record
([`tables/cross_client_anchor_precision_audit.csv`](tables/cross_client_anchor_precision_audit.csv))
showed it was not:

| Anchor kind and source | Concerns the anchor | Unclear | Does not |
|---|---:|---:|---:|
| EIP, from prose | 2 | 0 | 0 |
| EIP, from post-fix code | **0** | 2 | **12** |
| Consensus function, from post-fix code | 2 | 0 | 0 |

`eip:7928` had collected a Besu commit that pins Dockerfile base images by digest;
`eip:2718` had collected four Reth changes about RocksDB healing and p2p memory bounds;
`eip:8037` had collected a record whose own title names EIP-7928. The cause is
structural — a fix touching a fork-configuration or reference-test file inherits every
EIP that file mentions, so a code match means "this file knows about the EIP", not "this
fix concerns it". Consensus function names survive the same test because the function
must actually be called by code implementing that surface. EIP, opcode and fork anchors
are therefore read from prose only.

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

Anchors a record names itself are much closer to "the same specification text". After the
corrections above there are 148 distinct ones across 337 records, and 86 appear in two or
more clients:

| Anchor kind | In ≥2 clients |
|---|---:|
| consensus-spec function | 63 |
| fork name | 12 |
| EIP | 8 |
| opcode | 3 |

The 12 fork names are excluded from everything below. A fork marks a release cycle, not a
defect surface: `electra` appearing in seven clients means seven clients did Electra work,
not that they shared a bug. One further anchor lacks a dated record on one side, leaving
**73** for the precedence analysis.

**The anchor set skews to the consensus layer.** 63 of the 73 are consensus-spec
functions, because that is the one anchor kind readable from code; EIP and opcode anchors
survive only where an author named them in prose, which leaves 10. Execution-client
precedence is therefore barely measurable here, and the section below should not be read
as a statement about execution clients.

## 4. With dates, there is still no propagation

Ordering each of the 73 anchors by author date
([`tables/cross_client_anchor_precedence.csv`](tables/cross_client_anchor_precedence.csv)):

| Measure | Value |
|---|---:|
| Median span between first and last client | **1,723 days** (4.7 years) |
| Anchors spanning over 2 years | **62 / 73** |
| Anchors spanning ≤ 90 days | 4 / 73 |
| Distinct clients appearing first | 9 |
| Most times first by any single client | 25 (nimbus) |

Two things rule out the propagation reading.

**No client leads once volume is controlled.** Raw first-mover counts are not evidence:
a client appearing in more anchors gets more chances to be first. Ratios below are the
client's share of first positions divided by its share of all positions across the 73
anchors, so 1.0 means "first exactly as often as it turns up at all"
([`tables/cross_client_anchor_first_mover.csv`](tables/cross_client_anchor_first_mover.csv)).
They are only read for clients holding enough positions to mean anything — a client with
two positions posts a ratio of 9 from a single first place.

| Client | Positions | Position share | First share | Ratio |
|---|---:|---:|---:|---:|
| lodestar | **291** | **43.7%** | 28.8% | **0.66** |
| nimbus | 181 | 27.2% | 34.2% | 1.26 |
| lighthouse | 84 | 12.6% | 16.4% | 1.30 |
| teku | 47 | 7.1% | 6.8% | 0.96 |
| erigon | 24 | 3.6% | 2.7% | 0.75 |
| *besu, geth, nethermind, prysm* | 2–8 each | — | — | *not read* |

Among the five clients with at least twenty positions the ratio spans **0.66 to 1.30** —
no client is first materially more often than turning up explains. The client holding the
most positions by a wide margin, lodestar at 43.7%, is first *less* often than its share
predicts. The nominally striking ratios (nethermind 9.00, geth 5.40) each rest on two or
three positions and one first place.

**The gaps are too long to be propagation.** The median span between first and last
client is 4.7 years and 62 of 73 anchors exceed two years. At that scale "both clients
touched this surface" is close to guaranteed for any long-lived specification and says
nothing about one fix indicating another.

The four short-span anchors do not rescue it, because they are the opposite phenomenon:
EIP-7732 (54 days), EIP-7928 (48), EIP-8037 (17) and `get_head` (2) are all
current-fork development, where several clients implement new specification text
concurrently by design. That is coordinated engineering, not variant discovery.

The one reviewed anchor that does look like a genuine shared surface is
`process_bls_to_execution_change`: Teku fixing a validator-index check in
`verifyBlsToExecutionChanges` (2022-11-10) and Nimbus prioritising REST-supplied
BLS-to-execution changes over gossiped ones (2023-02-02), 84 days apart. Both are on the
same spec operation, but they address different concerns, so even the best case in this
set is co-location rather than a shared defect.

**Do not claim.** Neither long nor short spans support "a fix in one implementation
predicts variants in another". Long spans are independent work on a durable surface;
short spans are simultaneous implementation of new specification text.

## 5. Defensible claim

> Cross-client co-occurrence measured on a normalised protocol-and-cause taxonomy is
> explained by cluster size alone: surfaces bound by a shared specification spread
> across no more clients than surfaces that are each implementation's own business
> (stratified permutation p = 0.63, with the effect changing sign under a narrower
> reading of "specified"). Recovering fix dates for all 1,959 rows with a fix commit
> makes precedence testable and does not rescue the claim either: across the 73
> explicitly anchored multi-client cases, first-mover counts are proportional to each
> client's share of positions — every client holding twenty or more positions sits between
> 0.66 and 1.30, and the highest-volume client is first *less* often than its share
> predicts — while the median gap between first and last is 4.7 years. Cross-implementation
> recurrence is not demonstrated by this corpus at either granularity.

The contribution is a demonstration that both candidate units fail, and a dated,
per-anchor candidate list for anyone who wants to attempt the pairing manually.

## 6. What would make this answerable

1. **Anchors on the remaining 80% of records.** Scanning post-fix code took coverage from
   8.1% to 19.7%; the rest needs anchors the code does not name literally — the precompile
   address or gas-schedule constant a hunk touches, or the SSZ container it serialises.
2. **Manual pairing of the 73 dated anchor sets.** For each, decide whether the records
   describe the same defect, independent defects on a shared surface, or ordinary
   parallel feature work. Only that converts the candidate list into a measured rate
   with a stated denominator. At 73 anchors this is a feasible review; the 18-record
   sample already done suggests most pairs will be co-location rather than shared defects.
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
