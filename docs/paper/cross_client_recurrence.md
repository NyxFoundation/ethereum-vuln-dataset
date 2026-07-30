# RQ4: does a defect surface recur across independent implementations?

## Question

The corpus's stated novelty is cross-implementation coverage — eleven clients, six
languages — so the analysis that justifies it is whether a defect in one
implementation indicates variants in another. Two negative results follow: the
normalised taxonomy is too coarse to detect specification-driven recurrence at all, and
once fix dates are recovered, the explicitly anchored cases show no propagation either.

## 1. One limit fixed, one removed

**An anchor has to be readable off the record.** A record states its shared surface by
naming an EIP, a consensus-spec function, or an opcode. Only **174 of 2,225 rows (7.8%)**
do, and getting to that honest figure took reverting two of my own attempts to raise it.

*Enumerate spec functions, do not pattern-match them.* A generic `(process|get|is)_\w+`
pattern is dominated by language idiom: its most frequent hits across this corpus are
`is_empty` (38), `is_none` (23) and `is_some` (20) — Rust `Option` methods, not spec
surfaces. The ~120 real consensus-spec function names are listed instead.

*Match across naming conventions.* The specs are snake_case and Rust and Nim keep it, but
Java and TypeScript write `processAttestation` and Go writes `ProcessAttestation`. A
snake_case-only match is not merely incomplete — it decides which *languages* can appear
in a cross-client result at all, and under it Teku and Prysm never surfaced.

*Do not read anchors from code.* Scanning `post_fix_code` doubled coverage to 19.7% and
was adopted twice before being audited. Both times the audit killed it.

For EIP anchors ([`tables/cross_client_anchor_precision_audit.csv`](tables/cross_client_anchor_precision_audit.csv)),
18 reviewed records split by where the anchor came from:

| Anchor source | Concerns the anchor | Mentions it only | Does not |
|---|---:|---:|---:|
| Code only | 0 | 0 | **8** |
| Prose | **5** | 3 | 0 |

Consensus-function anchors were then kept from code on the strength of a single anchor
that reviewed 2/2. Sampling eleven of them covering 122 records
([`tables/cross_client_consensus_fn_audit.csv`](tables/cross_client_consensus_fn_audit.csv))
showed that was a generalisation from the best case: **all eleven are contaminated.**
`process_block` collected a Besu RLPx-deframer fix — an execution client, devp2p framing —
plus a lodestar eslint-rule change and a chai-assertion rename; `get_ancestor` collected
"Merge devel into master" and a clippy-lint pass; one Grandine release-notes record appears
under four different anchors.

Three mechanisms, none of which has a filter:

1. **A code match inherits the file's contents.** A fix touching a fork-configuration or
   reference-test file inherits every EIP that file mentions. The match means "this file
   knows about it", not "this fix concerns it".
2. **Generic names collide.** `process_block`, `process_slot`, `get_ancestor` and
   `get_block` are ordinary method names any client may define — and the
   naming-convention-agnostic matching that removed the language bias makes the collision
   worse. Requiring a more specific name does not save it: `get_next_sync_committee` has
   four components and its three records are a benchmark regression, a sim test and an
   optimistic-sync fix.
3. **A prose mention can still be a blocker or a changelog entry.** Erigon's peer-hygiene
   fix names EIP-7975 inside release notes listing other authors' PRs. No record in the
   corpus names four or more EIPs in prose, so an enumeration is not detectable by count.
   Separating subject from mention needs reading, which is why prose runs about 5-in-8
   rather than clean.

A fourth observation is not contamination but a data-quality note: **anchors inherit
author typos.** Both the Prysm and Lighthouse records write *EIP-7521* for EIP-7251
(MaxEB) — Lighthouse's own markdown link resolves to `eip-7251`. Those two records do
share a surface, and the pair exists only because the same transposition appears twice.

Only the author naming a surface, or a diff restricted to changed lines, carries the
aboutness signal. The snapshot holds pre/post code snapshots rather than a diff, so
anchors are read from prose.

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

After the corrections above there are 92 distinct anchors across 174 records, and 35
appear in two or more clients. Fork names are excluded — a fork marks a release cycle, not
a defect surface, so `electra` in seven clients means seven clients did Electra work.
Removing them and the anchors without a dated record on both sides leaves **22** for the
precedence analysis.

## 4. With dates: the span argues against propagation, the ordering cannot be tested

Ordering each of the 22 anchors by author date
([`tables/cross_client_anchor_precedence.csv`](tables/cross_client_anchor_precedence.csv)):

| Measure | Value |
|---|---:|
| Median span between first and last client | **1,447 days** (4.0 years) |
| Anchors spanning over 2 years | **15 / 22** |
| Anchors spanning ≤ 90 days | 4 / 22 |
| Distinct clients appearing first | 9 |
| Most times first by any single client | 6 (lodestar) |

**The gaps are too long to be propagation.** The median span between first and last client
is four years and 15 of 22 anchors exceed two years. At that scale "both clients touched
this surface" is close to guaranteed for any long-lived specification and says nothing
about one fix indicating another. Spans need no volume control, so this part of the
argument survives the shrunken anchor set.

The four short-span anchors do not rescue it, because they are the opposite phenomenon:
EIP-7732 (54 days), EIP-7928 (48), EIP-8037 (17) and one consensus-function anchor at 2
days are all current-fork development, where several clients implement new specification
text concurrently by design. That is coordinated engineering, not variant discovery.

**Whether any client leads cannot be answered here.** A raw first-mover count is not
evidence — a client appearing in more anchors gets more chances to be first — so it has to
be normalised by each client's share of positions. With 22 anchors and 63 positions in
total, **no client holds even twenty positions** (the largest, lodestar, holds sixteen), so
the normalised ratio has no denominator worth reading and the generated table reports it as
unavailable. The descriptive ratios sit near 1.0 for the four clients with nine or more
positions, but on that sample that is not a finding.

This is a change from an earlier draft of this document, which reported "no client leads"
from 92 anchors. Those 92 rested on code-derived anchors that the audit in section 1
invalidated. The honest statement at 22 anchors is *underpowered*, not *null*.

**Do not claim.** The span evidence argues against propagation. The ordering evidence is
absent, in either direction.

## 5. Defensible claim

> Cross-client co-occurrence measured on a normalised protocol-and-cause taxonomy is
> explained by cluster size alone: surfaces bound by a shared specification spread
> across no more clients than surfaces that are each implementation's own business
> (stratified permutation p = 0.63, with the effect changing sign under a narrower
> reading of "specified"). Recovering fix dates for all 1,959 rows with a fix commit
> makes precedence partly testable, and what it shows does not rescue the claim: across
> the 22 explicitly anchored multi-client cases the median gap between first and last
> client is four years and 15 of 22 exceed two years, while the anchor set is too small
> — no client holds twenty positions — to test whether any implementation leads.
> Cross-implementation recurrence is not demonstrated by this corpus, and the reason it
> cannot be is that an anchor at specification-text granularity is readable off only 7.8%
> of records: code-derived anchors fail validation because presence in a file is not
> aboutness.

The contribution is a demonstration that both candidate units fail, and a dated,
per-anchor candidate list for anyone who wants to attempt the pairing manually.

## 6. Why code-derived anchoring cannot work here

An anchor at specification-text granularity is readable off 7.8% of records, and five
attempts to raise that all failed. Their outcomes are checked in as
[`tables/cross_client_anchor_strategy_audit.csv`](tables/cross_client_anchor_strategy_audit.csv):

| Vocabulary | Match scope | Coverage | Outcome |
|---|---|---:|---|
| EIP reference | prose | 7.8% | **adopted** (~5-in-8 precise) |
| EIP reference | whole file | 18.2% | rejected — 0 of 14 reviewed matches real |
| Consensus function name | whole file | 18.2% | rejected — 11 of 11 sampled anchors contaminated |
| Any name | changed lines only | 16.5% | rejected — worse than prose at a 1-anchor cap |
| SSZ container type | changed lines only | 15.8% | rejected — types are ubiquitous, and collide |
| Spec constant | changed lines only | 6.0% | rejected — preset files enumerate every constant |

Each failure looked like a different bug and they are one structural fact. **The property
that makes a vocabulary usable as a cross-implementation anchor — being shared verbatim
across independent codebases — is the same property that makes it appear in every
codebase's configuration, preset and type-declaration files.** So:

- fork-configuration and reference-test files enumerate every EIP;
- network preset files enumerate every spec constant with its value — two lodestar preset
  records single-handedly manufacture the multi-client status of dozens of constants;
- `BeaconState` and `SignedBeaconBlock` are declared and passed everywhere in consensus
  code, appearing in 146 and 140 records respectively;
- spec functions call each other, so restricting to changed lines does not narrow a
  focused fix to one surface.

`Checkpoint` adds a plain cross-domain collision on top: it matched Erigon's
`BorRoSnapshots` checkpoint work, a Polygon concept unrelated to the beacon-chain type.

**Conclusion.** Presence-based matching is structurally unable to carry aboutness on this
corpus, at any granularity. Only two things can: the author naming the surface, which is
the 7.8% already used, or a semantic reading of what a change *does* rather than what it
mentions.

What remains worth doing:

1. **Manual pairing of the 22 dated anchor sets.** For each, decide whether the records
   describe the same defect, independent defects on a shared surface, or ordinary parallel
   feature work. Only that converts the candidate list into a measured rate with a stated
   denominator, and at 22 anchors it is a short review. The audits already done suggest most
   pairs will be co-location: even the best case found,
   `process_bls_to_execution_change` across Teku and Nimbus 84 days apart, has the two
   records addressing different concerns on a shared operation.
2. **Normalise anchors against the EIP registry.** Two records here reach the same surface
   only because both authors made the same typo (EIP-7521 for 7251). Validating extracted
   numbers against the published EIP list would merge misspellings and drop numbers that are
   not EIPs at all.
3. **Raise coverage by asking a model what a change does**, not by matching what it
   mentions — the one remaining route past 7.8%, and one this workspace would have to audit
   the same way it audited the severity estimates.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/resolve_fix_dates.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/cross_client_recurrence.py \
  --iterations 5000 --diff-anchor-diagnostic
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
- [`tables/cross_client_consensus_fn_audit.csv`](tables/cross_client_consensus_fn_audit.csv)
- [`tables/cross_client_anchor_precision_audit.csv`](tables/cross_client_anchor_precision_audit.csv)
- [`tables/cross_client_diff_anchor_diagnostic.csv`](tables/cross_client_diff_anchor_diagnostic.csv)
- [`tables/cross_client_anchor_strategy_audit.csv`](tables/cross_client_anchor_strategy_audit.csv)
- [`tables/cross_client_recurrence_summary.csv`](tables/cross_client_recurrence_summary.csv)
- [`tables/fix_date_coverage.csv`](tables/fix_date_coverage.csv)
