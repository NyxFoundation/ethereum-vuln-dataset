# RQ2: EF bug-bounty severity with an audited estimate layer

> **Superseded counts.** This document treats the 60 `bounty-graded` rows as
> published grades. They are not.
> [`bounty_graded_population_audit.md`](bounty_graded_population_audit.md) traces
> that label and finds only 14 rows backed by a maintainer-issued advisory; 45
> inherited a severity from a ten-keyword heuristic over cross-client pull requests.
> The confirmed Critical/High sample is **8, not 18**, and exact-tier inference has
> **13** usable rows, not 60. Every "n=60", "n=1,612", and "18 confirmed" figure
> below is the pre-audit value, kept so the correction is traceable.

## Question

Can `severity_estimated` overcome the small number of published EF-bounty
grades, and which conclusions remain valid after auditing the estimated High
labels?

## 1. Population

The frozen snapshot has 2,225 records. Severity provenance gives four disjoint
populations:

- 60 `bounty-graded` records;
- 1,552 `llm-estimated` records;
- 612 `upstream-cvss` records;
- one unassessed record.

Only the first two use the EF-bounty vocabulary. The CVSS and unassessed rows
are excluded, leaving 1,612 EF-comparable records. Before review, 592 have a
Critical/High/Medium/Low label and 1,020 are `not-eligible`.

`not-eligible` is a scope decision, not a tier below Low.

## 2. Audit correction

The original estimator assigned 110 LLM rows to High. We retain that source
output for reproducibility, but change the analysis label for all 110 to
`tier-uncertain`.

| Audit reason | Records | Correction |
|---|---:|---|
| `client_specific` | 55 | Exact High removed because the prompt used an unversioned static client-share prior; it does not establish that the affected client exceeded the EF >33% threshold at the fix date. |
| `spec_level` | 55 | Exact High removed because implementing a shared rule does not establish that every implementation shared the defect, or that >33% of the network was affected. |

This is a threshold correction, not a claim that the records are Medium or
Low. Assigning either tier would require the same missing historical impact
evidence. The corrected label therefore preserves uncertainty rather than
inventing a precise replacement.

The source and analysis labels are both present in
[`tables/ef_severity_high_review_queue.csv`](tables/ef_severity_high_review_queue.csv):

- `severity_estimated` is the immutable original label;
- `severity_analysis_label` is the audited label;
- `severity_review_status` and `severity_review_reason` make the change
  traceable.

## 3. Corrected tier distribution

| Source | Critical | High | Medium | Low | Not eligible | Tier uncertain |
|---|---:|---:|---:|---:|---:|---:|
| Bounty-graded (n=60) | 2 | 16 | 39 | 3 | 0 | 0 |
| LLM-estimated (n=1,552) | 0 | **0** | 242 | 180 | 1,020 | **110** |
| Combined EF (n=1,612) | **2** | **16** | **281** | **183** | **1,020** | **110** |

The important result is negative but useful: estimated severity expands the
eligibility and triage population, but it does **not** expand the
paper-quality exact High sample. There are still only 18 confirmed
Critical/High records, all bounty-graded.

**Corrected.** Of those 18, eight came from the `cross_client` keyword heuristic and
one is an upstream Go toolchain CVE. The confirmed severe sample is **8**; see
[`bounty_graded_population_audit.md`](bounty_graded_population_audit.md). The
negative result stands and strengthens: estimation did not expand a sample that was
half the size it appeared to be.

Consequently:

- exact-tier inference must use the 60 bounty-graded records and report its
  small-sample limitation;
- the 110 former High estimates are a candidate queue, not confirmed severe
  vulnerabilities;
- Critical remains too sparse for separate analysis (n=2), so even the
  bounty-grade analysis should combine Critical and High.

## 4. What is still interesting in the 110-candidate queue

The queue is useful for prioritizing manual validation:

- 89/110 (80.9%) are modelled as `liveness_dos`;
- 21/110 (19.1%) are modelled as `chain_split`;
- 99/110 (90.0%) are `B_corroborated`, while 11 are `C_candidate`;
- the leading root causes are `resource_exhaustion` (20),
  `missing_input_validation` (19), `integer_overflow_underflow` (18), and
  `consensus_divergence` (14);
- those four classes contain 71/110 candidates (64.5%).

These are workload counts, not incidence or risk estimates. The estimator saw
`root_cause`, `attack_path`, and `label`, so associations with those fields are
partly circular.

The queue also exposes a valuable data-quality target: five candidates have
`label=test`. Those records should receive source-level review before any
security or severity claim.

## 5. Client-share bias is measured, not ignored

The original candidate distribution is Geth 59, Lighthouse 48, and one each
for Erigon, Nethermind, and Prysm. Geth plus Lighthouse therefore account for
107/110 (97.3%) of candidates.

This is not evidence that those clients are less safe. Client identity entered
the estimator through hard-coded share classes, and the guardrail capped
client-specific DoS for clients called `MINOR`. All 55 client-specific
candidates are Geth or Lighthouse. The concentration is therefore a diagnostic
of estimator construction.

Permitted use:

- order a manual review queue under explicitly stated assumptions;
- compare reviewed source evidence within the queue;
- measure how much labels change under a blind re-estimation.

Prohibited use:

- rank client safety;
- compare vulnerability incidence by client;
- treat 107/110 as an empirical client-risk concentration;
- use the candidate label as the dependent variable in a test whose predictors
  were supplied to the estimator.

## 6. Paper contribution

The defensible contribution is a provenance-aware treatment of missing
severity:

> LLM decomposition makes 1,552 otherwise unrated client records searchable
> under EF-bounty concepts, but exact network-impact tiers require external
> threshold evidence. Auditing the 110 generated High labels therefore converts
> them to a traceable `tier-uncertain` queue instead of inflating the confirmed
> severe sample from 18 to 128.

This is more informative than either discarding all estimates or accepting
them at face value. It separates three research objects:

1. published grades for exact-tier inference;
2. estimated eligibility and impact components for exploratory analysis;
3. threshold-uncertain candidates for source-level validation.

## 7. The threshold is now inverted rather than assumed

The blocking factor in every correction above is the same: the EF tiers are
network-share statements, and network share is not in a repository artifact.
[`client_conditional_severity.md`](client_conditional_severity.md) resolves this
by decomposing the tier into

> affected_network_share = affected_client_share × client_conditional_reach

and asking the estimator only for the second factor, which the fix does show
(default configuration, node role, platform, feature gating). The share is no
longer supplied to the prompt at all; a deterministic step bounds the product and
reports the share a tier *would* require.

Two results follow immediately, without any new LLM output:

- a `client_specific` defect cannot reach High for 8 of the 11 clients even at
  100% client-conditional reach — only Geth, Lighthouse, and Prysm can host one;
- all 55 `client_specific` candidates in this queue need the defect to affect more
  than half of their client's operator population before High becomes
  arithmetically available, and the 21 Lighthouse rows need more than 100% at the
  bottom of that client's share band.

This makes the Geth-plus-Lighthouse concentration in §5 an arithmetic consequence
of the threshold rather than a client-risk signal, and it turns `tier-uncertain`
into a falsifiable share requirement per record.

## 8. Next validation analysis

For inferential use of estimated tiers:

1. review a stratified sample across all original tiers, not only High;
2. have at least two independent reviewers and report agreement;
3. record fix-date network share with a source and observation date;
4. rerun a blind estimator without client identity/share, `root_cause`,
   `attack_path`, or `label`;
5. compare original, blind, and human labels with a confusion matrix;
6. only promote `tier-uncertain` to an exact tier when the EF impact threshold
   is evidenced — which now means a sourced, dated client-share series meeting
   the record's `severity_required_client_share`.

The first source-level validation is complete for all 21 original chain-split
High candidates. Only nine contain direct evidence of a consensus-sensitive
defect, and zero establish a chain split or the EF >33% threshold. See
[`chain_split_candidate_audit.md`](chain_split_candidate_audit.md).

The liveness audit has also begun. The 89 liveness candidates contain 87
distinct diff artifacts; only seven source descriptions contain both
availability and remote-trigger vocabulary. A source review of all five
`label=test` rows found four unique production fixes but zero confirmed High
records. All seven records containing both vocabulary classes were also
reviewed: only one directly evidenced a single-input failure, but it was fixed
before mainnet, and zero established High. See
[`liveness_candidate_audit.md`](liveness_candidate_audit.md).
The three remote-term-only rows were also reviewed; none connects a single
remote input to an availability failure. In total, 15 targeted liveness rows
(14 distinct artifacts) have been source-reviewed with zero confirmed High.

## Generated evidence

- [`tables/ef_severity_population.csv`](tables/ef_severity_population.csv)
- [`tables/ef_severity_tier_counts.csv`](tables/ef_severity_tier_counts.csv)
- [`tables/ef_severity_by_dimension.csv`](tables/ef_severity_by_dimension.csv)
- [`tables/ef_severity_high_decomposition.csv`](tables/ef_severity_high_decomposition.csv)
- [`tables/ef_severity_client_diagnostic.csv`](tables/ef_severity_client_diagnostic.csv)
- [`tables/ef_severity_high_review_queue.csv`](tables/ef_severity_high_review_queue.csv)
- [`tables/chain_split_candidate_audit.csv`](tables/chain_split_candidate_audit.csv)
- [`tables/chain_split_audit_summary.csv`](tables/chain_split_audit_summary.csv)
- [`tables/liveness_candidate_summary.csv`](tables/liveness_candidate_summary.csv)
- [`tables/liveness_candidate_triage.csv`](tables/liveness_candidate_triage.csv)
- [`tables/liveness_test_label_audit.csv`](tables/liveness_test_label_audit.csv)
- [`tables/liveness_both_terms_audit.csv`](tables/liveness_both_terms_audit.csv)
- [`tables/liveness_remote_only_audit.csv`](tables/liveness_remote_only_audit.csv)
- [`tables/client_conditional_frontier.csv`](tables/client_conditional_frontier.csv)
- [`tables/client_conditional_candidate_bounds.csv`](tables/client_conditional_candidate_bounds.csv)
- [`tables/client_conditional_summary.csv`](tables/client_conditional_summary.csv)
