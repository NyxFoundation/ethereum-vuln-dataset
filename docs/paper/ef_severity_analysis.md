# RQ2: analysis with EF bug-bounty severity estimates

## Question

Can `severity_estimated` provide enough observations for severity analysis
without mixing the Ethereum Foundation (EF) bug-bounty impact model with
upstream CVSS?

## 1. Population and two-stage outcome

The primary population includes only:

- 60 records with `severity_source=bounty-graded`;
- 1,552 records with `severity_source=llm-estimated`.

Both use the EF-bounty model. We exclude 612 `upstream-cvss` records and one
unassessed record. This produces 1,612 EF-comparable records (72.4% of the
snapshot).

This exclusion is conservative rather than perfectly scoped. The current
dependency heuristic marks every NVD, changelog, or release URL
`upstream-cvss`, so the 612 excluded rows contain some client records as well as
true dependencies. The analysis avoids mixing CVSS with EF tiers at the cost of
dropping those false-positive dependency classifications.

Severity is analysed in two stages:

1. **Bounty eligibility:** Critical/High/Medium/Low versus `not-eligible`;
2. **Impact tier among eligible records:** Critical/High versus Medium/Low.

`not-eligible` is a scope decision, not a tier below Low.

| Outcome | Records | Denominator | Share |
|---|---:|---:|---:|
| EF-comparable | 1,612 | 2,225 | 72.4% |
| Bounty-eligible | 592 | 1,612 | 36.7% |
| Not eligible | 1,020 | 1,612 | 63.3% |
| Critical or High | 128 | 592 eligible | 21.6% |

This expands the EF-tiered analysis population from 60 ground-truth grades to
592 combined grades/estimates, a 9.9-fold increase. The Critical/High review
set expands from 18 bounty-graded records to 128 combined records.

## 2. Tier distribution and source sensitivity

| Source | Critical | High | Medium | Low | Not eligible |
|---|---:|---:|---:|---:|---:|
| Bounty-graded (n=60) | 2 | 16 | 39 | 3 | 0 |
| LLM-estimated (n=1,552) | 0 | 110 | 242 | 180 | 1,020 |
| Combined EF (n=1,612) | **2** | **126** | **281** | **183** | **1,020** |

The estimates solve the sample-size problem for an eligible and
Critical/High-versus-Medium/Low analysis. They do **not** solve it for Critical
alone: the LLM produced no Critical estimates, leaving only two
bounty-graded Critical records. Primary analysis must therefore combine
Critical and High.

## 3. What the 128-record Critical/High queue contains

Across the combined eligible population, the leading root causes among the 128
Critical/High records are:

| Root cause | Critical/High | Eligible in class | Share severe |
|---|---:|---:|---:|
| `missing_input_validation` | 26 | 146 | 17.8% |
| `resource_exhaustion` | 22 | 87 | 25.3% |
| `integer_overflow_underflow` | 20 | 78 | 25.6% |
| `consensus_divergence` | 18 | 65 | 27.7% |
| `missing_bounds_check` | 8 | 39 | 20.5% |
| `improper_state_update` | 8 | 28 | 28.6% |

The counts provide a practical audit queue: validation, bounded resource use,
arithmetic, determinism, bounds, and state updates cover 102/128 (79.7%) of the
combined Critical/High set.

Within the 110 LLM-estimated High records:

- 89 (80.9%) are `liveness_dos`;
- 21 (19.1%) are `chain_split`;
- all 110 are marked `remote_single_message_or_tx`;
- 55 are `spec_level` and 55 `client_specific`.

These values show that the model applies the EF-bounty semantics it was given:
High requires a remotely reachable, network-scale path. They are a model-output
decomposition, not independent evidence that these proportions describe the
true historical vulnerability population.

## 4. Why client severity rankings are invalid

The estimator prompt includes a hard-coded historical network-share class for
each client. Its deterministic guardrail caps client-specific liveness DoS on a
`MINOR` client from High to Medium. Therefore the output tier is mechanically
dependent on client identity.

This effect is visible in the data:

| Source | Geth Critical/High | Lighthouse Critical/High | Both | All Critical/High |
|---|---:|---:|---:|---:|
| Bounty-graded | 6 | 2 | 8 (44.4%) | 18 |
| LLM-estimated | 59 | 48 | **107 (97.3%)** | 110 |

All 55 LLM High records classified as `client_specific` are Geth (34) or
Lighthouse (21). This is consistent with the prompt's dominant/major share
priors and cap, so it must not be reported as evidence that Geth or Lighthouse
is intrinsically more vulnerable.

**Permitted use:** prioritize candidate fixes for manual review under the
specified historical share assumptions.

**Prohibited use:** rank clients, compare client safety, estimate vulnerability
incidence, or infer that a client causes higher severity.

## 5. Circularity with root cause, attack path, and subsystem

The prompt explicitly supplies `root_cause`, `attack_path`, and `label`.
Associations between those fields and `severity_estimated` are therefore partly
constructed by the estimator. They are useful for checking internal consistency
and organizing an audit backlog, but not as independent statistical discoveries.

For the same reason, p-values for “root cause predicts estimated severity” would
be misleading: the predictor was an input used to create the outcome. This
analysis reports counts and review priorities only.

## 6. Defensible paper use

The defensible severity contribution is methodological and operational:

> A provenance-aware EF-bounty model increases the analysable tiered population
> from 60 to 592 records, while a two-stage eligibility/severity design prevents
> out-of-scope fixes from being treated as Low. The resulting 128-record
> Critical/High queue is useful for audit prioritization, but client and
> category comparisons require bias controls because those variables informed
> the estimator.

Primary paper tables should therefore:

1. report bounty-graded and LLM-estimated counts separately;
2. exclude all `upstream-cvss` rows;
3. combine Critical/High, because estimated Critical has n=0;
4. treat the 128 records as a review queue, not 128 confirmed severe
   vulnerabilities;
5. report all client-level results as model diagnostics, not findings.

## 7. Validation required for inferential severity claims

Before using estimated severity for hypothesis tests:

1. manually review a stratified sample of the 110 LLM High, 242 Medium, 180
   Low, and 1,020 not-eligible records;
2. use at least two independent reviewers and report agreement;
3. rerun a blind estimator without client share, `root_cause`, `attack_path`,
   or `label`;
4. compare blind and context-assisted outputs;
5. replace static share classes with a versioned observation date and source if
   network-share-aware severity remains a research target.

## Generated evidence

- [`tables/ef_severity_population.csv`](tables/ef_severity_population.csv)
- [`tables/ef_severity_tier_counts.csv`](tables/ef_severity_tier_counts.csv)
- [`tables/ef_severity_by_dimension.csv`](tables/ef_severity_by_dimension.csv)
- [`tables/ef_severity_high_decomposition.csv`](tables/ef_severity_high_decomposition.csv)
- [`tables/ef_severity_client_diagnostic.csv`](tables/ef_severity_client_diagnostic.csv)
- [`tables/ef_severity_high_review_queue.csv`](tables/ef_severity_high_review_queue.csv)
