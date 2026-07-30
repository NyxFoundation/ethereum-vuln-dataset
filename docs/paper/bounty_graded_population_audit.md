# RQ2d: the bounty-graded ground truth is mostly collector output

## Question

Every severity result in this directory rests on one population:
`severity_source == 'bounty-graded'`, 60 rows,
[described](ef_severity_analysis.md) as the slice that "only `bounty-graded` is the
EF-bounty ground-truth slice" and used to claim 18 confirmed Critical/High records.
What actually set the `severity` value on those rows?

This audit was not planned. It came out of re-running the estimator with the revised
[client-conditional prompt](client_conditional_severity.md): the calibration pass
scored 6/60 exact-tier where the previous prompt was documented at 60%, and the
disagreement turned out to be in the ground truth rather than in the model.

## 1. `bounty-graded` is assigned by exclusion, not by evidence

`collection/estimate_severity.py` labelled provenance like this:

```python
if g and not dpp:                    # g = row has a rated severity
    src, est = "bounty-graded", r["severity"]
```

There is no check that a bounty ever graded the row. Any record carrying a rated
`severity` that the dependency regex did not catch became ground truth, so the label
delegates the entire question to whatever populated `severity` upstream.

For 45 of the 60 rows that producer is `collection/crawl_cross_client.py`, which
selects pull requests for *mentioning two client names* and then assigns:

```python
def _infer_severity(pr) -> str:
    """High if body/title contains a high-severity signal; Medium otherwise."""
    text = (pr.get("title") or "").lower() + (pr.get("body") or "")[:2000].lower()
    if any(sig.lower() in text for sig in HIGH_SEVERITY_SIGNALS):
        return "High"
    return "Medium"
```

`HIGH_SEVERITY_SIGNALS` is ten words: `divergence`, `consensus`, `fork choice`,
`fork_choice`, `state transition`, `state_transition`, `reorg`, `finality`,
`slashing`, `attestation`. No vulnerability determination happens anywhere in this
path. Every cross-client PR receives at least Medium, and any PR whose body contains
"consensus" or "attestation" receives High.

## 2. What the 60 rows actually are

| What produced the severity | Records | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| Published GitHub security advisory | 14 | 2 | 7 | 2 | 3 |
| `cross_client` keyword heuristic | 45 | 0 | **8** | **37** | 0 |
| Repository crawl, unattributed | 1 | 0 | 1 | 0 | 0 |

A published advisory URL (`/security/advisories/GHSA-…`) is the only self-evidencing
severity here: the tier was set by the maintainers who issued the advisory. All 14
such rows are real disclosures — Besu's CALL gas allocation error
(CVE-2022-36025), Geth's RETURNDATA corruption via datacopy, the `MulMod` DoS, the
0x4-precompile shallow copy, Lighthouse's Electra effective-balance processing, and
so on.

One of the 14 is an upstream Go toolchain CVE ("Denial of service due to Go
CVE-2020-28362"), which carries a CVSS score rather than an EF-bounty grade. It
evaded the dependency classifier because the title is phrased as an impact and names
no package or update verb.

The heuristic rows are what the wording predicts. A sample of the 45, all carrying a
`bounty-graded` tier in the frozen snapshot:

| Title | Tier |
|---|---|
| Ethereum 2.0 Networking Specification | High |
| Implement Kintsugi specs 🍵 (the Merge November sprint PR) | High |
| rename random to prevRandao as per the kiln v2 specs | High |
| Run sim single node test with Geth catalyst to finality | High |
| Fix execution integration test CI failure | Medium |
| Configuring nethermind with jwtAuth in CI | Medium |
| Add dockerized geth setup for amphora | Medium |
| Suppress RPC Error disconnect log | Medium |
| Error codes and messages for Geth compatibility | Medium |
| Interop: Checkout and build prysm | Medium |

These are CI plumbing, interop test harnesses, feature and spec implementation work,
and a specification document. The first four are High because their bodies discuss
finality, consensus, or the Merge.

## 3. Two independent models reject the same rows

The eligibility screen in the estimator (`impact_type ∈ {local_only, none}` or
`reachability == local_internal` → not eligible) was run over the population twice,
by `claude-sonnet-5` and by `glm-5.2`. Neither is authoritative, but both are
independent of the provenance classification above, and they converge on it.

| Provenance | Rows | claude accepts / rejects | glm accepts / rejects |
|---|---:|---:|---:|
| Published advisory | 14 | 13 / 1 | 13 / 0 |
| `cross_client` keyword heuristic | 45 | 4 / **41** | 4 / **41** |
| Repository crawl, unattributed | 1 | 0 / 1 | 0 / 1 |

Pairwise agreement between the two models is **55/59 (93.2%)**. The one advisory row
claude rejected is the upstream Go toolchain CVE, which it called dependency hygiene —
the conclusion this audit reaches on separate grounds; `glm-5.2` never saw that row
because the corrected dependency classifier now excludes it.

Both models accept exactly 13 rows as in-scope and both reject exactly 41 of the 45
heuristic rows. Each accepts four heuristic rows, but the two accept-sets overlap on
only two records, so the six-record union is larger than either model's own error and
the agreement is concentrated in the rejections. High pairwise agreement here means
the models agree about what is *not* a vulnerability; it is not evidence that the
screen is precise.

The cache is keyed by model, so each model's screen appends rather than overwrites,
and `tables/bounty_graded_model_screen_by_row.csv` carries the per-row comparison.

## 4. Corrected confirmed-severe population

| Claim | Paper as written | Corrected |
|---|---:|---:|
| Confirmed Critical/High records | **18** | **8** |
| Rows usable for exact-tier inference | 60 | 13 |
| Confirmed severe records with any CWE | 3/18 (16.7%) | 2/8 (25.0%) |
| Confirmed severe in MITRE 2025 CWE Top 25 | 0/18 | 0/8 |
| Confirmed severe with non-`other` root cause | 17/18 (94.4%) | 8/8 (100%) |
| Confirmed severe with non-`other` protocol label | 17/18 (94.4%) | 8/8 (100%) |

The eight are Besu's CALL gas allocation error (Critical) and, at High: Besu's
SHL/SHR/SAR native exception, Geth's p2p DoS, RETURNDATA corruption, block-processing
consensus flaw, `MulMod` DoS and 0x4-precompile shallow copy, and Lighthouse's
Electra effective-balance processing.

**Observation.** Eight of the 18 claimed severe records came from the ten-keyword
heuristic, and a ninth is an upstream toolchain CVE.

**Interpretation.** The direction of the CWE argument in
[`cwe_context_comparison.md`](cwe_context_comparison.md) survives and even sharpens —
all eight confirmed severe records carry both Ethereum coordinates, and none is in
the 2025 Top 25 — but it now rests on n=8, so it must be reported as an illustration
that a Top-25-only design would miss every confirmed severe record here, never as a
coverage rate.

## 5. The documented calibration was never a population measurement

`docs/severity_labeling.md` reports "exact-tier 60%, within ±1 tier 80%" and names
the rows it was measured on: RETURNDATA corruption, the consensus flaw, the `MulMod`
DoS, the 0x4 precompile, effective balances, and the p2p DoS. Those are six of the 13
published-advisory rows. The figure is agreement on a hand-picked severe subset, not
calibration over the graded population.

Running the same validation over the whole population scores 6/60 exact for
`claude-sonnet-5` and 2/59 for `glm-5.2`, with 44 and 46 rows predicted not-eligible.
That looks like a badly miscalibrated estimator. Splitting the same runs by what
produced the severity shows it is not:

| Model | Provenance | Scored | Exact | Exact % | Within ±1 | Within ±1 % |
|---|---|---:|---:|---:|---:|---:|
| claude-sonnet-5 | Published advisory | 14 | 5 | 35.7% | 13 | **92.9%** |
| claude-sonnet-5 | `cross_client` heuristic | 45 | 1 | 2.2% | 3 | 6.7% |
| glm-5.2 | Published advisory | 13 | 2 | 15.4% | 12 | **92.3%** |
| glm-5.2 | `cross_client` heuristic | 45 | 0 | 0.0% | 1 | 2.2% |

Against real published grades both models land within one tier on roughly 92% of
records — at or above the 80% the earlier methodology reported. Against the
collector-fabricated tiers they land within one tier on 2–7%. The pooled figure was
an artifact of scoring an estimator against tiers no grader ever assigned.

`glm-5.2`'s confusion matrix makes the mechanism explicit: its largest cell is
`medium → not-eligible` with 37 records, which is exactly the count of cross-client
rows that `_infer_severity` rated Medium by default, and its second is
`high → not-eligible` with 8, exactly the count it rated High by keyword.

Exact-tier agreement is lower than the previously documented 60%, and that is
expected rather than a regression: the revised prompt declines to assert an exact tier
when the threshold depends on deployment share, returning `share_dependent` instead
(see [`client_conditional_severity.md`](client_conditional_severity.md)). Within-±1
agreement is the comparable metric, and it holds.

**Do not claim.** No exact-tier agreement figure may be quoted without stating the
population it was measured on. A calibration number over `bounty-graded` as stored in
the frozen snapshot measures the collector's keyword rule, not the estimator.

## 6. Code correction

`severity_source` now distinguishes evidence from collector output:

- `bounty-graded` requires a `/security/advisories/GHSA-…` URL — 13 rows;
- `collector-inferred` retains the tier but refuses the ground-truth label — 46 rows;
- the upstream toolchain CVE moves to `upstream-cvss` via a new title pattern for
  advisories phrased as an impact.

This changes only future builds. The frozen snapshot keeps its original column so
every checked-in table still reproduces; the audit tables carry the corrected view.

## 7. Paper contribution

> A dataset's ground-truth label must be traced to what produced it. In this corpus
> `severity_source = bounty-graded` was assigned by exclusion rather than evidence,
> so 45 of 60 "graded" records inherited a severity from a ten-keyword heuristic over
> pull requests selected merely for mentioning two clients — promoting CI plumbing,
> interop harnesses, and a specification document into the exact-tier ground truth.
> Restricting the population to maintainer-issued advisories reduces the confirmed
> Critical/High sample from 18 to 8. Two independent models each reject 41 of the 45
> heuristic rows and accept all 13 advisory rows, agreeing with each other on 93.2%
> of the population, and both reach ~92% within-±1 agreement against real published
> grades while reaching 2–7% against the fabricated ones — so a pooled calibration
> figure over this population measures the collector, not the estimator.

This is a reusable methodological result rather than a local bug report: a severity
provenance column is only as strong as the weakest collector feeding it, and
"not classified as a dependency" is not evidence of a published grade.

## 8. Limits

- The provenance rule is a URL pattern. A genuine bounty grade published somewhere
  other than a GitHub advisory (an EF disclosure post, a private bounty award) is
  classified `collector-inferred` here and would be missed. The 13-row population is
  a lower bound on real graded records, not a census.
- The heuristic rows the models accepted as in-scope have not been individually
  source-reviewed. Some may be genuine vulnerabilities that merely lack an advisory.
  The union across both models is six records: both accept `feat: eip-8025 optional
  execution proofs` and Erigon's `Added SSZ REST for Engine API`; claude additionally
  accepts the Kintsugi spec PR and a merge-interop test assertion, while glm accepts
  the prevRandao rename and `PayloadId as string`. All six are assessed at
  `narrow_config` reach or lower, so none is a candidate for a severe tier even if it
  turns out to be a genuine defect.
- The model screen is one prompt and two models. It is reported as corroboration of
  the provenance split, never as the deciding evidence, and its agreement is
  concentrated in rejections rather than in acceptances.
- This audit does not revisit all 1,552 `llm-estimated` rows. Their provenance was
  never claimed to be authoritative, so the corrections above do not propagate to
  them by construction.

## 9. The defect does not reach the tier-uncertain queue

The obvious worry is that the same collector poisoned the 110-row candidate queue that
[`ef_severity_analysis.md`](ef_severity_analysis.md) and
[`client_conditional_severity.md`](client_conditional_severity.md) analyse. It did not.

None of the 110 rows comes from `cross_client`. They come from `stealth_pr` (34),
`networking` (30), Geth's repository and advisory collectors (26), Lighthouse's (18),
and one each from Prysm and Erigon. More decisively, **no collector assigned any of
them a tier**: all 110 carry `severity` of `Unrated` (90) or `Info` (20).
`mine_stealth_prs.py`, which contributes the largest share, writes
`"severity": "Unrated"` explicitly.

So every tier on those rows came from the estimator, was already labelled
`llm-estimated`, and was already corrected to `tier-uncertain`. The corruption was
confined to `crawl_cross_client.py::_infer_severity`.

**Observation.** The failure was not "the corpus fabricates severities." It was one
collector fabricating them, combined with a provenance label assigned by exclusion
that could not tell the difference. The second half is what made a local crawler
heuristic into the paper's ground truth.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/audit_bounty_graded_population.py
git diff --exit-code docs/paper/tables
```

## Generated evidence

- [`tables/bounty_graded_provenance.csv`](tables/bounty_graded_provenance.csv)
- [`tables/bounty_graded_provenance_counts.csv`](tables/bounty_graded_provenance_counts.csv)
- [`tables/bounty_graded_model_screen.csv`](tables/bounty_graded_model_screen.csv)
- [`tables/bounty_graded_model_screen_by_row.csv`](tables/bounty_graded_model_screen_by_row.csv)
- [`tables/bounty_graded_model_agreement.csv`](tables/bounty_graded_model_agreement.csv)
- [`tables/bounty_graded_calibration_by_provenance.csv`](tables/bounty_graded_calibration_by_provenance.csv)
- [`tables/bounty_graded_audit_summary.csv`](tables/bounty_graded_audit_summary.csv)
