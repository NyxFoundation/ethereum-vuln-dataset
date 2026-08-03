# RQ5: can the population rate of security-relevant fixes be estimated?

## Question

Every headline in this workspace is computed on a corpus assembled by keyword search. That
makes its central claim circular: asking a keyword-found corpus what share of security
fixes are *silent* measures the collector, because the sample was selected by the presence
of the very language whose absence defines the term. This asks whether a probability sample
of commits can break the circularity and state a population rate instead.

The answer is no, not with an LLM screen of this quality, and the reason is measurable.

## 1. The data was never the obstacle

Of the 752 commits behind the 279 MineBlockVuln references the corpus records as "not
collected", **751 resolve in the local Geth clone**. The full history of all eleven clients
is on disk: **595,966 distinct non-merge commits** after collapsing shared history, no API
access required. The curated corpus covers 1,737 of them — **0.291%**.

Coverage is also uneven in a way that matters: per-client it ranges from 0.092% (Prysm) to
0.943% (Nimbus), a tenfold spread
([`tables/commit_frame_coverage.csv`](tables/commit_frame_coverage.csv)). A cross-client
comparison drawn from the curated corpus is confounded with collection intensity before any
analysis begins.

## 2. Exhaustive filtering is not affordable, and a sample is better anyway

Measured against MineBlockVuln's 839 labelled vulnerability commits inside Geth's 65,678
([`tables/silent_fix_message_mining_ceiling.csv`](tables/silent_fix_message_mining_ceiling.csv)):

| Selector | Recall | Selects | Lift |
|---|---:|---:|---:|
| message: fix / failure / defensive union | 45.4% | 24.3% | 1.9× |
| message: failure nouns only | 25.9% | 2.5% | 10.2× |
| structure: references `#NNNN` | 22.4% | 21.8% | **1.0×** |
| structure: `closes/fixes #NNNN` | 6.4% | 1.1% | 5.7× |
| diff: ≥1 added guard clause | 56.1% (vs 39.0% control) | 39.0% | 1.4× |

Message mining cannot work by construction — a silent fix is one whose message does not
announce it — and the diff-shape medians of known vulnerability commits are nearly identical
to ordinary commits (2 files vs 1, 15 added lines vs 10); the large mean ratios are
outlier-driven. An optimistic union reaches 76% recall but selects 54% of history: 389,076
commits, roughly 400 hours of model time.

A probability sample of 3,000 costs about three hours and estimates a 2% rate to ±0.5
percentage points. It is also the better instrument: a convenience sample cannot state a
population rate at all.

## 3. The sample was drawn and classified

3,000 commits, stratified by client with proportional allocation, fixed seed, drawn from the
frame ([`tables/commit_sample_design.csv`](tables/commit_sample_design.csv)). Each was
classified from its local diff on two axes: whether it fixes a security-relevant defect, and
if so whether its own message discloses that.

Raw result: **507 of 2,999 classified commits (16.9%)** were called security-relevant, of
which 463 (91%) were called `silent`, 44 `implied_fix`, and **zero** `explicit_security`.

Taken at face value that is a headline. It is not reported as one.

## 4. Validation against external labels kills it

The classifier was run over a 300-commit validation set with labels it never saw: 150 Geth
commits MineBlockVuln attaches to a vulnerability issue, and 150 drawn at random
([`tables/commit_classifier_validation.csv`](tables/commit_classifier_validation.csv)).

| Measure | Rate | 95% CI |
|---|---:|---|
| Recall on known vulnerability fixes | **32.7%** | 25.7–40.5% |
| Positive rate on random commits | **18.7%** | 13.2–25.7% |
| Lift | **1.75×** | — |

The classifier misses two thirds of known vulnerability fixes while calling one random
commit in five security-relevant, and the two intervals nearly touch. A screen whose
positive rate on random material is within a factor of two of its recall on true positives
is not measuring what it claims to measure.

**Do not claim.** The 16.9% figure is not the population rate of security-relevant fixes.
It is dominated by the classifier's positive bias. Neither it nor the 91% silent share
derived from it may be reported.

A single-reviewer read of 18 randomly drawn positives
([`tables/commit_sample_precision_audit.csv`](tables/commit_sample_precision_audit.csv))
had put precision at 12/18 — defensible for a light-client negation bug and an atomic
`TryRemove` race fix, over-called for a log rename and a test re-enablement. The external
validation shows that read was itself too generous, which is the more useful lesson: a
reviewer checking a classifier's positives sees only the cases it selected, and cannot see
the two thirds it missed.

## 5. What this leaves standing

The negative result is specific and reusable:

> The population rate of security-relevant client fixes is not estimable with a
> general-purpose LLM commit screen. Against external labels the screen recalls 32.7% of
> known vulnerability fixes while calling 18.7% of random commits positive — a lift of
> 1.75× — so a raw sample rate of 16.9% cannot be separated from its own false positives.
> The obstacle is not data access: the full 595,966-commit history is local, and the
> curated corpus covers 0.291% of it.

Three things follow for anyone attempting this:

1. **Validate a screen against external labels before estimating from it.** The raw rate
   looked publishable and was an artifact. A held-out labelled set costs 300 classifications.
2. **Reviewer audits of positives are not sufficient.** They are blind to recall, and here
   they over-estimated precision.
3. **The frame and the sample are reusable.** Both are checked in, so a better screen — a
   fine-tuned model, a two-stage design, or human annotation of the drawn 3,000 — can be
   evaluated against the same validation set and compared directly.

## 6. What a usable design would need

- **Higher recall, verified.** The floor is a screen whose recall exceeds its random-commit
  positive rate by a wide margin. Neither prompt engineering alone nor a bigger sample fixes
  a 1.75× lift.
- **Human annotation of a subsample.** 300 human-labelled commits from the drawn sample
  would give a second ground-truth axis independent of MineBlockVuln's issue-linkage bias,
  which itself only labels *disclosed* vulnerabilities.
- **A two-stage estimator.** Classify cheaply, then human-review a stratified subsample of
  both positives and negatives, and correct the estimate for measured sensitivity and
  specificity. That design tolerates an imperfect screen; a single-stage one does not.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/build_commit_frame.py
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/sample_commit_frame.py
# classification requires OLLAMA_API_KEY and about three hours
UV_CACHE_DIR=/tmp/uv-cache uv run python collection/classify_commit_sample.py --workers 3
```

## Generated evidence

- [`tables/commit_frame_coverage.csv`](tables/commit_frame_coverage.csv)
- [`tables/silent_fix_message_mining_ceiling.csv`](tables/silent_fix_message_mining_ceiling.csv)
- [`tables/commit_sample_design.csv`](tables/commit_sample_design.csv)
- [`tables/commit_sample_precision_audit.csv`](tables/commit_sample_precision_audit.csv)
- [`tables/commit_classifier_validation.csv`](tables/commit_classifier_validation.csv)
