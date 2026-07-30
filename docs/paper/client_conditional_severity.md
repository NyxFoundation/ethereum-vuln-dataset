# RQ2c: replacing the network-share guess with client-conditional reach

## Question

The EF bug-bounty tiers are defined as a fraction of the *network*. That fraction
is not in a diff, an issue, or an advisory, which is why every audit so far ended
at `tier-uncertain`. Can the estimate be restated so that the part we can assess
from the fix is separated from the part we cannot?

## 1. The two factors

A tier claim under the bounty model is a product:

> affected_network_share = affected_client_share × client_conditional_reach

- **`affected_client_share`** is historical deployment data. It has an observation
  date, it moves, and it is absent from every record in this corpus.
- **`client_conditional_reach`** is the fraction of the operators *already running
  the affected client* that one attacker-supplied input can affect. It is decided
  by default configuration, node role, platform assumption, feature gating, and
  which code path consumes untrusted input — all of which the fix shows.

The earlier estimator collapsed both into one question and supplied the first
factor as a hard-coded prose prior inside the prompt (`This client is: DOMINANT
execution client (~45-55%)`). That is why the resulting High labels reproduced the
prior rather than measuring anything, and why all 55 `client_specific` candidates
landed on the two clients whose prior was largest.

The estimator now asks only for the assessable factor, and is no longer told the
client's share at all. A deterministic post-step bounds the product.

## 2. Reach vocabulary

| Band | Fraction of that client's operators | Meaning |
|---|---:|---|
| `all_nodes` | 0.90–1.00 | Any node on the default configuration processes the attacker-supplied input on the affected path. |
| `default_role_subset` | 0.25–0.75 | One common role or default-adjacent mode only: validating vs non-validating, archive vs pruned, snap vs full sync, a default-on endpoint that is not always exposed. |
| `narrow_config` | 0.01–0.25 | Needs a non-default flag, an unusual platform such as a 32-bit host, an opt-in or unreleased feature, or a specific deployment shape. |
| `operator_self_only` | 0.00–0.01 | Only the operator's own node, through local action; no attacker input crosses to other operators. |
| `unknown` | 0.00–1.00 | Not assessed. Widens the bound instead of silently assuming full reach. |

Definitions are checked in as
[`tables/client_conditional_reach_bands.csv`](tables/client_conditional_reach_bands.csv).

## 3. The threshold is inverted, not guessed

Rather than assert a share, each record reports the share it would *need*:

> required_client_share(tier) = ef_threshold(tier) / client_conditional_reach

This yields three share-independent states:

- **`excluded`** — even the most favourable share and reach fall below the
  threshold, so the tier is arithmetically impossible and needs no source review;
- **`share_dependent`** — the tier holds only if deployment share at the fix date
  was at least the printed value, which must be sourced separately;
- **`supported`** — the threshold is met even at the least favourable end of both
  bands.

## 4. Result: High is arithmetically impossible for most clients

The frontier below is pure arithmetic over the EF thresholds and the share bands.
It requires no LLM output and no record, and it answers "what would this client's
users have to look like for a client-local defect to be High?"

| Client | Share band | Min reach for High at band top | at band bottom | Client-specific High |
|---|---|---:|---:|---|
| geth | 0.45–0.55 | 60.0% | 73.3% | feasible |
| lighthouse | 0.30–0.40 | 82.5% | 110% | feasible only near band top |
| prysm | 0.30–0.40 | 82.5% | 110% | feasible only near band top |
| nethermind | 0.20–0.30 | 110% | 165% | **excluded** |
| erigon | 0.10–0.20 | 165% | 330% | **excluded** |
| teku | 0.10–0.15 | 220% | 330% | **excluded** |
| besu, reth, nimbus | 0.00–0.10 | 330% | — | **excluded** |
| lodestar, grandine | 0.00–0.05 | 660% | — | **excluded** |

**Observation.** For 8 of 11 clients, a `client_specific` defect cannot reach High
under the EF definition even if it affects *every single operator of that client*.
Only Geth, Lighthouse, and Prysm can host a client-specific High at all, and for
Lighthouse and Prysm it requires at least 82.5% client-conditional reach and the
top of their share band.

**Interpretation.** This explains the client concentration reported in
[`ef_severity_analysis.md`](ef_severity_analysis.md) §5 as arithmetic rather than
as risk: the 107/110 Geth-plus-Lighthouse concentration is close to what the
threshold permits, given that the two remaining feasible clients in the queue are
exactly those.

It also shows the old guardrail was far too permissive. It capped only
`client_specific` **and** `liveness_dos` **and** `MINOR`-share rows. The arithmetic
applies to every impact type and excludes MODERATE and MAJOR clients too:
Nethermind at the top of its band still needs 110% reach.

## 5. Applying the bound to the existing 110-row queue

The frozen snapshot has no `client_conditional_reach` value, because the estimator
that produced it never asked. Re-running the revised prompt with `glm-5.2` supplied
one for 109 of the 110 candidates; the remaining row keeps `reach=unknown`, which is
the most favourable assumption available to it.

| Measure | Reach unassessed | Reach measured |
|---|---:|---:|
| Tier-uncertain candidates | 110 | 110 |
| `client_specific` / `spec_level` | 55 / 55 | 55 / 55 |
| `client_specific` needing >50% reach at the top of the share band | 55 | 55 |
| Candidates with an assessed reach | 0 | **109** |
| High **excluded arithmetically** | 0 | **30** |
| High still **share-dependent** | 110 | **47** |
| High **supported at any plausible share** | 0 | **33** |

Measuring reach resolves 30 candidates without any source review: their assessed reach
is `narrow_config` (23) or `operator_self_only` (7), so the product cannot reach 33%
of the network at any share in the band. That is the payoff of the decomposition — a
third of the queue is ruled out of High by arithmetic rather than by argument.

The 33 supported records are all Geth with `all_nodes` reach (18 `client_specific`,
15 `spec_level`): at Geth's band, full client coverage clears 33% even at the bottom
of the band. Section 6 shows why that bucket must not be read as 33 confirmed High
records.

For `spec_level` rows the lower bound is still only the fixing client's share,
because no row enumerates which *other* implementations actually contained the
shared-rule defect. That asymmetry — upper bound the whole network, lower bound one
client — is the formal statement of the objection already recorded in
[`chain_split_candidate_audit.md`](chain_split_candidate_audit.md).

## 6. Scoring the measurement against source review

Moving the uncertainty onto reach is only progress if reach can actually be measured,
so the model's assessment is scored against the completed source reviews in
[`liveness_candidate_audit.md`](liveness_candidate_audit.md). Eight audited rows state
a configuration, platform, endpoint, or lifecycle restriction, which is what reach
describes. Rows whose audit faulted the *trigger* or *impact* evidence are excluded
from this comparison: that says nothing about how many operators the code path covers,
and reach must not be lowered for it.

| Row | Model | Source review | Direction | Model's High verdict |
|---|---|---|---|---|
| PeerDAS `getBlobs` race | `narrow_config` | `narrow_config` | agree | excluded |
| Verkle trie prefetcher | `narrow_config` | `narrow_config` | agree | excluded |
| Tree states per-slot diffs | `narrow_config` | `narrow_config` | agree | excluded |
| PeerDAS early sampling | `narrow_config` | `narrow_config` | agree | excluded |
| Parallel HTTP request cache | `narrow_config` | `default_role_subset` | more restrictive | excluded |
| Reorg-log OOM (32-bit host) | `all_nodes` | `narrow_config` | **more permissive** | **supported** |
| Ethash cache/dataset lifetime | `all_nodes` | `operator_self_only` | **more permissive** | **supported** |
| Engine API `logsBloom` panic | `all_nodes` | `narrow_config` | **more permissive** | **supported** |

The asymmetry is the result. Every reviewable `excluded` verdict is confirmed by the
audit or is more conservative than it. Every reviewable `supported` verdict is
over-permissive: the reorg OOM is conditioned on a 32-bit host, the Ethash crash is
local cache and finalizer lifecycle with no attacker input crossing operators, and the
Engine API sits behind an authenticated CL-to-EL endpoint rather than the public
network.

**Observation.** A single model's reach assessment is trustworthy when it says
"narrow" and unreliable when it says `all_nodes`, and the unreliable direction is the
one that produces the consequential verdict.

## 6b. A second annotator bounds how much of this survives

The same 110 candidates were assessed again with `claude-sonnet-5`. Reach is where the
annotators differ, and they differ in one direction:

| | Value |
|---|---:|
| Rows both models assessed | 109 |
| Exact reach-band agreement | 76 (69.7%) |
| Within one reach band | 91 (83.5%) |
| `glm-5.2` the more permissive of the two | **27** |
| `claude-sonnet-5` the more permissive | 6 |

Recomputing the arithmetic per annotator shows how far that propagates
([`tables/client_conditional_verdict_crosstab.csv`](tables/client_conditional_verdict_crosstab.csv);
rows `claude-sonnet-5`, columns `glm-5.2`):

| | glm excluded | glm share-dependent | glm supported |
|---|---:|---:|---:|
| **claude excluded** | **28** | 11 | **7** |
| **claude share-dependent** | 4 | 32 | 5 |
| **claude supported** | 0 | 1 | **21** |

Verdict agreement is 81/109 (74.3%). The headline counts move with the annotator: High
is excluded for 30 candidates under `glm-5.2` and 46 under `claude-sonnet-5`, and
supported for 33 versus 23.

Two things follow. First, **28 candidates are excluded from High under both
annotators** — that intersection, not either model's own count, is the defensible
arithmetic result. Second, seven records sit at opposite extremes, excluded by one
annotator and supported by the other, and `glm-5.2` is on the permissive side of every
one. A permissive reach bias is therefore not a calibration offset to be corrected
after the fact; on those seven records it decides the verdict outright.

**Do not claim.** The `supported` bucket is not a set of records meeting the EF >33%
threshold. All three of its source-reviewable members were over-permissive, and its
size varies by 10 records between annotators, so it is a review queue ordered by
arithmetic. The defensible output is the 28-record both-annotator exclusion.

## 7. Paper contribution

> EF bounty tiers are network-share statements, and a repository artifact does not
> contain network share. Decomposing the tier into deployment share × client-
> conditional reach moves the assessable factor into the fix and leaves the
> unsourced factor explicit. Under this decomposition a client-local defect cannot
> reach High for 8 of 11 clients even at complete client-conditional reach, and all
> 55 client-specific High candidates in the corpus require that a defect affect
> more than half of their client's operator population before the tier is
> arithmetically available. Measuring reach then rules 28 of 110 candidates out of
> High under two independent annotators. Scoring the measurement shows the
> decomposition also localises its own error: exclusions are confirmed on every
> source-reviewable record, while every record rated at full client coverage was
> over-permissive, and the two annotators reach opposite extremes on seven records with
> the same one always permissive. The corpus therefore reports the deployment share a
> tier would require, and reports which half of that judgement it can defend.

This converts `tier-uncertain` from an admission into a measurement: each record
carries a falsifiable share requirement that a sourced deployment series can test,
and the reach factor is itself auditable against the fix rather than being an
irreducible prior.

## 8. Limits

- The share bands are unsourced prose tiers inherited from the earlier prompt, with
  no observation date and no citation. They are used only for the *frontier* and
  are reported alongside every derived number. A sourced, dated client-share series
  is the next data dependency, and until it exists no row may present a
  `share_dependent` tier as final.
- Reach bands are ordinal ranges chosen for auditability, not measured
  distributions.
- Reach is populated by a model, not a human. `glm-5.2` supplies the values used in the
  bounds; `claude-sonnet-5` provides a second assessment for scoring only. Exact
  reach-band agreement between them is 69.7%, which is moderate for a four-band ordinal
  scale, so **human assignment on a stratified sample with reported agreement is still
  required** before a reach figure enters a headline claim. Prefer the 28-record
  both-annotator exclusion over either model's own count.
- Choosing `glm-5.2` for the bounds is not a claim that it is the better annotator. It
  is the more permissive one, so the checked-in tables understate exclusion; the
  crosstab in §6b is what bounds the alternative.
- One of the 110 candidates has no assessed reach and remains bounded at `unknown`.
- The audit-derived reach values in `REVIEWED_REACH` are read from the audit prose by
  a single reviewer. They are versioned in the script so a second reviewer can dispute
  a specific entry, but they are not an independent annotation study.
- The Critical tier is only partly share-shaped. The value-integrity forms
  ("create or finalize infinite ETH", "steal or burn ETH from all EOAs") are exempt
  from the cap, so a Critical value-integrity estimate is not constrained by this
  arithmetic and still needs its own review.

## Reproduce

```bash
# arithmetic only, no reach
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/client_conditional_severity.py

# with the measured reach overlay (does not touch the frozen snapshot)
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/client_conditional_severity.py \
  --severity-csv data/severity_est_v2.csv
git diff --exit-code docs/paper/tables
```

`data/severity_est_v2.csv` is produced by re-running the estimator over the queue:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python collection/estimate_severity.py --apply \
  --engine openai --model glm-5.2 --base-url https://ollama.com/v1 \
  --api-key-env OLLAMA_API_KEY --workers 2 \
  --only-ids queue_ids.txt --out data/severity_est_v2.csv --allow-partial
```

## Generated evidence

- [`tables/client_conditional_reach_bands.csv`](tables/client_conditional_reach_bands.csv)
- [`tables/client_conditional_frontier.csv`](tables/client_conditional_frontier.csv)
- [`tables/client_conditional_candidate_bounds.csv`](tables/client_conditional_candidate_bounds.csv)
- [`tables/client_conditional_reach_distribution.csv`](tables/client_conditional_reach_distribution.csv)
- [`tables/client_conditional_reach_vs_review.csv`](tables/client_conditional_reach_vs_review.csv)
- [`tables/client_conditional_reach_by_model.csv`](tables/client_conditional_reach_by_model.csv)
- [`tables/client_conditional_reach_model_agreement.csv`](tables/client_conditional_reach_model_agreement.csv)
- [`tables/client_conditional_verdict_by_model.csv`](tables/client_conditional_verdict_by_model.csv)
- [`tables/client_conditional_verdict_crosstab.csv`](tables/client_conditional_verdict_crosstab.csv)
- [`tables/client_conditional_summary.csv`](tables/client_conditional_summary.csv)
