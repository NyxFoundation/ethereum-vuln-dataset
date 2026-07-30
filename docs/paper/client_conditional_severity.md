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

The current snapshot has no `client_conditional_reach` value, because the estimator
that produced it never asked. Each candidate is therefore bounded with
`reach=unknown`, i.e. the most favourable assumption available to the record.

| Measure | Records |
|---|---:|
| Tier-uncertain candidates | 110 |
| `client_specific` | 55 |
| `spec_level` | 55 |
| `client_specific` needing >50% reach even at the top of the share band | **55** |
| `client_specific` for which High is infeasible at the bottom of the share band | **21** |
| Candidates with an assessed `client_conditional_reach` | **0** |

Every one of the 55 client-specific candidates requires that the defect affect
more than half of that client's entire operator population before High becomes
arithmetically available. The 21 infeasible-at-band-bottom rows are the Lighthouse
client-specific candidates, which need 110% reach at a 30% share.

For `spec_level` rows the lower bound is still only the fixing client's share,
because no row enumerates which *other* implementations actually contained the
shared-rule defect. That asymmetry — upper bound the whole network, lower bound one
client — is the formal statement of the objection already recorded in
[`chain_split_candidate_audit.md`](chain_split_candidate_audit.md).

## 6. What this changes for the audits already done

The completed source reviews can be reread as reach assessments, and they line up
with the bands rather than with High:

- the reorg-log OOM explicitly mentions a 32-bit-host condition → `narrow_config`;
- the Ethash cache/dataset lifetime crash is a local cache and finalizer lifecycle
  → `operator_self_only` to `narrow_config`;
- the Verkle predeployment panic and the PeerDAS rows touch unreleased features →
  `narrow_config`;
- the HTTP-request resource pressure needs many parallel requests against an
  endpoint an operator chose to expose → `default_role_subset`;
- the Engine API `logsBloom` panic sits behind an authenticated local endpoint →
  `narrow_config` at most.

None of these reaches the 60% reach that a Geth client-specific High would need,
which is consistent with the audits finding zero confirmed High and gives that
negative result a quantitative form instead of a verdict per record.

## 7. Paper contribution

> EF bounty tiers are network-share statements, and a repository artifact does not
> contain network share. Decomposing the tier into deployment share × client-
> conditional reach moves the assessable factor into the fix and leaves the
> unsourced factor explicit. Under this decomposition a client-local defect cannot
> reach High for 8 of 11 clients even at complete client-conditional reach, and all
> 55 client-specific High candidates in the corpus require that a defect affect
> more than half of their client's operator population before the tier is
> arithmetically available. The corpus therefore reports the deployment share a
> tier would require, not a tier that silently assumes one.

This converts `tier-uncertain` from an admission into a measurement: each record
carries a falsifiable share requirement that a sourced deployment series can test.

## 8. Limits

- The share bands are unsourced prose tiers inherited from the earlier prompt, with
  no observation date and no citation. They are used only for the *frontier* and
  are reported alongside every derived number. A sourced, dated client-share series
  is the next data dependency, and until it exists no row may present a
  `share_dependent` tier as final.
- Reach bands are ordinal ranges chosen for auditability, not measured
  distributions. Two reviewers should assign them independently and report
  agreement before any reach figure enters a headline claim.
- `client_conditional_reach` is not yet populated: it requires an estimator re-run
  with the revised prompt. The 110-row bounds above assume `unknown`, which is
  deliberately the most generous assumption for each record.
- The Critical tier is only partly share-shaped. The value-integrity forms
  ("create or finalize infinite ETH", "steal or burn ETH from all EOAs") are exempt
  from the cap, so a Critical value-integrity estimate is not constrained by this
  arithmetic and still needs its own review.

## Reproduce

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/client_conditional_severity.py
git diff --exit-code docs/paper/tables
```

## Generated evidence

- [`tables/client_conditional_reach_bands.csv`](tables/client_conditional_reach_bands.csv)
- [`tables/client_conditional_frontier.csv`](tables/client_conditional_frontier.csv)
- [`tables/client_conditional_candidate_bounds.csv`](tables/client_conditional_candidate_bounds.csv)
- [`tables/client_conditional_summary.csv`](tables/client_conditional_summary.csv)
