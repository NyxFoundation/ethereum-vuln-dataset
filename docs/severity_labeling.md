# Severity labeling with an LLM — methodology

Rated severity is present on **143 / 2,225 rows (6.4%)**. Provenance marks 60
rows `bounty-graded`; the other 83 rated rows are marked `upstream-cvss`. This
document is the design for estimating severity on the rest **against the Ethereum
Foundation bug-bounty model**, with the calibration results that justify it. The
tool is `collection/estimate_severity.py`.

## The premise (and why naive labeling fails)

Bounty severity is **network-scale impact reachable by a single packet / on-chain
tx** (Critical = infinite-ETH / take-down-network / slash >50%; High = split or
down >33%; …). Asking an LLM "is this Critical?" directly **over-rates**, because
the tier depends on *how much of the network* the exploit reaches — which is not
in the diff. So we do not ask for the tier; we **decompose, then map**.

### Pitfall 1 — two different severity models are mixed in the data
Of the 143 rated rows, **83 are currently marked `upstream-cvss`** and 60
`bounty-graded`. The first label must not be read as “83 verified dependency
CVEs”: the current classifier also treats changelog/release URLs as dependency
evidence, and `upstream-cvss` appears on 612 rows overall. Dependency scope
therefore requires a separate audit. A confirmed dependency bump such as log4j
does not split the Ethereum network, so confirmed dependency rows should retain
upstream CVSS and remain `not-eligible` under the bounty model.

### Pitfall 2 — spec-level vs client-specific is the hard axis
The tier hinges on blast radius: a bug in **shared spec logic** (EVM
opcodes/precompiles/gas, consensus state-transition, fork-choice, SSZ) forces a
divergence *every client shares* → whole-network impact → High/Critical; a bug in
**client-local** code (this client's DB, RPC server, CLI, sync internals) caps at
that client's share. The LLM must be told this explicitly, or it under-rates
EVM/consensus bugs as "client_specific" (see calibration).

### Pitfall 3 — a network percentage is not in the artifact
The tier is a share of the *network*, but a diff, issue, or advisory contains no
deployment data. An earlier revision papered over this by putting a hard-coded
prose share into the prompt (`This client is: DOMINANT execution client
(~45-55%)`), which made the tier a restatement of that prior — see
[`paper/client_conditional_severity.md`](./paper/client_conditional_severity.md).
The tier is therefore split into its two factors:

> affected_network_share = affected_client_share × client_conditional_reach

Only the second factor is asked of the LLM, and the prompt no longer states the
client's share at all.

## The method — decompose, then map

Per row the LLM (given the bounty definition, the fix's diff, and our
`root_cause` / `attack_path` / `label`) emits five **assessable** fields:

| field | values |
|---|---|
| `impact_type` | chain_split · liveness_dos · value_integrity · validator_slashing · local_only · none |
| `reachability` | remote_single_message_or_tx · remote_needs_conditions · local_internal |
| `blast_radius` | spec_level · client_specific · subset |
| `client_conditional_reach` | all_nodes · default_role_subset · narrow_config · operator_self_only |
| `severity_est` | Critical · High · Medium · Low · not-eligible, **for the case where this client were the entire network** |

`client_conditional_reach` is the share of the operators *already running this
client* that one attacker-supplied input can affect. Unlike a network percentage it
is visible in the fix: default configuration, node role, platform assumption,
feature gating, and which path consumes untrusted input all decide it.

A deterministic **guardrail** then bounds the product and corrects the tier:
- `local_internal` reachability, or `impact_type ∈ {local_only, none}` → **not-eligible** (out of bounty scope);
- the affected network share is bounded as an interval from `blast_radius`,
  `client_conditional_reach`, and a numeric share band, and the tier is capped by
  the interval's upper end. `spec_level` opens the upper end to the whole network;
  the lower end stays at the fixing client's share, because no output enumerates
  which *other* implementations actually had the shared-rule defect;
- a tier the lower end does not reach is marked `severity_certainty =
  share_dependent` and carries `severity_required_client_share`, the deployment
  share at which it would hold;
- `value_integrity` is exempt from the share cap: "create/finalize infinite ETH"
  and "steal or burn ETH from all EOAs" are not share criteria.

The components are the reliable, reusable output; the tier is a **calibrated
estimate**, never presented as a bounty grade.

The share bands live only in the deterministic step, are never shown to the LLM,
and are unsourced prose tiers with no observation date. Their consequences are
generated share-independently by
`scripts/client_conditional_severity.py`: a client-local defect cannot reach High
for **8 of 11 clients** even at 100% client-conditional reach, so only Geth,
Lighthouse, and Prysm can host a client-specific High at all.

The checked-in downstream analysis is
[`paper/ef_severity_analysis.md`](./paper/ef_severity_analysis.md). It excludes
`upstream-cvss`, separates eligibility from tier, and treats client-level
severity differences as estimator diagnostics because the prompt includes
historical client-share classes.

## Calibration (validated against the bounty grades)

Run `estimate_severity.py --validate`. Key results and what they mean:

- **On real severe client vulnerabilities** (RETURNDATA corruption, Consensus
  flaw, `MulMod` DoS, 0x4-precompile, effective-balance, p2p DoS):
  **exact-tier 60%, within ±1 tier 80%** after the spec-level guardrail. The
  genuine High bugs are recovered as High.
- **The LLM doubles as a severity-noise detector.** Several rows the *dataset*
  labels High are actually features/tests/specs mis-tagged by the crawl
  ("Implement Kintsugi specs", "Run sim single node test"); the LLM correctly
  returns `impact_type = none → not-eligible`. Much of the raw "disagreement" is
  the dataset's label noise, not the model's error — a useful by-product.
- **Manually confirmed dependency CVEs** (log4j/Netty/…) are returned
  `not-eligible` under
  the bounty model even though the row carries a CVSS High — confirming Pitfall 1.

Residual weakness: value-integrity Criticals (e.g. besu gas-allocation) are still
sometimes under-rated to Medium/High because the "infinite/incorrect ETH" impact
is subtle from the diff. Treat Critical estimates as a floor, not a ceiling.

## Operational notes
- **Concurrency degrades the model.** gemma4:31b on the long severity prompt
  returns truncated JSON under parallel load (empty `severity_est` → spurious
  `not-eligible`). Run at **≤2 workers** (or add a retry) — the sequential result
  is materially better than the 6-wide batch.
- Engine is pluggable (`--engine openai|claude|ollama`); gemma4:31b via Ollama
  Cloud is the default. A Claude pass would likely raise exact-tier further.

## Output contract (honest columns)
`--apply` writes `data/severity_est.csv` keyed by `id`, joined like the other
enrichments. It **never overwrites** the real `severity`:

| column | meaning |
|---|---|
| `severity_estimated` | the tier — the real grade where one exists, else the LLM estimate |
| `severity_source` | `bounty-graded` \| `upstream-cvss` \| `llm-estimated` \| `unassessed`; only `bounty-graded` is the EF-bounty ground-truth slice |
| `impact_type` · `reachability` · `blast_radius` · `client_conditional_reach` | the decomposition (the reliable part) |
| `severity_certainty` | `bounded` \| `share_dependent` \| `share_exempt` \| `out_of_scope` \| `below_lowest_threshold` \| `no_estimate` |
| `severity_required_client_share` | for a `share_dependent` tier, the deployment share at which it holds |
| `severity_why` | one-sentence rationale |

The frozen snapshot predates these three columns; populating them needs an
estimator re-run with the revised prompt. Until then the paper analysis bounds each
candidate with `client_conditional_reach=unknown`, the most favourable assumption
for the record.

## Audited High analysis label

The paper analysis does not treat the 110 LLM-generated High values as exact
tiers. `scripts/severity_analysis.py` preserves `severity_estimated` and adds a
non-destructive review layer:

- all 55 `client_specific` High estimates become `tier-uncertain` because the
  unversioned static share prior does not prove >33% impact at the fix date;
- all 55 `spec_level` High estimates become `tier-uncertain` because a shared
  rule does not prove that all implementations shared the defect or that >33%
  of the network was affected.

This correction does not infer Medium or Low without evidence. The original and
audited labels, status, and reason are checked into
[`paper/tables/ef_severity_high_review_queue.csv`](paper/tables/ef_severity_high_review_queue.csv).
See [`paper/ef_severity_analysis.md`](paper/ef_severity_analysis.md) for the
corrected counts and permitted analyses.

## Recommended rollout
1. Estimate EF-severity **only for client-code rows**; leave dependency-CVE rows
   as upstream CVSS + `not-eligible`.
2. Ship `severity_estimated` + `severity_source` + the components — never
   silently overwrite `severity`; let users take the `bounty-graded` slice as
   ground truth and the `llm-estimated` slice as a triage prior.
3. Re-validate whenever the prompt or model changes; report exact / ±1 tier on
   the client-code graded rows.
4. Do not promote an LLM tier to a paper-quality exact High without
   independently establishing the EF impact threshold at the fix date.

*See [`security_report.md`](./security_report.md) §2 for the bounty severity
definitions and [`limitations.md`](./limitations.md) for caveats.*
