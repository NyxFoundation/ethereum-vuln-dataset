# Severity labeling with an LLM — methodology

Severity is present on only **6.4%** of rows (the bounty-graded ones). This
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
Of the 143 rated rows, **~83 are upstream *dependency* CVEs** (log4j, Netty,
`golang.org/x/crypto`, `nim-libp2p`) carrying their **CVSS** severity, and only
**~60 are real client-code bugs** carrying (implicitly) the **EF-bounty** severity.
A log4j bump does not split the Ethereum network. **These must be separated:**
estimate EF-severity only for client-code bugs; dependency rows keep the upstream
CVSS and are `not-eligible` under the bounty model. (Conflating them was the
single biggest source of apparent disagreement.)

### Pitfall 2 — spec-level vs client-specific is the hard axis
The tier hinges on blast radius: a bug in **shared spec logic** (EVM
opcodes/precompiles/gas, consensus state-transition, fork-choice, SSZ) forces a
divergence *every client shares* → whole-network impact → High/Critical; a bug in
**client-local** code (this client's DB, RPC server, CLI, sync internals) caps at
that client's share. The LLM must be told this explicitly, or it under-rates
EVM/consensus bugs as "client_specific" (see calibration).

## The method — decompose, then map

Per row the LLM (given the bounty definition, the fix's diff, and our
`root_cause` / `attack_path` / `label`) emits four **assessable** fields:

| field | values |
|---|---|
| `impact_type` | chain_split · liveness_dos · value_integrity · validator_slashing · local_only · none |
| `reachability` | remote_single_message_or_tx · remote_needs_conditions · local_internal |
| `blast_radius` | spec_level · client_specific · subset |
| `severity_est` | Critical · High · Medium · Low · not-eligible |

A deterministic **guardrail** then corrects the tier:
- `local_internal` reachability, or `impact_type ∈ {local_only, none}` → **not-eligible** (out of bounty scope);
- `client_specific` **liveness_dos** on a MINOR client cannot reach >33% → capped to **Medium**;
- `spec_level` `chain_split` / `value_integrity` may reach **High/Critical** regardless of which client shipped the fix.

The components are the reliable, reusable output; the tier is a **calibrated
estimate**, never presented as a bounty grade.

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
- **Dependency CVEs** (log4j/Netty/…) are correctly returned `not-eligible` under
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
| `severity_source` | `bounty-graded` \| `llm-estimated` (so consumers can filter to ground truth) |
| `impact_type` · `reachability` · `blast_radius` | the decomposition (the reliable part) |
| `severity_why` | one-sentence rationale |

## Recommended rollout
1. Estimate EF-severity **only for client-code rows**; leave dependency-CVE rows
   as upstream CVSS + `not-eligible`.
2. Ship `severity_estimated` + `severity_source` + the components — never
   silently overwrite `severity`; let users take the `bounty-graded` slice as
   ground truth and the `llm-estimated` slice as a triage prior.
3. Re-validate whenever the prompt or model changes; report exact / ±1 tier on
   the client-code graded rows.

*See [`security_report.md`](./security_report.md) §2 for the bounty severity
definitions and [`limitations.md`](./limitations.md) for caveats.*
