# Label design — proposal & rationale

We add a small set of columns so each row says **which protocol area the bug is
in**, **why it was a bug**, **how it's triggered**, and carries the **actual
before/after code inline** — so `pd.read_csv(...)` alone gives a complete,
self-contained dataset (no diff-fetching needed to use it).

## Proposed columns

| column | meaning | values |
|---|---|---|
| `label` | protocol area of the bug | controlled vocabulary below (one primary value) |
| `root_cause` | why it was a vulnerability | enum below |
| `attack_path` | how it's triggered | enum below |
| `pre_fix_code` | vulnerable code, **inline** | JSON (multi-file) — see below |
| `post_fix_code` | fixed code, **inline** | JSON (multi-file) |
| `files_changed` | changed file paths | JSON list |
| `fix_commit` / `introduced_in_commit` | fix / pre-fix commit SHAs | existing keys |

---

## `label` — the protocol area

Grounded in the spec repos so the label is stable and language-agnostic:
consensus labels are the section names of
[`consensus-specs`](https://github.com/ethereum/consensus-specs)
(`specs/<fork>/<doc>.md`); execution labels are the modules of
[`execution-specs`](https://github.com/ethereum/execution-specs)
(`src/ethereum/forks/<fork>/…`) plus real client subsystems. Interpreted with
`layer` (execution / consensus, known from the client).

**Fork is not a column.** Areas that only exist from a given fork get their *own*
label, so the label already encodes the fork range. The "since" column is
informational.

### Consensus
`beacon-chain` is too broad (the whole state transition), so it is split by the
pyspec `process_*` operations:

| `label` | area | since |
|---|---|---|
| `beacon-chain:justification-and-finality` | `process_justification_and_finalization` (FFG source/target, finality) | phase0 |
| `beacon-chain:rewards-and-penalties` | `process_rewards_and_penalties`, inactivity leak | phase0 |
| `beacon-chain:registry-updates` | `process_registry_updates` (activation / exit queue, churn) | phase0 |
| `beacon-chain:effective-balance-updates` | `process_effective_balance_updates` (hysteresis) | phase0 |
| `beacon-chain:epoch-processing` | remaining per-epoch steps: resets, historical summaries, participation flags, RANDAO mix reset | phase0 |
| `beacon-chain:block-processing` | block header, RANDAO, eth1-data, block orchestration | phase0 |
| `beacon-chain:attestation` | `process_attestation`, attestation validation | phase0 |
| `beacon-chain:slashing` | proposer / attester slashing, `process_slashings` | phase0 |
| `beacon-chain:deposit` | `process_deposit`, deposit / pending-deposit requests | phase0 |
| `beacon-chain:withdrawal` | withdrawals, BLS-to-execution, withdrawal requests | capella |
| `beacon-chain:exit-consolidation` | voluntary exits, consolidations | phase0 / electra |
| `beacon-chain:sync-committee` | sync-committee processing | altair |
| `beacon-chain:execution-payload` | `process_execution_payload` (EL integration) | bellatrix |
| `fork-choice` | LMD-GHOST, `on_block`, proposer-boost | phase0 |
| `p2p-interface` | gossipsub topics, req/resp, encoding | phase0 |
| `validator` | proposer / attester / sync-committee duties | phase0 |
| `weak-subjectivity` | WS checkpoints / periods | phase0 |
| `deposit-contract` | deposit contract logic | phase0 |
| `bls` | BLS signature verify / aggregation | altair |
| `light-client` | light-client sync protocol | altair |
| `fork-transition` | `fork.py` upgrade / state-upgrade logic | altair |
| `kzg-commitments` | blob KZG (polynomial-commitments), EIP-4844 sidecars | **deneb** |
| `data-availability-sampling` | PeerDAS (`das-core`, sampling, partial-columns), EIP-7594 | **fulu** |
| `builder` | ePBS / builder flow | **gloas** |

### Execution
| `label` | area | since |
|---|---|---|
| `evm` | interpreter core / execution loop | — |
| `opcodes` | instruction semantics (`vm/instructions/`) | — |
| `precompiles` | precompiled contracts (`vm/precompiled_contracts/`) | — |
| `gas` | gas accounting, EIP-1559 fee market | — |
| `transactions` | tx types, validation, signatures | — |
| `txpool` | mempool / tx pool | — |
| `block-processing` | header/block validation, `state_transition` | — |
| `state-trie` | state, storage, Merkle-Patricia trie | — |
| `rlp` | RLP encode / decode | — |
| `p2p` | devp2p, `eth` wire, `snap` protocol | — |
| `sync` | snap-sync / downloader | — |
| `engine-api` | EL↔CL payload / engine API | paris |
| `blobs` | EIP-4844 blob txs / blob pool | **cancun** |
| `eof` | EVM Object Format | **osaka** |
| `rpc` | JSON-RPC surface | — |

### Cross-cutting (either layer)
`crypto` (hashing, secp256k1, BLS/KZG math) · `serialization` (SSZ / RLP not tied
to one area) · `database` (storage / DB layer) · `other` (keep rare; forces review).

---

## `root_cause` — why it was a bug
`missing_bounds_check` · `integer_overflow_underflow` · `unhandled_error_or_nil` ·
`missing_input_validation` · `incorrect_gas_accounting` · `consensus_divergence` ·
`resource_exhaustion` · `improper_state_update` · `crypto_misuse` ·
`race_condition` · `serialization_bug` · `reentrancy` · `other`

## `attack_path` — how it's triggered
`malicious_block` · `malicious_tx` · `malicious_attestation` ·
`malicious_p2p_message` · `malformed_input` · `crafted_state` · `peer` ·
`large_input` · `internal_only`

---

## Inline `pre_fix_code` / `post_fix_code` (multi-file)

Stored **inline as JSON** so a single CSV is the whole dataset. Each is a JSON
array with one object per changed file; each file carries its changed hunks in
the pre- (removed+context) or post- (added+context) form, with the starting line
number. Multi-file and multi-hunk fall out naturally.

```json
// post_fix_code
[
  {
    "file": "core/vm/contracts.go",
    "hunks": [
      { "start_line": 214, "code": "func (c *bigModExp) Run(input []byte) ...\n    if len(input) < 96 { return nil, errBadLength }\n    ..." }
    ]
  },
  {
    "file": "core/vm/contracts_test.go",
    "hunks": [ { "start_line": 88, "code": "..." } ]
  }
]
```
`pre_fix_code` has the same shape with the *old* line numbers and the removed+context code.

Derivation (deterministic, from the unified diff we already fetch via
`local_diffs`): for each `@@ -a,b +c,d @@` hunk, the **pre** version = context +
`-` lines (start line `a`); the **post** version = context + `+` lines (start
line `c`). A per-file cap (e.g. ≤ 400 lines / 16 KB) keeps the CSV bounded;
truncation is marked with a trailing `… [truncated]`. `files_changed` mirrors the
file list for cheap filtering.

Loading is trivial and self-contained:
```python
import pandas as pd, json
df = pd.read_csv("data/ethereum_vulns.csv")
post = json.loads(df.iloc[0]["post_fix_code"])   # [{file, hunks:[{start_line, code}]}]
```

---

## How labels get assigned
Deterministic-first, LLM only for the tail:
1. **Path rules** on the changed files (strongest): `vm/precompiled_contracts/` →
   `precompiles`; `fork_choice`/`on_block` → `fork-choice`;
   `das`/`data_column`/`peerdas` → `data-availability-sampling`;
   `process_attestation`/`attestation` → `beacon-chain:attestation`; etc.
2. **Keyword rules** on title/description for rows whose paths are ambiguous.
3. **LLM fallback** (`llm_classify_fixes.py`, already reads each diff) for
   `label` tie-breaks and for `root_cause` / `attack_path`, which it emits in the
   same call.

Multi-area fixes keep `label` = the primary area; a `labels` list can be added
later if needed.
