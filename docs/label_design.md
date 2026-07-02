# Label design proposal — pre-fix code · root cause · post-fix code · code range

**Goal (from the ask).** For every vulnerability fix we want three things to be
first-class and machine-usable:

1. **pre-fix code** — the vulnerable code as it stood *before* the fix,
2. **root cause** — *why* it was a vulnerability, and
3. **post-fix code** — the code *after* the fix,

plus **labels that demarcate the affected code range** (which file / lines /
function / spec clause), so a consumer can point at "the region this fix
touched" — and, crucially, tie it to the **canonical spec** so fixes for the
same logical bug across different clients (Go / Rust / Java / Nim / TS) can be
grouped.

This document (a) reads the two spec repos to ground the design, (b) does a gap
analysis vs. what the dataset stores today, and (c) proposes a concrete label
schema + how to populate it.

---

## 1. What the "complete version" covers today (gap analysis)

| Need | Field(s) today | Coverage | Gap |
|---|---|---|---|
| post-fix code | `source_url`, `fix_commit` → diff (added lines) | `fix_commit` **401 / 2,333** (`/commit/` only) | 1,340 `/pull/` rows need merge-commit resolution |
| pre-fix code | `introduced_in_commit` → parent state; diff (removed lines) | **0 / 2,333** | `blame_walk` never ran; must fill |
| root cause | `description`, classifier `vuln_class` + reason, `stride`/`cwe_top25` | ~898 classified; stride/cwe empty | no structured root-cause / trigger taxonomy |
| code range | — | **none** | no file/line/function labels at all |
| spec anchor | `contest` (repo slug) | none | no link to consensus/execution-specs |

**Bottom line:** pre/post code is *recoverable* (from `fix_commit` +
`introduced_in_commit` + diff) but the keys are thin, and **code-range / spec
labels do not exist yet**. This proposal fills exactly those.

---

## 2. The spec repos (canonical anchor targets)

Read from the two upstream repos so labels can point at a *stable* location, not
just a client's private file that moves over time.

### [`ethereum/consensus-specs`](https://github.com/ethereum/consensus-specs)
```
specs/<fork>/<doc>.md            fork ∈ phase0 · altair · bellatrix · capella
                                       · deneb · electra · fulu · gloas · heze
                                 doc ∈ beacon-chain · fork-choice · p2p-interface
                                       · validator · weak-subjectivity · deposit-contract
```
Each markdown embeds the **pyspec**: Python functions that *are* the executable
spec (`process_attestation`, `state_transition`, `get_active_validator_indices`,
`on_block`, …). → a consensus fix maps to **(fork, doc, function)**.

### [`ethereum/execution-specs`](https://github.com/ethereum/execution-specs) (EELS)
```
src/ethereum/forks/<fork>/<module>   fork ∈ frontier … london · paris · shanghai
                                           · cancun · prague · osaka · amsterdam
                                     module ∈ fork.py · blocks.py · transactions.py
                                           · trie · state · bloom.py
                                           · vm/{interpreter,gas,instructions/,
                                                 precompiled_contracts/}
src/ethereum/{crypto, merkle_patricia_trie.py, exceptions.py, …}   (shared)
```
→ an execution fix maps to **(fork, module, function)** and/or an **EIP number**
([`ethereum/EIPs`](https://github.com/ethereum/EIPs)).

The spec anchor is the key idea: `process_attestation` or
`vm/instructions/system.py::generic_call` is the *same* logical location whether
the bug was fixed in Lighthouse (Rust) or Prysm (Go).

---

## 3. Proposed label schema

Three axes — **WHERE** (code range), **WHY** (root cause), **WHAT** (code) —
added as columns to the curated row.

### The `label` column — the controlled vocabulary ⭐

`label` answers **"which area of the protocol is this bug in?"** — one value per
row (primary area). Grounded in the spec repos' own section names so it is
stable and language-agnostic. Interpreted together with `layer`
(execution / consensus, known from the client).

**Fork is deliberately NOT a separate column.** But some areas only exist from a
certain fork on (blobs, PeerDAS, ePBS). We handle that *by giving the feature
its own label* — so the label itself already tells you the fork range, without a
`fork` column. The "since" column below is informational.

#### Consensus labels — from `specs/<fork>/<doc>.md`
| `label` | area (spec doc) | since fork |
|---|---|---|
| `beacon-chain` | state transition: block/epoch processing, attestations, slashings, deposits, withdrawals | phase0 |
| `fork-choice` | LMD-GHOST / fork choice, `on_block`, proposer-boost | phase0 |
| `p2p-interface` | gossipsub topics, req/resp, encoding | phase0 |
| `validator` | proposer / attester / sync-committee duties | phase0 |
| `weak-subjectivity` | WS checkpoints / periods | phase0 |
| `deposit-contract` | deposit contract logic | phase0 |
| `bls` | BLS signature verification / aggregation | altair |
| `light-client` | light-client sync protocol | altair |
| `kzg-commitments` | blob KZG (polynomial-commitments), EIP-4844 sidecars | **deneb** |
| `data-availability-sampling` | PeerDAS: `das-core`, sampling, `partial-columns`, EIP-7594 | **fulu** |
| `builder` | ePBS / builder flow | **gloas** |
| `fork-transition` | `fork.py` upgrade / state-upgrade logic | altair |

#### Execution labels — from `src/ethereum/forks/<fork>/…` + client subsystems
| `label` | area | since fork (if gated) |
|---|---|---|
| `evm` | interpreter core / execution loop | — |
| `opcodes` | instruction semantics (`vm/instructions/`) | — |
| `precompiles` | precompiled contracts (`vm/precompiled_contracts/`) | — |
| `gas` | gas accounting, EIP-1559 fee market | — |
| `transactions` | tx types, validation, signatures (`transactions.py`) | — |
| `txpool` | mempool / tx pool (client-side) | — |
| `block-processing` | header/block validation, `state_transition` (`blocks.py`, `fork.py`) | — |
| `state-trie` | state, storage, Merkle-Patricia trie | — |
| `rlp` | RLP encode/decode | — |
| `p2p` | devp2p, `eth` wire, `snap` protocol | — |
| `sync` | snap-sync / downloader | — |
| `engine-api` | EL↔CL payload / engine API | paris |
| `blobs` | EIP-4844 blob txs / blob pool | **cancun** |
| `eof` | EVM Object Format | **osaka** |
| `rpc` | JSON-RPC surface | — |

#### Cross-cutting (either layer)
| `label` | area |
|---|---|
| `crypto` | hashing, secp256k1, BLS/KZG math, signature libs |
| `serialization` | SSZ / RLP (de)serialization bugs not tied to one area |
| `database` | storage / DB layer |
| `other` | none of the above (keep rare; forces review) |

**Assignment** (same deterministic-first rule): map the changed file paths +
title/description keywords → `label` (e.g. `vm/precompiled_contracts/` →
`precompiles`; `fork_choice`/`on_block` → `fork-choice`; `das`/`data_column`/
`peerdas` → `data-availability-sampling`), with the `llm_classify_fixes.py` model
as the fallback / tie-breaker. Multi-area fixes: keep `label` = primary area,
optionally add a `labels` list later.

### WHERE — code range & spec anchor
| field | type | example | source |
|---|---|---|---|
| `layer` | enum | `execution` \| `consensus` | client → layer map |
| `fork` | str | `cancun`, `deneb` | fix date / diff paths / release |
| `subsystem` | enum | `evm·precompile·opcode·gas·trie·txpool·p2p·fork_choice·state_transition·attestation·bls·kzg·crypto·rlp·ssz·sync` | existing sensitive-path detector |
| `client_code_range` | list⟨{file,start,end,symbol}⟩ | `[{file:"core/vm/contracts.go",start:214,end:239,symbol:"bigModExp.Run"}]` | **diff hunks** (`@@ -a,b +c,d @@ symbol`) |
| `spec_anchor` | str | `forks/cancun/vm/precompiled_contracts/modexp.py::modexp` · `specs/deneb/beacon-chain.md::process_attestation` · `EIP-198` | mapping (heuristic + LLM) |
| `eip` | list⟨int⟩ | `[198]` | title/desc/spec match |

### WHY — root cause
| field | type | values |
|---|---|---|
| `vuln_class` | enum | `dos·memory·overflow·consensus·auth·validation·other` (classifier already emits) |
| `root_cause` | enum | `missing_bounds_check · integer_overflow_underflow · unhandled_error_or_nil · missing_input_validation · incorrect_gas_accounting · consensus_divergence · resource_exhaustion · improper_state_update · crypto_misuse · reentrancy · race_condition · serialization_bug` |
| `trigger` | enum | `malicious_block · malicious_tx · malicious_p2p_message · malformed_input · crafted_state · peer · large_input · internal_only` |
| `stride`, `cwe_top25` | existing optional LLM labels |

### WHAT — code (before / after)
| field | type | notes |
|---|---|---|
| `fix_commit` | sha | the fixing commit (fill the 1,340 `/pull/` rows via merge-commit) |
| `introduced_in_commit` | sha | last commit that touched the removed lines (git blame) = pre-fix state |
| `pre_fix_code` / `post_fix_code` | text | the removed / added hunks (bounded), or omit and recover on demand from the two SHAs + `client_code_range` |

`(introduced_in_commit, fix_commit, client_code_range)` fully specifies
before-vs-after without storing megabytes of code inline.

---

## 4. How to populate each (deterministic first, LLM only where needed)

| label | method | cost |
|---|---|---|
| `client_code_range` | parse diff hunks from `local_diffs` (file headers + `@@` ranges; the hunk header already carries the enclosing symbol) | **deterministic, free** |
| `fix_commit` (/pull/) | resolve the merge/squash commit (`gh`/git) for 1,340 rows | cheap, one-time |
| `introduced_in_commit` | `git log -L`/`git blame` the removed lines in the local clone → the commit that last set them | deterministic, local (needs clones — already have them) |
| `subsystem`, `fork`, `eip` | regex/date heuristics (subsystem already computed; fork from date table; eip from `EIP-\d+` + spec match) | deterministic, cheap |
| `spec_anchor` | 2-step: (i) deterministic name-match of the changed symbol against the spec module/function index; (ii) LLM fallback ("which consensus/execution-spec function does this diff correspond to?") | mixed; LLM for the tail |
| `root_cause`, `trigger` | extend the existing `llm_classify_fixes.py` prompt to also emit these two enums (we already run gemma over each diff) | ~free (same call) |

Note the biggest single win is **already in hand**: the LLM classifier reads each
diff — adding `root_cause` + `trigger` to its JSON output is one prompt change,
and `client_code_range` falls straight out of the diff we already fetch.

---

## 5. Worked example (illustrative)

geth precompile fix → labels:
```yaml
source_url: https://github.com/ethereum/go-ethereum/pull/NNNN
fix_commit:            9f2e6a…            # resolved from the PR merge
introduced_in_commit:  1c3d8b…            # git blame of the removed lines
layer: execution
fork: byzantium                            # EIP-198 modexp precompile
subsystem: precompile
client_code_range:
  - {file: core/vm/contracts.go, start: 214, end: 239, symbol: bigModExp.Run}
spec_anchor: forks/byzantium/vm/precompiled_contracts/modexp.py::modexp
eip: [198]
vuln_class: dos
root_cause: missing_bounds_check
trigger: malicious_tx
pre_fix_code:  "<removed hunk>"
post_fix_code: "<added hunk>"
```
A tool can now: check out `introduced_in_commit`, run against
`client_code_range`, and ask "would I have flagged the missing bounds check in
`modexp`?" — with the spec anchor grouping the equivalent fix in every client.

---

## 6. Suggested phasing

1. **Deterministic core (no LLM):** `client_code_range` from diffs + `fix_commit`
   for `/pull/` + `introduced_in_commit` via blame + `subsystem`/`fork`/`eip`.
   This alone delivers "code range + pre/post pointers" for the whole set.
2. **Root cause (one prompt change):** add `root_cause` + `trigger` to the
   classifier output; re-run over the classified rows.
3. **Spec anchor:** deterministic symbol→spec index first; LLM for the tail.
   This is the highest-value, highest-effort piece — do it last, on the
   essential slice (A ∪ B) only.

---

*Open questions for you:* (a) store `pre_fix_code`/`post_fix_code` inline
(bigger repo, self-contained) or keep them as (commit, range) pointers
recovered on demand? (b) is the `root_cause` / `trigger` enum above the right
granularity, or do you want a finer taxonomy? (c) should the spec anchor be
mandatory (drop rows we can't map) or best-effort?
