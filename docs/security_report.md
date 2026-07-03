# Auditing Ethereum clients — where to look and what to look for

*A data-driven field guide for security researchers auditing Ethereum clients —
and, more broadly, any blockchain / distributed-consensus system. Distilled from
**2,225 historical security fixes** across all eleven production clients (six
languages, both layers). Numbers and examples are drawn from
`data/ethereum_vulns.parquet`; figures regenerate via `scripts/make_figures.py`.*

> **What this gives you.** An evidence-based answer to the two questions an
> auditor starts with — *which source-code regions to prioritize* and *which bug
> patterns to look for* — plus the entry points that matter, a severity model to
> rank findings, a cross-implementation variant-hunting method, and lessons that
> transfer to other consensus systems.

## 1. What matters — the impact model that sets priorities

Prioritize by **blast radius × remote reachability**, per the
[Ethereum Foundation bug bounty](https://ethereum.org/en/bug-bounty/): a finding
is severe if a **single network packet or on-chain transaction** can **split the
chain**, **take the network down**, **create/steal ETH**, or **slash validators**.
Everything below is ranked against that model — not CVSS, and not code-bug class
in isolation. (Note: clients patch ~94% of issues *silently*, so **the historical
fix record — not the CVE list — is the real map**; this guide is that map.)

## 2. Where to look — the audit priority map

![Figure 1 — audit priority map](figures/fig9_priority_map.png)

Plotting every subsystem by **audit volume** (how many bugs it has produced) and
**severity density** (share rated High/Critical) yields three actionable groups:

**① Deep-audit first — low volume, high severity density.** Few fixes, but a bug
here is disproportionately *critical* because it sits on consensus-critical or
cryptographic paths:

| Subsystem | fixes | %High/Crit | why it's severe |
|---|---:|---:|---|
| `crypto` | 40 | **15%** | signature/curve/hash errors → forgery, DoS, or divergence |
| `evm` / `opcodes` / `precompiles` | ~80 | **12%** | any semantic disagreement = **chain split** |

**② Highest priority — high volume *and* high severity.** The consensus and
network core; audit breadth *and* depth here:

| Subsystem | fixes | %High/Crit | dominant cause → entry |
|---|---:|---:|---|
| `p2p` | 82 | **17%** | resource_exhaustion ← malicious p2p message |
| `fork-choice` | 93 | **13%** | missing validation ← crafted state |
| `sync` | 140 | **11%** | resource_exhaustion ← malformed input |
| `beacon-chain:block-processing` | 84 | **10%** | **consensus_divergence** ← malformed input |
| `beacon-chain:attestation` | 106 | **9%** | missing validation ← malicious attestation |

**③ Highest volume, mostly availability.** Most churn and most bugs, but they
skew toward liveness/DoS rather than consensus — audit for resource limits and
input validation:

| Subsystem | fixes | %High/Crit | dominant cause |
|---|---:|---:|---|
| `state-trie` | 210 | 7% | improper_state_update |
| `p2p-interface` | 181 | 7% | missing_input_validation |
| `rpc` | 147 | 5% | resource_exhaustion |

**One-line takeaway:** *audit `crypto`, the `EVM`, and the consensus state-
transition for **critical** (chain-split/value) bugs; audit `p2p`, `sync`, and
`RPC` for **availability** (DoS) bugs.*

## 3. The attack surface — where untrusted input enters

![Figure 2 — attack surface](figures/fig8_attack_surface.png)

Severity requires a remotely-reachable trigger, so your taint sources are the
places a node ingests adversary-controlled data. In order of exposure: **p2p /
gossip** (messages, attestations, blocks, peers), the **untrusted-parsing** layer
(RLP / SSZ / JSON decoders that run *before* validation), **on-chain transactions
/ the EVM**, and **crafted chain state** (snap-sync, historical data). Start taint
analysis here; the `internal_only` slice is not bounty-reachable.

## 4. What raises severity — rank findings by class

![Figure 3 — what raises severity](figures/fig7_severity_drivers.png)

Three root causes are over-represented among High/Critical fixes and should raise
your priority on a finding: **integer overflow/underflow (×1.71)** — gas/balance/
slot arithmetic that can mint invalid value or diverge; **consensus divergence
(×1.60)** — the chain-split class; and **resource exhaustion / DoS (×1.26)**.
Conversely, `race_condition` (×0.29) and `unhandled_error/nil` (×0.67) are common
but usually *locally* triggered and low-blast-radius — real bugs, lower priority
under this model. (Fig 3b: most such severe bugs were **never publicly graded** —
another reason to trust the fix record over the CVE list.)

## 5. The recurring vulnerability patterns — what to look for

![Figure 4 — root cause & trigger](figures/fig2_rootcause_attack.png)

Six archetypes cover most of the corpus. Each is a hunting hypothesis: a
mechanism, a trigger, and a **code smell** to grep for.

- **P1 · Unbounded work from an attacker-controlled count → DoS.** A size/count
  field from the wire drives unbounded allocation or iteration. *340 fixes.*
  Examples: *"LES Server DoS via GetProofsV2"*, *"DoS via malicious snap/1
  request"*. **Smell:** a length/count from a request used before it is bounded.
- **P2 · Missing length/bounds validation in a decoder → OOB / panic.** RLP, SSZ,
  JSON decoders that index or slice pre-validation. *522 fixes — the largest
  class.* Example: besu *"SHL/SHR/SAR trigger native exception at key values"*.
  **Smell:** slice/index on decoded input with no length check.
- **P3 · Integer overflow/underflow in protocol arithmetic.** Gas, balance, slot,
  length math. *185 fixes.* Examples: geth *"DoS via `MulMod`"*, besu *"Gas
  allocation error in CALL"* (Critical). **Smell:** unchecked `+/-/*` on
  attacker-influenced 32/64-bit quantities in consensus-critical code.
- **P4 · Nil / unwrap / unhandled error on malformed input → crash.** *208 fixes.*
  **Smell:** `unwrap()` / nil-deref / `panic` reachable from a decode path.
- **P5 · Consensus divergence — implementations disagree on an edge case.** The
  crown-jewel class: EVM opcode/precompile semantics, gas accounting, state copy.
  *174 fixes.* Examples: *RETURNDATA corruption*, *0x4-precompile shallow copy*.
  **Smell:** any behaviour on a corner case not bit-for-bit pinned by the spec.
- **P6 · Fork-choice / reorg edge cases.** *93 fixes across 6 clients.* **Smell:**
  `on_block`, proposer-boost, reorg handling under crafted timing/state.

## 6. Cross-implementation variant hunting — a repeatable method

Eleven clients implement **one** specification in **six** languages, so the same
logical bug recurs across them and the `label` area is the language-agnostic join
key. Subsystems fixed in *many* clients are the best variant-hunting grounds:
`p2p-interface` (6 clients), `sync` (6), `fork-choice` (6), `crypto` (8),
`kzg-commitments` (6), `sync-committee` (6).

**The method (N-day / variant analysis):** take a fix in client *A*, find the
analogous code in *B…K* by `label`, and check whether the same guard exists.
Because fixes are usually silent, a fix that landed in one client is frequently
**not yet** mirrored in the others — a repeatable path to fresh findings unique to
a multi-implementation ecosystem. Its sharpest form is **spec-divergence testing**
(P5): where clients implement the same pyspec/EELS function (EVM opcodes,
precompiles, SSZ, epoch processing), fuzz edge cases for behavioural disagreement
— the direct route to chain-split severity.

## 7. Case studies (real fixes)

- **Consensus split via `RETURNDATA` corruption** (geth, `core/vm/instructions.go`,
  High). A crafted tx exercised `RETURNDATACOPY` so `RETURNDATA` could be
  corrupted; a client computing a different result accepts a different state root
  → **chain split**. Archetype P5.
- **Node takedown via a malicious p2p message** (geth, `crypto/secp256k1/curve.go`,
  High). A crafted handshake drove excessive work → remote takedown — the bounty's
  "bring down the network with one packet." Archetype P1/P3 at the crypto/network
  boundary.
- **Value integrity via a gas-allocation error** (besu, EVM `CALL`, **Critical**).
  A signed/unsigned 32-bit error in available-gas computation passed wrong gas into
  sub-calls — an execution-semantics divergence with value impact. Archetype P3;
  gas arithmetic is consensus-critical.

## 8. Transferable lessons for auditing any blockchain / consensus system

1. **Determinism is a security property.** Any two nodes must produce the *same*
   result bit-for-bit; every non-determinism (arithmetic edge case, serialization
   ambiguity, iteration order, floating point, uninitialized memory) is a
   potential **chain split**. Audit the deterministic core (VM, state transition,
   encoding) for disagreement, not just for crashes.
2. **Untrusted peer input is the main attack surface.** Parse-before-validate,
   trusting a wire-supplied count, and unbounded per-peer work are the DoS
   engine. Treat every decoder and every `count`/`length` from the network as
   hostile.
3. **Arithmetic in the value/consensus path is consensus-critical.** Gas, balances,
   stake/slashing weights, and slot math must never overflow, underflow, or round
   differently across implementations.
4. **Implementation monoculture is a systemic risk — and a research asset.** A
   bug shared by clients with >33% combined share is a network-level event; a bug
   in one client is a lead to check the others. Diversity both mitigates and
   *reveals* bugs (variant hunting).
5. **Prioritize by reachability × blast radius, not by CVE existence.** The
   highest-impact bugs here were patched silently; a CVE-only view misses them.

## 9. Audit playbook (checklist)

1. **Scope by the priority map (§2):** deep-audit `crypto` / `EVM` / consensus
   state-transition first for critical bugs; sweep `p2p` / `sync` / `RPC` for DoS.
2. **Taint from the entry points (§3):** p2p/gossip, RPC, tx, attestation decoders
   → follow untrusted fields to allocations (P1), slices/indexing (P2), arithmetic
   (P3), nil/unwrap (P4).
3. **Grep the pattern smells (§5)** across the target subsystem.
4. **Run spec-divergence & variant analysis (§6):** diff the same spec function
   across clients; a missing guard in one is a candidate.
5. **Rank findings by the severity model (§4/§1):** weight chain-split / value /
   network-takedown / slashing potential, reachable by a single packet/tx.

## 10. Limitations & responsible disclosure

Labels are model/heuristic-derived (~0.90 precision), not human-verified; severity
on unrated rows is *estimated* (calibrated ~60% exact / ~80% ±1 tier —
[`severity_labeling.md`](./severity_labeling.md)); the corpus is historical, so a
"variant lead" must be verified against current code before it is a finding. Full
caveats: [`limitations.md`](./limitations.md). Coordinate any new finding through
the relevant client's security process and the
[Ethereum bug bounty](https://ethereum.org/en/bug-bounty/).

*Companion: [`analysis.md`](./analysis.md) (dataset-level statistics) ·
[`limitations.md`](./limitations.md).*
