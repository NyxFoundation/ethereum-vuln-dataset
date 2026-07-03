# Critical / High severity vulnerabilities, by protocol area

Ethereum client vulnerabilities rated Critical or High severity, drawn from
across Geth, Besu, Erigon, Reth, Nethermind, Lighthouse, Teku, Nimbus, Lodestar,
and Grandine. Each entry states the root cause, the specific attacker input,
and the resulting impact.

Two evidentiary tiers are covered, in two parts:

- **Part 1 — officially rated.** An advisory, CVE, or GHSA record assigned
  the severity itself. 66 entries: 3 Critical, 63 High.
- **Part 2 — estimated severity.** The fix shipped with no CVE or advisory —
  most Ethereum client fixes ship this way. Severity here was inferred from
  the fix diff by an LLM classifier, reasoning primarily from client market
  share (a bug that can crash a client running >33% of the network is scored
  High even with no public disclosure). 110 entries meet that bar, concentrated
  in Geth and Lighthouse.

---

# Part 1 — Officially rated

## Critical

- **[Besu] CALL / DELEGATECALL gas accounting.** A 32-bit signed/unsigned type
  conversion error in the gas calculation for `CALL` and `DELEGATECALL` meant
  that whenever the amount of gas passed to an inner call affected its
  success or failure, an attacker who submitted a transaction shaped to hit
  that boundary could make Besu compute a `stateRoot` different from other
  clients, splitting the chain (`GHSA-4456-w38r-m53x`, CVE-2022-36025). On a
  single-implementation network, the same bug let a transaction run with far
  more gas than it should have been granted. Found by differential fuzzing
  (goevmlab); no exploitation on a production network was confirmed.

- **[Geth] Go runtime dependency.** Nodes built with Go `<1.15.5` or
  `<1.14.12` inherited a Go standard-library denial-of-service flaw
  (CVE-2020-28362, `GHSA-m6gx-rhvj-fh52`): certain inputs could crash the
  process. The fix required no Geth code change, only a rebuild against a
  patched Go toolchain — a supply-chain-style risk rather than a client bug.

- **[Teku] Bundled log4j (Log4Shell).** Teku shipped a log4j version
  vulnerable to JNDI-lookup remote code execution: an attacker who got a
  string like `${jndi:ldap://...}` logged could achieve RCE and, in the worst
  case, reach a validator's signing key (CVE-2021-44228, `GHSA-mwfw-vm54-g3p7`).
  Teku's actual use of the logging library was judged to limit real-world
  exploitability, but an emergency patch (21.12.1) shipped immediately.

---

## p2p — devp2p / `eth` wire protocol

- **[Geth] Unbounded header-request count.** `GetBlockHeadersRequest` did not
  reject a `count` of `0`. An attacker who sent one such message triggered an
  integer underflow on `count-1`, driving the node to allocate excessive
  memory and crash (CWE-190).

- **[Geth] Unbounded goroutine spawn on ping.** Every incoming `ping` request
  spawned a new goroutine to reply. An attacker who flooded a node with ping
  requests could grow the goroutine count without bound, exhausting memory
  and crashing the process (fixed in v1.12.1).

- **[Reth] Unbounded libp2p stream opens.** libp2p imposed no limit on new
  stream creation. An attacker node that kept opening connections and streams
  could accumulate enough small allocations to have the victim process killed
  by the OS for out-of-memory (CWE-770). The same class of gap was found
  independently in the libp2p stacks of Grandine and Lighthouse.

- **[Geth] Integer overflow in WebSocket frame length.** A length-overflow bug
  in the `gorilla/websocket` dependency let an attacker send a WebSocket frame
  with a crafted length field to trigger denial of service (CWE-190).

- Two further entries — "high CPU usage via a crafted p2p message" (CWE-400)
  and "crash via a crafted p2p message" (CWE-248) — were reported through the
  Ethereum Foundation bug bounty. Both advisories shipped a patch with the
  triggering input withheld ("more details to be released later").

---

## rpc — JSON-RPC / GraphQL surface

- **[Geth] Unbounded GraphQL query cost.** The GraphQL endpoint had no query
  complexity or cost limit. Geth's GraphQL schema exposes a recursive
  `parent` field on `Block`, so an attacker who nested that field many levels
  deep in one query (`block { parent { parent { parent { ... } } } }`) could
  force the server to walk arbitrarily far back through ancestor blocks in a
  single request, exhausting memory and hanging the daemon (CWE-400, requires
  `--http --graphql`). The vendor's stated position: the GraphQL endpoint was
  not designed to withstand hostile clients.

- **[Erigon] Out-of-bounds read in the JSON parser dependency.** A bounds
  check gap in the `jsonparser` dependency let an attacker send malformed
  JSON — an input with mismatched or truncated brackets/quotes — that made
  the parser's scanner walk past the end of the input buffer instead of
  detecting the malformed structure, triggering an out-of-bounds read
  (CVE-2026-32285, CVSS 7.5, CWE-125).

- **[Geth] Missing block-range validation.** `TraceChain` (now
  `debug_traceChain`) did not verify that the end block came after the start
  block. A caller who requested a range with the end block before the start
  block could trigger excessive load or abnormal behavior (CWE-20, geth <
  1.8.14).

- **[Reth] Sync-time panic / bad state.** A specific state transition during
  live sync could panic the node or leave it in a bad state; the release note
  does not name which state transition triggers it (v0.1.0-alpha.21).

---

## crypto — hashing, signatures, secp256k1 / BLS

- **[Geth] Missing field-element bounds check.** `IsOnCurve` and the
  underlying secp256k1 field-element setter did not verify that a point's `x`
  and `y` coordinates were below the field prime `P`. An attacker who sent a
  public key or signature with an out-of-range coordinate — over the p2p
  handshake or wherever the value is verified — broke an invariant the
  downstream field-element code relied on, triggering undefined behavior
  (panic or crash) and taking the whole node process down
  (`GHSA-2gjw-fg97-vg3r`). The fix added bounds checks in both the Go
  implementation (`curve.go`, `signature_nocgo.go`) and the C wrapper
  (`ext.h`), which had also ignored a failed return value. Fixed in v1.16.9 /
  v1.17.0.

- Five further entries are CVEs in `golang.org/x/crypto/ssh` (host-key
  verification bypass enabling MITM, a nil-pointer panic on the GSSAPI path,
  a panic on an empty-plaintext AES-GCM/ChaCha20Poly1305 packet, and related
  issues). Geth does not run an SSH server itself; these surfaced through
  dependency scanning (govulncheck) and their reachability from an actual
  Ethereum node's attack surface is unconfirmed.

---

## p2p-interface — gossipsub / req-resp (consensus layer)

- **[Reth / Grandine / Lighthouse] Unbounded libp2p stream opens.** Same
  class of bug as the p2p entry above: no cap on new stream creation let an
  attacker node exhaust memory through repeated small allocations and get the
  victim process OOM-killed (CWE-770), independently in three clients'
  libp2p stacks.

- **[Teku] Netty decompression-bomb DoS.** The bundled Netty dependency's
  `Bzip2Decoder` and `SnappyFrameDecoder` did not cap the size a compressed
  stream could expand to when decompressed (CVE-2021-37136,
  CVE-2021-37137). An attacker who sent a small, highly-compressed bzip2 or
  Snappy-framed payload could make Netty expand it into a much larger buffer,
  exhausting memory.

- **[Lighthouse] Outdated `blst` cryptography library.** Nodes still on
  `<v1.2.0` carried a known vulnerability in `blst`, the BLS-signature
  library shared by several consensus clients, tied to the April 2021
  "Finalized #25" incident — a bug in signature verification reachable
  through network-supplied signed consensus data (attestations/blocks). The
  advisory does not spell out the exact bypass mechanism.

---

## EVM / opcodes

- **[Geth] Memory-corruption bug in RETURNDATA handling.** A memory-handling
  bug in the interpreter's return-data path let an attacker who chained
  specific call and memory operations in one transaction cause Geth to
  compute a `stateRoot` different from spec-compliant clients
  (`GHSA-9856-9gg9-qcmq`). This was exploited on Ethereum mainnet at block
  13107518 on 2021-08-22, causing a minority chain split. Fixed in v1.10.8.

- **[Geth] Missing zero-modulus check in `MULMOD`.** The `uint256` library
  backing the `MULMOD` opcode did not handle a modulus of `0`. An attacker
  who called a contract executing `mulmod(a, b, 0)` triggered an
  out-of-bounds access (index `-1`) in the library's internal buffer,
  panicking the node and dropping it off the network (`GHSA-jm5c-rv3w-w83m`).

- **[Besu] Signed-type coercion in SHL / SHR / SAR.** A 32-bit signed-integer
  coercion error meant a shift amount in the roughly 2–4 billion range —
  meaningless but formally valid — made execution abort instead of failing
  validation cleanly. On a network mixing patched and unpatched clients, this
  produced a fork (CVE-2021-41272).

- **[Geth] Missing bytecode bounds check in `cmd/evm`.** The standalone
  EVM runner/debugging tool did not bounds-check input bytecode; crafted
  bytecode could trigger a SEGV and crash the process (CWE-119). This affects
  the standalone tool, not a production node's live execution path.

- **[Geth] Insufficient dynamic array-length validation (CVE-2018-20421).**
  An attacker who used `assembly { mstore }` to rewrite an array's length and
  then wrote to a large index could force a large memory allocation, causing
  denial of service.

---

## gas — gas accounting / fee market

- Same underlying bug as the Besu CALL/DELEGATECALL gas-accounting entry
  above (CVE-2022-36025).

---

## transactions

- **[Geth] Incorrect balance carry-over after self-destruct.** A change to
  `createObject`'s handling of a destructed account's balance meant an
  attacker who submitted a transaction sequence that self-destructed an
  account and then sent it further value within the same transaction could
  make Geth compute a different balance than spec-compliant clients,
  splitting the chain (`GHSA-xw37-57qp-9mm4`, reported 2020-08-11, fixed in
  v1.9.20). The minimal fix was a single added check for `prev.deleted`.

- **[Nethermind / Juno] Integer overflow in Sierra bytecode decompression.**
  An overflow in the `cairo-lang-starknet-classes` library's decompression
  logic let an attacker submit a crafted `Declare v2/v3` transaction to
  trigger an infinite loop and high CPU usage, denying service to affected
  Starknet full nodes (CVE-2025-29072).

---

## sync — snap-sync / LES

- **[Geth] Signedness error in LES header-request skip value.** The
  `GetBlockHeadersMsg` handler in the LES protocol converted the `Skip`
  field incorrectly. An attacker who sent a single packet with
  `query.Skip = -1` triggered an out-of-bounds array access, crashing the
  node immediately (geth < 1.8.11). Known as the "Ethereum Packet of Death."

---

## beacon-chain:sync-committee — Electra epoch processing

- **[Lighthouse] Incorrect effective-balance computation in `process_epoch`.**
  A bug in Electra epoch processing meant that as an Electra-enabled network
  simply advanced through normal epoch transitions, affected Lighthouse
  versions (`v7.0.0-beta.0`–`beta.4`) computed a different effective balance
  than the rest of the network, risking a fork away from the canonical chain
  (`GHSA-wm9c-xvqq-5c28`). Since Lighthouse runs roughly a third of
  validators, exploitation could have stalled finality. Found during the
  Ethereum Foundation / Cantina Pectra security competition and fixed before
  Electra reached mainnet.

---

## beacon-chain:slashing

- **[Lodestar] `uint64` slashing values represented as JS `number`.**
  Because slashing amounts were stored as native JavaScript numbers rather
  than a true 64-bit integer type, an attacker who included an
  `AttesterSlashing` or `ProposerSlashing` with a value above 2^53 in a block
  could cause rounding errors that made some clients reject it as invalid
  while others accepted it, splitting consensus (CWE-190, fixed in v0.36.0).

---

## precompiles

- **[Geth] Shallow copy in the `dataCopy` precompile (0x04).** The
  precompile at `0x00...04` performed a shallow copy on invocation. An
  attacker could deploy a contract that writes a value `X` to memory region
  `R`, calls `0x04` with `R` as its argument, overwrites `R` with `Y`, and
  then calls `RETURNDATACOPY` — causing Geth alone to push the wrong value
  `Y` onto the stack instead of `X`, splitting the chain
  (`GHSA-69v6-xc2j-r2jf`, fixed in v1.9.17).

---

## txpool

- **[Geth] No cap on future-transaction submissions.** The mempool did not
  bound the number of "future" (not-yet-executable) transactions accepted in
  one batch. An attacker who sent 5,120 future transactions with a high gas
  price in a single message could purge a victim node's entire pending
  transaction pool, denying service (geth ≤ 1.10.12).

---

## database

- **[Geth] 2016 Shanghai DoS attacks.** Opcodes such as `EXTCODESIZE` and
  `SLOAD` were underpriced relative to their I/O and storage-growth cost.
  Attackers exploited this with a sustained flood of cheap transactions to
  bloat state and degrade node performance across the network. v1.4.13
  shipped as a hotfix mitigation while longer-term fixes (cache journaling,
  cache-miss mitigation) followed.

---

# Part 2 — Estimated severity (not officially rated)

None of the entries below carry a CVE or advisory. They are ordinary fix
commits and PRs whose diff and description an LLM classifier judged, after
the fact, to have been High-severity while the bug was live — mainly because
the affected client's market share means a single-node crash there removes
a large enough slice of the network to matter. Confidence on the specific
trigger varies by entry; several PRs carry no more detail than their title.

## beacon-chain:attestation (Lighthouse)

- **Slasher OOM via an oversized validator index.** The slasher processed an
  attestation's `validator_index` before capping it against a sane maximum.
  An attacker who submitted a single attestation carrying an artificially
  large `validator_index` could make the slasher allocate memory
  proportional to that index and OOM the node (`PR#9141`, high confidence).

- **Gossip duplicate-cache overrun.** Gossipsub's duplicate-message cache
  held only 256 entries. An attacker who got more than 256 validators
  to cast attestations for different heads within one slot could exceed the
  cache, causing already-seen attestations to be re-propagated and loop
  through the network (`PR#832`).

- **Unbounded slot counter in epoch iteration.** An epoch-slot iterator did
  not bound its counter; a slot value close to `u64::MAX` sent it into an
  infinite loop (`PR#249`).

- **Reprocess-queue memory leak.** An attestation's entry in the reprocess
  queue was only evicted when its *last* attestation timed out. An attacker
  who broadcast attestations for random, never-imported block roots left
  entries in the queue indefinitely, growing memory without bound (`PR#8065`).

## bls — BLS signature verification (Lighthouse, Prysm)

- **[Prysm] Zero-coefficient bypass in batch signature verification.**
  `VerifyMultipleSignatures`'s fast batch-verification scheme assigns each
  signature a random coefficient `r_i` and its correctness depends on every
  `r_i` being nonzero, but the implementation never checked that. A
  coefficient of `0` drops that signature's contribution from the check
  entirely — an attacker who could influence which signature received a
  zero coefficient could get an invalid signature accepted alongside valid
  ones in the same batch (`ISSUE#9098`, CWE-327).

- **[Lighthouse] `is_infinity` flag computed before branching.** The
  aggregate-signature type computed its `is_infinity` flag ahead of the
  branch that determined which operands were actually being combined, so
  aggregating a point-at-infinity signature onto an already-empty aggregate
  produced the wrong flag value — a correctness bug reachable during normal
  signature aggregation, not attacker input, but one that risked clients
  disagreeing on whether an aggregate was valid (`PR#8496`).

## beacon-chain:block-processing (Lighthouse)

- **Memory exhaustion from skip-slot fast-forwarding.** Fast-forwarding a
  state through skipped slots stored every intermediate state — each several
  MB when SSZ-encoded — in RAM. A chain that skipped forward many slots at
  once, whether from an absent proposer or a block referencing a far-future
  slot, could force the node to hold more multi-megabyte states than it had
  memory for (`ISSUE#800`, CWE-770).

- **Balance-check underflow in `verify_transfer`.** The (now-removed) Eth1-phase
  `Transfer` operation checked the sender's balance against `amount` alone
  instead of `amount + fee`; a transfer whose `fee` pushed the true cost
  above the balance could underflow that check and be wrongly accepted
  (`PR#457`).

- **Underflow in Eth1 deposit-count bookkeeping** during block processing,
  triggerable by a crafted deposit count in an incoming block (`PR#977`).

## database

- **[Geth] Wrong length field in trie-history address lookup.** The
  path-based state-history reader validated an address's length against the
  wrong field, so a lookup whose address didn't match the expected
  account-key length could read out of bounds (`c9009154`, CWE-125).

## fork-choice (Lighthouse)

- **O(n²) rescans and stack overflow in `filter_block_tree`.**
  Fork-choice's block-tree filter recursed once per block in the candidate
  tree and rescanned all nodes at every step to find each node's children.
  On a long, unpruned chain the recursion could overflow the stack around
  ~30,000 blocks, and even short of that the per-step rescan made processing
  cost grow quadratically with chain length (`PR#9090`, high confidence).

- **LMDB cursor-reuse memory corruption in the slasher.** The slasher's
  LMDB-backed database returned a reference into a cursor's internal buffer
  without copying it; when the caller then deleted that cursor entry, LMDB
  was free to overwrite the same memory the caller still held — a bug
  present for a long time but only reachable after a later refactor made the
  code path executable (`PR#6211`).

## p2p (Geth)

- **`Skip`-value integer overflow in header requests.** `GetBlockHeaders`
  and the LES `GetBlockHeadersMsg` handler both computed `num + count - 1`
  from a peer-supplied `Skip` field without checking for overflow; a request
  with a large or negative `Skip` could over/underflow that computation and
  crash the handler (`e84e13f5`, `2ea9db06`, CWE-190) — the same bug class
  the later, officially-rated "Ethereum Packet of Death" advisory fixed for
  a different code path in the LES protocol (see Part 1, `sync`).

- **Discovery self-lookup race.** The node-discovery table could begin a
  self-lookup before its own constructor had finished returning the table
  reference to the caller; a discovery request racing with node startup
  could dereference a nil table (`78dc88ca`).

## p2p-interface (Lighthouse)

- **Fork-choice timing attack.** A general timing attack against the
  LMD-GHOST fork-choice rule (documented in `consensus-specs#2101`): an
  attacker who controlled *when*, relative to slot boundaries, they
  broadcast an attestation could bias which block the network's fork-choice
  converged on (`ISSUE#1773`, high confidence).

## rlp (Geth)

- **Overflow in RLP list-length bounds checking.** RLP list decoding
  compared the remaining bytes needed for a nested value against the outer
  list's declared size, but that comparison could itself overflow when the
  inner size field was large enough. go-fuzz found an input that passed the
  check anyway, causing an out-of-bounds read during decoding (`02b6b045`).

## serialization

- **[Lighthouse] Out-of-range offset in SSZ variable-length list decoding.**
  SSZ's variable-length-list decoder read a length-prefix offset from
  attacker-controlled bytes without checking it stayed within the buffer. An
  out-of-range offset made the decoder try to allocate a billion-element
  vector; the failed allocation crashed the node. The author had documented
  this exact bug class ("SSZ offset exploits") the year before, but had
  missed enforcing it in this decoder (`PR#974`, high confidence).

## state-trie (Geth)

- **16-bit overflow in trie parent-reference counting.** Geth's in-memory
  trie-pruning mechanism counted, in a `uint16` field, how many parent nodes
  referenced each trie node. On a node running with a large cache allowance,
  a burst of contract deployments that all referenced the same code hash —
  observed in production against Bittrex's wallets — pushed that count past
  65,535, overflowing the counter (`bad60eea`).

- **Race condition on a snapshot diff-layer's `origin` field.** The field
  was written outside the layer's lock, so a concurrent read of `origin`
  from another goroutine could see a stale or half-written pointer
  (`geth:...:PR#22540`).

- **Deadlock from unlocking on the panic path.** Two code paths in the
  state-snapshot iterator returned or panicked without releasing an `RWLock`
  they had already acquired; any panic on those paths — including one
  reachable via a crafted transaction — permanently deadlocked the snapshot
  for every future caller (`PR#20948`).

## sync (Geth)

- **32-bit index overflow in Ethash DAG generation.** DAG-generation
  indexes were computed as 32-bit values. Once the DAG grew large enough for
  its size to exceed the 32-bit range — a threshold the chain was on track
  to reach at a predictable future block — index arithmetic would wrap and
  generate an incorrect DAG, diverging that node from the rest of the
  network (`ab4b3b42`, CWE-190).

- **Disproportionate re-hashing via chained `DELEGATECALL`.** The VM
  re-hashed a contract's bytecode on every call, even though the code was
  already stored and addressed by that same hash. A transaction that chained
  many `DELEGATECALL`s into the same contract forced repeated re-hashing of
  identical code, burning CPU disproportionate to the gas paid — one of the
  vectors used in the 2016 Shanghai DoS attacks (`08c1cedc`).

- **Unbounded in-flight header buffer during sync.** The downloader placed
  no cap on how many block headers it would hold in memory while fetching
  from peers; a sync partner that kept the header queue full could exhaust
  the node's memory (`971ef372`).

## test (Geth)

- **Inverted throttle in transaction-announcement flood protection.** The
  transaction-announcement fetcher's flood-protection logic kept the
  *overflow* amount (`want - maxTxAnnounces`) instead of the *allowed*
  amount (`maxTxAnnounces - used`) when trimming a peer's announcement list
  — inverting the intended throttle, so a peer flooding announcements past
  the limit triggered a slice-indexing panic instead of being throttled
  (`7dce34f9` / `61ef89e2`, duplicate fixes for the same regression).

- **Unbounded reorg-log allocation.** Chain reorgs emitted one log object
  per removed/added block with no cap; a sufficiently deep reorg could
  allocate enough log objects to exhaust memory (`b1c9a13d`).

## transactions (Geth)

- **Txpool panic on an unvalidated signature.** The transaction pool ran an
  account lookup (`GetAccount`) against a transaction's sender before
  validating that the transaction carried a well-formed signature. An
  attacker who handcrafted RLP-encoded transaction bytes with an invalid
  signature could panic the pool during that lookup (`PR#195`).

- **No upper bound on RLP-declared input size**, letting a peer-supplied
  message with a crafted length field trigger an integer overflow during
  decoding (`204dd28e`).

## txpool (Geth)

- **Future transactions could evict funded pending ones.** Before this fix,
  an incoming "future" (not-yet-executable) transaction could evict an
  already-funded, currently-pending transaction from the pool, and the pool
  did not check whether a sender could actually cover an incoming
  transaction's cost against funds already committed elsewhere in the pool.
  An attacker could exploit either gap to evict other users' transactions or
  reserve funds that weren't really available (`83cccb97`, high confidence).

## gas (Geth)

- **Wrong threshold in the EVM memory-expansion overflow guard.** The guard
  against overflow in memory-expansion gas costs used a threshold too large
  for the arithmetic it was protecting: `0x7FFFFFFFF` squared does not
  overflow a `uint64`, but a value near `0x100000000` does. A
  memory-expansion request sized just under the guard's threshold could
  still overflow the real gas computation (`fef6b529`).

## evm (Nethermind)

- **Hardcoded pad direction in zero-padding helper.** A `UInt256`
  zero-padding helper ignored the caller-specified pad direction on its
  out-of-bounds branch and always padded right; call sites that needed
  left-padding on that branch received silently wrong byte layouts instead
  (`3d74c0f5`).

## blobs (Geth)

- **One bad cell proof dropped an entire Engine API batch.** `GetBlobs`
  aborted its whole response — discarding every blob already collected — the
  moment it hit one corrupted or out-of-bounds cell proof while serving an
  Engine API request. A single bad blob sidecar sitting in the pool could
  deny the whole batch to the consensus client that requested it
  (`4830cc6f`).

## kzg-commitments (Lighthouse)

- **Unchecked proof size from the paired execution client.** KZG proof-size
  handling used an assertion (`.expect()`) on a value the execution client
  supplied over the Engine API. An execution client that returned an
  unexpected proof size — buggy or malicious — could panic the consensus
  client (`PR#7957`).

---

Source: `data/ethereum_vulns.csv`.
