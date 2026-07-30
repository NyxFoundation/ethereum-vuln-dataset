# RQ3 preliminary: replication against MineBlockVuln

## Question

How much of the closest prior blockchain-system vulnerability dataset is
recovered by the current corpus, and what is genuinely new about the
eleven-client dataset?

The comparison target is Yi et al., *An Empirical Study of Blockchain System
Vulnerabilities: Modules, Types, and Patterns* (ESEC/FSE 2022). Its public
SQLite database covers Bitcoin, Ethereum/Geth, Monero, and Stellar.

- Paper: <https://doi.org/10.1145/3540250.3549105>
- Repository: <https://github.com/VPRLab/BlkVulnDataset>
- Public DB link: <https://drive.google.com/file/d/1ntKMt4U4FN6VTi1x-PQw-ZNh1cqKQDLD/view>
- Downloaded DB SHA-256:
  `a827279d8abe8b44451df11f46b2be2acc589f75712a75bfff5280580b968525`

The 1.5 GiB external DB is not checked into this repository. Reproduce the
checked-in comparison tables with:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/compare_mineblockvuln.py \
  --mineblock-db /path/to/BlkVulnDataset.db
```

## 1. Published populations

| Measure | MineBlockVuln | Current corpus |
|---|---:|---:|
| Scope | 4 blockchain systems | 11 Ethereum clients + consensus specs |
| Ethereum implementation scope | Geth | 5 execution + 6 consensus clients |
| Public Geth vulnerability-issue rows | 367 in DB; 365 final in paper | 407 curated Geth rows |
| Geth Top-20 typed issues | 212 | different protocol/root-cause taxonomy |
| Geth implementation language | Go | 6 languages across all clients |

The current corpus has more curated Geth rows than MineBlockVuln has Geth
issues, but row count alone hides low identity overlap.

## 2. Exact overlap is low

Exact GitHub issue/PR identity:

| Recall stage | Shared legacy refs | Share of 367 |
|---|---:|---:|
| Current raw Geth collection | 88 | 24.0% |
| Current curated Geth corpus | 63 | 17.2% |
| Curated corpus, allowing the Geth ref in any client row | 68 | 18.5% |

The recall decomposition is:

- 63 MineBlockVuln refs appear in the curated Geth corpus;
- 25 additional refs were collected into raw Geth data but removed by the
  current gate;
- 279 refs are absent from the raw Geth collection.

Allowing Geth references inherited or cited by other client rows raises raw
coverage only from 88 to 93 refs. The dominant gap is therefore collection,
not the curation gate.

Exact fix-commit identity is lower:

| Measure | Count / share |
|---|---:|
| Unique MineBlockVuln Geth commits linked to vulnerability issues | 1,008 |
| Unique current Geth `fix_commit` values | 337 |
| Shared exact commit SHAs | 65 |
| Legacy commit recall | 6.4% |
| Current Geth commit overlap with legacy | 19.3% |

Commit recall is not directly comparable to issue recall: MineBlockVuln links
multiple commits to one issue, while the current corpus selects one fixing
commit and de-duplicates within a client.

The full row-level decomposition is checked in as
[`tables/mineblock_recall_decomposition.csv`](tables/mineblock_recall_decomposition.csv).

## 3. This falsifies a possible dataset claim

**Do not claim.** The current corpus is not a comprehensive replacement or
superset of MineBlockVuln's historical Geth data.

The raw crawl is trace-biased and misses three quarters of the earlier Geth
issue/PR set by exact URL. The missed set contains not only generic hardening
and operational fixes but also explicitly security-labelled historical issues,
so the gap cannot be dismissed as a pure scope-definition difference.

**Observation.** The new corpus primarily extends the *implementation axis*:
eleven clients, execution and consensus layers, six languages, evidence tiers,
and inline pre/post code. It does not yet establish higher historical recall
within Geth.

**Interpretation.** The strongest novelty claim is cross-implementation and
protocol-native analysis, not “largest” or “most complete” historical
Ethereum-vulnerability coverage.

## 4. The old “type” taxonomy mixes three semantic axes

MineBlockVuln's leading typed Geth categories were:

| Type | Geth issues |
|---|---:|
| Race Condition | 48 |
| Go Panic | 36 |
| Block Related | 21 |
| Check/Validation | 14 |
| Deadlock | 13 |
| Resource Leak | 12 |
| Denial-of-Service | 11 |
| Peer/Node Related | 11 |

Only 45 current rows match a MineBlockVuln Top-20 issue by issue/PR number.
Twenty-three of those matches are in the old “Go Panic” category. This shared
slice is too small and selected to support a distributional replication claim.

The taxonomies also answer different questions. Classifying all 212 typed Geth
issues by what the category name denotes gives:

| Semantic axis | MineBlockVuln issues | Share |
|---|---:|---:|
| Root cause | 109 | 51.4% |
| Subsystem or affected object | 53 | 25.0% |
| Symptom or impact | 50 | 23.6% |

- MineBlockVuln types mix symptoms (`Go Panic`), root causes (`Race
  Condition`), affected objects (`Block Related`), and modules (`RPC Related`);
- the current corpus separates protocol area, root cause, and attack path.

This means a single distribution cannot be compared directly with the current
`root_cause` column. “Go Panic,” for example, is a Go-specific runtime symptom,
not a protocol vulnerability class that can be transferred to Rust, Java, C#,
Nim, or TypeScript.

The generated
[`tables/mineblock_type_crosswalk.csv`](tables/mineblock_type_crosswalk.csv)
therefore serves as an annotation queue, not a one-to-one mapping. The explicit
axis classification is in
[`tables/mineblock_type_axes.csv`](tables/mineblock_type_axes.csv).

## 5. Exact-overlap rows validate some categories and reject others

The 45 matched current rows are too selected for population inference, but they
can test whether an old label has a stable root-cause meaning:

| MineBlockVuln type | Matched rows | Current root causes | Expected-root alignment |
|---|---:|---:|---:|
| Overflow | 5 | 2 distinct | 4/5 (80.0%) |
| Nil Pointer Dereference | 3 | 2 distinct | 2/3 (66.7%) |
| Race Condition | 4 | 3 distinct | 2/4 (50.0%) |
| Go Panic | 23 | **6 distinct** | not applicable: symptom |
| Denial-of-Service | 3 | **3 distinct** | not applicable: impact |

`Overflow` behaves mostly like a root-cause category. `Go Panic` does not: its
23 shared rows spread across `other` (9), `unhandled_error_or_nil` (6),
`race_condition` (4), `resource_exhaustion` (2),
`improper_state_update` (1), and `serialization_bug` (1). A panic label tells
the researcher how a Go process failed, not why the vulnerability existed.

This decomposition changes the cross-language research question. The paper
should not ask whether “Go Panic” reproduces in six languages. It should ask
whether the underlying causes hidden by that symptom—unchecked errors,
concurrency, resource exhaustion, state updates, and serialization—recur across
implementations.

## 6. Descriptive distribution shift, not a replication claim

Within MineBlockVuln's selected Top-20 Geth issues, `Race Condition` is 48/212
(22.6%). The current schema assigns `race_condition` to 52/407 Geth records
(12.8%) and 217/2,225 records across all clients (9.8%). Conversely, the current
Geth corpus is led by `resource_exhaustion` (77; 18.9%) and
`missing_input_validation` (55; 13.5%).

These differences are descriptive only. The datasets have low exact overlap,
different collection frames, different units, and different annotation
taxonomies. They cannot establish a temporal change in Ethereum vulnerabilities
or a language effect. Their value is to show that the prior headline
distribution depends materially on a mixed-axis type system.

## 7. Next validity work

1. Manually stratify the 279 not-collected refs into:
   - in-scope vulnerability/security fix;
   - security hardening without a concrete vulnerability;
   - ordinary reliability bug;
   - obsolete Swarm/UI/wallet scope;
   - unresolved.
2. Treat the manually reviewed legacy set as an external recall benchmark for
   the collection pipeline.
3. Add a MineBlockVuln ingestion source or explicitly narrow the corpus claim to
   trace-leaving fixes collected by the documented sources.
4. Compare old and current type distributions only after constructing a
   reviewed crosswalk that separates symptom, root cause, module, and trigger.
5. Test the prior paper's language-dependent conclusion (“Go Panic” in
   Ethereum) across the six implementation languages. Do not attribute a
   Geth/Go observation to the Ethereum protocol.

## 8. Candidate contribution after correction

The defensible replication story is:

> Prior work established that repository mining finds blockchain security work
> beyond CVEs, but studied Ethereum through one Go implementation. The current
> corpus exposes that the prior “type” distribution combines root cause,
> subsystem, and language-specific symptom. Separating those axes enables the
> first defensible cross-implementation comparison across eleven clients and six
> languages, while the exact-overlap audit makes the recall limits explicit.

This is a stronger empirical contribution than repeating the prior paper's
module and type counts on a differently selected sample.

## 9. Generated category evidence

- [`tables/mineblock_type_axes.csv`](tables/mineblock_type_axes.csv)
- [`tables/mineblock_taxonomy_alignment.csv`](tables/mineblock_taxonomy_alignment.csv)
- [`tables/mineblock_current_root_cause_counts.csv`](tables/mineblock_current_root_cause_counts.csv)
