# Dataset analysis

What this corpus says — read through the lens of the vulnerability-dataset
literature (CVEfixes, BigVul, Devign, CrossVul, DiverseVul, PrimeVul, and Croft
et al.'s data-quality framework). Numbers are for the current snapshot
(n = 2,225 curated rows).

## Snapshot

| dimension | value |
|---|---|
| rows | 2,225 (A_authoritative 235 · B_corroborated 1,573 · C_candidate 417) |
| layers | execution 1,259 · consensus 966 |
| languages | Go 945 · Rust 419 · Nim 269 · Java 235 · TypeScript 225 · C# 130 |
| rated severity | **6.4%** · carries a CVE/GHSA id **4.9%** |
| top root causes | missing_input_validation 522 · resource_exhaustion 340 · race_condition 217 · unhandled_error/nil 208 · integer_overflow 185 · consensus_divergence 174 |
| top attack paths | malformed_input 926 · crafted_state 415 · malicious_p2p_message 241 · malicious_attestation 174 |
| fix size | median **45 LOC**, 41% ≤30 LOC · median **2 files**, **43% single-file** |

## 1. The silent-fix majority is the point (not a bug)

**Only 6.4% of curated fixes carry a rated severity and 4.9% carry a CVE/GHSA
id.** So **~94% shipped silently** — no advisory, often a vague message. This
quantifies, for Ethereum clients specifically, the phenomenon VulFixMiner and
Sawadogo et al. describe generally.

*Implication vs prior datasets.* CVE-anchored corpora (**CVEfixes**, **BigVul**)
start from an advisory and walk to the fix, so by construction they can only see
the ~5–6% advisory-linked slice. This corpus is built the other way — surface the
silent majority via multi-signal mining — so it is complementary to, not a subset
of, CVE-anchored datasets.

## 2. The vulnerability profile is availability-first, and protocol-specific

Root causes are dominated by **input-validation gaps, resource exhaustion,
races, nil/unhandled errors, integer overflow, and consensus divergence**;
attack paths are dominated by **malformed input, crafted state, and malicious
p2p / attestation messages**. The modal bug is *"untrusted network input crashes
or diverges the node"* — an **availability / consensus** class.

*Implication.* This differs sharply from the memory-corruption / injection profile
that dominates C/C++ datasets (BigVul, Devign are largely CWE-119/787/476). Two
classes here are essentially **absent from generic datasets**: `consensus_divergence`
(chain split / invalid-block acceptance) and DoS-via-p2p. A detector trained only
on generic CWE data would be blind to the highest-severity Ethereum-specific
class. This argues for domain-specific corpora, echoing CrossVul/DiverseVul's
finding that distribution shift across domains degrades transfer.

## 3. Fixes are surgical — which supports the counterfactual use-case

**43% touch a single file, 41% change ≤30 LOC, median 45 LOC.** Security fixes
being small and localized is exactly the prior that VulFixMiner / GraphSPD exploit,
and it matters for this corpus's stated purpose — *"given the pre-fix state, would
the tool have caught it?"*: a tightly-scoped diff + `introduced_in_commit` gives a
clean counterfactual boundary. (The mean of 298 LOC is skewed by a few large
refactor-bundled fixes — median is the honest centre.)

## 4. Rare axis: one spec, eleven implementations, six languages

Most vuln datasets are single-language (usually C/C++) and single-project or
project-agnostic. This corpus is **multi-language (6) × multi-implementation (11)
of one protocol**. Because all clients implement the *same* consensus/execution
spec, the **same logical vulnerability can recur across languages** (and the
`label` area is the language-agnostic join key). That enables studies generic
datasets can't support: cross-implementation recurrence, language-specific bug
proneness for an identical spec, and transfer across implementations. This is the
diversity dimension **DiverseVul** and **CrossVul** argue reduces overfitting —
here obtained within a single, well-specified domain.

## 5. Data quality, by Croft et al.'s dimensions

- **Accuracy (label correctness).** Multi-signal gate + `authority_tier` + an
  LLM classifier validated at ~0.90 precision; labels are *not* human-verified
  (see [`limitations.md`](./limitations.md)). The tiering makes the
  accuracy/coverage trade-off explicit rather than hidden in a single noisy label
  — the direction **PrimeVul** advocates after showing BigVul/Devign labels are
  substantially noisy.
- **Uniqueness.** De-duplicated by `fix_commit` within a client (108 removed);
  only 2 commits are shared across clients (fork-inherited). Duplication is the
  #1 metric-inflation risk **PrimeVul** and **Croft et al.** flag; it is handled.
- **Consistency.** One schema across 11 heterogeneous sources (advisory / stealth
  PR / commit / release / CVE / OSV / RustSec).
- **Currentness.** Freshly crawled (2026), including the newest forks
  (deneb→fulu/gloas, cancun→osaka) — where most datasets lag years behind.

## 6. Selection under a <1% base rate

Security fixes are a fraction of a percent of commits (the "needle in a haystack"
of VulFixMiner). The pipeline responds with a **cheap high-recall pre-filter →
gate → LLM classifier** cascade rather than a blind full-commit scan (measured at
~18 h with precision collapse). The `authority_tier` / `n_signals` columns let a
consumer pick their point on the recall/precision curve — treating selection as a
first-class, tunable step instead of a fixed threshold.

## 7. It is a *corpus*, not a ready-made benchmark

**PrimeVul**'s central lesson is that naive splits leak: near-duplicate and
temporally-entangled samples inflate reported model performance. This dataset is a
*corpus* — no train/test split is shipped. A consumer building a benchmark from it
**must** add a temporal and/or by-client split (and treat the fork-shared commits
and the recurring cross-implementation fixes as leakage risks) to get an honest
generalization estimate.

---

*Reproduce these numbers from `data/ethereum_vulns.parquet`; see
[`BUILD_REPORT.md`](./BUILD_REPORT.md) for coverage and [`limitations.md`](./limitations.md)
for caveats.*
