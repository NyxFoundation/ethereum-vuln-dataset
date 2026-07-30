# Limitations & known caveats

An honest inventory of what this dataset does *not* cover and where its labels
are approximate. Numbers are for the current snapshot (n = 2,225 curated rows);
canonical definitions are in [`DATA_SNAPSHOT.md`](./DATA_SNAPSHOT.md).

## 1. Coverage gaps

| gap | state | fixable? |
|---|---|---|
| **`severity` rated** | 143 / 2,225 (6.4%) | ❌ structural — 2,082 rows (93.6%) are Info/Unrated. This does not imply that all 2,082 lack an advisory. |
| **`pre_fix_code` / `post_fix_code`** | 1,923 / 2,225 (86.4%); 1,923 / 1,959 (98.2%) among rows with a fix commit | ⚠ mostly structural — 266 rows map to no single fix commit, and 36 committed rows lack a fetchable post-fix diff. |
| **`fix_commit` / `introduced_in_commit`** | 88.0% | ⚠ the 12% without a commit are advisory/NVD/release rows (no single commit exists). |
| **`cwe_top25`** | 396 / 2,225 (17.8%) | ⚠ sparse and misleadingly named — it stores general CWE labels; only 130 rows (5.8% overall) are in MITRE's 2025 Top 25. |
| **`silent_fix_prob`** | 40.3% | by design — only the C_candidate + plausible gate-dropped rows were LLM-classified; classifying *all* commits is impractical (see §2). |
| **`label = other`** | 6.6% | near floor — the remainder are genuinely generic (event/backend orchestration, advisory rows with no diff, vendored code). Forcing a label would be wrong. |

## 2. Recall is bounded — "trace-leaving" fixes only

The raw crawl is **keyword/advisory-biased** (security-term commit greps, stealth-PR
body search, advisory DBs). A *truly* silent fix — vague commit message **and** no
advisory **and** a change in an area whose path gives no hint — leaves no trace
for the crawl to catch, and is **missed**.

Classifying *all* commits with the LLM to find these was measured at **~18 hours**
and rejected: at a <1% base rate, precision collapses (the "needle in a haystack"
problem), so a blind full-scan yields mostly false positives. The dataset
therefore covers fixes that left **some** trace; it is not an exhaustive census
of every historical vulnerability.

## 3. Label / classification caveats

- **Not human-verified.** `label`, `root_cause`, `attack_path`, `cwe_top25` come
  from path/keyword rules + the `gemma4:31b` LLM. Spot-checks look good
  (precision ~0.90 on the silent-fix eval) but individual rows can be wrong.
- **`attack_path` is 100% only because of a best-effort default** — treat low-
  signal rows' attack_path as a guess.
- **LLM output is non-deterministic.** gemma via Ollama Cloud varies run-to-run
  (~±0.05 on labels/metrics), so counts shift slightly on a rebuild. A cache
  stabilises repeated runs.
- **The silent-fix classifier is hosted** (Ollama Cloud), not local — full
  reproducibility depends on that API. Regex/TF-IDF classifiers were tried and
  **validated-negative** (see [`silent_fix_detection.md`](./silent_fix_detection.md)); only the LLM
  classifier and patch-backlinking survived validation.

## 4. Provenance caveats

- **`introduced_in_commit` = parent of the fix commit** (the last pre-fix state),
  **not** the commit that first introduced the bug. A `git blame` walk would be
  needed for the true introduction point.
- **`fix_commit` for `/pull/` rows = the PR head**, and the diff is the 3-dot
  (merge-base…head) diff. For a few divergent-fork PRs the local diff is
  unreliable and falls back to `gh`.
- **Cross-client duplicates are intentionally kept.** The same commit SHA shared
  via a fork (e.g. Geth → Erigon early history) appears as one row per client.
  Within-client same-commit duplicates *are* de-duplicated.
- **Dependency-bump rows.** Some rows are dep bumps that cite a CVE (kept because
  they carry an advisory id); their pre/post "code" is a manifest change, not a
  client-code fix.
- **`spec_anchor` is not implemented.** Labels map a row to a protocol *area*
  (e.g. `beacon-chain:attestation`), not to a specific pyspec function / EIP
  (proposed in [`label_design.md`](./label_design.md), not built).

## 5. Source-specific

- **`ethereum/execution-specs` & spec-divergence coverage ≈ 0** — the
  spec-divergence crawler returned no matches this run; only the 11 clients +
  `consensus-specs` are represented.
- **NVD is noisy.** `crawl_cve` matches the client name as a substring; the T2b
  stage removes the glibc/X.Org/kernel false positives, but the NVD source is
  inherently low-precision.
- **`Critical` severity is under-counted** — the supplementary-merge path maps
  `critical → High`; only rows on the canonical path preserve `Critical` (3 rows).

---

*See [`BUILD_REPORT.md`](./BUILD_REPORT.md) for per-column coverage and
[`silent_fix_detection.md`](./silent_fix_detection.md) for the methodology behind these trade-offs.*
