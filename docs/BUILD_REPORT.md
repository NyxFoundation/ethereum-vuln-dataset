# Build report

Fresh crawl + deterministic curation. Raw snapshot re-collected from all 11
clients (+ consensus-specs) via `collection/run_pipeline.sh` (uncapped), then the
curated security-only set derived offline by `pipeline/build_security_dataset.py`.

> **Current-snapshot rule:** all “After” counts and coverage below are computed
> from `data/ethereum_vulns.parquet` (2,225 rows). Iteration-local history lives
> in [`IMPROVEMENT_LOG.md`](./IMPROVEMENT_LOG.md); canonical definitions and
> hashes live in [`DATA_SNAPSHOT.md`](./DATA_SNAPSHOT.md).

## Before (raw crawl)

- rows (build_derived): **20,915**
- after cross-reference dedup: **18,475**

## Pipeline stages

- **T1** dropped 11 release-note boilerplate rows {'nimbus': 8, 'geth': 3}
- **T2** dropped **1,417** CI/docs/dep-bump meta-work rows (title-anchored;
  rows citing a CVE/GHSA/RustSec id, strong vuln language, or a rated severity
  are protected)
- **T2b** dropped **49** NVD substring-match false positives — `crawl_cve.py`
  matched the client name inside unrelated strings (`gethostbyaddr`, `GetHost`,
  "Gether Technology", Linux `usb: g…`), dumping glibc/X.Org/Samba/kernel CVEs
  into the authoritative tier. Kept only rows whose description names the client
  (6 real: Besu ×4, go-ethereum, Nethermind Juno). Source also fixed in the crawler.
- **T7 + GATE** kept the security-relevant remainder
- New provenance columns: **`authority_tier`** (A_authoritative / B_corroborated
  / C_candidate) and **`n_signals`** (count of independent security signals).
  The **essential slice** = `authority_tier in {A,B}`.

## Authoritative spine

Per-repo GitHub Security Advisories crawled via `crawl_ghsa_advisories.py`:
25 advisories (geth 17, besu 3, lodestar 3, lighthouse 1, teku 1), incl. **3
Critical** (geth, besu, teku). Severities preserved through the canonical path.

## After (curated)

- rows: **2,225** (after removing 108 same-fix-commit duplicates)
- residual boilerplate FP: **0**  ✅
- **essential slice (A+B): 1,808** (was 173 rated-only) — clean high-precision core
- by authority_tier: {'B_corroborated': 1573, 'C_candidate': 417, 'A_authoritative': 235}
- **learned silent-fix signal (gemma4:31b):** classified **1,519** PR/commit diffs
  across all 11 clients (curated C_candidate + gate-dropped *plausible* rows),
  flagged **696** as real silent fixes. This both promotes classified fixes C→B
  and, via the gate, **admits +453 silent fixes the deterministic keyword gate
  had dropped** in that intermediate iteration. Model chosen by an 80-item eval sweep
  (F1 0.872, precision 0.895); see `docs/model_evaluation.md`. Diffs served
  rate-limit-free by `local_diffs.py` (bulk PR-ref clone). Regenerate via
  `collection/llm_classify_fixes.py --apply` → `data/silent_fix_llm.csv`.
- by confidence: {'medium': 1445, 'low': 454, 'high': 326}
- by severity: {'Unrated': 1332, 'Info': 750, 'High': 63, 'Medium': 57, 'Low': 20, 'Critical': 3}
- by source:
  - erigon: 425
  - geth: 407
  - nimbus: 269
  - lodestar: 225
  - lighthouse: 217
  - reth: 183
  - nethermind: 130
  - teku: 123
  - prysm: 113
  - besu: 112
  - grandine: 19
  - consensus-specs: 2
- security_score distribution: {'0.0': 220, '0.3': 271, '0.5': 1119, '0.8': 289, '0.9': 159, '1.0': 167}

## Validation checkpoints (issue #89)

- c-kzg-4844 / blst: present (kzg×12, 4844×13, blst×13 in curated)
- Lodestar: 225 · Nimbus: 269 · Prysm: 113 — all present
- `ethereum_specs` source: **0** (spec-divergence crawler returned no matches this run; the 11 clients + consensus-specs are covered)

## Column coverage (n=2,225)

| column | coverage | notes |
|---|---:|---|
| `source_url`, `title`, `description`, `attack_path` | 100.0% | attack_path defaults to a best-effort class |
| `label` (assigned, non-`other`) | **93.4%** | deterministic path/keyword + LLM fallback (`gemma4:31b`) reading the diff or, for no-commit rows, the advisory text |
| `root_cause` (assigned) | 86.5% | keyword + classifier reason + LLM |
| `cwe_top25` (general CWE label assigned) | **17.8%** | despite the legacy column name, only 130 rows (5.8% overall) are in MITRE's 2025 Top 25 |
| `fix_commit` / `introduced_in_commit` | **88.0%** | `/commit/` + `/pull/` URLs, GHSA advisory patch-releases, and **inline `#PR` / commit refs parsed from CHANGELOG/release text** (author-linked, high precision) |
| `pre_fix_code` / `post_fix_code` (inline) | **86.4%** | **98.2% of the 1,959 rows with a resolved commit**; 36 committed rows lack post-fix code and 266 have no fix commit |
| `silent_fix_prob` (LLM classifier) | 40.3% | 897 classified rows (C_candidate + plausible gate-dropped) |
| `severity` (rated) | 6.4% | 143 rows; provenance is 60 `bounty-graded` and 83 rated `upstream-cvss` |
| `severity_estimated` (bounty-tier) | **30.3%** | 675 Low/Medium/High/Critical estimates; 1,549 `not-eligible`, one unassessed. See `docs/severity_labeling.md`. |
