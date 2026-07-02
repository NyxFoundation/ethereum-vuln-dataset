# Build report

Fresh crawl + deterministic curation. Raw snapshot re-collected from all 11
clients (+ consensus-specs) via `collection/run_pipeline.sh` (uncapped), then the
curated security-only set derived offline by `pipeline/build_security_dataset.py`.

> **Note:** LLM STRIDE/CWE classification was **skipped** for this build, so
> `stride=Other` / `cwe_top25=N/A` for every row. The GATE therefore keeps a row
> only on an *independent non-LLM* signal: a CVE/GHSA id, a rated severity
> (Critical/High/Medium/Low), or a security-keyword match (`security_score ≥ 0.5`).
> This yields a smaller, higher-precision set than a classified build — the
> ~16k rows dropped below are the unrated "stealth" fixes that only an LLM
> STRIDE label would have admitted.

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

- rows: **1,880**
- residual boilerplate FP: **0**  ✅
- **essential slice (A+B): 1,535** (was 173 rated-only) — clean high-precision core
- by authority_tier: {'B_corroborated': 1296, 'C_candidate': 345, 'A_authoritative': 239}
- **learned silent-fix signal (gemma4:31b):** classified 339 C_candidate diffs,
  flagged 166 as real silent fixes (133 DoS / 16 consensus / 11 validation …),
  promoting them C→B. Model chosen by an 80-item eval sweep (F1 0.872, precision
  0.895); see `docs/model_evaluation.md`. Regenerate via
  `collection/llm_classify_fixes.py --apply` → `data/silent_fix_llm.csv`.
- by severity: {'Unrated': 963, 'Info': 773, 'High': 63, 'Medium': 54, 'Low': 21, 'Critical': 3}
  (High/Medium dropped vs iter-1 because T2b removed 49 unrelated CVEs' bogus CVSS severities)
- by source:
  - geth: 438
  - erigon: 371
  - lodestar: 276
  - nimbus: 232
  - lighthouse: 178
  - reth: 172
  - prysm: 116
  - nethermind: 108
  - besu: 94
  - teku: 93
  - grandine: 16
  - consensus-specs: 2
- security_score distribution: {'0.0': 34, '0.3': 4, '0.5': 1253, '0.8': 423, '0.9': 172, '1.0': 210}

## Validation checkpoints (issue #89)

- c-kzg-4844 / blst: present (kzg×12, 4844×13, blst×13 in curated)
- Lodestar: 276 · Nimbus: 232 · Prysm: 116 — all present
- `ethereum_specs` source: **0** (spec-divergence crawler returned no matches this run; the 11 clients + consensus-specs are covered)
