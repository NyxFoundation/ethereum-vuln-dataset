# Canonical dataset snapshot

This page is the single source of truth for counts quoted in current
documentation. Every value is computed from
`data/ethereum_vulns.parquet`, not copied from an intermediate build log.

- Rows: **2,225**
- Parquet SHA-256:
  `09bb9642023e4fa914268d86e723435cf16626d55f480fc248c43ad6af79e0e7`
- Recompute: `uv run python scripts/paper_analysis.py`
- Machine-readable metrics:
  [`paper/tables/snapshot_metrics.csv`](paper/tables/snapshot_metrics.csv)

## Canonical public-evidence definition

A record is **advisory-linked** when a case-insensitive, syntactically valid
CVE, GHSA, or RustSec identifier occurs in any of `title`, `description`,
`issue_id`, `contest`, `source_url`, or `evidence`. A record is **rated** when
`severity` is Critical, High, Medium, or Low.

| Public evidence | Records | Share |
|---|---:|---:|
| Advisory ID and rating | 52 | 2.3% |
| Advisory ID only | 120 | 5.4% |
| Rating only | 91 | 4.1% |
| Neither advisory ID nor rating | **1,962** | **88.2%** |
| Total | 2,225 | 100.0% |

Thus, 172 records (7.7%) have a recognized advisory ID and 143 (6.4%) have a
rated severity. Separately, 2,082 (93.6%) are **unrated**. The 93.6% value must
not be described as “no advisory” or “silent”; it measures rating absence only.
In current documentation, the precise phrase for 88.2% is “neither a recognized
advisory ID nor a rated severity.”

The older title/description-only, case-sensitive `CVE-|GHSA-` search finds 109
records (4.9%). It is retained only as a sensitivity/reproducibility result in
the paper audit, never as the headline definition.

## Current distributions

| Measure | Count |
|---|---:|
| A_authoritative | 235 |
| B_corroborated | 1,573 |
| C_candidate | 417 |
| A ∪ B essential slice | 1,808 |
| Confidence: high / medium / low | 326 / 1,445 / 454 |
| Severity: Critical / High / Medium / Low | 3 / 63 / 57 / 20 |
| Severity: Info / Unrated | 750 / 1,332 |
| Fix commit present | 1,959 (88.0%) |
| Post-fix code present | 1,923 (86.4%) |
| Post-fix code among rows with a fix commit | 1,923 / 1,959 (98.2%) |
| Fix commit present but post-fix code absent | 36 |
| CWE assigned (`cwe_top25 != N/A`) | 396 (17.8%) |
| Assigned CWE in MITRE 2025 Top 25 | 130 (5.8% of all rows) |
| `silent_fix_prob` assessed | 897 (40.3%) |

Despite its legacy name, `cwe_top25` stores general CWE labels. Only 130 of its
396 assigned values are members of MITRE's 2025 Top 25.

## Drift policy

`data/manifest.json` distributions must equal counts computed from the Parquet
snapshot. `tests/test_security_dataset.py` enforces that invariant and also
checks the four-way advisory/rating partition above. Historical experiment logs
may contain iteration-local counts, but they must identify themselves as
historical and link here for the current snapshot.
