# collection/ — raw acquisition (network-bound)

These scripts rebuild the *raw* snapshot (`data/raw/train.classified.parquet`)
from scratch. They need network access and, for classification, an LLM API key.
The curated dataset is derived from the raw snapshot **offline** by
`pipeline/build_security_dataset.py` — you do not need these to use the dataset.

| Group | Scripts |
|---|---|
| Per-client repo crawl | `crawl_eth_past_fixes.py`, `crawl_ghsa_advisories.py`, `grep_eth_commits.py`, `mine_eth_releases.py`, `mine_stealth_prs.py`, `mine_direct_pulls.py`, `parse_eth_changelogs.py`, `extract_nimbus_urgency.py` |
| Advisory databases | `crawl_cve.py`, `crawl_osv.py`, `crawl_rustsec.py`, `crawl_govulncheck.py`, `crawl_teku_jira_refs.py` |
| Cross-client / specs | `crawl_cross_client.py`, `crawl_specs_divergence.py` |
| Merge + enrich | `merge_crawl_csvs.py`, `build_derived.py`, `cross_reference.py`, `blame_walk.py` |
| STRIDE/CWE classify (optional) | `classify_stride_cwe.py`, `classify_stride_cwe_sdk.py` |
| **Silent-fix classify** | `llm_classify_fixes.py` (LLM), `local_diffs.py` (rate-limit-free diffs) — see [`silent_fix_detection.md`](./silent_fix_detection.md) |
| Orchestrator | `run_pipeline.sh` |

Collection methodology (per-client security-label taxonomies, a body-keyword path
filter for unlabeled "stealth" fixes, and the rule that a severity from a release
header is never trusted) is summarized in the root README. Documentation lives in
[`docs/`](./): [BUILD_REPORT](./BUILD_REPORT.md) · [IMPROVEMENT_LOG](./IMPROVEMENT_LOG.md)
· [silent_fix_detection](./silent_fix_detection.md) · [model_evaluation](./model_evaluation.md).
