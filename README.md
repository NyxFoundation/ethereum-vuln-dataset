# ethereum-vuln-dataset

A curated corpus of **past security fixes** from the eleven production Ethereum
clients (six execution-layer, five consensus-layer). Each row is one historical
vulnerability fix — a merged PR, commit, advisory, or CVE — normalized to a
single schema, classified by STRIDE and CWE, and scored for security relevance.

The corpus is built for training and evaluating spec-compliance / audit tooling:
"given the code state just before this fix, would the tool have caught the bug?"

The curated table ships in the repo as a single parquet file:

```python
import pandas as pd
df = pd.read_parquet("data/ethereum_vulns.parquet")
```

(A HuggingFace `datasets` mirror under `NyxFoundation/` is a planned follow-up.)

## What makes this "vulnerabilities only"

A naive crawl of client repositories is mostly noise: refactors, docs, CI
changes, dependency bumps, and release notes vastly outnumber the security fixes.
An early version of this corpus illustrated the trap — Nimbus release notes carry
an *"Urgency guidelines"* template (`critical update required for Nimbus`) that a
severity regex read as ~95 phantom `Critical` findings.

The build pipeline removes that noise in three deterministic stages
(`pipeline/build_security_dataset.py`):

| Stage | What it does | Why |
|---|---|---|
| **T1 — de-boilerplate** | Drop release-note / urgency-template rows; never trust a severity that came from a release header | Kills the structural false positives (e.g. the 95 phantom Nimbus criticals) before anything else reads them |
| **T7 — relevance score** | Assign `security_score ∈ [0,1]` from CVE/GHSA ids, rated severity, and a weighted keyword match (incl. protocol-specific terms: consensus split, equivocation, eclipse, finality stall, …) | Cheap, offline, reproducible signal that also catches stealth fixes that carry no security label |
| **GATE — keep on evidence** | Keep a row only if an *independent* signal fires: a CVE/GHSA id, a rated severity, a security keyword, an LLM STRIDE category, or a CWE-Top-25 label | Union of signals = high recall; the per-row `confidence` tier lets you trade recall for precision |

Result on the current snapshot:

| | rows | note |
|---|---:|---|
| raw crawl | 33,789 | ~44% had no security signal at all |
| → after T1 | 33,690 | 99 boilerplate rows dropped (96 Nimbus, 3 geth) |
| → **curated (security-only)** | **19,046** | 0 residual boilerplate; phantom Nimbus criticals gone (102 → 15 real `Critical`) |

By confidence: **high 877** · medium 16,426 · low 1,743. Take the slice you need:

```python
high = df[df.confidence == "high"]                 # CVE/GHSA, rated High/Critical, or strong keyword
solid = df[df.confidence != "low"]                 # high + medium (recommended default)
```

## Schema

| Column | Description |
|---|---|
| `id` | `<client>:<repo>:<issue_id>` |
| `source_platform` | client slug (`geth`, `lighthouse`, …) |
| `contest` | upstream repo slug |
| `issue_id` | PR / issue / commit / advisory id |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Info` / `Unrated` |
| `title`, `description` | fix text (verbatim from the client's own public repo) |
| `source_url` | link to the upstream fix |
| `introduced_in_commit` | parent of the fix commit (the last state in which the bug was present) |
| `stride` | STRIDE category (LLM-classified) or `Other` |
| `cwe_top25` | CWE-Top-25 (2024) id (LLM-classified) or `N/A` |
| `security_score` | T7 relevance score, 0.0–1.0 |
| `confidence` | `high` / `medium` / `low` evidence that the row is a real vulnerability fix |
| `scraped_at` | ISO-8601 UTC |

## Clients

| Layer | Clients |
|---|---|
| Execution | geth, nethermind, besu, erigon, reth |
| Consensus | lighthouse, lodestar, nimbus, prysm, teku, grandine |

Plus spec repos (`ethereum_specs`, `consensus-specs`) for spec-divergence fixes.

## Reproduce

The curated table is derived deterministically from the raw snapshot — no network,
no API key:

```bash
uv run python pipeline/build_security_dataset.py \
  --in data/raw/train.classified.parquet \
  --out data/ethereum_vulns.parquet
uv run python -m pytest tests/ -q
```

Re-collecting the raw snapshot from scratch (network-bound) uses the crawlers and
classifier under [`collection/`](collection/): per-client label taxonomies, a
body-keyword path filter for unlabeled "stealth" fixes, multi-source advisory
pulls (NVD / OSV / RustSec / govulncheck), and an LLM STRIDE+CWE classifier. See
[`collection/`](collection/) for the individual scripts.

## Build report

[`docs/BUILD_REPORT.md`](docs/BUILD_REPORT.md) records the before/after of every
build stage for the current snapshot.

## License

Data: [CC-BY-4.0](LICENSE). Sourced from each client's own public repository
(commits, advisories, CVEs); `title`/`description` are verbatim from those public
sources. Code under `collection/` and `pipeline/`: MIT.
