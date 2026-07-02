# Silent-fix detection — research background & the algorithm we use

**Silent (a.k.a. stealth) security fixes** are patches that repair an exploitable
or availability-affecting defect but ship *without* an advisory (no CVE/GHSA),
often with a deliberately uninformative commit message, so users upgrade before
attackers notice. Ethereum clients do this heavily — issue #2 in this project
found **~98–100% of client security fixes are silent**. Detecting them is the
core problem this dataset addresses.

This document covers (1) the research landscape and (2) exactly what algorithm
this repo runs, including what we tried and rejected.

---

## 1. Research landscape

The literature splits along two axes: **what evidence** is used (commit message
vs. code change vs. external advisory) and **how** (hand-rules vs. trained model
vs. prompted LLM). Two families matter for silent fixes.

### A. Learned code-change classifiers — *detect unknown* silent fixes
The message is useless for a silent fix by construction, so these learn from the
**code change** itself.

| work | idea | representation |
|---|---|---|
| Sabetta & Bezzi, ESEM 2018 | security-relevant commit classification | patch **as a document** (bag-of-words) + classifier |
| **VulFixMiner**, Zhou et al. ASE 2021 | "needle in a haystack" — mine *silent* vuln fixes | **CodeBERT** on the code change |
| **GraphSPD**, Wang et al. S&P 2023 | merge pre/post-patch **code property graphs** (MCPG) | multi-attributed graph convolution |
| SPI / E-SPI, CoLeFunDa | contrastive learning, function-change augmentation | PLM embeddings |
| VulCurator | multi-modal (message + code + issue) | ensemble |
| XGV-BERT, CSGVD | **CodeBERT + GNN** fusion | hybrid |

Recurring finding: **surface features don't separate security fixes from
ordinary code**; you need semantic code embeddings or graph structure. Class
imbalance is brutal — real fixes are <1% of commits, so precision collapses
without a pre-filter (VulFixMiner's title says it: *finding a needle in a
haystack*).

### B. Patch backlinking — *recover known* silent fixes from advisories
Start from a confirmed advisory and trace to the fixing commit. High precision,
but only covers vulns that eventually got an advisory.

- **VCMatch**, **PatchScout**, **Midas** — rank commits for a given CVE by
  feature similarity (code, message, CVE text).
- **OSV** structured data — `affected[].ranges[].events[].fixed` gives the exact
  fixing commit/version; `references[type=FIX]` links the patch.

### C. LLM-based (recent, 2024–2026) — training-free
The axis this project ultimately uses.

| work | approach | trained? |
|---|---|---|
| **LLM4VFD**, arXiv 2501.14983 (2025) | CoT over **diff + dev-artifacts (issue/PR) + history-RAG**; +68–145% F1 over PLM baselines | no — prompting only |
| **From LLMs to Agents**, arXiv 2511.08060 (2025) | zero-shot LLM / ReAct agent for security-patch detection; agent reaches graph-level precision (**86%**); notes **LLM×graph is unexplored** | no |
| **LLMDA** (Just-in-Time Detection of Silent Security Patches), arXiv 2312.01241 | LLM-generated patch explanations + code-text alignment; beats GraphSPD +20% F1 | yes |
| **VulReaD**, arXiv 2602.10787 (2026) | **knowledge-graph-guided** LLM reasoning (anchors CWE semantics, cuts hallucination) | yes (LoRA/ORPO) |
| **Vul-RAG** (2024) | knowledge-level RAG + LLM | mostly no |

Key takeaways for a *training-free* setting: (a) LLM4VFD-style prompting works
without fine-tuning; (b) diff + artifacts are the signal; (c) light structural
("graph-lite") context is a cheap, largely-unexplored add-on; (d) LLMs still
need a pre-filter because of the base-rate problem; (e) commercial models beat
open ones, but strong open code-models are close.

---

## 2. The algorithm in this repo

We implement **both** working families and reject what doesn't survive
validation. The guiding discipline: **a signal ships only if it survives an
*applied-ranking* spot-check**, not just an aggregate metric (a TF-IDF model
with CV-AUC 0.97 was killed because it ranked features above real fixes).

### Pipeline

```
  raw crawl (11 clients)                         [collection/]
        │  advisories · stealth PRs · commits · releases · CVE/OSV/RustSec
        ▼
  build_derived → merge → cross_reference (dedup)
        ▼
  data/raw/train.classified.parquet   (~18.5k rows)
        │
        ▼  pipeline/build_security_dataset.py  (deterministic gate + tiering)
        │
        ├─ T1  drop release-note boilerplate
        ├─ T2  drop CI/docs/dep-bump meta-work (title-anchored; advisory-id/
        │      strong-kw/severity protected)
        ├─ T2b drop NVD substring-match false positives (glibc/X.Org/… mis-hits)
        ├─ GATE keep a row on ANY independent signal
        ├─ authority_tier  A_authoritative · B_corroborated · C_candidate
        ├─ n_signals       count of independent signals
        └─ fix_commit      from /commit/ URLs                 ← method B (backlink)
        ▼
  data/ethereum_vulns.parquet   (essential slice = tier A∪B)
```

### Signals feeding the gate / tiering (`count_signals`)
Independent, order-free; ≥2 stacking promotes C→B:
1. advisory **id** (CVE/GHSA/RustSec)  ·  2. rated **severity**
3. strong security keyword  ·  4. moderate bug-class keyword
5. **sensitive subsystem** touched (A2 "graph-lite": fork-choice, evm, p2p, kzg…)
6. **fix-verb × crash-class impact** co-occurrence ("fix panic on …")
7. LLM STRIDE / CWE (if a classification pass was run)
8. **learned silent-fix classifier** — `silent_fix_prob ≥ 0.70`  ← method A

### Method B — patch backlinking (`collection/crawl_osv.py`, `fix_commit`)
OSV's structured `introduced`/`fixed` events are extracted into
`introduced_in_commit` + a fix backlink; `fix_commit` is pulled from `/commit/`
source URLs. Deterministic, high precision, bounded to advisory-covered vulns.

### Method A — training-free LLM classifier (`collection/llm_classify_fixes.py`)
LLM4VFD-style, **no training, no torch**:

```
  row → diff (via local_diffs, rate-limit-free) ─┐
        title + description (dev artifacts) ──────┼─► CoT prompt ─► LLM ─► JSON
        sensitive subsystem (graph-lite) ─────────┘        {is_security_fix,
                                                             confidence, vuln_class}
        → silent_fix_prob = confidence if fix else 1-confidence
        → ≥0.70 counts as an independent signal (promotes C→B)
```

- **Diffs:** `collection/local_diffs.py` serves them from a bare **blobless git
  clone** (geth = 21 MB / 1.7 s) with a persistent cache + delta `git fetch` —
  no GitHub REST rate limit, and re-runs only fetch new rows. Falls back to `gh`
  for the rare divergent-fork PR.
- **Model:** `gemma4:31b` (chosen by an 80-item eval sweep — F1 0.872, precision
  0.895, recall 0.85; see [`model_evaluation.md`](./model_evaluation.md)). Runs
  off-Claude via the env's Ollama-Cloud route (`--engine openai`); Claude and
  local Ollama are also selectable.
- **Graph-lite, not full graph:** we feed the touched security-sensitive
  subsystem as context — the cheap LLM×graph combination the 2025 survey calls
  unexplored. Full CPG/GNN would need training and a code checkout.

### What we rejected (validated negatives)
- **Regex diff classifier** (`detect_silent_fixes.py`) — surface guard/impact
  regexes don't discriminate (ranking inverted, then collapsed to ≈chance).
  This reproduces the literature's reason for using learned embeddings.
- **TF-IDF patch-as-document classifier** (`train_silent_fix_classifier.py`) —
  CV-AUC 0.97 but *misleading*: dep-bump/manifest confound, then topic-vocabulary
  overfitting; in deployment it ranked features above real fixes. Not shipped.
- **Multi-agent consensus** (devstral + qwen, majority vote) — no gain over the
  best single model; the models' errors are correlated (devstral+qwen are
  nested). Only `AND(gemma,qwen)` is useful, as a 0.93-precision sub-tier.

### Result
The learned silent-fix pass classified 339 `C_candidate` diffs and promoted
**166** real silent fixes (133 DoS / 16 consensus / 11 validation …) into the
corroborated tier. Essential slice (A∪B): **173 → 1,535** across the project.

---

## References
- Sabetta & Bezzi, *A practical approach to the automatic classification of security-relevant commits*, ESEM 2018.
- Zhou et al., *VulFixMiner: Finding a Needle in a Haystack — Automated Mining of Silent Vulnerability Fixes*, ASE 2021.
- Wang et al., *GraphSPD: Graph-Based Security Patch Detection with Enriched Code Semantics*, IEEE S&P 2023 — https://csis.gmu.edu/ksun/publications/SP23_GraphSPD.pdf
- *Just-in-Time Detection of Silent Security Patches* (LLMDA), arXiv 2312.01241.
- *Code Change Intention, Development Artifact and History Vulnerability … by LLM* (LLM4VFD), arXiv 2501.14983.
- *From LLMs to Agents: … LLMs and LLM-based Agents in Security Patch Detection*, arXiv 2511.08060.
- *VulReaD: Knowledge-Graph-guided Software Vulnerability Reasoning and Detection*, arXiv 2602.10787.
- *Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG*, arXiv 2406.11147.
- OSV schema — https://ossf.github.io/osv-schema/ ; VCMatch / PatchScout (CVE→commit ranking).

_See also [`model_evaluation.md`](./model_evaluation.md) for model benchmarks and
`collection/IMPROVEMENT_LOG.md` for the full iteration ledger._
