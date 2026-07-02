# Self-recursive improvement loop — collection coverage

Durable state for the `/loop` self-improvement run (context resets between
wake-ups; this file is the memory). Each iteration: **acquire additional diff →
evaluate → improve**, repeated until vulnerability coverage saturates
(loop-until-dry: N consecutive iterations add no new distinct vulns).

## Baseline (before loop) — 2026-07-02
- curated rows: **2096**, rated-severity: **173** (8.3%), high-confidence: **382**
- Diagnosis: volume-driven (60k+ commit-grep rows), only a tiny authoritative core
  carries real severity. Hidden fixes detected by a single weak signal (body keyword).

## Planned program (from the two assessments)
Authority sources: **[A] per-repo GHSA advisories**, [B] repo-specific security
labels, [C] NVD CPE-match (fix false positives). Hidden-fix signals: [D6]
advisory→patched-tag→commit backlink (ground truth), [A2] small-diff × sensitive
path × vague message, [B4] review-comment security language, [C5] linked-issue /
fuzzer report, [A1] cherry-pick/backport. Architecture: **multi-signal scoring**
(≥2 independent signals) + `authority_tier` column.

## Iteration ledger
| # | signal implemented | essential (A+B) | curated rows | rated/Crit | notes |
|---|---|---|---|---|---|
| 0 | baseline | 173 | 2096 | 173 / 0 | pre-loop |
| 1 | [A] GHSA spine + [A2] sensitive-path + T2 de-noise + authority_tier | **934** | 1926 | 173 / **3** | +25 GHSA (deduped into PR refs), 170 CI/docs/dep-bump FPs removed from curated (1417 from raw); new cols n_signals, authority_tier. Essential slice now selectable & 5.4× larger. |
| 2 | [C] T2b NVD substring-match FP filter (+ source fix in crawl_cve.py) | 885 | 1877 | 173 / 3 | **Authoritative tier was 17% garbage** — "geth" matched as substring in gethostbyaddr/GetHost/"Gether Technology"/Linux usb. Dropped 49 unrelated CVEs (glibc/X.Org/Samba/kernel); 6 real client CVEs kept. Precision iteration: A-tier now clean. |
| 3 | [C5'] fix-verb × impact co-occurrence signal | **1367** | 1877 | 173 / 3 | **C5-via-API dead end**: client PRs almost never use formal `Closes #N` (0/116 inline-ref PRs had closingIssuesReferences). Pivoted to the offline reservoir: "fix panic on…"/"prevent race in…" adjacency is a strong independent defect signal. +482 crash/DoS fixes promoted C→B. 907 rows now ≥2 signals (was 376). `enrich_linked_issues.py` kept as a tool (with `--require-inline-ref`). |

| 4 | fix-impact added to the GATE (title-level, recall) + test coverage | 1367 | 1878 | 173 / 3 | Title-level fix-impact admits only **+1** new row — title crash fixes already score ≥0.5. Description-level would admit 200 but pulls release-note noise (rejected). **Deterministic recall is saturated.** |

**Loop status — deterministic techniques exhausted (loop-until-dry hit).**
Recall was flat across all 4 iterations (corpus already ~complete at 18,475 raw
/ 1,878 curated); the wins were **precision + tiering**: essential slice
173 → 1367 (7.9×), authoritative tier de-garbaged (−49 unrelated CVEs), −1417
CI/docs/dep-bump noise. Two consecutive iterations (3,4) added <10 new corpus
rows → termination condition met for deterministic signals.

| 5 | silent-fix detection research (diff-classifier + patch-backlinking) | 1367 | 1878 | 173 / 3 | Two branches implemented. **(a) Code-diff feature classifier** (VulFixMiner/GraphSPD-style, `detect_silent_fixes.py`): **validated negative** — no discrimination (broad guards invert the ranking; tight guards collapse to ≈0), reproducing why the research needs code embeddings not regex. NOT wired into the gate. **(b) Patch backlinking** (VCMatch/PatchScout branch, `crawl_osv.py`): extract OSV `fixed` commit/version — 21 advisories now carry deterministic fix backlinks (curated impact ~1 due to cross-ref dedup). |

**Silent-fix research — what worked vs didn't (2026-07-02):**
- ❌ Regex/metadata approximation of code-change classifiers (VulFixMiner,
  GraphSPD): surface patterns don't separate security fixes from ordinary code.
  Needs learned embeddings (CodeBERT / CPG) — infra out of scope here.
- ✅ Patch backlinking (advisory → fixed commit/version via OSV structured
  ranges): deterministic, high-precision, fills fix-provenance. Limited reach
  (only CVE/GHSA-covered advisories) and dedup-collapsed in curation.
- Takeaway: without a trained model, silent-fix *detection* (of unknown fixes)
  is not reliably solvable by regex; silent-fix *recovery* (of known ones) is.

| 6 | **Learned silent-fix classifier (method 1, done right)** | 1367 | 1878 | 173 / 3 | User course-correction: drop ad-hoc heuristics, narrow to the research's methods. Built a Sabetta&Bezzi-style patch-as-document classifier (TF-IDF diff tokens + LogReg, torch-free). **ROC-AUC 0.971 / PR-AUC 0.975** (5-fold CV) — vs the regex proxy's 0.50. The *same* data regex couldn't split is highly separable by a *learned* model, exactly as the research predicts. `train_silent_fix_classifier.py`; model saved. Next: apply to C_candidate, wire as `silent_fix_signal`. |

| 6b | apply learned classifier + **honest deployment validation** | 1367 | 1878 | 173 / 3 | Applied the model and **spot-checked the ranking** — twice caught it failing: (1) top rows were `/docs` dep-bumps → 47% of positives were dep-bumps / 36% manifest-only diffs (confound); (2) after forcing source-code-only labels, CV-AUC stayed 0.97 but feature/CI PRs ranked highest, real fixes lowest (TF-IDF learns topic vocab, not fix semantics, on ~44 positives). **Not shipped**; dataset restored to validated-signals-only. `silent_fix_prob` column removed. |

**Focus (per user): silent-fix research reduces to 2 methods —**
1. **Learned code-change classifier** (Sabetta&Bezzi'18 → VulFixMiner'21 →
   GraphSPD'23). ❌ **Not deployable here.** Torch-free TF-IDF + small in-domain
   labels gives a *misleading* CV-AUC (0.97) that collapses on the real
   application distribution — it learns topic vocabulary, not fix-vs-non-fix.
   The research works because it uses a LARGE labelled corpus + SEMANTIC code
   embeddings (CodeBERT/CPG); neither is available torch-free here. Harness kept
   (`train_silent_fix_classifier.py`) for when embeddings/labels exist.
2. **Patch backlinking** (VCMatch/PatchScout/OSV). ✅ **The one shipped silent-fix
   technique** (iter 5): recovers *known* silent fixes from advisories with the
   exact fixed commit/version. High precision, bounded reach (CVE/GHSA-covered).

**Meta-lesson (the value of this loop):** rigorous evaluation = spot-check the
*applied* ranking, not just CV metrics. Two "0.97 AUC" models were caught being
useless in deployment. Only ship a signal that survives application spot-check.
The iter 3–4 keyword/path signals are NOT from silent-fix research and are
retained only as coarse tiering hints, subordinate to method 2.

**Remaining levers require a technique switch (heavier / user-gated):**
- [A1] cherry-pick/backport via local clones — the one untapped *new-source*
  (geth silently backports fixes to release branches). Uncertain yield, ~1 GB
  clones. **Next iteration to attempt.**
- [B4] review-comment mining — per-PR API, slow, low expected yield (like C5).
- **LLM STRIDE/CWE classification** — the biggest recall lever by far (admits the
  ~16k unrated stealth fixes the keyword gate drops), but the user deferred it
  ("ひとまずskip"). Re-enabling it is the real path to *comprehensive* coverage.

### Next iterations (API-heavy hidden-fix signals — recall expansion)
- **iter 2** [C5] linked-issue / fuzzer-report signal: `gh pr view --json closingIssuesReferences`, score issue body for crash/panic/fuzz + reporter (oss-fuzz/Guido Vranken).
- **iter 3** [B4] review-comment security language: `gh api /repos/{}/pulls/{}/comments` — "exploit"/"DoS"/"request a CVE".
- **iter 4** [A1] cherry-pick/backport: local clone `git log --grep "cherry picked from"` + release-branch-only commits.
- **iter 5** [D6] advisory→patched-tag→commit diff: resolve `patched_versions` to tag, diff prev..patch, extract fix commits (ground truth for calibration).
- Enrichment writes per-row signal columns (comment_signal / linked_issue_signal / backport_signal) that `count_signals()` already consumes → promotes real fixes to B without touching the gate.
- **Termination (loop-until-dry):** stop when 2 consecutive iterations add < ~10 new distinct essential (A+B) vulns.
</content>
