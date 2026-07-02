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

**Loop status:** deterministic precision+recall largely worked through. Essential
slice 173 → 1367 (7.9×) across 3 iterations. Remaining levers are heavier:
[A1] cherry-pick/backport (needs local clones), [B4] review-comment mining
(per-PR API), and the deferred LLM STRIDE/CWE classification (biggest recall
lever — would admit the ~16k unrated stealth fixes; user deferred it, "ひとまずskip").

### Next iterations (API-heavy hidden-fix signals — recall expansion)
- **iter 2** [C5] linked-issue / fuzzer-report signal: `gh pr view --json closingIssuesReferences`, score issue body for crash/panic/fuzz + reporter (oss-fuzz/Guido Vranken).
- **iter 3** [B4] review-comment security language: `gh api /repos/{}/pulls/{}/comments` — "exploit"/"DoS"/"request a CVE".
- **iter 4** [A1] cherry-pick/backport: local clone `git log --grep "cherry picked from"` + release-branch-only commits.
- **iter 5** [D6] advisory→patched-tag→commit diff: resolve `patched_versions` to tag, diff prev..patch, extract fix commits (ground truth for calibration).
- Enrichment writes per-row signal columns (comment_signal / linked_issue_signal / backport_signal) that `count_signals()` already consumes → promotes real fixes to B without touching the gate.
- **Termination (loop-until-dry):** stop when 2 consecutive iterations add < ~10 new distinct essential (A+B) vulns.
</content>
