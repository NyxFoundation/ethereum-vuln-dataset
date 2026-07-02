# Silent-fix classifier — model evaluation

Evaluation of LLM backends for the training-free silent-fix classifier
(`collection/llm_classify_fixes.py`). All numbers are on **one fixed 80-item
eval set** (40 positive / 40 negative) so every model and ensemble is directly
comparable. Runs on **Ollama Cloud** via the environment's `hermes-agent`
(OpenAI-compatible `https://ollama.com/v1`); `claude -p` (Opus) is the baseline.

_Last updated: 2026-07-02._

## Method

- **Task:** given a code diff + dev artifacts (title/description) + a "graph-lite"
  hint (the security-sensitive subsystem touched), decide `is_security_fix`
  with a confidence, via a Chain-of-Thought prompt (LLM4VFD-style, arXiv
  2501.14983). No training / fine-tuning.
- **Labels:** unambiguous title-based ground truth — positives are explicit
  "fix panic/crash/overflow/race/consensus…" changes; negatives are clear
  feature/refactor/perf. Vendored-dep, revert, and test/CI-only changes are
  excluded from positives. (The LLM often reasons *more* precisely than these
  labels — attacker-reachability, prod-vs-test — so measured F1 slightly
  understates true quality.)
- **Discipline:** every candidate is judged on precision/recall/F1 **and** the
  applied-confidence ranking; a good aggregate that ranks features above real
  fixes is rejected. (A TF-IDF classifier with CV-AUC 0.97 was killed this way.)
- **Caveat:** at n=80 there is ~±0.05 run-to-run variance, so gaps under ~0.06
  are not meaningful. "Speed" = wall-clock for all 80 items at the noted worker
  count against Ollama Cloud (network-bound, indicative not benchmark-grade).

## Single-model results

| engine · model | precision | recall | F1 | errors | speed (80 items) | notes |
|---|---|---|---|---|---|---|
| **openai · gemma4:31b** ⭐ **default** | **0.895** | 0.850 | **0.872** | 0 | ~137s (6w) | best F1; two clean runs identical (0.872) |
| openai · devstral-2:123b | 0.78 | 0.90 | 0.84 / 0.84 | 0 | ~170s (8w) | consistent ×2, high recall |
| openai · nemotron-3-nano:30b | 0.78 | 0.90 | 0.83 / 0.84 | 0 | ~150s (8w) | matches devstral, smaller |
| _claude · opus (baseline)_ | 0.93 | 0.68 | 0.78 | 0 | — | highest precision, lower recall |
| openai · qwen3-coder:480b | 0.90 | 0.65 | 0.75 | 0 | ~112s (8w) | precision-leaning |
| openai · gpt-oss:120b | 0.74 | 0.78 | 0.76 | 1 | ~94s (8w) | balanced |
| openai · qwen3-coder-next | 0.75 | 0.38 | 0.50 | 0 | ~55s (8w) | weak recall |
| openai · gemma4:31b (run under contention) | 1.00 | 0.13 | 0.22 | **73** | ~45s | JSON truncated by concurrent-sweep API contention; not representative |
| openai · kimi-k2.7-code | — | — | — | — | **>320s timeout** | fast on trivial prompts, very slow on real diffs |
| openai · glm-5 / qwen3.5:397b / deepseek-v3.2 | — | — | — | — | ~20–45s **per call** | reasoning models, impractical at scale |

**Winner: `gemma4:31b`** — near-Claude precision (0.895 vs 0.93) *and* higher
recall (0.85 vs 0.68), best F1 (0.872, beats Claude's 0.78), 0 parse errors,
reproducible. `--model` empty resolves to it for the `openai` engine.

### Latency note (trivial probe vs real prompt)
A one-line "reply ok" probe is misleading: gemma4:31b 0.5s, qwen3-coder-next
0.7s, kimi 1.1s, gpt-oss:120b 2.1s — but on the full ~5k-char diff prompt kimi
blows past 320s and glm-5/qwen3.5/deepseek run 20–45s **per call** (hours for a
500-row production run). Pick the default on *real-prompt* speed × accuracy.

## Multi-agent / consensus

Computed offline by combining saved per-model predictions on the same eval set
(no extra calls).

| strategy | precision | recall | F1 |
|---|---|---|---|
| gemma4:31b solo (best single) | 0.895 | 0.850 | **0.872** |
| majority(gemma, devstral, qwen) | 0.872 | 0.850 | 0.861 |
| majority(gemma, devstral, nemotron) | 0.818 | 0.900 | 0.857 |
| majority(5 models) | 0.854 | 0.875 | 0.864 |
| **AND(gemma, qwen)** — precision-max | **0.929** | 0.650 | 0.765 |
| AND(gemma, devstral) | 0.895 | 0.850 | 0.872 |
| OR(gemma, devstral) — recall-max | 0.771 | 0.925 | 0.841 |
| devstral + qwen: AND | 0.897 | 0.650 | 0.754 |
| devstral + qwen: OR | 0.771 | 0.925 | 0.841 |

**Finding: consensus does not beat the best single model here.** The models'
errors are *correlated* (they read the same code signal), so ensembles only
slide along the precision/recall curve a single confidence threshold already
covers — majority votes score slightly *below* gemma solo. In particular
**devstral + qwen are nested** (qwen's positives ⊂ devstral's), so their AND =
qwen's operating point and OR = devstral's — zero synergy.

**The one useful ensemble:** `AND(gemma, qwen)` reaches **0.929 precision**
(Claude-level) — worth a 2× cost only when you want a precision-max sub-tier
(e.g. auto-promote near-certain fixes). For general use, gemma solo dominates on
cost and F1.

## How to run

```bash
export OLLAMA_API_KEY="$(grep ^OLLAMA_API_KEY= ~/.hermes/.env | cut -d= -f2-)"

# default engine (gemma4:31b) on the eval set
uv run python collection/llm_classify_fixes.py --run \
  --engine openai --base-url https://ollama.com/v1 --api-key-env OLLAMA_API_KEY

# precision-leaning single model
#   ... --model qwen3-coder:480b
# Anthropic baseline
#   ... --engine claude
```

Diffs are served rate-limit-free by `collection/local_diffs.py` (bare blobless
clone + persistent cache + delta `git fetch`), so a full off-Claude,
cache-resumable classification run over the dataset is practical.
