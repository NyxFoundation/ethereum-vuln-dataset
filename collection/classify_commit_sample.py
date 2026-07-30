#!/usr/bin/env python3
"""Classify a probability sample of client commits, to estimate population rates.

The curated corpus was found by keyword search, so it cannot say what fraction of
security-relevant fixes are silent — the sample was selected by the very language whose
absence defines "silent". This classifies an unbiased sample instead, which can.

Two quantities are asked of each commit, and they are separate:

* ``security_relevant`` — does the change fix a defect that could affect consensus
  correctness, node availability, fund or state integrity, or operator safety? Features,
  refactors, docs, tests, CI, dependency bumps and pure performance work are not.
* ``disclosure`` — if it is such a fix, does its own message say so? ``explicit_security``
  names a CVE, GHSA or advisory or calls it a security fix; ``implied_fix`` names the
  failure (panic, overflow, race) so a keyword crawler would find it; ``silent`` gives no
  indication at all and is visible only in the diff.

The second is the paper's central claim made measurable: the silent share among
security-relevant fixes, with a confidence interval, from a sample that was not chosen for
its wording.

The prompt is written against the failure mode this repository has repeatedly hit — a model
asked "is this security-relevant?" says yes too often. It therefore demands a quoted line
from the diff as evidence and instructs that an unquotable judgement is a no.

Diffs come from the local bare clones, so this makes no API calls for data. Results are
cached by ``sha@prompt_version@engine:model``, so a prompt or model change re-runs rather
than silently reusing answers to a different question.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import llm_classify_fixes as llm  # noqa: E402

PROMPT_VERSION = "commit-sample-v1"
REPO_DIR = Path("scratchpad_crawl/repos")
DIFF_CHARS = 6000

DEFECT_CLASSES = (
    "memory_safety", "input_validation", "consensus_divergence", "resource_exhaustion",
    "concurrency", "arithmetic", "state_corruption", "cryptography", "other", "none",
)


def cache_key(sha: str) -> str:
    model = llm.ENGINE.get("model") or "default"
    return f"{sha}@{PROMPT_VERSION}@{llm.ENGINE.get('engine')}:{model}"


def commit_text(client: str, sha: str, repo_dir: Path) -> tuple[str, str]:
    """Return (message, diff) for a commit, read from the local clone."""
    repo = repo_dir / f"{client}.git"
    if not repo.exists():
        return "", ""
    msg = subprocess.run(
        ["git", "-C", str(repo), "show", "-s", "--format=%s%n%n%b", sha],
        capture_output=True, text=True, errors="replace",
    ).stdout
    diff = subprocess.run(
        ["git", "-C", str(repo), "show", sha, "--format=", "--unified=3"],
        capture_output=True, text=True, errors="replace",
    ).stdout
    return msg, diff


def build_prompt(client: str, message: str, diff: str) -> str:
    return f"""You are triaging one commit from the {client} Ethereum client to estimate how
often such commits fix security-relevant defects, and how often those fixes are silent.

A commit is SECURITY-RELEVANT only if it fixes a defect that could affect one of:
  - consensus correctness (a node computing a different result from its peers),
  - node availability (crash, panic, hang, deadlock, unbounded resource use),
  - fund or state integrity (incorrect balances, state, proofs, signatures),
  - operator safety (key exposure, unauthenticated access to privileged endpoints).

It is NOT security-relevant if it is a feature, refactor, rename, test-only change, CI or
build change, documentation, logging, metrics, a dependency bump, or a performance change
with no correctness consequence. Adding a check that was never reachable in a broken state
is hardening, not a fix — say no.

Judge from the DIFF, not the message. You must quote one line of the diff as evidence. If
you cannot quote a line that shows the defect being fixed, the answer is false.

Then, only if it is security-relevant, classify how the commit message discloses it:
  - "explicit_security": names a CVE, GHSA, advisory, or calls it a security/vulnerability fix
  - "implied_fix": names the failure (panic, crash, overflow, race, leak, deadlock, DoS) so a
    keyword search over commit messages would find it
  - "silent": the message gives no indication; only the diff reveals it

Commit message:
{message[:1500]}

Diff (truncated):
{diff[:DIFF_CHARS] or '(no diff)'}

Output ONLY one JSON object on the last line:
{{"security_relevant":true|false,"confidence":0.0,"defect_class":"one of {'|'.join(DEFECT_CLASSES)}","disclosure":"explicit_security|implied_fix|silent|none","evidence":"<one quoted diff line>","why":"<one sentence>"}}"""


def extract_json(text: str) -> dict:
    """Pull the answer object out of a model reply.

    A regex that forbids nested braces is wrong here: the ``evidence`` field quotes a line
    of source, which routinely contains ``{`` or ``}``, so such a pattern silently fails on
    exactly the commits that produced evidence. This scans for brace-balanced spans
    instead, taking the last one that parses and carries the answer field.
    """
    best: dict = {}
    for start in (i for i, ch in enumerate(text) if ch == "{"):
        depth = 0
        in_string = False
        escaped = False
        for end in range(start, len(text)):
            ch = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        candidate = json.loads(text[start:end + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(candidate, dict) and "security_relevant" in candidate:
                        best = candidate
                    break
    return best


def classify(job, retries=1):
    client, sha, message, diff = job
    out: dict = {}
    for _ in range(retries + 1):
        try:
            raw = llm._call_llm(build_prompt(client, message, diff))
            out = extract_json(raw)
        except Exception as exc:  # noqa: BLE001 - recorded, not raised
            out = {"error": str(exc)}
        if "security_relevant" in out:
            break
    # A commit claimed security-relevant without a quoted diff line fails the prompt's own
    # evidence rule, so it is demoted here rather than trusted.
    if out.get("security_relevant") and not str(out.get("evidence") or "").strip():
        out["security_relevant"] = False
        out["evidence_missing"] = True
    out["prompt_version"] = PROMPT_VERSION
    out["model"] = str(llm.ENGINE.get("model") or "")
    return sha, out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=Path, default=Path("data/commit_sample.csv"))
    ap.add_argument("--repo-dir", type=Path, default=REPO_DIR)
    ap.add_argument("--cache", type=Path,
                    default=Path("scratchpad_crawl/commit_sample_cache.json"))
    ap.add_argument("--out", type=Path, default=Path("data/commit_sample_labels.csv"))
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0)
    import os
    ap.add_argument("--engine", default="openai")
    ap.add_argument("--model", default="glm-5.2")
    ap.add_argument("--base-url", default="https://ollama.com/v1")
    ap.add_argument("--api-key-env", default="OLLAMA_API_KEY")
    args = ap.parse_args()
    llm.ENGINE.update(engine=args.engine, model=args.model, base_url=args.base_url,
                      api_key=os.environ.get(args.api_key_env, ""))

    sample = pd.read_csv(args.sample)
    if args.limit:
        sample = sample.head(args.limit)
    cache = json.loads(args.cache.read_text()) if args.cache.exists() else {}

    todo = [r for r in sample.to_dict("records") if cache_key(r["sha"]) not in cache]
    print(f"[sample] {len(sample)} commits, {len(todo)} to classify "
          f"({len(sample) - len(todo)} cached at {PROMPT_VERSION})", file=sys.stderr)

    jobs = []
    for record in todo:
        message, diff = commit_text(record["client"], record["sha"], args.repo_dir)
        jobs.append((record["client"], record["sha"], message, diff))

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for sha, result in pool.map(classify, jobs):
            cache[cache_key(sha)] = result
            done += 1
            if done % 25 == 0:
                args.cache.write_text(json.dumps(cache))
                print(f"  [sample] {done}/{len(jobs)}", file=sys.stderr, flush=True)
    args.cache.write_text(json.dumps(cache))

    rows = []
    for record in sample.to_dict("records"):
        result = cache.get(cache_key(record["sha"]), {})
        rows.append({
            **{k: record[k] for k in ("sha", "client", "author_date", "year", "subject",
                                      "weight")},
            "security_relevant": result.get("security_relevant"),
            "defect_class": result.get("defect_class", ""),
            "disclosure": result.get("disclosure", ""),
            "confidence": result.get("confidence", ""),
            "evidence": str(result.get("evidence", ""))[:300],
            "why": str(result.get("why", ""))[:300],
            "classified": "security_relevant" in result,
        })
    out = pd.DataFrame(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False)
    n = int(out["classified"].sum())
    hits = int(out["security_relevant"].eq(True).sum())
    print(f"wrote {args.out}: {n}/{len(out)} classified, {hits} security-relevant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
