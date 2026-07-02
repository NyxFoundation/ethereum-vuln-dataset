#!/usr/bin/env python3
"""local_diffs.py — serve PR/commit diffs from a local git clone.

Drop-in replacement for the per-item `gh pr diff` / `gh api /commits` calls used
by the classifiers. Git transport (clone/fetch) is NOT subject to the REST API's
5,000/hr or the secondary-rate-limit 403s we fought with — so this removes the
rate-limit ceiling and turns each diff fetch from a ~0.3-1s network call into a
~1-5ms local `git` read.

Design:
  * One bare, blobless clone per client (`--filter=blob:none`): fast to create,
    full commit/tree graph, blobs fetched lazily on first access (still git
    transport, no REST limit). Cached under scratchpad_crawl/repos/<client>.git.
  * commit SHA  -> `git show` (fetch the object on demand if absent).
  * PR number   -> ensure refs/pull/N/head, then diff merge-base(default,head)
    ..head — the same 3-dot semantics as `gh pr diff`, so diffs match the cache.

CLI:
  warm  --client geth                 # create/refresh the local clone
  diff  --client geth --url <github url>
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

CLIENT_REPOS: dict[str, str] = {
    "geth": "ethereum/go-ethereum", "nethermind": "NethermindEth/nethermind",
    "besu": "hyperledger/besu", "erigon": "erigontech/erigon",
    "reth": "paradigmxyz/reth", "lighthouse": "sigp/lighthouse",
    "lodestar": "ChainSafe/lodestar", "nimbus": "status-im/nimbus-eth2",
    "prysm": "prysmaticlabs/prysm", "teku": "Consensys/teku",
    "grandine": "grandinetech/grandine",
}
REPO_DIR = Path("scratchpad_crawl/repos")
PR_RE = re.compile(r"github\.com/[^/]+/[^/]+/pull/(\d+)")
SHA_RE = re.compile(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", re.I)


def _run(args, timeout=600):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def repo_path(client: str) -> Path:
    return REPO_DIR / f"{client}.git"


def ensure_clone(client: str, blobless: bool = True) -> Path:
    p = repo_path(client)
    if (p / "HEAD").exists():
        return p
    p.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{CLIENT_REPOS[client]}.git"
    args = ["git", "clone", "--bare"] + (["--filter=blob:none"] if blobless else []) + [url, str(p)]
    print(f"[local_diffs] cloning {url} (bare{'/blobless' if blobless else ''})…", file=sys.stderr)
    r = _run(args, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed for {client}: {r.stderr[:300]}")
    return p


def _default_ref(p: Path) -> str:
    r = _run(["git", "-C", str(p), "symbolic-ref", "--short", "HEAD"])
    return f"refs/heads/{r.stdout.strip()}" if r.returncode == 0 and r.stdout.strip() else "HEAD"


def get_commit_diff(client: str, sha: str) -> str | None:
    p = ensure_clone(client)
    if _run(["git", "-C", str(p), "cat-file", "-e", sha]).returncode != 0:
        _run(["git", "-C", str(p), "fetch", "--quiet", "origin", sha], timeout=300)
    r = _run(["git", "-C", str(p), "show", "--format=", "--unified=3", sha])
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


def warm_prs(client: str) -> None:
    """Bulk-fetch every PR head ref so all PR diffs are served locally/instantly.
    One fetch per repo (~+120 MB blobless for geth) instead of a network call per
    PR — turns the 17k-row classification into an LLM-bound-only job."""
    p = ensure_clone(client)
    r = _run(["git", "-C", str(p), "fetch", "--filter=blob:none", "--quiet",
              "origin", "+refs/pull/*/head:refs/pull/*/head"], timeout=1200)
    n = _run(["git", "-C", str(p), "for-each-ref", "refs/pull/", "--format=x"]).stdout.count("x")
    print(f"[local_diffs] {client}: {n} PR refs local"
          + ("" if r.returncode == 0 else " (some conflicts skipped)"), file=sys.stderr)


def _resolve_pr_ref(p: Path, n: str) -> str | None:
    """PR head ref, tolerating both layouts (refs/pull/N/head and refs/pull/N)."""
    for ref in (f"refs/pull/{n}/head", f"refs/pull/{n}"):
        if _run(["git", "-C", str(p), "rev-parse", "--verify", "--quiet", ref]).returncode == 0:
            return ref
    return None


def get_pr_diff(client: str, n: str) -> str | None:
    p = ensure_clone(client)
    ref = _resolve_pr_ref(p, n)
    if ref is None:
        target = f"refs/pull/{n}/head"
        if _run(["git", "-C", str(p), "fetch", "--quiet", "origin",
                 f"{target}:{target}"], timeout=300).returncode != 0:
            return None
        ref = target
    head = _run(["git", "-C", str(p), "rev-parse", ref]).stdout.strip()
    if not head:
        return None
    base = _run(["git", "-C", str(p), "merge-base", _default_ref(p), head]).stdout.strip()
    # No common ancestor (e.g. an unrelated-history fork) -> we cannot reproduce
    # GitHub's diff locally; signal miss so the caller falls back to `gh`.
    if not base:
        return None
    r = _run(["git", "-C", str(p), "diff", "--unified=3", f"{base}..{head}"])
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


def diff_for_url(url: str, client: str) -> str | None:
    m = SHA_RE.search(url)
    if m:
        return get_commit_diff(client, m.group(1))
    m = PR_RE.search(url)
    if m:
        return get_pr_diff(client, m.group(1))
    return None


def refresh(client: str) -> None:
    """Delta fetch: pull only new objects into an existing clone (cheap)."""
    p = repo_path(client)
    if not (p / "HEAD").exists():
        ensure_clone(client)
        return
    r = _run(["git", "-C", str(p), "fetch", "--filter=blob:none", "--quiet",
              "--prune", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"],
             timeout=900)
    print(f"[local_diffs] {client} refreshed" + ("" if r.returncode == 0 else f" (warn: {r.stderr[:120]})"),
          file=sys.stderr)


def _gh_fallback(url: str, client: str) -> str | None:
    """Rare fork-PR cases where the local 3-dot diff is unreliable -> use gh."""
    repo = CLIENT_REPOS[client]
    m = PR_RE.search(url)
    if m:
        r = _run(["gh", "pr", "diff", m.group(1), "--repo", repo], timeout=60)
    else:
        m = SHA_RE.search(url)
        if not m:
            return None
        r = _run(["gh", "api", f"/repos/{repo}/commits/{m.group(1)}",
                  "--jq", ".files[] | .patch // empty"], timeout=60)
    return r.stdout if r.returncode == 0 and r.stdout.strip() else None


def get_diff_cached(url: str, client: str, cache: dict, allow_gh: bool = True) -> str | None:
    """Canonical diff provider: persistent JSON cache -> local git -> gh fallback.

    Re-runs pay nothing for already-seen URLs; new rows fetch only their own
    objects (git transport, no REST rate limit). `cache` is mutated in place;
    the caller persists it. An empty-string cache entry means "known-missing".
    """
    if url in cache:
        return cache[url] or None
    d = diff_for_url(url, client)
    if d is None and allow_gh:
        d = _gh_fallback(url, client)
    cache[url] = d or ""
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("warm"); w.add_argument("--client", required=True)
    wp = sub.add_parser("warm-prs"); wp.add_argument("--client", required=True)
    rf = sub.add_parser("refresh"); rf.add_argument("--client", required=True)
    d = sub.add_parser("diff")
    d.add_argument("--client", required=True); d.add_argument("--url", required=True)
    a = ap.parse_args()
    clients = sorted(CLIENT_REPOS) if a.client == "all" else [a.client]
    if a.cmd == "warm":
        for c in clients:
            ensure_clone(c)
            print(f"[local_diffs] {c} ready at {repo_path(c)}")
        return 0
    if a.cmd == "warm-prs":
        for c in clients:
            warm_prs(c)
        return 0
    if a.cmd == "refresh":
        for c in clients:
            refresh(c)
        return 0
    if a.cmd == "diff":
        diff = diff_for_url(a.url, a.client)
        if diff is None:
            print("NO DIFF", file=sys.stderr); return 1
        sys.stdout.write(diff)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
