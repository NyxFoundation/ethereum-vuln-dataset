#!/usr/bin/env python3
"""crawl_ghsa_advisories.py — per-repo GitHub Security Advisory (GHSA) crawler.

The authoritative-severity spine of the dataset. Each in-scope client repo
publishes reviewed advisories at `/repos/{owner}/{repo}/security-advisories`
carrying a *real* severity (critical/high/medium/low), a CVE id, a GHSA id, and
the patched version(s). Unlike commit-grep, these are confirmed vulnerabilities —
near-zero noise. This is signal [A]/[D6] of the improvement loop.

Output (build_derived canonical schema, so Critical severity is preserved):
    <out-dir>/<client>.ghsa.csv
    <out-dir>/<client>.ghsa_manifest.json

CSV columns:
    source, contest, issue_id, severity, title, description,
    source_url, introduced_in_commit

The GHSA id and CVE id are appended to the title so the downstream CVE/GHSA
id-regex fires (score 1.0, confidence high). `patched_versions` is recorded in
the description so a later iteration can resolve tag→commit for the fix diff.

Usage:
    uv run python collection/crawl_ghsa_advisories.py --client all --out-dir OUT
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CLIENT_REPOS: dict[str, str] = {
    "geth":       "ethereum/go-ethereum",
    "nethermind": "NethermindEth/nethermind",
    "besu":       "hyperledger/besu",
    "erigon":     "erigontech/erigon",
    "reth":       "paradigmxyz/reth",
    "lighthouse": "sigp/lighthouse",
    "lodestar":   "ChainSafe/lodestar",
    "nimbus":     "status-im/nimbus-eth2",
    "prysm":      "prysmaticlabs/prysm",
    "teku":       "Consensys/teku",
    "grandine":   "grandinetech/grandine",
}

# GHSA severity -> canonical (build_derived capitalizes; keep Critical distinct)
SEV_MAP = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}

CSV_FIELDS = (
    "source", "contest", "issue_id", "severity", "title",
    "description", "source_url", "introduced_in_commit",
)

_DESC_MAX = 1500


def _gh_json(path: str) -> list[dict]:
    """GET a paginated gh api endpoint, return a flat list of JSON objects."""
    try:
        r = subprocess.run(
            ["gh", "api", "--paginate", path],
            capture_output=True, text=True, timeout=120,
            encoding="utf-8", errors="replace",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  [warn] gh api {path}: {e}", file=sys.stderr)
        return []
    if r.returncode != 0:
        print(f"  [warn] gh api {path} exit {r.returncode}: {r.stderr.strip()[:200]}",
              file=sys.stderr)
        return []
    out: list[dict] = []
    # --paginate concatenates JSON arrays; split on "][" boundaries.
    blob = r.stdout.strip()
    if not blob:
        return []
    for chunk in blob.replace("][", "]\x00[").split("\x00"):
        try:
            data = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            out.extend(data)
    return out


def _advisory_to_row(adv: dict, client: str) -> dict | None:
    ghsa = (adv.get("ghsa_id") or "").strip()
    if not ghsa:
        return None
    cve = (adv.get("cve_id") or "").strip()
    sev = SEV_MAP.get((adv.get("severity") or "").lower(), "Unrated")
    summary = (adv.get("summary") or "").strip()
    body = (adv.get("description") or "").strip()
    patched = []
    for v in (adv.get("vulnerabilities") or []):
        pv = (v or {}).get("patched_versions")
        if pv:
            patched.append(pv)
    # id suffix in title so downstream CVE/GHSA regex fires
    id_tag = " ".join(x for x in (ghsa, cve) if x)
    title = f"{summary} [{id_tag}]" if summary else id_tag
    desc = body
    if patched:
        desc = f"{body}\n\npatched_versions: {', '.join(patched)}"
    return {
        "source": client,
        "contest": "ghsa_advisory",
        "issue_id": ghsa,
        "severity": sev,
        "title": title[:500],
        "description": desc[:_DESC_MAX],
        "source_url": (adv.get("html_url") or "").strip(),
        "introduced_in_commit": "",
    }


def crawl_client(client: str, out_dir: Path) -> int:
    repo = CLIENT_REPOS[client]
    advs = _gh_json(f"/repos/{repo}/security-advisories?per_page=100")
    rows = [r for r in (_advisory_to_row(a, client) for a in advs) if r]
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"{client}.ghsa.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    by_sev: dict[str, int] = {}
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    (out_dir / f"{client}.ghsa_manifest.json").write_text(
        json.dumps({
            "client": client, "repo": repo, "n_rows": len(rows),
            "by_severity": by_sev,
            "crawled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, indent=2) + "\n", encoding="utf-8")
    print(f"[{client}] {len(rows)} advisories {by_sev} -> {csv_path}", file=sys.stderr)
    return len(rows)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--client", required=True, help="client slug or 'all'")
    p.add_argument("--out-dir", required=True, type=Path)
    a = p.parse_args()
    clients = sorted(CLIENT_REPOS) if a.client == "all" else [a.client]
    total = sum(crawl_client(c, a.out_dir) for c in clients)
    print(f"done — {total} GHSA advisory rows across {len(clients)} client(s)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
