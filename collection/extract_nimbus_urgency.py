#!/usr/bin/env python3
"""Extract release-level urgency metadata from nimbus-eth2 GitHub Releases.

Background (issue #2 / T15):
    nimbus-eth2 release bodies contain an "Urgency guidelines" template
    section with lines such as:

        Urgency: high
        high-urgency: true
        ## Urgency: Medium
        **Urgency**: Critical

    Earlier scrapers (mine_eth_releases.py) matched ``Critical``/``High``
    within INDIVIDUAL lines, causing 95/97 "Critical" rows to be false
    positives — they came from the template metadata, not actual findings.

    This script extracts the RELEASE-LEVEL urgency from that header line
    only, producing a metadata CSV.  Downstream, mine_eth_releases.py can
    use this file (via --apply-to) to override row-level severity on nimbus
    rows by tag_name.

Header-only extraction:
    Two regex patterns are tried per release body (first match wins):
      Form A (prose): ``r'`?<level>`?-urgency'``   e.g. "`medium-urgency` release"
      Form B (header): ``r'urgency[:\\s]+<level>'`` e.g. "Urgency: Medium"
    Only the first match per release body is used.  A match anchors the
    urgency for ALL rows derived from that release.
    If no match is found -> severity = "Unrated"

Output: ``<out-dir>/nimbus.urgency.csv``
Columns: tag_name, release_url, urgency_level, published_at, title

Usage:
    # Write urgency metadata:
    uv run python3 benchmarks/scripts/extract_nimbus_urgency.py \\
        --out-dir dataset/ethereum_past_fixes/nimbus_urgency

    # Patch an existing nimbus releases CSV produced by mine_eth_releases.py:
    uv run python3 benchmarks/scripts/extract_nimbus_urgency.py \\
        --out-dir dataset/ethereum_past_fixes/nimbus_urgency \\
        --apply-to benchmarks/data/ethereum_past_fixes/nimbus.releases.csv \\
        --apply-out benchmarks/data/ethereum_past_fixes/nimbus.releases.patched.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

NIMBUS_REPO = "status-im/nimbus-eth2"

# Nimbus releases express urgency in two forms:
#
#   Form A — prose sentence (most common, first Notes paragraph):
#     "Nimbus `v25.1.0` is a `medium-urgency` release ..."
#     "Nimbus `v25.4.1` is a high-urgency release ..."
#     i.e. the LEVEL word appears BEFORE the word "urgency", hyphenated.
#     Pattern: `?<level>`?-urgency   OR   <level>-urgency
#
#   Form B — explicit header (template section, lower in the body):
#     "## Urgency: Medium"
#     "**Urgency**: Critical"
#     "Urgency: high"
#     i.e. the word "urgency" appears first, then the level word.
#     Pattern: urgency[:\s]+<level>
#
# We try Form A first (line-level, first match wins) because it describes
# the overall release urgency; Form B lines in the template section say
# "low-urgency: update at your own convenience" which are NOT the release
# urgency — they define what each level means.  The first line in the body
# that matches Form A is authoritative.

# Form A: backtick-optional level word followed by -urgency
_URGENCY_PROSE_RE = re.compile(
    r"`?(?P<level>critical|high|medium|low)`?-urgency",
    re.IGNORECASE,
)

# Form B: "Urgency:" header style (used only if Form A gives no match)
_URGENCY_HEADER_RE = re.compile(
    r"\burgency[:\s]+(?P<level>critical|high|medium|low)\b",
    re.IGNORECASE,
)

# Canonical level words we accept.
_VALID_LEVELS = {"critical", "high", "medium", "low"}

# Map nimbus urgency levels onto the shared schema's severity enum.
# "critical" is intentionally kept distinct here so callers can see the raw
# urgency level in the metadata CSV; the APPLY step maps it to "High" if needed.
URGENCY_TO_SEVERITY: dict[str, str] = {
    "critical": "High",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
}

URGENCY_CSV_FIELDS = ("tag_name", "release_url", "urgency_level", "published_at", "title")


# ---------------------------------------------------------------------------
# Fetch releases
# ---------------------------------------------------------------------------

def fetch_releases(repo: str = NIMBUS_REPO) -> list[dict]:
    """Fetch all non-draft releases from nimbus-eth2 via gh CLI.

    Uses --paginate to walk all pages.  Capped at 1000 releases to avoid
    runaway (nimbus has ~200 releases as of 2026-06; this cap is generous).
    """
    try:
        result = subprocess.run(
            [
                "gh", "api",
                f"repos/{repo}/releases",
                "-X", "GET",
                "--paginate",
                "-f", "per_page=100",
            ],
            capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  [warn] gh failed for {repo}: {exc}", file=sys.stderr)
        return []

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        print(
            f"  [warn] gh exit {result.returncode} for {repo}/releases: {stderr[:300]}",
            file=sys.stderr,
        )
        return []

    body = result.stdout.strip()
    if not body:
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"  [warn] gh output not JSON for {repo}: {exc}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        print(f"  [warn] unexpected response shape: {type(data)}", file=sys.stderr)
        return []

    # Drop drafts only; keep pre-releases (security fixes often ship there first).
    releases = [r for r in data if not r.get("draft", False)]
    if len(releases) > 1000:
        print(
            f"  [warn] release list truncated at 1000 (total: {len(releases)})",
            file=sys.stderr,
        )
        releases = releases[:1000]
    return releases


# ---------------------------------------------------------------------------
# Urgency extraction
# ---------------------------------------------------------------------------

def extract_urgency(body: str) -> str | None:
    """Return the release-level urgency word from a nimbus release body.

    Strategy:
      1. Scan lines top-to-bottom for Form A (``<level>-urgency``).
         The first match is taken as the authoritative release urgency.
         This fires on the "Notes" prose paragraph near the top of the body.
      2. If Form A produces no match, scan for Form B (``Urgency: <level>``
         header style) — used in some older releases.
      3. Return None if neither pattern matches.

    The "Urgency guidelines" template section further down the body also
    contains Form A patterns like "`low-urgency`: update at your own
    convenience" — those describe what each level means, not the release
    urgency.  Because we take FIRST match and the Notes paragraph precedes
    the guidelines section, the first match is correct.

    Returns lowercase level string ("critical", "high", "medium", "low")
    or None.
    """
    if not body:
        return None

    # Pass 1: Form A — level-urgency (prose form)
    for line in body.splitlines():
        m = _URGENCY_PROSE_RE.search(line)
        if m:
            level = m.group("level").lower()
            if level in _VALID_LEVELS:
                return level

    # Pass 2: Form B — Urgency: level (header form)
    for line in body.splitlines():
        m = _URGENCY_HEADER_RE.search(line)
        if m:
            level = m.group("level").lower()
            if level in _VALID_LEVELS:
                return level

    return None


def releases_to_urgency_rows(releases: list[dict]) -> list[dict]:
    """Convert GitHub release dicts to urgency metadata rows."""
    rows: list[dict] = []
    for rel in releases:
        tag = (rel.get("tag_name") or "").strip()
        if not tag:
            continue
        body = rel.get("body") or ""
        level = extract_urgency(body)
        rows.append({
            "tag_name":     tag,
            "release_url":  (rel.get("html_url") or "").strip(),
            "urgency_level": level if level else "Unrated",
            "published_at": (rel.get("published_at") or "").strip(),
            "title":        (rel.get("name") or tag).strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# --apply-to: patch a mine_eth_releases.py output CSV
# ---------------------------------------------------------------------------

def apply_urgency_to_releases_csv(
    releases_csv: Path,
    urgency_rows: list[dict],
    out_path: Path,
) -> tuple[int, int]:
    """Patch the 'severity' column in a nimbus.releases.csv by tag_name.

    For each row whose issue_id starts with ``RELEASE#<tag_name>#``, we
    look up the urgency_level for that tag and map it to a severity:
      critical/high  -> High
      medium         -> Medium
      low            -> Low
      Unrated        -> Unrated   (replaces whatever was there before)

    Returns (total_rows, patched_rows).
    """
    # Build a lookup: tag_name -> severity string
    tag_severity: dict[str, str] = {}
    for row in urgency_rows:
        tag = row["tag_name"]
        level = row["urgency_level"].lower()
        tag_severity[tag] = URGENCY_TO_SEVERITY.get(level, "Unrated")

    # Read + patch
    with releases_csv.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        input_rows = list(reader)

    patched = 0
    for row in input_rows:
        issue_id = row.get("issue_id", "")
        if issue_id.startswith("RELEASE#"):
            parts = issue_id.split("#", 2)
            if len(parts) >= 2:
                tag = parts[1]
                new_sev = tag_severity.get(tag, "Unrated")
                if row.get("severity") != new_sev:
                    row["severity"] = new_sev
                    patched += 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(input_rows)

    return len(input_rows), patched


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_urgency_csv(rows: list[dict], out_path: Path) -> int:
    """Write urgency metadata CSV. Returns row count (excluding header)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=URGENCY_CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in URGENCY_CSV_FIELDS})
    return len(rows)


def write_manifest(out_path: Path, *, n_releases: int, n_annotated: int,
                   distribution: dict[str, int]) -> None:
    """Write a JSON provenance snapshot."""
    gh_version = ""
    try:
        v = subprocess.run(
            ["gh", "--version"], capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        if v.returncode == 0:
            gh_version = v.stdout.strip().splitlines()[0]
    except Exception:
        pass

    manifest = {
        "repo":        NIMBUS_REPO,
        "n_releases":  n_releases,
        "n_annotated": n_annotated,
        "n_unrated":   n_releases - n_annotated,
        "distribution": distribution,
        "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gh_version":  gh_version,
        "method":      "header-only urgency line (T15)",
    }
    out_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--out-dir", required=True,
        help="Output directory for nimbus.urgency.csv + nimbus.urgency_manifest.json",
    )
    p.add_argument(
        "--apply-to", default="",
        help=(
            "Path to an existing nimbus.releases.csv (from mine_eth_releases.py). "
            "When provided, patches its 'severity' column by tag_name and writes "
            "the result to --apply-out."
        ),
    )
    p.add_argument(
        "--apply-out", default="",
        help=(
            "Path for the patched CSV (default: <apply-to>.patched.csv). "
            "Ignored unless --apply-to is given."
        ),
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Fetch releases
    print(f"[nimbus] fetching releases from {NIMBUS_REPO}...", file=sys.stderr)
    releases = fetch_releases(NIMBUS_REPO)
    print(f"[nimbus] {len(releases)} releases fetched", file=sys.stderr)

    # 2. Extract urgency metadata
    urgency_rows = releases_to_urgency_rows(releases)

    # 3. Compute summary stats
    n_annotated = sum(1 for r in urgency_rows if r["urgency_level"] != "Unrated")
    distribution: dict[str, int] = {}
    for r in urgency_rows:
        lvl = r["urgency_level"]
        distribution[lvl] = distribution.get(lvl, 0) + 1

    # 4. Write outputs
    csv_path = out_dir / "nimbus.urgency.csv"
    manifest_path = out_dir / "nimbus.urgency_manifest.json"

    n = write_urgency_csv(urgency_rows, csv_path)
    write_manifest(
        manifest_path,
        n_releases=len(urgency_rows),
        n_annotated=n_annotated,
        distribution=distribution,
    )

    print(
        f"[nimbus] {n} releases -> {csv_path}",
        file=sys.stderr,
    )
    print(
        f"[nimbus] annotated: {n_annotated}/{n}  distribution: {distribution}",
        file=sys.stderr,
    )

    # 5. Optionally apply urgency to an existing releases CSV
    if args.apply_to:
        releases_csv = Path(args.apply_to)
        if not releases_csv.exists():
            print(f"  [error] --apply-to path not found: {releases_csv}", file=sys.stderr)
            return 1

        apply_out = (
            Path(args.apply_out)
            if args.apply_out
            else releases_csv.with_suffix(".patched.csv")
        )
        total, patched = apply_urgency_to_releases_csv(
            releases_csv, urgency_rows, apply_out
        )
        print(
            f"[nimbus] patched {patched}/{total} rows -> {apply_out}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
