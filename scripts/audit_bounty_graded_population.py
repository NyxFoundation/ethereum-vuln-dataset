#!/usr/bin/env python3
"""Audit the population that the paper treats as EF-bounty ground truth.

``docs/paper/ef_severity_analysis.md`` uses ``severity_source == 'bounty-graded'``
as the exact-tier ground truth and reports 18 confirmed Critical/High records from
60 graded rows. That label is not a published grade. ``estimate_severity.py``
assigns it to *any* row that carries a rated ``severity`` and is not caught by the
dependency regex, so whatever produced ``severity`` upstream decides what counts as
ground truth.

For most of these rows that producer is ``collection/crawl_cross_client.py``, whose
``_infer_severity`` makes no vulnerability determination at all:

    def _infer_severity(pr):          # High if a keyword appears, Medium otherwise
        text = title + body[:2000]
        if any(sig in text for sig in HIGH_SEVERITY_SIGNALS):   # 10 keywords incl.
            return "High"                                       # "consensus",
        return "Medium"                                         # "attestation"

A pull request selected only for mentioning two client names therefore enters the
paper as a bounty-graded Medium, and one whose body contains the word "consensus"
enters as a bounty-graded High.

This script separates the graded population by what actually produced its severity
and recomputes the confirmed-severe count on the defensible subset. It reads the
frozen snapshot and, when present, the model screens cached by
``collection/estimate_severity.py`` -- used only as an independent second opinion,
never as the deciding evidence.

Outputs under ``docs/paper/tables``:

* ``bounty_graded_provenance.csv``       per-row provenance and tier
* ``bounty_graded_provenance_counts.csv`` tier distribution per provenance class
* ``bounty_graded_model_screen.csv``     per-model out-of-scope screen vs provenance
* ``bounty_graded_audit_summary.csv``    headline counts
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pandas as pd


# A published GitHub security advisory is the only self-evidencing severity in this
# population: the tier was assigned by the maintainers who issued the advisory.
ADVISORY_URL_RE = re.compile(r"/security/advisories/(GHSA-[0-9a-z-]+)", re.IGNORECASE)

# Upstream toolchain and dependency CVEs carry a CVSS score, not an EF-bounty grade.
# The estimator's dependency regex checks for update verbs and package names, so an
# advisory phrased as an impact ("Denial of service due to Go CVE-...") slips past it.
UPSTREAM_TOOLCHAIN_RE = re.compile(
    r"\bdue to (?:the )?(?:Go|Rust|Java|\.NET|Node|OpenSSL)\b"
    r"|\bGo CVE-|\bgolang\b.*\bCVE-",
    re.IGNORECASE,
)

SEVERE = {"Critical", "High"}
TIER_ORDER = ["Critical", "High", "Medium", "Low"]


def classify_provenance(row: pd.Series) -> str:
    """What actually decided this row's severity."""
    if ADVISORY_URL_RE.search(str(row.get("source_url") or "")):
        return "published_advisory"
    if str(row.get("contest") or "") == "cross_client":
        return "cross_client_keyword_heuristic"
    return "repo_crawl_unattributed"


def load_model_screens(cache_path: Path) -> pd.DataFrame:
    """Per (row, model) eligibility screen from the severity cache, if available.

    The cache is keyed ``id@prompt_version@engine:model``. Only entries that carry
    ``client_conditional_reach`` come from the revised prompt; earlier entries are
    ignored so two different questions are not pooled.
    """
    if not cache_path.exists():
        return pd.DataFrame(columns=["id", "model", "impact_type", "reachability",
                                     "client_conditional_reach", "model_out_of_scope"])
    cache = json.loads(cache_path.read_text())
    rows = []
    for key, entry in cache.items():
        if not isinstance(entry, dict) or "client_conditional_reach" not in entry:
            continue
        parts = key.split("@")
        if len(parts) < 3:
            continue
        row_id, model = parts[0], parts[-1]
        rows.append(
            {
                "id": row_id,
                "model": model,
                "impact_type": entry.get("impact_type", ""),
                "reachability": entry.get("reachability", ""),
                "client_conditional_reach": entry.get("client_conditional_reach", ""),
                "model_out_of_scope": bool(
                    entry.get("reachability") == "local_internal"
                    or entry.get("impact_type") in ("local_only", "none")
                ),
            }
        )
    return pd.DataFrame(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path,
                    default=Path("data/ethereum_vulns.parquet"))
    ap.add_argument("--sev-cache", type=Path,
                    default=Path("scratchpad_crawl/severity_cache.json"))
    ap.add_argument("--out-dir", type=Path, default=Path("docs/paper/tables"))
    args = ap.parse_args()

    data = pd.read_parquet(args.inp)
    graded = data[data["severity_source"].eq("bounty-graded")].copy()
    graded["provenance"] = graded.apply(classify_provenance, axis=1)
    graded["advisory_id"] = graded["source_url"].map(
        lambda u: (m.group(1) if (m := ADVISORY_URL_RE.search(str(u or ""))) else "")
    )
    graded["upstream_toolchain_cve"] = graded["title"].map(
        lambda t: bool(UPSTREAM_TOOLCHAIN_RE.search(str(t or "")))
    )

    advisory = graded[graded["provenance"].eq("published_advisory")]
    client_advisory = advisory[~advisory["upstream_toolchain_cve"]]

    per_row = graded[
        ["id", "source_platform", "contest", "severity", "provenance", "advisory_id",
         "upstream_toolchain_cve", "title", "source_url"]
    ].sort_values(["provenance", "severity", "source_platform"])

    counts = (
        graded.groupby(["provenance", "severity"]).size().reset_index(name="records")
        .sort_values(["provenance", "severity"])
    )

    screens = load_model_screens(args.sev_cache)
    if not screens.empty:
        screens = screens.merge(
            graded[["id", "provenance", "severity"]], on="id", how="inner"
        )
        screen_table = (
            screens.groupby(["model", "provenance", "model_out_of_scope"])
            .size()
            .reset_index(name="records")
            .sort_values(["model", "provenance", "model_out_of_scope"])
        )
    else:
        screen_table = pd.DataFrame(
            columns=["model", "provenance", "model_out_of_scope", "records"]
        )

    def severe(frame: pd.DataFrame) -> int:
        return int(frame["severity"].isin(SEVERE).sum())

    summary = pd.DataFrame(
        [
            ("bounty_graded_rows", len(graded)),
            ("published_advisory_rows", len(advisory)),
            ("cross_client_keyword_heuristic_rows",
             int(graded["provenance"].eq("cross_client_keyword_heuristic").sum())),
            ("repo_crawl_unattributed_rows",
             int(graded["provenance"].eq("repo_crawl_unattributed").sum())),
            ("severe_claimed_all_graded", severe(graded)),
            ("severe_from_published_advisory", severe(advisory)),
            ("severe_from_published_advisory_excluding_upstream_toolchain",
             severe(client_advisory)),
            ("severe_from_keyword_heuristic",
             severe(graded[graded["provenance"].eq("cross_client_keyword_heuristic")])),
            ("upstream_toolchain_cves_labelled_bounty_graded",
             int(graded["upstream_toolchain_cve"].sum())),
            ("distinct_advisory_ids", int((graded["advisory_id"] != "").sum())),
            ("models_screening", int(screens["model"].nunique()) if not screens.empty else 0),
        ],
        columns=["measure", "value"],
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    per_row.to_csv(args.out_dir / "bounty_graded_provenance.csv", index=False)
    counts.to_csv(args.out_dir / "bounty_graded_provenance_counts.csv", index=False)
    screen_table.to_csv(args.out_dir / "bounty_graded_model_screen.csv", index=False)
    summary.to_csv(args.out_dir / "bounty_graded_audit_summary.csv", index=False)

    print("=== tier distribution by what produced the severity ===")
    pivot = (
        graded.pivot_table(index="provenance", columns="severity", values="id",
                           aggfunc="count", fill_value=0)
        .reindex(columns=[t for t in TIER_ORDER if t in graded["severity"].unique()],
                 fill_value=0)
    )
    print(pivot.to_string())
    print("\n=== summary ===")
    for row in summary.to_dict("records"):
        print(f"  {row['measure']}: {row['value']}")
    if not screen_table.empty:
        print("\n=== independent model eligibility screen ===")
        print(screen_table.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
