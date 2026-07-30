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
import sys
from pathlib import Path

import pandas as pd

try:  # same import shim as scripts/cwe_context_analysis.py
    from scripts.paper_analysis import CWE_TOP_25_2025
except ImportError:  # pragma: no cover - direct script invocation
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from paper_analysis import CWE_TOP_25_2025


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
                                     "client_conditional_reach", "severity_final",
                                     "model_out_of_scope"])
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
                "severity_final": str(entry.get("severity_final") or ""),
                "model_out_of_scope": bool(
                    entry.get("reachability") == "local_internal"
                    or entry.get("impact_type") in ("local_only", "none")
                ),
            }
        )
    return pd.DataFrame(rows)


TIER_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "not-eligible": 0}


def severe_cwe_audit(graded: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Recompute the CWE-coverage claim on the pre- and post-audit severe populations.

    ``cwe_context_comparison.md`` reported this on all 18 apparently severe rows. Half
    of those were never graded, so the claim needs the corrected denominator, and it
    needs to come from a generated table rather than from prose arithmetic.
    """
    severe = graded[graded["severity"].isin(SEVERE)].copy()
    severe["has_cwe"] = (
        severe["cwe_top25"].notna()
        & severe["cwe_top25"].ne("N/A")
        & severe["cwe_top25"].ne("")
    )
    severe["in_top25_2025"] = severe["cwe_top25"].isin(CWE_TOP_25_2025)
    severe["has_root_cause"] = severe["root_cause"].ne("other")
    severe["has_protocol_label"] = severe["label"].ne("other")

    populations = {
        "all_graded_rows_as_published": severe,
        "published_advisory_only": severe[severe["provenance"].eq("published_advisory")],
        "published_advisory_client_code": severe[
            severe["provenance"].eq("published_advisory")
            & ~severe["upstream_toolchain_cve"]
        ],
    }
    rows = []
    for name, frame in populations.items():
        n = len(frame)
        rows.append(
            {
                "population": name,
                "records": n,
                "any_cwe": int(frame["has_cwe"].sum()),
                "any_cwe_pct": round(100 * frame["has_cwe"].sum() / n, 1) if n else 0.0,
                "in_mitre_2025_top25": int(frame["in_top25_2025"].sum()),
                "non_other_root_cause": int(frame["has_root_cause"].sum()),
                "non_other_root_cause_pct":
                    round(100 * frame["has_root_cause"].sum() / n, 1) if n else 0.0,
                "non_other_protocol_label": int(frame["has_protocol_label"].sum()),
                "non_other_protocol_label_pct":
                    round(100 * frame["has_protocol_label"].sum() / n, 1) if n else 0.0,
                "cwe_values": ";".join(sorted(frame.loc[frame["has_cwe"], "cwe_top25"])),
            }
        )
    per_row = severe[
        ["id", "source_platform", "severity", "provenance", "upstream_toolchain_cve",
         "cwe_top25", "in_top25_2025", "root_cause", "label", "title"]
    ].sort_values(["provenance", "severity", "source_platform"])
    return pd.DataFrame(rows), per_row


def calibration_by_provenance(screens: pd.DataFrame) -> pd.DataFrame:
    """Exact-tier and +/-1 agreement per model, split by what produced the severity.

    A single pooled calibration figure over this population measures the collector's
    keyword rule, not the estimator. Splitting it shows where the disagreement lives:
    the estimator is being scored against tiers that no grader ever assigned.
    """
    if screens.empty or "severity_final" not in screens.columns:
        return pd.DataFrame(
            columns=["model", "provenance", "scored", "exact", "exact_pct",
                     "within_1", "within_1_pct", "predicted_not_eligible"]
        )
    rows = []
    for (model, prov), grp in screens.groupby(["model", "provenance"]):
        scored = grp[grp["severity_final"].astype(str).str.len() > 0]
        if scored.empty:
            continue
        pred = scored["severity_final"].str.lower().map(TIER_RANK)
        true = scored["severity"].str.lower().map(TIER_RANK)
        usable = pred.notna() & true.notna()
        pred, true = pred[usable], true[usable]
        exact = int((pred == true).sum())
        within = int(((pred - true).abs() <= 1).sum())
        total = int(usable.sum())
        rows.append(
            {
                "model": model,
                "provenance": prov,
                "scored": total,
                "exact": exact,
                "exact_pct": round(100 * exact / total, 1) if total else 0.0,
                "within_1": within,
                "within_1_pct": round(100 * within / total, 1) if total else 0.0,
                "predicted_not_eligible": int(
                    (scored["severity_final"].str.lower() == "not-eligible").sum()
                ),
            }
        )
    return pd.DataFrame(rows).sort_values(["model", "provenance"])


def model_agreement(screens: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Pairwise agreement between models on the in-scope/out-of-scope screen.

    Two models are two annotators. Reporting their agreement is what lets the screen
    corroborate the provenance split instead of standing in for it. Rows only one
    model has seen are excluded from the pairwise counts rather than counted as
    agreement.
    """
    if screens.empty or screens["model"].nunique() < 2:
        empty = pd.DataFrame(columns=["model_a", "model_b", "compared", "agree",
                                      "agreement_pct"])
        return screens.head(0), empty

    wide = screens.pivot_table(
        index=["id", "provenance", "severity"], columns="model",
        values="model_out_of_scope", aggfunc="first",
    ).reset_index()

    models = sorted(screens["model"].unique())
    rows = []
    for i, a in enumerate(models):
        for b in models[i + 1:]:
            both = wide[wide[a].notna() & wide[b].notna()]
            agree = int((both[a] == both[b]).sum())
            rows.append(
                {
                    "model_a": a,
                    "model_b": b,
                    "compared": len(both),
                    "agree": agree,
                    "agreement_pct": round(100 * agree / len(both), 1) if len(both) else 0.0,
                }
            )
    return wide, pd.DataFrame(rows)


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
    per_row_screen, agreement = model_agreement(screens)
    calibration = calibration_by_provenance(screens)
    cwe_populations, cwe_per_row = severe_cwe_audit(graded)

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
    cwe_populations.to_csv(
        args.out_dir / "bounty_graded_severe_cwe_by_population.csv", index=False
    )
    cwe_per_row.to_csv(
        args.out_dir / "bounty_graded_severe_cwe_rows.csv", index=False
    )
    screen_table.to_csv(args.out_dir / "bounty_graded_model_screen.csv", index=False)
    summary.to_csv(args.out_dir / "bounty_graded_audit_summary.csv", index=False)
    if not calibration.empty:
        calibration.to_csv(
            args.out_dir / "bounty_graded_calibration_by_provenance.csv", index=False
        )
    if not agreement.empty:
        per_row_screen.to_csv(
            args.out_dir / "bounty_graded_model_screen_by_row.csv", index=False
        )
        agreement.to_csv(
            args.out_dir / "bounty_graded_model_agreement.csv", index=False
        )

    print("=== tier distribution by what produced the severity ===")
    pivot = (
        graded.pivot_table(index="provenance", columns="severity", values="id",
                           aggfunc="count", fill_value=0)
        .reindex(columns=[t for t in TIER_ORDER if t in graded["severity"].unique()],
                 fill_value=0)
    )
    print(pivot.to_string())
    print("\n=== CWE coverage of the severe slice, by population ===")
    print(cwe_populations[
        ["population", "records", "any_cwe", "in_mitre_2025_top25",
         "non_other_root_cause", "non_other_protocol_label", "cwe_values"]
    ].to_string(index=False))
    print("\n=== summary ===")
    for row in summary.to_dict("records"):
        print(f"  {row['measure']}: {row['value']}")
    if not screen_table.empty:
        print("\n=== independent model eligibility screen ===")
        print(screen_table.to_string(index=False))
    if not agreement.empty:
        print("\n=== pairwise model agreement on the eligibility screen ===")
        print(agreement.to_string(index=False))
    if not calibration.empty:
        print("\n=== calibration split by what produced the severity ===")
        print(calibration.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
