# RQ1 preliminary: what gets an advisory identifier?

**Question:** Are advisory-linked records merely a smaller sample, or a
distributionally different sample of Ethereum-client security work?

**Status:** exploratory result; the manual scope review is not complete.

The analysis uses the broad definition established in
[`snapshot_audit.md`](snapshot_audit.md): a row is advisory-linked when a
case-insensitive CVE, GHSA, or RustSec identifier occurs in any provenance
field. Results are generated in:

- [`tables/advisory_prevalence.csv`](tables/advisory_prevalence.csv)
- [`tables/advisory_bias_global.csv`](tables/advisory_bias_global.csv)
- [`tables/advisory_bias_categories.csv`](tables/advisory_bias_categories.csv)
- [`tables/advisory_review_queue.csv`](tables/advisory_review_queue.csv)

## 1. Prevalence depends on the evidence population

| Population | Rows | Advisory-ID rows | Share |
|---|---:|---:|---:|
| A_authoritative only | 235 | 144 | 61.3% |
| A_authoritative ∪ B_corroborated | 1,808 | 152 | 8.4% |
| All tiers | 2,225 | 172 | 7.7% |

The A-only percentage is descriptive but circular: an advisory identifier is
one of the signals used to assign A_authoritative. The defensible populations
for selection analysis are A∪B and all tiers.

## 2. Raw associations are large, but not yet protocol findings

For each category with at least 20 rows, the script computes:

- advisory prevalence;
- a one-category-versus-rest odds ratio with Haldane–Anscombe correction;
- a Wald 95% confidence interval;
- a two-sided normal-approximation p-value;
- Benjamini–Hochberg correction within each population/dimension.

Global association is summarized with Pearson chi-square and uncorrected
Cramér's V.

For all tiers, protocol label has the largest raw association with advisory
presence (V=0.380), followed by attack path (V=0.189), root cause (V=0.182),
client (V=0.162), language (V=0.106), and layer (V=0.032). The A∪B results are
similar: label V=0.388, attack path V=0.212, and root cause V=0.205.

Selected all-tier associations are:

| Dimension | Category | Advisory share | Odds ratio | 95% CI |
|---|---|---:|---:|---:|
| label | crypto | 40.0% | 8.73 | 4.58–16.65 |
| label | p2p-interface | 27.6% | 6.03 | 4.15–8.75 |
| label | build-ci | 26.2% | 4.89 | 3.06–7.80 |
| label | p2p | 23.2% | 3.98 | 2.34–6.79 |
| label | state-trie | 1.4% | 0.18 | 0.06–0.53 |
| root cause | crypto_misuse | 38.7% | 8.13 | 3.92–16.83 |
| root cause | race_condition | 1.4% | 0.18 | 0.06–0.52 |
| attack path | malformed_input | 11.9% | 2.68 | 1.94–3.70 |
| attack path | crafted_state | 1.9% | 0.21 | 0.10–0.42 |
| attack path | malicious_attestation | 1.1% | 0.16 | 0.05–0.56 |

All listed categories remain below q=0.05 in the exploratory within-dimension
tests.

## 3. The first validity gate fails: product scope is mixed

The 172 advisory-linked rows do not form one coherent population. They mix:

1. direct vulnerabilities in Ethereum-client code;
2. upstream dependency CVEs and RustSec advisories;
3. documentation, CI, test, and developer-tool dependency updates.

A conservative automated triage of the 172 rows currently suggests:

| Suggested scope | Rows | Share |
|---|---:|---:|
| dependency_or_tooling | 117 | 68.0% |
| client_implementation | 46 | 26.7% |
| needs_manual_review | 9 | 5.2% |

These are review suggestions, not final labels. The checked-in review queue
contains blank `reviewed_scope` and `review_notes` columns for human validation.

This mixture materially affects the raw result. For example, many dependency
updates in documentation or JavaScript tooling carry a protocol-looking
`p2p-interface` label. The raw p2p-interface odds ratio therefore cannot be
interpreted as evidence that protocol P2P bugs are more likely to receive a CVE.
Similarly, language and client associations partly reflect dependency managers
and disclosure practices rather than vulnerability incidence.

**Observation.** In the current corpus, the public advisory-identifier view is
dominated by software-supply-chain and tooling work, while the non-advisory view
contains most historical client-fix candidates.

**Hypothesis.** After scope validation, direct client advisories will still
overrepresent remotely triggered crash/DoS classes and underrepresent
state-dependent, concurrency, and consensus-edge-case fixes.

**Do not claim yet.** The raw odds ratios above do not establish that CVE
assignment is caused by protocol area, root cause, client, or language.

## 4. Revised comparison design

The publication analysis should compare three groups rather than binary
“CVE versus no CVE”:

1. **Direct client advisory** — a CVE/GHSA describing the Ethereum client
   implementation itself.
2. **Upstream dependency/tooling advisory** — a library, build, docs, CI, or
   test dependency.
3. **Non-advisory client fix** — a historical client-code fix with no public
   advisory identifier.

After manual review:

- rerun odds ratios and effect sizes using the reviewed scope;
- exclude dependency/tooling rows from protocol-area inference;
- add client fixed effects so disclosure-policy differences do not masquerade
  as bug-type differences;
- report A∪B as the primary population and all tiers as sensitivity;
- keep A-only descriptive because it is selected partly by advisory evidence.

## 5. Research contribution exposed by the failed naive analysis

The contamination is not merely a cleaning nuisance. It supports a sharper
question:

> Does the CVE ecosystem around Ethereum repositories describe protocol risk,
> or mostly the inherited software supply chain?

If validated, the paper can show two distinct blind spots:

- **scope bias:** public identifiers disproportionately describe dependencies
  rather than Ethereum protocol implementation failures;
- **type bias:** within direct client vulnerabilities, public advisories may
  favor easily described remote DoS over silent determinism and state-machine
  edge cases.

This distinction is stronger and more reproducible than treating every CVE
mention in an Ethereum repository as an Ethereum-client vulnerability.
