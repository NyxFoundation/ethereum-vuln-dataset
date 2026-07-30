# RQ1 scope review: what do advisory-linked records actually describe?

**Question:** When a CVE, GHSA, or RustSec identifier appears in an Ethereum
client repository, does it describe the client implementation or inherited
software-supply-chain work?

**Population:** 172 advisory-linked records in the frozen 2,225-row snapshot.
The identifier definition is fixed in
[`../DATA_SNAPSHOT.md`](../DATA_SNAPSHOT.md).

## 1. Review method

The preliminary classifier used dependency names, update verbs, repository
names, paths, and source URLs. We then audited all 172 queue entries using the
title, description excerpt, issue identifier, source URL, and changed-file
context. Explicit corrections are versioned in `SCOPE_OVERRIDES` in
[`scripts/paper_analysis.py`](../../scripts/paper_analysis.py), and every row's
decision and note are checked into
[`tables/advisory_review_queue.csv`](tables/advisory_review_queue.csv).

The record-level classes are:

1. `direct_client_implementation`: the identifier is attached to client code or
   a client-side remediation/regression test;
2. `dependency_or_tooling`: dependency, build, CI, documentation, test tooling,
   or an upstream library advisory;
3. `other_product`: a product-name match outside the Ethereum-client scope.

“Direct” does not necessarily mean the CVE was assigned to that client. For
example, an Erigon regression test for a Geth CVE is direct client remediation
but not an Erigon advisory.

## 2. The repository-CVE view is mostly supply-chain work

| Reviewed scope | Records | Share of 172 |
|---|---:|---:|
| Dependency or tooling | **135** | **78.5%** |
| Direct client implementation | **36** | **20.9%** |
| Other product | 1 | 0.6% |

The initial automated triage suggested 117 dependency/tooling and 46 client
records. Review moved client-name false positives such as Besu's Netty update
([CVE-2024-47535](https://nvd.nist.gov/vuln/detail/CVE-2024-47535)),
Prysm's `golang.org/x/crypto` update
([CVE-2025-22869](https://nvd.nist.gov/vuln/detail/CVE-2025-22869)), and
Lodestar development dependencies into the dependency/tooling group. The one
other-product record is Nethermind Juno, a Starknet client
([CVE-2025-29072](https://nvd.nist.gov/vuln/detail/CVE-2025-29072)), not the
Nethermind Ethereum execution client.

Three CVE identifiers occur in more than one scope: they describe a direct Geth
issue and also appear in an Erigon dependency update. Scope therefore belongs
to a repository record, not globally to an identifier.

## 3. Disclosure is concentrated by client and layer

The 36 direct-client records occur in only five clients:

| Client | Direct records | Dependency/tooling | Total advisory-linked |
|---|---:|---:|---:|
| Geth | 23 | 26 | 49 |
| Besu | 7 | 12 | 19 |
| Lodestar | 3 | 23 | 26 |
| Erigon | 2 | 13 | 15 |
| Lighthouse | 1 | 15 | 16 |

The other six clients have no direct-client record under this operational
definition. This is evidence of disclosure and collection concentration, not
evidence that those clients have no vulnerabilities.

All 36 direct records fall in `A_authoritative`. Against the A∪B no-identifier
population (n=1,656), direct records are strongly concentrated in execution
clients: 88.9% versus 58.6% (OR 5.11, 95% CI 1.90–13.76, BH-adjusted
q=0.0013). Geth alone contributes 63.9% of direct records versus 17.9% of the
no-ID population (OR 7.95, q<0.000001); Besu contributes 19.4% versus 4.2%
(OR 5.81, q=0.00019).

These client effects are too large to interpret pooled category odds ratios as
vulnerability-incidence effects. They primarily expose differences in advisory
publication, NVD coverage, repository history, and collection.

## 4. What kinds of direct issues receive identifiers?

Using A∪B as the primary population:

| Category | Direct | No recognized ID | Odds ratio | BH q |
|---|---:|---:|---:|---:|
| Attack path: malicious transaction | 9/36 (25.0%) | 16/1,656 (1.0%) | **34.35** | <0.000001 |
| Attack path: malicious P2P message | 10/36 (27.8%) | 194/1,656 (11.7%) | **2.98** | 0.015 |
| Label: P2P | 7/36 (19.4%) | 54/1,656 (3.3%) | **7.48** | <0.0001 |
| Label: EVM | 3/36 (8.3%) | 28/1,656 (1.7%) | **5.97** | 0.028 |
| Label: block processing | 3/36 (8.3%) | 32/1,656 (1.9%) | **5.22** | 0.037 |

The result supports a narrower and more interesting selection hypothesis:
public identifiers favor externally triggerable, compactly describable failures
such as a transaction, packet, opcode, or block-processing edge case.

No `root_cause` category survives BH correction in A∪B or all tiers. The
evidence currently supports **trigger and subsystem selection**, not a claim
that advisory-linked bugs have a different underlying root-cause distribution.

## 5. CWE comparison is dominated by missingness

| Group | Rows | CWE assigned | 2025 Top-25 member | Top-25 among CWE-known |
|---|---:|---:|---:|---:|
| Direct client implementation | 36 | 26 (72.2%) | 11 (30.6%) | 42.3% |
| Dependency/tooling | 135 | 43 (31.9%) | 18 (13.3%) | 41.9% |
| No recognized advisory ID | 2,053 | 326 (15.9%) | 101 (4.9%) | 31.0% |
| Other product | 1 | 1 (100.0%) | 0 | 0% |

CWE availability is itself selected by advisory linkage: a direct-client record
is 4.5 times as likely to have a CWE assignment as a no-ID record
(72.2% versus 15.9%). A naive comparison of CWE frequencies would therefore
confound vulnerability type with annotation availability.

Among CWE-known records, Top-25 membership is similar for direct and dependency
records (42.3% and 41.9%) and lower for no-ID records (31.0%). The sample is too
small and the missingness too unequal to call this domain shift. The defensible
contribution is instead: **CWE-only views preferentially retain advisory-linked
records and discard most of the low-disclosure corpus.**

## 6. Paper contribution supported now

The strongest current contribution is not “Ethereum has few CVEs.” It is:

> A repository-level CVE search is not merely incomplete; it changes the unit
> of analysis. In this snapshot, 78.5% of advisory-linked records describe
> dependencies or tooling, while direct client identifiers concentrate in two
> execution clients and in transaction/P2P-triggered failures.

This creates two measurable biases:

- **scope bias:** dependency and tooling remediation dominates identifier-linked
  repository activity;
- **disclosure bias:** among direct client records, identifiers concentrate by
  client, layer, trigger, and subsystem.

## 7. Limits and next validity gate

- This is a one-pass metadata and changed-file review, not an independent
  two-reviewer annotation study.
- The 2,053 no-ID records were not manually scope-reviewed; some dependency or
  tooling work may remain there.
- `authority_tier=A` partly uses advisory evidence, so A-only comparisons are
  circular. A∪B is primary and all tiers is the sensitivity analysis.
- Category labels are heuristic/LLM-derived. Odds ratios are exploratory and do
  not estimate causal effects.
- The direct group has only 36 records and strong client imbalance. A
  publication claim needs a second reviewer and client-adjusted or matched
  analysis.

## Generated evidence

- [`tables/reviewed_advisory_scope_counts.csv`](tables/reviewed_advisory_scope_counts.csv)
- [`tables/reviewed_advisory_scope_by_client.csv`](tables/reviewed_advisory_scope_by_client.csv)
- [`tables/reviewed_advisory_identifiers.csv`](tables/reviewed_advisory_identifiers.csv)
- [`tables/reviewed_scope_cwe_coverage.csv`](tables/reviewed_scope_cwe_coverage.csv)
- [`tables/direct_advisory_vs_no_id.csv`](tables/direct_advisory_vs_no_id.csv)
