# RQ3: what Ethereum context adds beyond CWE categories

## Question

How much of the dataset—and especially its confirmed severe slice—is described
by generic CWE labels, and what information remains available when CWE is
absent?

## 1. Coverage is sparse and provenance-dependent

Across the frozen 2,225-record snapshot:

| Representation | Records | Coverage |
|---|---:|---:|
| Any assigned CWE | 396 | 17.8% |
| Member of MITRE 2025 CWE Top 25 | 130 | 5.8% |
| Non-`other` Ethereum root cause | 1,925 | 86.5% |
| Non-`other` protocol/subsystem label | 2,078 | 93.4% |

The legacy column name `cwe_top25` is misleading: it stores 57 distinct CWE
identifiers, only some of which belong to MITRE's 2025 Top 25.

CWE coverage must not be interpreted as the prevalence of CWE-applicable
defects. It is strongly associated with public advisory provenance. The
completed advisory review found an assigned CWE on 26/36 direct-client advisory
records (72.2%), compared with 326/2,053 records without a recognized advisory
ID (15.9%). This is annotation and disclosure selection as well as vulnerability
semantics.

## 2. Confirmed severe vulnerabilities are poorly represented

Among the 18 bounty-graded Critical/High records:

- 3/18 (16.7%) have any CWE (`CWE-190`, `CWE-400`, and `CWE-439`);
- 0/18 are members of MITRE's 2025 CWE Top 25;
- 17/18 (94.4%) have a non-`other` root cause;
- 17/18 (94.4%) have a non-`other` protocol/subsystem label;
- of the 15 records without a CWE, 14 (93.3%) still have both a root cause and
  a protocol label.

The zero Top-25 count is a descriptive result from a small sample, not proof
that the Top 25 is irrelevant to Ethereum. With n=18, the paper should not make
a population-level coverage claim from this slice alone. It does show that a
Top-25-only empirical design would omit every confirmed severe example in this
snapshot.

## 3. CWE and protocol context answer different questions

CWE generally describes a software weakness mechanism. The dataset's
`root_cause` normalizes that mechanism for client code, while `label` locates it
in an Ethereum protocol or implementation surface.

This distinction is visible even for common CWE values:

| CWE | Records | Distinct root causes | Distinct protocol labels |
|---|---:|---:|---:|
| CWE-248 | 60 | 2 | 16 |
| CWE-20 | 50 | 4 | 12 |
| CWE-362 | 48 | 1 | 14 |
| CWE-400 | 42 | 2 | 12 |
| CWE-190 | 22 | 1 | 12 |

For example, `CWE-190` says integer overflow/underflow, but its 22 records span
12 protocol/subsystem labels. The protocol label distinguishes whether the
arithmetic defect appears in gas accounting, opcodes, fork choice, state
transition, or another surface. These are not interchangeable categories.

Conversely, Ethereum-specific failure classes are often missing CWE:

| Root cause | Records | CWE assigned | Coverage |
|---|---:|---:|---:|
| `consensus_divergence` | 174 | 2 | 1.1% |
| `incorrect_gas_accounting` | 48 | 0 | 0.0% |
| `serialization_bug` | 19 | 0 | 0.0% |
| `integer_overflow_underflow` | 185 | 24 | 13.0% |
| `missing_input_validation` | 522 | 61 | 11.7% |

This does not mean CWE cannot represent these rows. It means the current public
and generated metadata rarely provides that representation, while the
Ethereum-specific axes remain available.

## 4. Quantified complementarity

Of the 1,829 records without an assigned CWE:

- 1,544 (84.4%) still have a non-`other` root cause;
- 1,745 (95.4%) still have a non-`other` protocol/subsystem label;
- 1,541 (84.3%) have both.

The contribution is therefore not a replacement taxonomy. It is a
two-coordinate description:

> generic weakness mechanism × Ethereum protocol location.

That representation retains structured information for 1,541 records that
would otherwise be uncategorized in a CWE-only analysis.

## 5. Defensible paper claim

> CWE metadata is sparse and disclosure-biased in this corpus: only 396/2,225
> records have any CWE, and none of the 18 confirmed Critical/High records maps
> to the MITRE 2025 Top 25. Ethereum-specific root-cause and protocol-location
> axes provide both coordinates for 1,541/1,829 records lacking CWE, exposing
> consensus divergence, gas accounting, and other protocol failure modes that a
> CWE-only dataset view does not operationally capture.

The phrase “does not operationally capture” is important. The data supports a
metadata-coverage claim, not the stronger ontological claim that CWE is
incapable of representing blockchain-client defects.

## Generated evidence

- [`tables/cwe_context_coverage.csv`](tables/cwe_context_coverage.csv)
- [`tables/cwe_root_cause_coverage.csv`](tables/cwe_root_cause_coverage.csv)
- [`tables/cwe_semantic_multiplicity.csv`](tables/cwe_semantic_multiplicity.csv)
- [`tables/bounty_severe_cwe_audit.csv`](tables/bounty_severe_cwe_audit.csv)
- [`tables/reviewed_scope_cwe_coverage.csv`](tables/reviewed_scope_cwe_coverage.csv)
