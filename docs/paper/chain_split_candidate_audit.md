# RQ2a: source-level audit of estimated chain-split candidates

## Question

Of the 21 LLM High records whose inferred impact was `chain_split`, how many
are supported by the upstream description and captured code as concrete
consensus-sensitive defects?

This audit does not infer severity from the title. It separates three claims:

1. a concrete software defect exists;
2. the defect is in consensus-sensitive behavior;
3. exploitation caused, or could meet the EF threshold for, a >33% chain split.

Evidence for an earlier claim does not automatically prove the later claims.

## 1. Audit result

All 21 records were reviewed against their upstream title/description and the
captured pre/post-fix code.

| Verdict | Records | Share |
|---|---:|---:|
| Concrete consensus-sensitive defect | 9 | 42.9% |
| Operational or non-consensus change | 4 | 19.0% |
| Preventive hardening without a realized failure | 4 | 19.0% |
| Feature or predeployment change | 2 | 9.5% |
| Availability defect, not chain split | 1 | 4.8% |
| Source linkage insufficient | 1 | 4.8% |
| **Confirmed chain split** | **0** | **0.0%** |

Thus the LLM impact label has useful recall for consensus-sensitive code, but
poor precision for the stronger statement “this record is a chain-split
vulnerability.” Only 9/21 survive as consensus-defect candidates, and none
provides evidence of an actual chain split or the EF >33% impact threshold.

## 2. The nine surviving consensus-defect candidates

The nine records concern:

- EIP-7928 validity checks in Erigon;
- Geth stack-trie behavior and EVM memory-gas overflow;
- Lighthouse Capella payload logic, pre-mainnet transfer verification,
  indexed-attestation collisions, PeerDAS custody-column arithmetic, and BLS
  infinity-state tracking;
- Nethermind EVM zero-padding direction.

They remain `tier-uncertain`. Their deployment context further limits severity
interpretation:

| Deployment context | Candidates |
|---|---:|
| Predeployment fork/spec work | 4 |
| Pre-mainnet | 1 |
| Deployed code | 1 |
| Deployment unclear | 3 |

The single record marked `deployed_code` is Geth's EVM memory-gas overflow
boundary correction. The code establishes consensus sensitivity, but the
record does not demonstrate practical transaction reachability or historical
network share at the fix date. It therefore cannot be promoted to High.

## 3. Why twelve candidates were rejected as chain-split evidence

The rejected set reveals systematic estimator errors:

- A blob-receipt encoding record explicitly reports a panic on blob testnets.
  That is availability evidence, not chain-split evidence.
- Four records introduce checked arithmetic or defense-in-depth without a
  concrete remotely realized divergent state.
- Two records are broad feature/future-fork implementation work rather than a
  single vulnerability fix.
- Four concern recovery behavior, reward calculation, removal of an obsolete
  mitigation, or local CLI/spec configuration.
- One Lighthouse timing-attack issue is paired with a captured compression
  error change that does not substantiate the issue-level claim.

This last case is also a dataset-quality finding: issue-to-fix linkage must be
audited independently of semantic classification.

## 4. Implication for estimated severity

The earlier correction of all 110 LLM High labels to `tier-uncertain` is
supported, not weakened, by this audit.

Within the most apparently severe subset—21 rows already classified by the
model as remotely reachable, spec-level chain split:

- only 9 contain direct evidence of a consensus-sensitive defect;
- 0 establish an actual chain split;
- 0 establish the EF >33% threshold.

Therefore neither `impact_type=chain_split` nor `blast_radius=spec_level` should
be used as a substitute for historical affected share, deployment state, or an
executable trigger.

## 5. Paper contribution

> Decomposed LLM labels are effective retrieval cues but not impact evidence.
> Source-level review reduced 21 estimated chain-split High records to nine
> concrete consensus-defect candidates, while zero records independently
> established a chain split or the EF >33% threshold. Feature timing,
> deployment state, and issue-to-fix linkage are necessary audit dimensions
> beyond conventional weakness and severity labels.

This gives the paper a measurable validation result rather than a generic
warning that LLM labels may be noisy.

## 6. Next audit

The next highest-value slice is the 89 `liveness_dos` candidates. Review should
start with:

1. the five records labelled `test`;
2. client-specific candidates whose High rationale depends on static share;
3. records whose source does not show a single-message or single-transaction
   trigger;
4. records fixed before the relevant fork or feature deployment.

## Generated evidence

- [`tables/chain_split_candidate_audit.csv`](tables/chain_split_candidate_audit.csv)
- [`tables/chain_split_audit_summary.csv`](tables/chain_split_audit_summary.csv)
- [`tables/ef_severity_high_review_queue.csv`](tables/ef_severity_high_review_queue.csv)
