# Build report

Deterministic build of the curated security-only set from the raw snapshot.

## Before (raw crawl)

- rows: **33,744**
- no security signal at all (CWE=N/A & STRIDE=Other & unrated): **14,745** (43.7%)
- release-note / urgency boilerplate (T1 targets): **96** rows, of which 87 were mislabeled `Critical`
- `Critical` severity total: 102 (mostly the boilerplate FP above)

## Pipeline stages

- **T1** dropped 99 boilerplate rows {'nimbus': 96, 'geth': 3}
- **T7 + GATE** kept 19,046 of 33,645 (dropped 14,599 low-signal)

## After (curated)

- rows: **19,046**
- residual boilerplate FP: **0**  ✅
- `Critical` severity total: **15** (phantom Nimbus criticals removed)
- by confidence: {'medium': 16426, 'low': 1743, 'high': 877}
- by severity: {'Info': 12583, 'Unrated': 4663, 'Medium': 1056, 'Low': 475, 'High': 254, 'Critical': 15}
- by source:
  - geth: 3,496
  - lodestar: 2,738
  - nimbus: 2,324
  - prysm: 2,288
  - teku: 1,750
  - besu: 1,616
  - lighthouse: 1,279
  - erigon: 1,211
  - ethereum_specs: 789
  - nethermind: 698
  - reth: 641
  - grandine: 214
  - consensus-specs: 2
- security_score distribution: {'0.0': 13643, '0.3': 1535, '0.5': 2427, '0.8': 564, '0.9': 345, '1.0': 532}
