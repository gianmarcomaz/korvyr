# SupplyGuard Baseline Accuracy Report - 2026-05-18 04:00

## Scope

- Run type: partial production-path baseline.
- Reason full raw-corpus evaluation was not run: recursive raw-corpus counting and full manifest target collection timed out locally before evaluation. The baseline therefore uses the largest existing balanced evaluation target set available from local files.
- Do not treat this as proof of the 99.9% precision / 89-90% recall target. It is the comparison baseline for future accuracy work.

## Provenance

- Git commit before run: `800712e4998c89b58550a5de73a7595cb0caf2b8`
- Dataset source: `data/processed/hybrid_real_evaluation_phase1_manifest.json`
- Output JSON: `results/baseline_accuracy_20260518_0400.json`
- Raw evaluator Markdown: `results/baseline_accuracy_20260518_0400_raw.md`
- Model checkpoint path: `checkpoints\best_model.pt`
- Model loaded: `True`
- Device: `cpu`
- Elapsed seconds: `1878.64`

Exact command used:

```powershell
$env:PYTHONPATH="C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard\.venv\Lib\site-packages;C:\Users\gianm\Desktop\Everything\Projects\SupplyGuard"; C:\Users\gianm\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe scripts\evaluate_production.py --from-existing-eval data\processed\hybrid_real_evaluation_phase1_manifest.json --model-path checkpoints\best_model.pt --output-json results\baseline_accuracy_20260518_0400.json --output-md results\baseline_accuracy_20260518_0400_raw.md --device cpu --log-level INFO
```

## Dataset Counts

- Total packages: 600
- Malicious packages: 300
- Benign packages: 300
- Label source: `true_label` values from the existing evaluation JSON.

## Threshold Config

| Setting | Value |
|---|---:|
| `gnn_auto_pass` | `0.4` |
| `gnn_auto_block` | `0.75` |
| `gnn_uncertain_low` | `0.4` |
| `gnn_uncertain_high` | `0.75` |
| `rules_block_on_critical` | `True` |
| `rules_block_threshold` | `15.0` |
| `rules_auto_block_threshold` | `15.0` |
| `rules_moderate_block_threshold` | `10.0` |

## Accuracy Metrics

| System | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|
| GNN-only | 0.9065 | 0.8400 | 0.8720 | 252 | 26 | 48 | 274 |
| Rules-only | 0.8882 | 0.5033 | 0.6426 | 151 | 19 | 149 | 281 |
| Hybrid | 1.0000 | 0.4800 | 0.6486 | 144 | 0 | 156 | 300 |

## Coverage And Failure Rates

- GNN coverage rate: 100.00%
- GNN failure count: 0
- GNN error rate: 0.00%
- GNN error buckets: `{}`
- CPG none count: 0
- CPG failure count: 0
- CPG failure rate: 0.00%
- CPG status counts: `{'success': 600}`

## Decision Buckets

| Bucket | Count |
|---|---:|
| `critical_rule_block` | 46 |
| `gnn_confident_clean` | 183 |
| `gnn_rules_confirmed_block` | 90 |
| `gnn_unconfirmed_review` | 90 |
| `gnn_very_high_block` | 8 |
| `review_only_critical` | 18 |
| `static_evidence_review` | 165 |

## Per-Rule Saved/Hurt

| Rule | Saved | Hurt |
|---|---:|---:|
| `CRIT_DYNAMIC_REQUIRE_EXEC` | 0 | 1 |
| `CRIT_EXFIL_CREDENTIALS` | 1 | 0 |
| `CRIT_INSTALL_HOOK_EXEC` | 1 | 0 |
| `CRIT_MANIFEST_NODE_EVAL` | 1 | 0 |
| `CRIT_REVERSE_SHELL` | 0 | 2 |
| `HIGH_ENCODED_PAYLOAD_CHAIN` | 3 | 5 |
| `HIGH_EVAL_DECODED` | 2 | 3 |
| `HIGH_OBFUSCATED_INSTALL` | 0 | 2 |
| `HIGH_PROCESS_ENV_BULK` | 1 | 0 |
| `HIGH_RUNTIME_PROTOTYPE_POLLUTION` | 6 | 5 |
| `HIGH_STEGANOGRAPHIC_PAYLOAD` | 1 | 1 |
| `HIGH_WEBHOOK_EXFIL` | 4 | 16 |
| `MED_INSTALL_HOOK_EXISTS` | 1 | 26 |
| `MED_MANIFEST_INSTALL_HOOK_ONLY` | 0 | 7 |
| `MED_MINIFIED_SINGLE_FILE` | 2 | 2 |
| `MED_NETWORK_PLUS_FS` | 4 | 25 |
| `MED_SUSPICIOUS_PACKAGE_STRUCTURE` | 0 | 9 |

## Top False Positives

- None measured in this partial baseline.

## Top False Negatives

Sorted by highest hybrid confidence, then highest GNN score.

| Package | Confidence | GNN | Rules | Decision | Path |
|---|---:|---:|---|---|---|
| `phantom-module` | 0.8500 | 0.9476 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.948) without strong static confirmation | `data/raw/malicious/npm/phantom-module/111.0.8/tmp/tmpbsheog8r/phantom-module/package` |
| `elf-stats-snowdusted-lantern-234` | 0.8500 | 0.9472 | HIGH_WEBHOOK_EXFIL, MED_INSTALL_HOOK_EXISTS, MED_NETWORK_PLUS_FS | GNN high malicious score (0.947) without strong static confirmation | `data/raw/malicious/npm/elf-stats-snowdusted-lantern-234/1.0.6/tmp/tmp_w955mki/elf-stats-snowdusted-lantern-234/package` |
| `package-with-import-assertions` | 0.8500 | 0.9465 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.946) without strong static confirmation | `data/raw/malicious/npm/package-with-import-assertions/1.0.3/tmp/tmpolinqupm/package-with-import-assertions/package` |
| `admin0911` | 0.8500 | 0.9452 | HIGH_WEBHOOK_EXFIL, MED_INSTALL_HOOK_EXISTS, MED_SUSPICIOUS_PACKAGE_STRUCTURE, MED_MANIFEST_INSTALL_HOOK_ONLY | GNN high malicious score (0.945) without strong static confirmation | `data/raw/malicious/npm/admin0911/1.0.19/tmp/tmpfekxs3th/admin0911/package` |
| `magala` | 0.8500 | 0.9444 | none | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/magala/1.0.2/tmp/tmppkih0s6f/magala/package` |
| `blocks-nextjs` | 0.8500 | 0.9441 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/blocks-nextjs/9999.9999.10393/tmp/tmpvg2c953o/blocks-nextjs/package` |
| `blocks-nextjs` | 0.8500 | 0.9441 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/blocks-nextjs/9999.9999.10275/tmp/tmppfy39e4h/blocks-nextjs/package` |
| `blocks-nextjs` | 0.8500 | 0.9441 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/blocks-nextjs/9999.9999.10195/tmp/tmp3raeifcl/blocks-nextjs/package` |
| `blocks-nextjs` | 0.8500 | 0.9441 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/blocks-nextjs/9999.9999.10249/tmp/tmpht0gy4g4/blocks-nextjs/package` |
| `blocks-nextjs` | 0.8500 | 0.9441 | HIGH_WEBHOOK_EXFIL, MED_NETWORK_PLUS_FS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/blocks-nextjs/9999.9999.10246/tmp/tmpla8hjoz1/blocks-nextjs/package` |
| `tree-sitter-your-language` | 0.8500 | 0.9438 | MED_INSTALL_HOOK_EXISTS | GNN high malicious score (0.944) without strong static confirmation | `data/raw/malicious/npm/tree-sitter-your-language/1.0.3/tmp/tmprb177ek3/tree-sitter-your-language/package` |
| `magic-enum` | 0.8500 | 0.9426 | HIGH_WEBHOOK_EXFIL | GNN high malicious score (0.943) without strong static confirmation | `data/raw/malicious/npm/magic-enum/14.9.9/tmp/tmpnvaox82f/magic-enum/package` |
| `mad-3.0.1.2.2.8.` | 0.8500 | 0.9424 | MED_MINIFIED_SINGLE_FILE | GNN high malicious score (0.942) without strong static confirmation | `data/raw/malicious/npm/mad-3.0.1.2.2.8/1.0.0/tmp/tmp9ecswy6t/mad-3.0.1.2.2.8/package` |
| `abhiktestnpm` | 0.8500 | 0.9407 | MED_INSTALL_HOOK_EXISTS, MED_SUSPICIOUS_PACKAGE_STRUCTURE, MED_MANIFEST_INSTALL_HOOK_ONLY | GNN high malicious score (0.941) without strong static confirmation | `data/raw/malicious/npm/abhiktestnpm/1.0.1/tmp/tmp7i2so0qr/abhiktestnpm/package` |
| `elf-stats-shimmering-toolkit-483` | 0.8500 | 0.9404 | none | GNN high malicious score (0.940) without strong static confirmation | `data/raw/malicious/npm/elf-stats-shimmering-toolkit-483/1.0.0/tmp/tmp8kk3k6c0/elf-stats-shimmering-toolkit-483/package` |
| `token-discord-encryptation` | 0.8500 | 0.9352 | none | GNN high malicious score (0.935) without strong static confirmation | `data/raw/malicious/npm/token-discord-encryptation/1.2.5/tmp/tmpsy63w1f7/token-discord-encryptation/package` |
| `elf-stats-lanternlit-sled-571` | 0.8500 | 0.9326 | none | GNN high malicious score (0.933) without strong static confirmation | `data/raw/malicious/npm/elf-stats-lanternlit-sled-571/9998.0.1/tmp/tmp0_artse_/elf-stats-lanternlit-sled-571/package` |
| `elf-stats-rooftop-mitten-324` | 0.8500 | 0.9284 | HIGH_WEBHOOK_EXFIL, MED_INSTALL_HOOK_EXISTS, MED_NETWORK_PLUS_FS | GNN high malicious score (0.928) without strong static confirmation | `data/raw/malicious/npm/elf-stats-rooftop-mitten-324/1.0.0/tmp/tmp46tvm9un/elf-stats-rooftop-mitten-324/package` |
| `rollup-plugin-polyfill-build` | 0.8500 | 0.9229 | none | GNN high malicious score (0.923) without strong static confirmation | `data/raw/malicious/npm/rollup-plugin-polyfill-build/1.0.2/tmp/tmp4bgidakr/rollup-plugin-polyfill-build/package` |
| `waterline-mongo-native` | 0.8500 | 0.9190 | MED_INSTALL_HOOK_EXISTS, MED_SUSPICIOUS_PACKAGE_STRUCTURE, MED_MANIFEST_INSTALL_HOOK_ONLY | GNN high malicious score (0.919) without strong static confirmation | `data/raw/malicious/npm/waterline-mongo-native/1.0.0/tmp/tmplhct6jkx/waterline-mongo-native/package` |
| `vite-plugin-remove` | 0.8500 | 0.9188 | MED_INSTALL_HOOK_EXISTS, MED_SUSPICIOUS_PACKAGE_STRUCTURE, MED_MANIFEST_INSTALL_HOOK_ONLY | GNN high malicious score (0.919) without strong static confirmation | `data/raw/malicious/npm/vite-plugin-remove/1.0.0/tmp/tmpq5h3kvtv/vite-plugin-remove/package` |
| `react-bindify-decorators` | 0.8500 | 0.9186 | MED_INSTALL_HOOK_EXISTS | GNN high malicious score (0.919) without strong static confirmation | `data/raw/malicious/npm/react-bindify-decorators/8.10.10/tmp/tmpa55yelw_/react-bindify-decorators/package` |
| `elf-stats-merry-fir-592` | 0.8500 | 0.9157 | MED_NETWORK_PLUS_FS | GNN high malicious score (0.916) without strong static confirmation | `data/raw/malicious/npm/elf-stats-merry-fir-592/1.0.0/tmp/tmpceledazj/elf-stats-merry-fir-592/package` |
| `ember-glimmer` | 0.8500 | 0.9134 | none | GNN high malicious score (0.913) without strong static confirmation | `data/raw/malicious/npm/ember-glimmer/1.0.0/tmp/tmpnjkh3i5x/ember-glimmer/package` |
| `greasy-green-cricket` | 0.8500 | 0.9111 | none | GNN high malicious score (0.911) without strong static confirmation | `data/raw/malicious/npm/greasy-green-cricket/9.4.4/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmp3cb7wd38/package` |

## Caveats

- This run uses an existing balanced 600-package target list, not the entire local raw corpus.
- Several packages reached the CPG AST node cap during evaluation, but all 600 still produced CPG status `success`.
- Suspicious/review verdicts are counted as negative for precision/recall because the evaluator only treats hard `malicious` blocks as positive predictions.
- The JSON contains full package-level records for follow-up false-negative inspection.

