# Architecture

A module-by-module walkthrough of how a package becomes a verdict. See the
README for the threat model and the limitations of each stage.

## Scan path

```
tarball or package directory
  |
  v  korvyr.scanner.tarball.extract_package        safe extraction
  v  korvyr.parsing.ast_extractor.extract_ast      tree-sitter AST + node features
  v  korvyr.parsing.cfg_extractor.extract_cfg      approximate control flow
  v  korvyr.parsing.dfg_extractor.extract_dfg      lexical def-use + taint flags
  v  korvyr.graph.cpg_builder.build_cpg            one PyG Data object per package
  v  korvyr.model.gin_classifier.KorvyrGIN         gnn_score in [0, 1]
  |
  +  korvyr.scanner.rules_engine.run_rules         22 rules over raw source
  +  korvyr.scanner.manifest_scanner               package.json lifecycle rules
  +  korvyr.metadata.risk_scorer                   typosquat / structural risk
  |
  v  korvyr.scanner.scan_pipeline._decide          verdict, confidence, evidence
```

`korvyr/scanner/scan_pipeline.py::scan_package` is the single entry point that
runs all of the above. The API, the CLI (via the API), and the evaluation
harness all go through it or through `_decide` directly.

## Parsing (`korvyr/parsing/`)

**`ast_extractor.py`** parses every `.js`/`.mjs` file with
`tree-sitter-javascript`, walks the tree, and emits node dicts plus `ast_child`
edges. `get_node_features` encodes each node as a `FEATURE_DIM` (35) float
vector: a one-hot over `NODE_TYPE_CATEGORIES` with an implicit `OTHER` bucket,
followed by binary flags computed from the node's source text (eval use, exec
use, network call, file operation, dangerous require, hex/unicode escapes,
base64-looking literals, dynamic require, crypto call, timer callback, string
manipulation).

`FEATURE_DIM` is the contract between the parser and the model. Changing the
node-type list changes the feature width and invalidates every existing
checkpoint — `korvyr/model/checkpoint.py` binds `NODE_FEATURE_DIM` to it so the
mismatch surfaces as a load error rather than as silent garbage scores.

**`cfg_extractor.py`** derives `cfg_next` and `cfg_branch` edges from AST
statement structure: sequential statements chain, conditionals and loops branch.
This is a structural approximation, not a real control-flow analysis — there is
no interprocedural edge construction and no path sensitivity.

**`dfg_extractor.py`** derives `dfg_def_use` edges by matching identifier names
between definitions and uses, and marks taint sources (`process.env`, file
reads, `os.*`) and sinks (network calls, `exec`, `eval`). Name matching is
lexical: shadowing, aliasing, and property flows are not modelled.

## Graph construction (`korvyr/graph/`)

**`cpg_builder.py`** merges the three edge sets into one
`torch_geometric.data.Data` with `x` `[N, 35]`, `edge_index` `[2, E]`,
`edge_type` `[E]` (values from `EDGE_TYPE_MAP`), an 8-element package metadata
vector, and the label.

Two behaviours matter operationally:

- **Dummy graphs.** A package with a `package.json` but no parseable JavaScript
  yields a single-node zero-feature graph with real metadata, so the model can
  still score it through the metadata branch instead of the package being
  skipped. `korvyr/evaluation/context_signals.py` treats "dummy graph" as a
  context signal for exactly this reason.
- **Diagnostics.** `build_cpg` degrades every failure to `None`;
  `build_cpg_with_diagnostics` returns the same result plus a status bucket and
  the failing sub-step, which is what the evaluator records. Setting
  `KORVYR_CPG_FAILURE_LOG` additionally appends failures to a CSV; unset (the
  default), nothing is written to disk.

## Model (`korvyr/model/`)

**`gin_classifier.py`** — `KorvyrGIN`. Node features are projected to
`hidden_dim`, edge types are embedded and injected through `GINEConv`, four
message-passing layers run with BatchNorm, ReLU, dropout, and residual skips,
all layer outputs are concatenated (jumping knowledge) and projected back.
Readout concatenates mean, sum, and max pooling with a normalised edge-type
histogram and the 8 metadata features, and an MLP head emits one logit.

**`checkpoint.py`** is the only place that instantiates the architecture and
loads weights. `load_model(path, device, required=...)` returns `None` for a
missing or unreadable checkpoint (static-only mode) or raises `CheckpointError`
with an actionable message when the caller requires the GNN.

**`training.py`** holds the lazy-loading `GraphDataset`, the `Trainer`, metric
computation, and threshold selection. Checkpoints record the feature dimensions,
training configuration, dataset fingerprint, and selected threshold strategy so a
checkpoint can be traced back to the run that produced it.

## Static analysis (`korvyr/scanner/`)

**`rules_engine.py`** loads all JS sources once (skipping `node_modules`,
`.git`, `vendor`) and runs 22 independent checks, each returning at most one
`MatchedRule`. Every check is wrapped so one failing rule cannot fail the scan.
Scores come from `rule.score`, then `RULE_SCORE_OVERRIDES`, then
`SEVERITY_WEIGHTS`.

Rules that look at install hooks resolve the hook's entry file and follow one
level of local `require()` calls, so a hook that delegates to `./lib/setup.js`
is still inspected.

**`manifest_scanner.py`** works only from `package.json`. It exists because a
package whose payload lives entirely in a lifecycle command has no JavaScript
for the graph pipeline to analyse. It filters known-benign hooks (`husky
install`, `patch-package`) before matching.

**Overlapping detections are intentional.** `CRIT_DNS_EXFIL` (DNS plus
credential variables) and `HIGH_DNS_EXFIL` (DNS plus any sensitive data source)
overlap; so do the manifest curl-pipe rule and the source-level install-hook
shell rule. Each produces its own evidence string, and each survives conditions
that would silence the other. They are not merged.

**`tarball.py`** centralises registry URL construction and extraction. Every
extraction path rejects members that would escape the destination directory and
skips symlinks and hardlinks — Korvyr routinely unpacks archives that are
expected to be hostile.

## Decision layer

`_decide` receives the model score (or `None`), the merged rules result, the
threshold config, and the metadata risk, and returns
`(verdict, confidence, decision_path, evidence)`. The `decision_path` string is
parsed back into a stable bucket by
`korvyr/evaluation/reporting.py::decision_bucket`, which is how evaluation
reports group outcomes — keep the two in sync when changing decision text.

Two rule scores drive the policy:

- **weighted score** — every matched rule scaled by `RULE_PRECISION_WEIGHTS`.
- **hard score** — only rules in `HARD_BLOCK_CAPABLE_RULES`, scaled the same
  way. This is what can block without model support.

`NON_CONFIRMING_RULES` additionally lists rules excluded from confirming a model
hit on their own. The weights are calibration output, not judgements about how
"bad" a behaviour is: a rule with weight 0.1 still reports its evidence, it just
cannot carry a block by itself.

## Service layer

**`korvyr/api/server.py`** loads the model once at startup through the lifespan
handler, keeps a thread pool for lockfile fan-out, and exposes the four
endpoints documented in [`api.md`](api.md). Every response carries `scan_mode`
so a caller can tell a hybrid verdict from a static-only one.

**`korvyr/cli/main.py`** is a thin HTTP client — it holds no scanning logic, so
the CLI and any other API consumer always see identical verdicts.

**`proxy/`** is a separate Node.js service; see [`proxy.md`](proxy.md).

## Configuration

`korvyr/config.py` is the single source of runtime configuration, reading
`KORVYR_`-prefixed environment variables. `proxy/src/config.js` does the same on
the Node side with the same prefix. `.env.example` documents every variable.
