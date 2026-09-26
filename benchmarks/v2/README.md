# V2 expert fixtures

All events are synthetic. Addresses use documentation ranges and the DNS resource
uses the reserved `.example` namespace. No external service or detector is used.

[`suite.json`](suite.json) declares one diagnostic/control pair for every V2 category.
Eight pairs reference the existing parent-directory V1 scenarios and fixtures;
their acceptance declarations are preserved. New YAML scenarios and JSONL inputs
exercise the implemented engines. `sequence_change.json` declares a bounded timing
change, and the intent YAML files declare independently checked contracts.

From the repository root, after installing the package:

```sh
python examples/run_v2_benchmarks.py --out runs/benchmarks/v2
```

Expected values are fixture oracles, not generated snapshots of observed outputs.
The [benchmark contract](../../docs/benchmarks.md#v2-expert-suite) explains all sixteen
pairs, score scopes, true unknowns, non-applicable analyses, bounds and exit codes.
The suite's success means the expected diagnostic behavior was reproduced; several
inputs deliberately fail their underlying detection or integrity contracts.
