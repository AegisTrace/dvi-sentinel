# ADR 0003: Deterministic experiments and evidence

Status: accepted; implemented in planning, serialization, comparison and artifacts.

A reported regression is difficult to assess if sampling order, implicit clocks,
changed inputs or unavailable observations can silently change the experiment.

Decision: use explicit seeds and budgets, a local RNG, stable ordering/IDs,
canonical DVI JSON and SHA-256 evidence inventories. Check exact case identity
before comparing detector changes. Preserve unknowns and record all denominators.

Consequence: the same inputs, tool version and configuration reproduce analysis
bytes. Whole bundles still record real clocks and invocation/git provenance;
their manifests therefore vary. An external trusted digest anchors integrity,
but hashes do not prove authorship. Search coverage and minima remain bounded.
See [reproduction proof](../reproduction.md) and [artifacts](../run_artifacts.md).
