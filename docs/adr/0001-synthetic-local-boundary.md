# ADR 0001: Synthetic local telemetry boundary

Status: accepted; implemented in scenario/policy, local readers and harnesses.

Detection-resilience experiments need controlled observations. Live target or
detector integrations introduce operational effects, credentials and unavailable
oracles that are unnecessary for the V1 engineering question.

Decision: accept only synthetic/documentation fixtures and two local harnesses.
Scenarios have strict declarative fields and required safety attestations. Apply
policy at input boundaries and after transformations; do not provide subprocess,
network or executable-expression hooks.

Consequence: V1 can reproduce local fragility without contacting a system, but
cannot validate production detector behavior. Provenance is a declaration, and
the host filesystem must be trusted. The boundary is enforced in code and tested;
it is not an OS sandbox. See [safety model](../safety_model.md).
