# Explainable detection matching

`match_detection(expected, observed, events, parser_success=True,
preservation=None)` returns a `MatchResult` with detected/missed/unknown status,
reason, matching alert IDs, delay, evidence availability, and every candidate's
normalized field comparisons. It does not execute a detector or access I/O.

## Decision rules

1. A failed semantic invariant, incomplete normalization, or unavailable harness
   result is unknown before inspecting candidate matches. No completeness value
   can override these guards.
2. Simultaneously configured exact and contained signatures, or repeated expected
   set members, are ambiguous expectations. Duplicate observed/input event IDs
   prevent unique evidence attribution. Both conditions return explicit unknown.
3. Candidates have the exact configured detector identity. None means missed
   with `DVI-MATCH-NO-CANDIDATE`.
4. Every configured check must pass within one candidate. Checks are evaluated
   in documented order: required fields, detector/source, signature/title,
   severity, labels/tags/techniques, event IDs, correlation, and time.
5. A proven missing required field or contradiction makes that candidate missed;
   otherwise unavailable time attribution makes it unknown. All passing checks
   make it detected. The first hard failure determines its primary reason;
   every other comparison remains in the output.
6. Any detected candidate makes the result detected. Otherwise an unknown
   candidate makes the result unknown; otherwise it is missed. Distinct failing
   candidates cannot hide a valid match. Evidence from different candidates is
   never combined to fabricate one passing candidate.

Candidates are sorted by alert ID. Matching IDs include all passing alerts.
Summary delay is the earliest passing delay, or the decisive candidate's delay
when there is no match. Summary evidence comes from a passing candidate first,
then an unknown candidate, then a failed candidate; within that group, fewer
missing/contradictory fields and then ID select a deterministic representative.
The full candidate list prevents this summary from concealing conflicting data.

## Field and time semantics

- `signature` is exact; `signature_contains` and `title_contains` are literal,
  case-sensitive substrings only. There are no regexes or fuzzy matching.
- `source_adapter`, when set, compares the observation's `raw.adapter`, not the
  input telemetry adapter. `detector` always matches exactly.
- Severity is the normalized DVI level. Required severity treats unknown level
  zero as missing; the threshold otherwise compares numeric levels.
- Expected labels, tags, techniques, and event IDs are subsets. Extra metadata
  is allowed. Event IDs refer to the detection's `related_event_ids`.
- Correlation identity is exact. Missing and contradictory values remain
  distinguishable in the comparison outcome even when sharing a field reason.
- Explicit `reference_time` wins. Otherwise use the latest input timestamp among
  expected event IDs, or among the candidate's related IDs when none are expected.
  All referenced IDs must resolve. With no IDs and exactly one input, its time is
  unambiguous. Other unattributed cases remain unknown.
- Delay is alert timestamp minus reference time in milliseconds. The window is
  inclusive `[0, max_delay_ms]`; negative and late delays have separate reasons.
  There is no wall-clock inference. Latest linked input is appropriate for an
  aggregate rule observation; configure an explicit time for another convention.

`evidence_completeness` is available comparison values divided by all configured
comparisons. Passes and contradictions are available; missing and unknown are
not. It is not a probability, confidence, quality score, or resilience score.
A fully evidenced miss can have completeness 1.0. Top-level unknown guards and
no-candidate results have zero because no candidate assessment is available.

## Reasons and integration

Reason codes distinguish detected, no candidate, early/late, missing required
field, severity, labels, tags, techniques, signature, title, source, event IDs,
correlation, normalization, ambiguous expectation/observation, unavailable time,
harness, and invariant failure. `match_models.py` defines the finite contract.

`run_probes(..., expected=...)` and `run_differential(..., expected=...)` now
retain baseline and candidate `MatchResult` objects and compare full expected
semantics. A baseline must be detected before asserting downstream fragility.
For callers that intentionally omit an expectation, the existing identity-only
observation comparison remains explicit in the probe report. With expectations,
schema fragility compares match outcomes only after input semantics agree.

`tests/test_matching.py` proves successful matches, every configured dimension,
distinct reasons, missing fields, malformed-normalization guards, conflicting
candidates, ambiguous IDs/expectations, inference and missing time, deterministic
ordering, exact inclusive windows through Hypothesis, and integration cases where
title/severity failure is discovered even though detector/signature identities
survive. The CLI orchestration belongs to Phase 14.
