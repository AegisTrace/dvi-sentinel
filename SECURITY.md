# Security policy

DVI Sentinel is a local synthetic/documentation-fixture harness. No live targets,
attack traffic, credential handling, scenario command execution or external
detector integrations are supported. Review the [safety model](docs/safety_model.md)
and [release safety review](RELEASE_SAFETY_REVIEW.md) before using custom fixtures.

## Report a vulnerability

Use GitHub's enabled [private vulnerability reporting](https://github.com/AegisTrace/dvi-sentinel/security/advisories/new).
Include the affected commit/version, environment, expected boundary, observed
behavior and the smallest safe synthetic reproducer. Do not include credentials,
real host data, private telemetry or a working exploit. Do not test against third
parties or a production detector to demonstrate a DVI issue.

Keep vulnerability details out of public issues until coordinated disclosure.
Ordinary functional bugs can use the issue tracker with synthetic examples.
There is no guaranteed response or remediation time.

## Supported state and limits

The current release is `1.0.0`; `main` contains unreleased V2 development. Reports
should identify the affected version or commit and reproduce against current main
when practical. No separate maintenance branch or production-support guarantee
is offered.

Use a trusted local filesystem and validated public APIs. Policy is not an OS
sandbox, provenance declarations are not content classification, and unkeyed
manifests do not prove authorship. The documented Docker runtime disables
networking as an additional restriction; dependency installation/build may use
the network. Never supply real secrets or live telemetry to a fixture experiment.

## Dependency and CI maintenance

Repository vulnerability alerts are enabled. Maintainers review alerts, update the
relevant package lock, image digest or action SHA, and run the full quality gate
before publishing directly on `main`. Dependabot version pull requests and automatic
security update pull requests are disabled to preserve the single-branch policy.
Alerts are review input, not a claim that dependencies are vulnerability-free.

The [CI gate](docs/ci.md) uses read-only repository permissions, full action commit
pins, no required secrets and bounded jobs. It checks both supported Python versions,
installed package assets, actual benchmark/report evidence and expected refusals.
A separate container job disables networking and runs with a non-root user and
read-only root filesystem. Test socket denial and container restrictions supplement
the fixture policy; neither turns untrusted scenario text into executable code.
