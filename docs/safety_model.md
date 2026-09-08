# Safety model

DVI accepts local synthetic/documentation fixtures. It contains no capability to
connect to a detector, issue a network request, run a shell command, or generate
attack traffic. The scenario contract is an allowlist of declarative fields;
there is no executable expression, template, plugin, URL input, or command slot.

The boundary combines strict Pydantic fields, explicit safety declarations,
bounded local file access, documentation network identifiers, and supplementary
structured-content checks. A keyword blacklist is not the execution boundary.
For example, descriptive text about malware detection is inert and accepted;
an unrecognized `malware` content field is rejected.

## Stable policy rules

Every decision has rule_id, allow/reject/warn, evidence path, and explanation.

| ID | Meaning |
|---|---|
| DVI-POL-000 | Valid strict local synthetic declaration (allow) |
| DVI-POL-001 | Invalid/unsupported schema or YAML |
| DVI-POL-002 | Unsafe or escaping filesystem path |
| DVI-POL-003 | Missing/invalid safety attestation |
| DVI-POL-004 | Command/execution field |
| DVI-POL-005 | Payload/exploit/malware field |
| DVI-POL-006 | Credential field |
| DVI-POL-007 | Stealth/persistence/escalation field |
| DVI-POL-008 | Live-target/scan/destructive capability field |
| DVI-POL-009 | Missing/unreadable local regular file |
| DVI-POL-010 | Resource size/depth limit exceeded |
| DVI-POL-011 | Unsafe URL/network identifier |
| DVI-POL-012 | Unsafe or contradictory variation permission |
| DVI-POL-013 | No variation families configured (warn) |

Input fields are checked using normalized Unicode/case/punctuation for explicit
forbidden capability keys. Unknown DSL fields fail independently of that check.
Known network fields and URL-shaped content must use documentation addresses:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32; example.com/net/org
and their subdomains; or names under .example, .test, .invalid. Private and
loopback addresses are excluded because fixtures do not need real lab hosts.
HTTP(S) documentation URLs and relative HTTP resource paths are inert strings;
protocol-relative URLs, credentials, and other URL schemes
are rejected. No identifier validation performs a DNS lookup.

`local_fixtures.py` refuses absolute/UNC paths, backslashes, percent encoding,
colon/alternate streams, traversal components, reserved Windows device names,
symlinks, and paths resolving outside the scenario directory. Reads are bounded
and never modify fixtures. Scenario files are limited to 128 KiB; other inputs
to 2 MiB; YAML and structured payload nesting to 24 levels.

`load_scenario` checks declarations and local paths. `evaluate_events` checks
normalized event data, source metadata, and raw payloads. The variation engine
must call it after transformations as well as before experiments. Any reject
must exclude that candidate from execution and scoring as a valid experiment.

## Limitations

This is an application policy, not an operating-system sandbox or a classifier
of arbitrary malicious text. Fixture provenance is a declaration; unknown or
encoded content cannot be certified benign by string inspection. Known network
field checks do not infer the meaning of every vendor-specific field. Adapters
must expose normalized identifiers and preserve raw evidence for inspection.
No accepted string is evaluated as code, even if its content is not recognized.

The caller must supply a trusted local filesystem root. Concurrent filesystem
replacement, mounted remote drives, OS compromise, and hostile Python callers
using unchecked construction are outside this process-level boundary. Run the
container with networking disabled for an additional OS-level restriction.

Proof: `uv run pytest tests/test_policy.py`. Tests assert rule IDs and evidence,
including Unicode/casing obfuscation of prohibited fields, URL encoding,
traversal/device paths, declaration coercion, malformed YAML, generated network
boundaries, and raw/normalized post-transformation content.
The real symlink rejection test runs in Linux CI. On Windows it is skipped only
when the OS reports missing symlink-creation privilege (WinError 1314); other
filesystem failures remain test failures. No system privileges are changed.
