# Examples

Inspect the CLI with `dvi --help` and `dvi --version`.
`canonical_event.json` is a validated synthetic flow event using documentation
addresses. Load it with `TelemetryEvent.model_validate_json` to inspect its UTC
timestamp and retained source timestamp. It is an event-model example, not a
scenario or generated network traffic.
