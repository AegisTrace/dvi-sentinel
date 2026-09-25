"""Trace measured local gaps, controls and proposed review actions to source evidence."""

import argparse
from pathlib import Path

from dvi_sentinel.counterfactual_models import CounterfactualBudget
from dvi_sentinel.counterfactuals import mine_counterfactuals
from dvi_sentinel.knowledge_graph import graph_artifacts
from dvi_sentinel.knowledge_graph_models import GraphReport
from dvi_sentinel.run_artifacts import json_bytes
from dvi_sentinel.serialization import parse_json

if __package__:
    from .counterfactuals import fixture
else:
    from counterfactuals import fixture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/v2/knowledge-graph-proof"))
    destination: Path = parser.parse_args().out
    if str(destination).startswith(("\\\\", "//")) or any(
        p.is_symlink() or p.is_junction() for p in (destination, *destination.parents)
    ):
        parser.error("output must be a plain local directory without linked ancestors")
    destination = destination.resolve()
    if destination.exists():
        parser.error("output must be a new local directory")
    outputs = {}
    for mode in ("combination", "robust", "incomplete"):
        request = fixture("combination" if mode == "incomplete" else mode)
        if mode == "incomplete":
            request = request.model_copy(update={"budget": CounterfactualBudget(max_cases=1)})
        source = mine_counterfactuals(request, expected_digest=request.stable_digest())
        artifacts = graph_artifacts(source, expected_digest=source.stable_digest())
        report = GraphReport.model_validate(parse_json(artifacts["detection_graph.json"]))
        assert report.state == "built"
        assert report.summary.findings == (1 if mode == "combination" else 0)
        assert report.summary.recommendations == report.summary.findings
        assert report.summary.weak_edges > 0
        artifacts["counterfactual_summary.json"] = json_bytes(source)
        outputs[mode] = artifacts
        print(
            f"{mode}: {report.summary.nodes} nodes, {report.summary.edges} edges; "
            f"{report.summary.findings} findings, {report.summary.weak_edges} weak edges"
        )
    destination.mkdir(parents=True, exist_ok=False)
    for mode, artifacts in outputs.items():
        directory = destination / mode
        directory.mkdir()
        for name, content in artifacts.items():
            with (directory / name).open("xb") as stream:
                stream.write(content)
    print(destination)


if __name__ == "__main__":
    main()
