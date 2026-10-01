"""Typed native evidence retained by the version-three report (D)."""

from typing import Annotated

from pydantic import Field

from dvi_sentinel.confidence_models import ConfidenceReport
from dvi_sentinel.consensus_shrinking_models import OracleShrinkReport
from dvi_sentinel.counterfactual_models import CounterfactualSummary
from dvi_sentinel.intent_models import IntentAnalysis
from dvi_sentinel.knowledge_graph_models import GraphReport
from dvi_sentinel.metamorphic_models import MetamorphicReport
from dvi_sentinel.models import ValueModel
from dvi_sentinel.ontology_models import OntologyExtraction
from dvi_sentinel.oracle_models import OracleConsensus
from dvi_sentinel.temporal_models import TemporalSummary


class AdvancedEvidence(ValueModel):
    semantics: Annotated[tuple[OntologyExtraction, ...], Field(max_length=128)]
    intent: IntentAnalysis | None = None
    mapping: MetamorphicReport | None = None
    temporal: TemporalSummary | None = None
    oracle: OracleConsensus | None = None
    counterfactual: CounterfactualSummary | None = None
    confidence: ConfidenceReport | None = None
    graph: GraphReport | None = None
    minimum: OracleShrinkReport | None = None
