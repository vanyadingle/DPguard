"""Shared type definitions for DP-Guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional


class MetricType(str, Enum):
    """Supported typed metrics in the telemetry catalog."""

    THREAT_LEVEL = "threat_level"
    ACTIVE_CONNECTIONS = "active_connections"
    ANOMALY_SCORE = "anomaly_score"
    FAILED_AUTH_ATTEMPTS = "failed_auth_attempts"
    SLICE_LOAD_PERCENT = "slice_load_percent"
    PACKET_LOSS_RATE = "packet_loss_rate"


class OperatorRole(str, Enum):
    """Typed access-control roles for the policy plane."""

    SECURITY_OPERATOR = "security_operator"
    NETWORK_ADMIN = "network_admin"
    READONLY_AUDITOR = "readonly_auditor"


@dataclass(frozen=True)
class MetricDefinition:
    """
    Typed metric metadata binding query, sensitivity, and semantic contract.

    Attributes:
        metric_type: Catalog identifier for the metric.
        sensitivity: Global L1 sensitivity Delta1(q) for the aggregation query.
        description: Human-readable description of the metric semantics.
        min_epsilon: Minimum allowed per-release epsilon for this metric.
        max_epsilon: Maximum allowed per-release epsilon for this metric.
        authorized_roles: Roles permitted to request this metric type.
    """

    metric_type: MetricType
    sensitivity: float
    description: str
    min_epsilon: float = 0.05
    max_epsilon: float = 1.0
    authorized_roles: frozenset[OperatorRole] = frozenset({OperatorRole.SECURITY_OPERATOR})


@dataclass(frozen=True)
class MetricQuery:
    """
    A single metric read request in an orchestration plan.

    Attributes:
        metric_type: Which typed metric to release.
        epsilon: Per-release privacy cost epsilon for the Laplace mechanism.
    """

    metric_type: MetricType
    epsilon: float


@dataclass
class OrchestrationPlan:
    """
    LLM-proposed sequence of DP metric reads.

    Attributes:
        queries: Ordered list of metric queries to execute.
        reasoning: Optional natural-language rationale from the LLM.
    """

    queries: List[MetricQuery]
    reasoning: str = ""


ActionType = Literal[
    "allow_traffic",
    "block_traffic",
    "isolate_segment",
    "safe_fallback",
    "monitor_only",
    "rate_limit_slice",
]


class SubagentRole(str, Enum):
    """Specialized roles for autonomous subagents in the multi-agent swarm."""

    ANOMALY_FORENSICS = "anomaly_forensics"
    SLICING_QOS = "slicing_qos"
    THREAT_MITIGATION = "threat_mitigation"


@dataclass(frozen=True)
class SubagentSpec:
    """
    Specification for a spawned subagent.

    Attributes:
        name: Unique subagent identifier.
        role: Domain specialization.
        target_metrics: DP metrics assigned to this subagent.
        allocated_epsilon: Privacy sub-budget assigned by the lead agent.
    """

    name: str
    role: SubagentRole
    target_metrics: List[MetricType]
    allocated_epsilon: float


@dataclass
class SubagentDecision:
    """
    Autonomous domain recommendation produced by a spawned subagent.

    Attributes:
        subagent_name: Identifier of the reporting subagent.
        role: Subagent specialization role.
        observations: Noisy observations evaluated by this subagent.
        local_assessment: Domain-specific evaluation and rationale.
        recommended_action: Action candidate recommended by this subagent.
        confidence: Confidence score in [0.0, 1.0].
    """

    subagent_name: str
    role: SubagentRole
    observations: List["NoisyObservation"]
    local_assessment: str
    recommended_action: ActionType
    confidence: float = 0.95


@dataclass
class MultiAgentTrace:
    """Execution trace of the multi-agent swarm in a single epoch."""

    lead_intent: str
    spawned_subagents: List[SubagentSpec]
    subagent_decisions: List[SubagentDecision]
    synthesized_action: ActionType
    lead_synthesis_rationale: str


@dataclass(frozen=True)
class ProposedAction:
    """
    LLM-proposed control action against network actuators.

    Attributes:
        action_type: Command identifier from the admissible action schema.
        parameters: Optional action-specific parameters.
    """

    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NoisyObservation:
    """
    Differentially private release of a single metric.

    Attributes:
        metric_type: Source metric type.
        noisy_value: Noisy aggregate returned to the orchestrator.
        epsilon: Privacy cost charged for this release.
        sensitivity: L1 sensitivity used for noise calibration.
        scale: Laplace scale b = Delta1(q) / epsilon.
    """

    metric_type: MetricType
    noisy_value: float
    epsilon: float
    sensitivity: float
    scale: float


@dataclass(frozen=True)
class UESessionRecord:
    """Single UE session record from raw network telemetry."""

    ue_id: str
    slice: str
    threat_score: float
    anomaly_flag: int
    bytes_tx: float
    auth_failures: int


@dataclass(frozen=True)
class NetworkSlice:
    """Network slice definition from topology catalog."""

    id: str
    type: str
    description: str
    capacity_ue: int
    sla_latency_ms: int


@dataclass
class NetworkContext:
    """
    Sanitized network context passed to the LLM (no raw subscriber data).

    Attributes:
        gnb_id: Base station identifier.
        region: Deployment region.
        slices: Available network slices (topology only).
        epoch_index: Current orchestration epoch number.
        remaining_epsilon: Privacy budget still available.
    """

    gnb_id: str
    region: str
    slices: List[NetworkSlice]
    epoch_index: int
    remaining_epsilon: float


@dataclass
class ActionExecutionResult:
    """Outcome of executing a control action on the network actuator plane."""

    action: ProposedAction
    success: bool
    message: str
    side_effects: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EpochResult:
    """Outcome of a single DP-Guard orchestration epoch."""

    intent: str
    plan: OrchestrationPlan
    proposed_action: ProposedAction
    observations: List[NoisyObservation]
    executed_action: ProposedAction
    execution_result: Optional[ActionExecutionResult]
    admissible: bool
    verification_message: str
    remaining_epsilon: float
    budget_exhausted: bool = False
    llm_provider: str = "mock"
    multi_agent_trace: Optional[MultiAgentTrace] = None
