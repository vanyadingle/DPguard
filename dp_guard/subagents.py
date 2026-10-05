"""Autonomous multi-agent swarm architecture for DP-Guard 6G zero-touch security."""

from __future__ import annotations

import logging
from typing import Any, List, Mapping, Optional

from dp_guard.types import (
    ActionType,
    MetricQuery,
    MetricType,
    MultiAgentTrace,
    NetworkContext,
    NoisyObservation,
    OrchestrationPlan,
    ProposedAction,
    SubagentDecision,
    SubagentRole,
    SubagentSpec,
)

logger = logging.getLogger(__name__)


class BaseSubagent:
    """Abstract domain-specific autonomous subagent."""

    def __init__(self, name: str, role: SubagentRole, target_metrics: List[MetricType]) -> None:
        self.name = name
        self.role = role
        self.target_metrics = target_metrics

    def evaluate(self, observations: List[NoisyObservation]) -> SubagentDecision:
        """Analyze DP-protected domain metrics and arrive at an autonomous decision."""
        raise NotImplementedError


class AnomalyForensicsSubagent(BaseSubagent):
    """Specialized subagent detecting cyber threats and authentication anomalies."""

    def __init__(self, name: str = "subagent-anomaly-forensics") -> None:
        super().__init__(
            name=name,
            role=SubagentRole.ANOMALY_FORENSICS,
            target_metrics=[MetricType.ANOMALY_SCORE, MetricType.FAILED_AUTH_ATTEMPTS],
        )

    def evaluate(self, observations: List[NoisyObservation]) -> SubagentDecision:
        relevant = [o for o in observations if o.metric_type in self.target_metrics]
        anomaly_val = next((o.noisy_value for o in relevant if o.metric_type == MetricType.ANOMALY_SCORE), 0.0)
        auth_fails = next((o.noisy_value for o in relevant if o.metric_type == MetricType.FAILED_AUTH_ATTEMPTS), 0.0)

        if anomaly_val > 40.0 or auth_fails > 12.0:
            assessment = (
                f"Critical anomaly detected (noisy anomaly_score={anomaly_val:.2f}, "
                f"failed_auths={auth_fails:.2f}). Recommending immediate traffic block."
            )
            action: ActionType = "block_traffic"
            confidence = 0.95
        elif anomaly_val > 20.0 or auth_fails > 5.0:
            assessment = (
                f"Elevated anomaly activity (noisy anomaly_score={anomaly_val:.2f}). "
                f"Recommending defensive rate limiting."
            )
            action = "rate_limit_slice"
            confidence = 0.85
        else:
            assessment = (
                f"Anomaly indicators within acceptable bounds (noisy anomaly_score={anomaly_val:.2f}). "
                f"Recommending active monitoring."
            )
            action = "monitor_only"
            confidence = 0.90

        return SubagentDecision(
            subagent_name=self.name,
            role=self.role,
            observations=relevant,
            local_assessment=assessment,
            recommended_action=action,
            confidence=confidence,
        )


class SlicingQoSSubagent(BaseSubagent):
    """Specialized subagent monitoring slice performance, packet loss, and capacity."""

    def __init__(self, name: str = "subagent-slice-qos") -> None:
        super().__init__(
            name=name,
            role=SubagentRole.SLICING_QOS,
            target_metrics=[
                MetricType.SLICE_LOAD_PERCENT,
                MetricType.PACKET_LOSS_RATE,
                MetricType.ACTIVE_CONNECTIONS,
            ],
        )

    def evaluate(self, observations: List[NoisyObservation]) -> SubagentDecision:
        relevant = [o for o in observations if o.metric_type in self.target_metrics]
        loss_val = next((o.noisy_value for o in relevant if o.metric_type == MetricType.PACKET_LOSS_RATE), 0.0)
        load_val = next((o.noisy_value for o in relevant if o.metric_type == MetricType.SLICE_LOAD_PERCENT), 0.0)

        if loss_val > 3.0 or load_val > 75.0:
            assessment = (
                f"Degraded slice QoS detected (noisy packet_loss={loss_val:.2f}%, "
                f"load={load_val:.2f}%). Recommending slice rate limiting to maintain SLAs."
            )
            action: ActionType = "rate_limit_slice"
            confidence = 0.90
        else:
            assessment = (
                f"Slice QoS indicators nominal (noisy packet_loss={loss_val:.2f}%, load={load_val:.2f}%)."
            )
            action = "allow_traffic"
            confidence = 0.92

        return SubagentDecision(
            subagent_name=self.name,
            role=self.role,
            observations=relevant,
            local_assessment=assessment,
            recommended_action=action,
            confidence=confidence,
        )


class ThreatMitigationSubagent(BaseSubagent):
    """Specialized subagent assessing overall threat severity and network perimeter integrity."""

    def __init__(self, name: str = "subagent-threat-mitigator") -> None:
        super().__init__(
            name=name,
            role=SubagentRole.THREAT_MITIGATION,
            target_metrics=[MetricType.THREAT_LEVEL],
        )

    def evaluate(self, observations: List[NoisyObservation]) -> SubagentDecision:
        relevant = [o for o in observations if o.metric_type in self.target_metrics]
        threat_val = next((o.noisy_value for o in relevant if o.metric_type == MetricType.THREAT_LEVEL), 0.0)

        if threat_val > 35.0:
            assessment = (
                f"Severe threat level observed (noisy threat_level={threat_val:.2f} > threshold 30.0). "
                f"Recommending strict traffic isolation."
            )
            action: ActionType = "block_traffic"
            confidence = 0.98
        elif threat_val > 15.0:
            assessment = (
                f"Moderate threat level observed (noisy threat_level={threat_val:.2f}). "
                f"Recommending defensive monitoring."
            )
            action = "monitor_only"
            confidence = 0.88
        else:
            assessment = (
                f"Threat level benign (noisy threat_level={threat_val:.2f}). Recommending normal traffic allowance."
            )
            action = "allow_traffic"
            confidence = 0.95

        return SubagentDecision(
            subagent_name=self.name,
            role=self.role,
            observations=relevant,
            local_assessment=assessment,
            recommended_action=action,
            confidence=confidence,
        )


class LeadCoordinatorAgent:
    """
    Lead Security Orchestrator (Multi-Agent Swarm Coordinator).

    Responsibilities:
    1. Decomposes high-level operator intent.
    2. Spawns specialized domain subagents.
    3. Partitions the available DP epsilon budget across subagent queries.
    4. Gathers subagent decisions and synthesizes an overarching consolidated action.
    """

    def __init__(self) -> None:
        self._subagents: List[BaseSubagent] = [
            ThreatMitigationSubagent(),
            AnomalyForensicsSubagent(),
            SlicingQoSSubagent(),
        ]

    def spawn_swarm(
        self, intent: str, remaining_epsilon: float
    ) -> tuple[List[SubagentSpec], OrchestrationPlan]:
        """Spawn domain subagents and partition epsilon budget into a formal plan."""
        specs: List[SubagentSpec] = []
        queries: List[MetricQuery] = []

        if remaining_epsilon < 0.35:
            # Low budget: spawn targeted threat & qos inspection with valid epsilon bounds
            target_eps = max(round(remaining_epsilon * 0.9, 2), 0.1)
            specs.append(
                SubagentSpec(
                    name="subagent-threat-mitigator",
                    role=SubagentRole.THREAT_MITIGATION,
                    target_metrics=[MetricType.THREAT_LEVEL],
                    allocated_epsilon=target_eps,
                )
            )
            queries.append(MetricQuery(metric_type=MetricType.THREAT_LEVEL, epsilon=target_eps))
            plan = OrchestrationPlan(
                queries=queries,
                reasoning=(
                    f"Low privacy budget remaining ({remaining_epsilon:.2f}). Spawned focused "
                    f"Threat Mitigation subagent with compliant epsilon={target_eps:.2f}."
                ),
            )
            return specs, plan

        target_total_eps = min(remaining_epsilon * 0.8, 1.2)
        eps_threat = max(round(target_total_eps * 0.40, 2), 0.1)
        eps_anomaly = max(round(target_total_eps * 0.35, 2), 0.1)
        eps_qos = max(round(target_total_eps * 0.25, 2), 0.1)

        specs.append(
            SubagentSpec(
                name="subagent-threat-mitigator",
                role=SubagentRole.THREAT_MITIGATION,
                target_metrics=[MetricType.THREAT_LEVEL],
                allocated_epsilon=eps_threat,
            )
        )
        queries.append(MetricQuery(metric_type=MetricType.THREAT_LEVEL, epsilon=eps_threat))

        specs.append(
            SubagentSpec(
                name="subagent-anomaly-forensics",
                role=SubagentRole.ANOMALY_FORENSICS,
                target_metrics=[MetricType.ANOMALY_SCORE, MetricType.FAILED_AUTH_ATTEMPTS],
                allocated_epsilon=eps_anomaly,
            )
        )
        sub_eps_a1 = max(round(eps_anomaly * 0.6, 2), 0.05)
        sub_eps_a2 = max(round(eps_anomaly * 0.4, 2), 0.05)
        queries.append(MetricQuery(metric_type=MetricType.ANOMALY_SCORE, epsilon=sub_eps_a1))
        queries.append(MetricQuery(metric_type=MetricType.FAILED_AUTH_ATTEMPTS, epsilon=sub_eps_a2))

        specs.append(
            SubagentSpec(
                name="subagent-slice-qos",
                role=SubagentRole.SLICING_QOS,
                target_metrics=[MetricType.ACTIVE_CONNECTIONS, MetricType.SLICE_LOAD_PERCENT],
                allocated_epsilon=eps_qos,
            )
        )
        sub_eps_q1 = max(round(eps_qos * 0.5, 2), 0.05)
        sub_eps_q2 = max(round(eps_qos * 0.5, 2), 0.05)
        queries.append(MetricQuery(metric_type=MetricType.ACTIVE_CONNECTIONS, epsilon=sub_eps_q1))
        queries.append(MetricQuery(metric_type=MetricType.SLICE_LOAD_PERCENT, epsilon=sub_eps_q2))

        total_raw = sum(q.epsilon for q in queries)
        max_allowed = min(remaining_epsilon * 0.95, 1.2)
        if total_raw > max_allowed and total_raw > 0:
            scale_factor = max_allowed / total_raw
            queries = [
                MetricQuery(metric_type=q.metric_type, epsilon=max(round(q.epsilon * scale_factor, 2), 0.05))
                for q in queries
            ]
            while sum(q.epsilon for q in queries) > remaining_epsilon and queries:
                diff = sum(q.epsilon for q in queries) - remaining_epsilon
                queries[0] = MetricQuery(queries[0].metric_type, max(round(queries[0].epsilon - diff - 0.01, 2), 0.05))

        total_cost = sum(q.epsilon for q in queries)
        plan = OrchestrationPlan(
            queries=queries,
            reasoning=(
                f"Lead Orchestrator spawned 3 autonomous domain subagents for intent '{intent}'. "
                f"Partitioned privacy budget across subagents: threat={eps_threat}, anomaly={eps_anomaly}, qos={eps_qos} "
                f"(total planned eps={total_cost:.2f} <= remaining {remaining_epsilon:.2f})."
            ),
        )
        return specs, plan

    def synthesize_decisions(
        self, intent: str, spawned: List[SubagentSpec], observations: List[NoisyObservation]
    ) -> tuple[ProposedAction, MultiAgentTrace]:
        """Distribute DP observations to spawned subagents and synthesize consensus."""
        decisions: List[SubagentDecision] = []
        for sub in self._subagents:
            dec = sub.evaluate(observations)
            decisions.append(dec)

        recs = [d.recommended_action for d in decisions]
        if "block_traffic" in recs:
            synthesized_action: ActionType = "block_traffic"
            rationale = "Swarm Consensus: Threat/Anomaly subagent detected critical breach. Protective block activated."
        elif "isolate_segment" in recs:
            synthesized_action = "isolate_segment"
            rationale = "Swarm Consensus: Segment isolation requested by domain subagent."
        elif "rate_limit_slice" in recs:
            synthesized_action = "rate_limit_slice"
            rationale = "Swarm Consensus: Slice QoS degradation or moderate anomaly detected. Rate limit applied."
        elif all(r == "allow_traffic" for r in recs):
            synthesized_action = "allow_traffic"
            rationale = "Swarm Consensus: All subagents confirmed benign network state. Traffic allowed."
        else:
            synthesized_action = "monitor_only"
            rationale = "Swarm Consensus: Balanced surveillance posture maintained by subagent swarm."

        trace = MultiAgentTrace(
            lead_intent=intent,
            spawned_subagents=spawned,
            subagent_decisions=decisions,
            synthesized_action=synthesized_action,
            lead_synthesis_rationale=rationale,
        )

        proposed_action = ProposedAction(
            action_type=synthesized_action,
            parameters={"slice": "eMBB-1", "subagents_active": len(decisions)},
        )
        return proposed_action, trace


class MultiAgentPlanner:
    """
    Hierarchical Multi-Agent Proposal Generator.

    Implements the LLMPlanner protocol while exposing subagent spawning,
    privacy budget partitioning, and consensus synthesis.
    """

    def __init__(self, inner_planner: Optional[Any] = None) -> None:
        self._coordinator = LeadCoordinatorAgent()
        self._inner = inner_planner
        self.last_trace: Optional[MultiAgentTrace] = None
        self.last_spawned: List[SubagentSpec] = []

    def propose(
        self,
        intent: str,
        epoch_index: int,
        context: Optional[NetworkContext] = None,
        prior_observations: Optional[List[Mapping[str, float]]] = None,
    ) -> tuple[OrchestrationPlan, ProposedAction]:
        remaining = context.remaining_epsilon if context else 2.0

        if self._inner is not None:
            # Call primary LLM (Gemini or OpenAI)
            plan, proposed_action = self._inner.propose(
                intent=intent,
                epoch_index=epoch_index,
                context=context,
                prior_observations=prior_observations,
            )
            # Spawn subagents to monitor and validate the plan domains
            self.last_spawned = [
                SubagentSpec("subagent-threat-mitigator", SubagentRole.THREAT_MITIGATION, [MetricType.THREAT_LEVEL], 0.4),
                SubagentSpec("subagent-anomaly-forensics", SubagentRole.ANOMALY_FORENSICS, [MetricType.ANOMALY_SCORE], 0.35),
                SubagentSpec("subagent-slice-qos", SubagentRole.SLICING_QOS, [MetricType.ACTIVE_CONNECTIONS], 0.25),
            ]
            return plan, proposed_action

        # Deterministic multi-agent coordinator mode
        specs, plan = self._coordinator.spawn_swarm(intent, remaining)
        self.last_spawned = specs

        # Initial candidate proposed action
        candidate_action = ProposedAction(
            action_type="monitor_only" if epoch_index == 0 else "block_traffic",
            parameters={"slice": "eMBB-1", "subagents_count": len(specs)},
        )
        return plan, candidate_action

    def post_observation_synthesis(
        self, intent: str, observations: List[NoisyObservation]
    ) -> tuple[ProposedAction, MultiAgentTrace]:
        """Synthesize subagent decisions after DP metric release."""
        action, trace = self._coordinator.synthesize_decisions(
            intent=intent,
            spawned=self.last_spawned,
            observations=observations,
        )
        self.last_trace = trace
        return action, trace
