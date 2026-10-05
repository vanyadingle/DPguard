"""Audit logging for DP-Guard orchestration transcripts."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict

from dp_guard.types import EpochResult


class AuditLog:
    """
    Append-only JSONL audit trail for orchestration epochs.

    Records intents, plans, DP observations, verification outcomes,
    and executed actions for compliance and reproducibility.
    """

    def __init__(self, log_path: Path) -> None:
        """
        Initialize the audit log.

        Args:
            log_path: Path to JSONL log file (created if missing).
        """
        self._path = log_path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record_epoch(self, result: EpochResult) -> None:
        """
        Append one epoch result to the audit log.

        Args:
            result: Completed epoch outcome.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intent": result.intent,
            "llm_provider": result.llm_provider,
            "plan": {
                "reasoning": result.plan.reasoning,
                "queries": [
                    {"metric": q.metric_type.value, "epsilon": q.epsilon}
                    for q in result.plan.queries
                ],
            },
            "proposed_action": {
                "type": result.proposed_action.action_type,
                "parameters": result.proposed_action.parameters,
            },
            "observations": [
                {
                    "metric": o.metric_type.value,
                    "noisy_value": o.noisy_value,
                    "epsilon": o.epsilon,
                    "scale": o.scale,
                }
                for o in result.observations
            ],
            "admissible": result.admissible,
            "verification_message": result.verification_message,
            "executed_action": result.executed_action.action_type,
            "execution_result": self._serialize(result.execution_result),
            "remaining_epsilon": result.remaining_epsilon,
            "budget_exhausted": result.budget_exhausted,
        }
        if result.multi_agent_trace:
            entry["multi_agent_swarm"] = {
                "lead_intent": result.multi_agent_trace.lead_intent,
                "spawned_subagents": [
                    {
                        "name": s.name,
                        "role": s.role.value if isinstance(s.role, Enum) else str(s.role),
                        "target_metrics": [m.value if isinstance(m, Enum) else str(m) for m in s.target_metrics],
                        "allocated_epsilon": s.allocated_epsilon,
                    }
                    for s in result.multi_agent_trace.spawned_subagents
                ],
                "subagent_decisions": [
                    {
                        "subagent_name": d.subagent_name,
                        "role": d.role.value if isinstance(d.role, Enum) else str(d.role),
                        "local_assessment": d.local_assessment,
                        "recommended_action": d.recommended_action,
                        "confidence": d.confidence,
                    }
                    for d in result.multi_agent_trace.subagent_decisions
                ],
                "synthesized_action": result.multi_agent_trace.synthesized_action,
                "lead_synthesis_rationale": result.multi_agent_trace.lead_synthesis_rationale,
            }
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")

    @staticmethod
    def _serialize(obj: Any) -> Dict[str, Any] | None:
        """Convert dataclass objects to JSON-serializable dicts."""
        if obj is None:
            return None
        if is_dataclass(obj):
            data = asdict(obj)
            for key, value in data.items():
                if isinstance(value, Enum):
                    data[key] = value.value
            return data
        return {"value": str(obj)}
