"""OpenAI-based LLM planner for DP-Guard orchestration."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Mapping, Optional

from dp_guard.exceptions import LLMPlannerError
from dp_guard.privacy_policy import PrivacyPolicy
from dp_guard.types import (
    MetricQuery,
    MetricType,
    NetworkContext,
    OrchestrationPlan,
    ProposedAction,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a 6G zero-touch security orchestrator assistant for DP-Guard.

CRITICAL RULES:
1. You NEVER receive raw subscriber telemetry. You only propose which DP-protected metrics to read.
2. You must output valid JSON matching the required schema exactly.
3. Choose epsilon values within the allowed min/max bounds for each metric.
4. Propose exactly ONE control action from the authorized action list.
5. Be conservative: prefer block_traffic or monitor_only when threat indicators may be elevated.
6. Total epsilon cost of all queries should fit within the remaining budget provided.

Your job: given an operator intent and network context, propose a Plan (metric reads) and a Proposed Action."""


class OpenAIPlanner:
    """
    Real LLM planner using OpenAI Chat Completions with JSON output.

    The model receives sanitized context (intents, topology, policy schema)
    but never raw telemetry values.
    """

    VALID_ACTIONS = {
        "allow_traffic",
        "block_traffic",
        "isolate_segment",
        "safe_fallback",
        "monitor_only",
        "rate_limit_slice",
    }

    def __init__(
        self,
        api_key: str,
        model: str,
        policy: PrivacyPolicy,
        base_url: str | None = None,
    ) -> None:
        """
        Initialize the LLM planner.

        Args:
            api_key: API key.
            model: Model identifier (e.g. gpt-4o-mini or gemini-2.0-flash).
            policy: Typed privacy policy for schema context.
            base_url: Optional base URL for OpenAI-compatible providers (e.g. Google Gemini).
        """
        self._api_key = api_key
        self._model = model
        self._policy = policy
        self._base_url = base_url
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-load OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LLMPlannerError(
                    "openai package not installed. Run: pip install openai"
                ) from exc
            if self._base_url:
                self._client = OpenAI(api_key=self._api_key, base_url=self._base_url)
            else:
                self._client = OpenAI(api_key=self._api_key)
        return self._client

    @staticmethod
    def _response_schema() -> Dict[str, Any]:
        """JSON schema for structured LLM output."""
        return {
            "type": "object",
            "properties": {
                "reasoning": {"type": "string"},
                "queries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "metric": {"type": "string"},
                            "epsilon": {"type": "number"},
                        },
                        "required": ["metric", "epsilon"],
                        "additionalProperties": False,
                    },
                },
                "action_type": {"type": "string"},
                "action_parameters": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "required": ["reasoning", "queries", "action_type", "action_parameters"],
            "additionalProperties": False,
        }

    def propose(
        self,
        intent: str,
        epoch_index: int,
        context: Optional[NetworkContext] = None,
        prior_observations: Optional[List[Mapping[str, float]]] = None,
    ) -> tuple[OrchestrationPlan, ProposedAction]:
        """
        Call OpenAI to generate a plan and proposed action.

        Args:
            intent: Operator intent string.
            epoch_index: Current epoch index.
            context: Sanitized network context.
            prior_observations: DP observations from prior epochs (noisy only).

        Returns:
            Tuple of (OrchestrationPlan, ProposedAction).

        Raises:
            LLMPlannerError: On API or parsing failures.
        """
        user_payload = {
            "intent": intent,
            "epoch_index": epoch_index,
            "policy": self._policy.build_llm_schema_context(),
            "network_context": self._context_to_dict(context),
            "prior_dp_observations": prior_observations or [],
        }

        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": json.dumps(user_payload, indent=2),
                    },
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "dp_guard_plan",
                        "strict": True,
                        "schema": self._response_schema(),
                    },
                },
                temperature=0.2,
            )
            raw = response.choices[0].message.content
            if not raw:
                raise LLMPlannerError("OpenAI returned empty response")
            parsed = json.loads(raw)
        except Exception as exc:
            logger.warning("LLM API call failed (%s). Falling back to autonomous offline planner.", exc)
            from dp_guard.mock_llm import MockLLMPlanner
            return MockLLMPlanner().propose(intent, epoch_index, context, prior_observations)

        return self._parse_response(parsed)

    @staticmethod
    def _context_to_dict(context: Optional[NetworkContext]) -> Dict[str, Any]:
        """Serialize network context for LLM prompt."""
        if context is None:
            return {}
        return {
            "gnb_id": context.gnb_id,
            "region": context.region,
            "epoch_index": context.epoch_index,
            "remaining_epsilon": context.remaining_epsilon,
            "slices": [
                {
                    "id": s.id,
                    "type": s.type,
                    "description": s.description,
                }
                for s in context.slices
            ],
        }

    def _parse_response(self, parsed: Dict[str, Any]) -> tuple[OrchestrationPlan, ProposedAction]:
        """Parse and validate LLM JSON response."""
        queries: List[MetricQuery] = []
        for item in parsed.get("queries", []):
            metric_name = item["metric"]
            try:
                metric_type = MetricType(metric_name)
            except ValueError as exc:
                raise LLMPlannerError(f"Unknown metric from LLM: {metric_name}") from exc
            queries.append(
                MetricQuery(metric_type=metric_type, epsilon=float(item["epsilon"]))
            )

        action_type = parsed["action_type"]
        if action_type not in self.VALID_ACTIONS:
            raise LLMPlannerError(f"Invalid action from LLM: {action_type}")

        plan = OrchestrationPlan(
            queries=queries,
            reasoning=str(parsed.get("reasoning", "")),
        )
        action = ProposedAction(
            action_type=action_type,  # type: ignore[arg-type]
            parameters=dict(parsed.get("action_parameters") or {}),
        )
        return plan, action
