"""Orchestration Plane - closed-loop event loop connecting all DP-Guard planes."""

from __future__ import annotations

import logging
from typing import List, Optional

from dp_guard.action_executor import ActionExecutor
from dp_guard.admissibility_verifier import AdmissibilityVerifier
from dp_guard.audit_log import AuditLog
from dp_guard.exceptions import PolicyViolationError, PrivacyBudgetExceededError
from dp_guard.llm_factory import LLMPlanner
from dp_guard.network_telemetry import NetworkTelemetrySource
from dp_guard.privacy_accountant import PrivacyAccountant
from dp_guard.privacy_policy import PrivacyPolicy
from dp_guard.telemetry_plane import TelemetryPlane
from dp_guard.types import (
    EpochResult,
    NetworkContext,
    NoisyObservation,
    OrchestrationPlan,
    ProposedAction,
)

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Main DP-Guard control loop.

    The orchestrator never accesses raw telemetry. It:
      1. Receives an operator intent.
      2. Prompts LLM with sanitized context to generate Plan + Proposed Action.
      3. Validates typed policy and privacy budget.
      4. Executes DP metric reads via Telemetry Plane.
      5. Verifies admissibility under DP uncertainty.
      6. Executes action or safe fallback via ActionExecutor.
      7. Records audit transcript.
    """

    SAFE_FALLBACK = ProposedAction(
        action_type="safe_fallback",
        parameters={"mode": "deny-by-default"},
    )

    def __init__(
        self,
        telemetry_plane: TelemetryPlane,
        telemetry_source: NetworkTelemetrySource,
        privacy_accountant: PrivacyAccountant,
        verifier: AdmissibilityVerifier,
        policy: PrivacyPolicy,
        llm_planner: LLMPlanner,
        action_executor: ActionExecutor,
        audit_log: AuditLog,
        llm_provider: str = "mock",
    ) -> None:
        """Wire all architectural planes."""
        self._telemetry = telemetry_plane
        self._telemetry_source = telemetry_source
        self._accountant = privacy_accountant
        self._verifier = verifier
        self._policy = policy
        self._llm = llm_planner
        self._executor = action_executor
        self._audit = audit_log
        self._llm_provider = llm_provider
        self._epoch_index = 0
        self._history: List[EpochResult] = []
        self._prior_observations: List[dict[str, float]] = []

    @property
    def history(self) -> List[EpochResult]:
        """Return completed epoch results."""
        return list(self._history)

    def _build_context(self) -> NetworkContext:
        """Build sanitized network context for LLM prompting."""
        return NetworkContext(
            gnb_id=self._telemetry_source.gnb_id,
            region=self._telemetry_source.region,
            slices=self._telemetry_source.slices,
            epoch_index=self._epoch_index,
            remaining_epsilon=self._accountant.epsilon_remaining,
        )

    def run_epoch(self, intent: str) -> EpochResult:
        """
        Execute one DP-Guard orchestration epoch.

        Args:
            intent: Sanitized operator intent (no raw telemetry).

        Returns:
            EpochResult summarizing plan execution, verification, and action.
        """
        self._telemetry.refresh_raw_aggregates()
        context = self._build_context()

        plan, proposed_action = self._llm.propose(
            intent=intent,
            epoch_index=self._epoch_index,
            context=context,
            prior_observations=self._prior_observations,
        )

        observations: List[NoisyObservation] = []
        budget_exhausted = False
        verification_message = ""
        admissible = False
        executed_action = self.SAFE_FALLBACK
        execution_result = None

        print(f"\n{'=' * 60}")
        print(f"EPOCH {self._epoch_index + 1} | Intent: {intent}")
        print(f"LLM coordinator: {self._llm_provider}")
        print(f"{'=' * 60}")
        print("[LOCAL TELEMETRY ENCLAVE] Raw subscriber records strictly isolated in local memory. Zero cloud leakage.")
        print(f"Lead Plan ({len(plan.queries)} queries): {plan.reasoning}")

        if hasattr(self._llm, "last_spawned") and self._llm.last_spawned:
            print(f"[MULTI-AGENT SWARM] Spawned {len(self._llm.last_spawned)} specialized autonomous subagents:")
            for sub in self._llm.last_spawned:
                m_str = ", ".join(m.value for m in sub.target_metrics)
                print(f"  * {sub.name} [{sub.role.value}] | metrics=[{m_str}] | eps_budget={sub.allocated_epsilon}")

        print(f"Initial candidate action: {proposed_action.action_type}")

        # Static policy validation
        try:
            self._policy.validate_plan(plan)
            self._policy.validate_action(proposed_action)
        except PolicyViolationError as exc:
            verification_message = f"Policy violation: {exc}"
            print(f"[POLICY] {verification_message}")
            result = self._finalize_and_log(
                intent, plan, proposed_action, observations,
                self.SAFE_FALLBACK, None, False, verification_message, False,
            )
            self._telemetry_source.advance_epoch()
            self._epoch_index += 1
            return result

        # Type-and-budget check
        try:
            self._accountant.check_plan_budget(plan)
        except PrivacyBudgetExceededError as exc:
            budget_exhausted = True
            verification_message = f"Plan rejected at budget gate: {exc}"
            print(f"[PRIVACY] {verification_message}")
            result = self._finalize_and_log(
                intent, plan, proposed_action, observations,
                self.SAFE_FALLBACK, None, False, verification_message, budget_exhausted,
            )
            self._telemetry_source.advance_epoch()
            self._epoch_index += 1
            return result

        # Adaptive DP metric reads
        for query in plan.queries:
            try:
                self._accountant.check_budget(query.epsilon)
            except PrivacyBudgetExceededError as exc:
                budget_exhausted = True
                verification_message = f"Budget exhausted mid-plan: {exc}"
                print(f"[PRIVACY] {verification_message}")
                result = self._finalize_and_log(
                    intent, plan, proposed_action, observations,
                    self.SAFE_FALLBACK, None, False, verification_message, budget_exhausted,
                )
                self._telemetry_source.advance_epoch()
                self._epoch_index += 1
                return result

            obs = self._telemetry.release_metric(query.metric_type, query.epsilon)
            self._accountant.charge(query)
            observations.append(obs)
            self._prior_observations.append(
                {obs.metric_type.value: obs.noisy_value}
            )
            print(
                f"  [DP-READ] {query.metric_type.value}: "
                f"z_noisy={obs.noisy_value:.2f} (eps={query.epsilon}, b={obs.scale:.2f})"
            )

        # Multi-Agent Consensus and Decision Synthesis
        multi_trace = None
        if hasattr(self._llm, "post_observation_synthesis") and observations:
            synth_action, multi_trace = self._llm.post_observation_synthesis(intent, observations)
            print("[SUBAGENTS CONSENSUS]")
            for dec in multi_trace.subagent_decisions:
                print(f"  * {dec.subagent_name}: vote='{dec.recommended_action}' (conf={dec.confidence:.2f})")
                print(f"    Rationale: {dec.local_assessment}")
            print(f"  Synthesis: {multi_trace.lead_synthesis_rationale}")
            print(f"  Consensus Proposed Action: {synth_action.action_type}")
            proposed_action = synth_action

        # Admissibility verification
        verification = self._verifier.verify(proposed_action, observations)
        admissible = verification.admissible
        verification_message = verification.message

        if admissible:
            executed_action = proposed_action
            print(f"[VERIFY] ADMISSIBLE - {verification_message}")
            execution_result = self._executor.execute(executed_action)
            print(f"[ACTION] Executed: {execution_result.message}")
        else:
            executed_action = self.SAFE_FALLBACK
            print(f"[VERIFY] BLOCKED - {verification_message}")
            execution_result = self._executor.execute(executed_action)
            print(f"[ACTION] Safe fallback: {execution_result.message}")

        for metric, (lo, hi) in verification.confidence_intervals.items():
            print(f"  CI({metric}): [{lo:.2f}, {hi:.2f}] @ confidence 1-beta")

        state = self._accountant.get_state()
        print(
            f"[BUDGET] Spent eps={state.epsilon_spent:.2f} / "
            f"eps_tot={state.epsilon_total:.2f} "
            f"(remaining={state.epsilon_remaining:.2f})"
        )

        result = self._finalize_and_log(
            intent, plan, proposed_action, observations,
            executed_action, execution_result, admissible,
            verification_message, budget_exhausted, multi_trace,
        )

        self._telemetry_source.advance_epoch()
        self._epoch_index += 1
        return result

    def _finalize_and_log(
        self,
        intent: str,
        plan: OrchestrationPlan,
        proposed_action: ProposedAction,
        observations: List[NoisyObservation],
        executed_action: ProposedAction,
        execution_result: Optional[object],
        admissible: bool,
        verification_message: str,
        budget_exhausted: bool,
        multi_agent_trace: Optional[object] = None,
    ) -> EpochResult:
        """Build epoch result, append to history, write audit log."""
        state = self._accountant.get_state()
        result = EpochResult(
            intent=intent,
            plan=plan,
            proposed_action=proposed_action,
            observations=observations,
            executed_action=executed_action,
            execution_result=execution_result,  # type: ignore[arg-type]
            admissible=admissible,
            verification_message=verification_message,
            remaining_epsilon=state.epsilon_remaining,
            budget_exhausted=budget_exhausted,
            llm_provider=self._llm_provider,
            multi_agent_trace=multi_agent_trace,  # type: ignore[arg-type]
        )
        self._history.append(result)
        self._audit.record_epoch(result)
        return result
