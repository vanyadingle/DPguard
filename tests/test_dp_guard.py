"""Unit tests for DP-Guard core mechanisms."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from dp_guard.admissibility_verifier import AdmissibilityVerifier
from dp_guard.network_telemetry import NetworkTelemetrySource
from dp_guard.privacy_accountant import PrivacyAccountant
from dp_guard.privacy_policy import PrivacyPolicy
from dp_guard.telemetry_plane import RawTelemetryStore, TelemetryPlane
from dp_guard.types import MetricQuery, MetricType, NoisyObservation, ProposedAction


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def telemetry_source() -> NetworkTelemetrySource:
    """Create telemetry source from test data files."""
    return NetworkTelemetrySource(
        records_path=ROOT / "data" / "ue_sessions.json",
        topology_path=ROOT / "data" / "network_slices.json",
    )


def test_telemetry_aggregates_from_real_records(telemetry_source: NetworkTelemetrySource) -> None:
    """Aggregates should reflect UE session JSON data."""
    metrics = telemetry_source.aggregate_metrics()
    assert metrics["active_connections"] == 8  # 8 eMBB-1 sessions in data
    assert metrics["threat_level"] == 71  # max threat in eMBB-1
    assert metrics["failed_auth_attempts"] == 19


def test_laplace_mechanism_adds_noise(telemetry_source: NetworkTelemetrySource) -> None:
    """DP release should differ from raw value due to noise."""
    np.random.seed(0)
    store = RawTelemetryStore(telemetry_source)
    plane = TelemetryPlane(store)
    raw = store._read_raw("threat_level")  # noqa: SLF001
    obs = plane.release_metric(MetricType.THREAT_LEVEL, epsilon=0.5)
    assert obs.noisy_value != raw
    assert obs.scale == pytest.approx(2.0)  # sensitivity 1.0 / epsilon 0.5


def test_privacy_budget_exceeded() -> None:
    """Accountant should reject queries exceeding budget."""
    accountant = PrivacyAccountant(epsilon_total=0.5)
    with pytest.raises(Exception):
        accountant.check_budget(0.6)


def test_admissibility_blocks_permissive_action() -> None:
    """Verifier should block allow_traffic when threat upper bound exceeds threshold."""
    verifier = AdmissibilityVerifier(threat_safety_threshold=30.0, beta=0.05)
    observations = [
        NoisyObservation(
            metric_type=MetricType.THREAT_LEVEL,
            noisy_value=45.0,
            epsilon=0.3,
            sensitivity=1.0,
            scale=1.0 / 0.3,
        )
    ]
    result = verifier.verify(
        ProposedAction(action_type="allow_traffic"),
        observations,
    )
    assert result.admissible is False


def test_policy_rejects_unauthorized_metric() -> None:
    """Policy should reject metrics outside role authorization for auditor."""
    from dp_guard.types import OperatorRole

    policy = PrivacyPolicy(role=OperatorRole.READONLY_AUDITOR)
    plan_query = MetricQuery(metric_type=MetricType.THREAT_LEVEL, epsilon=0.2)
    with pytest.raises(Exception):
        policy.validate_query(plan_query)


def test_audit_log_writes_jsonl(tmp_path: Path, telemetry_source: NetworkTelemetrySource) -> None:
    """Audit log should append valid JSON lines."""
    from dp_guard.audit_log import AuditLog
    from dp_guard.types import EpochResult, OrchestrationPlan

    log_path = tmp_path / "test_audit.jsonl"
    audit = AuditLog(log_path)
    epoch = EpochResult(
        intent="test",
        plan=OrchestrationPlan(queries=[]),
        proposed_action=ProposedAction(action_type="monitor_only"),
        observations=[],
        executed_action=ProposedAction(action_type="safe_fallback"),
        execution_result=None,
        admissible=False,
        verification_message="test",
        remaining_epsilon=1.0,
    )
    audit.record_epoch(epoch)
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["intent"] == "test"


def test_multi_agent_swarm_spawning_and_consensus() -> None:
    """Lead coordinator should spawn 3 subagents and synthesize consensus."""
    from dp_guard.subagents import LeadCoordinatorAgent
    from dp_guard.types import NoisyObservation

    coordinator = LeadCoordinatorAgent()
    specs, plan = coordinator.spawn_swarm(intent="Investigate DDoS spike", remaining_epsilon=1.5)

    assert len(specs) == 3
    assert len(plan.queries) >= 3
    assert any(s.role.value == "threat_mitigation" for s in specs)
    assert any(s.role.value == "anomaly_forensics" for s in specs)
    assert any(s.role.value == "slicing_qos" for s in specs)

    # Test consensus under high threat observations
    observations = [
        NoisyObservation(MetricType.THREAT_LEVEL, noisy_value=65.0, epsilon=0.4, sensitivity=1.0, scale=2.5),
        NoisyObservation(MetricType.ANOMALY_SCORE, noisy_value=72.0, epsilon=0.3, sensitivity=5.0, scale=16.6),
        NoisyObservation(MetricType.ACTIVE_CONNECTIONS, noisy_value=15.0, epsilon=0.2, sensitivity=1.0, scale=5.0),
    ]
    action, trace = coordinator.synthesize_decisions("Investigate DDoS spike", specs, observations)
    assert action.action_type == "block_traffic"
    assert len(trace.subagent_decisions) == 3
    assert trace.synthesized_action == "block_traffic"


def test_subagent_budget_partitioning_strictly_bounded() -> None:
    """Sum of subagent DP queries must not exceed remaining budget."""
    from dp_guard.subagents import LeadCoordinatorAgent

    coordinator = LeadCoordinatorAgent()
    for test_budget in [0.2, 0.5, 1.0, 2.0]:
        specs, plan = coordinator.spawn_swarm("Audit slice", remaining_epsilon=test_budget)
        total_eps = sum(q.epsilon for q in plan.queries)
        assert total_eps <= test_budget + 1e-6


def test_live_5g_adapter_closed_loop(tmp_path: Path) -> None:
    """Live 5G adapter should track interface and simulate real attack reaction."""
    from dp_guard.live_5g_adapter import Live5GTelemetryAdapter

    adapter = Live5GTelemetryAdapter(interface="ogstun", target_slice="eMBB-1")
    initial_metrics = adapter.aggregate_metrics()

    # Simulate attack
    adapter.simulate_attack_spike(compromised_ue_count=2)
    spike_metrics = adapter.aggregate_metrics()
    assert spike_metrics["active_connections"] == initial_metrics["active_connections"] + 2
    assert spike_metrics["threat_level"] >= initial_metrics["threat_level"]

    # Apply closed-loop block action
    adapter.apply_action_effects("block_traffic", {"ue_ip": "10.45.0.3"})
    post_block_metrics = adapter.aggregate_metrics()
    assert post_block_metrics["active_connections"] <= spike_metrics["active_connections"]


def test_multi_agent_orchestration_epoch(telemetry_source: NetworkTelemetrySource, tmp_path: Path) -> None:
    """Full epoch execution with MultiAgentPlanner and local enclave."""
    from dp_guard.action_executor import ActionExecutor
    from dp_guard.admissibility_verifier import AdmissibilityVerifier
    from dp_guard.audit_log import AuditLog
    from dp_guard.orchestrator import Orchestrator
    from dp_guard.privacy_accountant import PrivacyAccountant
    from dp_guard.privacy_policy import PrivacyPolicy
    from dp_guard.subagents import MultiAgentPlanner
    from dp_guard.telemetry_plane import RawTelemetryStore, TelemetryPlane
    from dp_guard.types import OperatorRole

    raw_store = RawTelemetryStore(telemetry_source)
    telemetry = TelemetryPlane(raw_store)
    accountant = PrivacyAccountant(epsilon_total=2.0)
    policy = PrivacyPolicy(role=OperatorRole.SECURITY_OPERATOR)
    verifier = AdmissibilityVerifier(threat_safety_threshold=30.0)
    planner = MultiAgentPlanner()
    executor = ActionExecutor(telemetry_source)
    audit = AuditLog(tmp_path / "multi_audit.jsonl")

    orchestrator = Orchestrator(
        telemetry_plane=telemetry,
        telemetry_source=telemetry_source,
        privacy_accountant=accountant,
        verifier=verifier,
        policy=policy,
        llm_planner=planner,
        action_executor=executor,
        audit_log=audit,
        llm_provider="multi-agent[mock]",
    )

    result = orchestrator.run_epoch("Inspect slice for unauthorized signaling")
    assert result is not None
    assert result.multi_agent_trace is not None
    assert len(result.multi_agent_trace.spawned_subagents) == 3
    assert result.remaining_epsilon < 2.0
