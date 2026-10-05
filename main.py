"""
DP-Guard full prototype - closed-loop security orchestrator demo.

Uses real structured UE session telemetry, optional OpenAI LLM,
typed privacy policy, DP Laplace releases, admissibility verification,
and audit logging.
"""

from __future__ import annotations

import argparse
import logging
import sys

import numpy as np

from dp_guard.action_executor import ActionExecutor
from dp_guard.admissibility_verifier import AdmissibilityVerifier
from dp_guard.audit_log import AuditLog
from dp_guard.config import DPGuardConfig
from dp_guard.llm_factory import create_llm_planner
from dp_guard.network_telemetry import NetworkTelemetrySource
from dp_guard.orchestrator import Orchestrator
from dp_guard.privacy_accountant import PrivacyAccountant
from dp_guard.privacy_policy import PrivacyPolicy
from dp_guard.telemetry_plane import RawTelemetryStore, TelemetryPlane
from dp_guard.types import OperatorRole

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def build_orchestrator(config: DPGuardConfig) -> Orchestrator:
    """
    Wire all DP-Guard planes from configuration.

    Args:
        config: Runtime configuration.

    Returns:
        Fully configured Orchestrator instance.
    """
    telemetry_source = NetworkTelemetrySource(
        records_path=config.telemetry_path,
        topology_path=config.topology_path,
        target_slice="eMBB-1",
    )

    raw_store = RawTelemetryStore(telemetry_source)
    telemetry = TelemetryPlane(raw_store)
    accountant = PrivacyAccountant(epsilon_total=config.epsilon_total)
    policy = PrivacyPolicy(role=config.operator_role)
    verifier = AdmissibilityVerifier(
        threat_safety_threshold=config.threat_safety_threshold,
        anomaly_safety_threshold=config.anomaly_safety_threshold,
        beta=config.verification_beta,
    )
    llm, provider = create_llm_planner(config, policy)
    executor = ActionExecutor(telemetry_source)
    audit = AuditLog(config.audit_log_path)

    return Orchestrator(
        telemetry_plane=telemetry,
        telemetry_source=telemetry_source,
        privacy_accountant=accountant,
        verifier=verifier,
        policy=policy,
        llm_planner=llm,
        action_executor=executor,
        audit_log=audit,
        llm_provider=provider,
    )


def print_banner(config: DPGuardConfig, orchestrator: Orchestrator) -> None:
    """Print startup banner with runtime info."""
    source = orchestrator._telemetry_source  # noqa: SLF001 - demo introspection
    metrics = source.aggregate_metrics()

    print("=" * 60)
    print("DP-Guard FULL - Typed DP Security Orchestrator")
    print("=" * 60)
    print(f"gNodeB: {source.gnb_id} | Region: {source.region}")
    print(f"Target slice: eMBB-1 | UE sessions: {int(metrics['active_connections'])}")
    print(f"LLM provider: {orchestrator._llm_provider}")
    print(f"Privacy budget eps_tot: {config.epsilon_total}")
    print(f"Role: {config.operator_role.value}")
    print()
    print("Raw aggregates (HIDDEN from LLM/orchestrator):")
    for key, value in metrics.items():
        print(f"  {key}: {value:.2f}")
    print("Telemetry Mode: LOCAL EDGE ENCLAVE (No raw cloud transmission)")
    print()


def build_orchestrator(
    config: DPGuardConfig,
    use_live_5g: bool = False,
    interface: str = "ogstun",
) -> Orchestrator:
    """
    Wire all DP-Guard planes from configuration.

    Args:
        config: Runtime configuration.
        use_live_5g: If True, attach to physical/virtual 5G testbed interface (ogstun).
        interface: Name of 5G testbed network interface.

    Returns:
        Fully configured Orchestrator instance.
    """
    if use_live_5g:
        from dp_guard.live_5g_adapter import Live5GTelemetryAdapter

        telemetry_source: NetworkTelemetrySource = Live5GTelemetryAdapter(
            interface=interface,
            target_slice="eMBB-1",
            data_dir=config.project_root / "data",
        )
    else:
        telemetry_source = NetworkTelemetrySource(
            records_path=config.telemetry_path,
            topology_path=config.topology_path,
            target_slice="eMBB-1",
        )

    raw_store = RawTelemetryStore(telemetry_source)
    telemetry = TelemetryPlane(raw_store)
    accountant = PrivacyAccountant(epsilon_total=config.epsilon_total)
    policy = PrivacyPolicy(role=config.operator_role)
    verifier = AdmissibilityVerifier(
        threat_safety_threshold=config.threat_safety_threshold,
        anomaly_safety_threshold=config.anomaly_safety_threshold,
        beta=config.verification_beta,
    )
    llm, provider = create_llm_planner(config, policy)
    executor = ActionExecutor(telemetry_source)
    audit = AuditLog(config.audit_log_path)

    return Orchestrator(
        telemetry_plane=telemetry,
        telemetry_source=telemetry_source,
        privacy_accountant=accountant,
        verifier=verifier,
        policy=policy,
        llm_planner=llm,
        action_executor=executor,
        audit_log=audit,
        llm_provider=provider,
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="dp_guard",
        description="DP-Guard: Differential Privacy Security Orchestrator for 6G Zero-Touch Networks.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    demo_parser = subparsers.add_parser("demo", help="Run closed-loop orchestration demo")
    demo_parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of orchestration epochs to run (default: 3)",
    )
    demo_parser.add_argument(
        "--mock",
        action="store_true",
        help="Force deterministic offline Mock LLM instead of API",
    )
    demo_parser.add_argument(
        "--llm",
        action="store_true",
        help="Explicit flag for LLM mode (default when API key is set in .env)",
    )
    demo_parser.add_argument(
        "--role",
        type=str,
        choices=["security_operator", "network_admin", "readonly_auditor"],
        default=None,
        help="Operator role for typed policy validation",
    )
    demo_parser.add_argument(
        "--epsilon",
        type=float,
        default=None,
        help="Total privacy budget epsilon (default: 2.0)",
    )

    # 5G Testbed live runner
    live_parser = subparsers.add_parser("live-5g", help="Run real-time orchestration on 5G Testbed (Open5GS + UERANSIM)")
    live_parser.add_argument(
        "--interface",
        type=str,
        default="ogstun",
        help="5G UPF network interface to monitor (default: ogstun)",
    )
    live_parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of orchestration epochs to run (default: 3)",
    )
    live_parser.add_argument(
        "--mock",
        action="store_true",
        help="Force deterministic offline Mock LLM instead of API",
    )
    live_parser.add_argument(
        "--llm",
        action="store_true",
        help="Explicit flag for LLM mode",
    )
    live_parser.add_argument(
        "--simulate-attack",
        action="store_true",
        help="Simulate real-time cyber attack spike on the 5G testbed",
    )

    return parser.parse_args()


def main() -> None:
    """Main CLI entrypoint."""
    args = parse_args()

    # If no subcommand passed, default to demo
    epochs = getattr(args, "epochs", 3)
    force_mock = getattr(args, "mock", False)
    role_arg = getattr(args, "role", None)
    eps_arg = getattr(args, "epsilon", None)

    np.random.seed(42)
    base_config = DPGuardConfig.from_env()

    # Override config based on CLI flags
    role = OperatorRole(role_arg) if role_arg else base_config.operator_role
    epsilon = eps_arg if eps_arg is not None else base_config.epsilon_total
    provider = "mock" if force_mock else base_config.llm_provider

    config = DPGuardConfig(
        project_root=base_config.project_root,
        openai_api_key=base_config.openai_api_key,
        openai_model=base_config.openai_model,
        gemini_api_key=base_config.gemini_api_key,
        gemini_model=base_config.gemini_model,
        llm_provider=provider,
        epsilon_total=epsilon,
        threat_safety_threshold=base_config.threat_safety_threshold,
        anomaly_safety_threshold=base_config.anomaly_safety_threshold,
        verification_beta=base_config.verification_beta,
        operator_role=role,
        telemetry_path=base_config.telemetry_path,
        topology_path=base_config.topology_path,
        audit_log_path=base_config.audit_log_path,
        use_mock_llm=(provider == "mock"),
    )

    is_live_5g = getattr(args, "command", "") == "live-5g"
    interface = getattr(args, "interface", "ogstun")
    simulate_attack = getattr(args, "simulate_attack", False)

    orchestrator = build_orchestrator(config, use_live_5g=is_live_5g, interface=interface)

    if is_live_5g and simulate_attack:
        source = orchestrator._telemetry_source  # noqa: SLF001
        if hasattr(source, "simulate_attack_spike"):
            source.simulate_attack_spike(compromised_ue_count=3)

    print_banner(config, orchestrator)

    default_intents = [
        "Maintain secure connectivity for eMBB slice under elevated threat watch",
        "Investigate authentication anomalies and packet loss on eMBB-1",
        "Adaptive re-assessment after prior mitigation attempts",
    ]

    for epoch_idx in range(epochs):
        intent = default_intents[epoch_idx % len(default_intents)]
        orchestrator.run_epoch(intent)

    print("\n" + "=" * 60)
    print("DEMO SUMMARY")
    print("=" * 60)
    for idx, epoch in enumerate(orchestrator.history, start=1):
        status = "OK" if epoch.admissible else "BLOCKED/FALLBACK"
        if epoch.budget_exhausted:
            status = "BUDGET EXHAUSTED"
        print(
            f"Epoch {idx}: llm={epoch.llm_provider}, "
            f"proposed={epoch.proposed_action.action_type}, "
            f"executed={epoch.executed_action.action_type}, "
            f"status={status}, eps_remaining={epoch.remaining_epsilon:.2f}"
        )

    print(f"\nAudit log: {config.audit_log_path}")
    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
