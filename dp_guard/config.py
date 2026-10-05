"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dp_guard.types import OperatorRole

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

def _fallback_load_env(search_paths: list[Path]) -> None:
    """Manually parse .env if python-dotenv is not installed."""
    for path in search_paths:
        env_file = path / ".env" if path.is_dir() else path
        if env_file.is_file():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass



def _env_float(name: str, default: float) -> float:
    """Parse a float environment variable with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw)


def _env_str(name: str, default: str) -> str:
    """Read a string environment variable with fallback."""
    return os.getenv(name, default)


@dataclass(frozen=True)
class DPGuardConfig:
    """Central configuration for the DP-Guard runtime."""

    project_root: Path
    openai_api_key: str | None
    openai_model: str
    gemini_api_key: str | None
    gemini_model: str
    llm_provider: str
    epsilon_total: float
    threat_safety_threshold: float
    anomaly_safety_threshold: float
    verification_beta: float
    operator_role: OperatorRole
    telemetry_path: Path
    topology_path: Path
    audit_log_path: Path
    use_mock_llm: bool

    @classmethod
    def from_env(cls, project_root: Path | None = None) -> "DPGuardConfig":
        """
        Build configuration from environment variables and defaults.

        Args:
            project_root: Project root directory. Defaults to parent of dp_guard package.

        Returns:
            Populated DPGuardConfig instance.
        """
        root = project_root or Path(__file__).resolve().parent.parent
        _fallback_load_env([Path.cwd(), root])
        openai_key = os.getenv("OPENAI_API_KEY") or None
        gemini_key = os.getenv("GEMINI_API_KEY") or None
        explicit_provider = os.getenv("LLM_PROVIDER")

        if explicit_provider:
            provider = explicit_provider.lower()
        elif gemini_key:
            provider = "gemini"
        elif openai_key:
            provider = "openai"
        else:
            provider = "mock"

        role_raw = _env_str("DP_GUARD_ROLE", "security_operator")
        role = OperatorRole(role_raw)

        return cls(
            project_root=root,
            openai_api_key=openai_key,
            openai_model=_env_str("OPENAI_MODEL", "gpt-4o-mini"),
            gemini_api_key=gemini_key,
            gemini_model=_env_str("GEMINI_MODEL", "gemini-3.6-flash"),
            llm_provider=provider,
            epsilon_total=_env_float("DP_EPSILON_TOTAL", 2.0),
            threat_safety_threshold=_env_float("THREAT_SAFETY_THRESHOLD", 30.0),
            anomaly_safety_threshold=_env_float("ANOMALY_SAFETY_THRESHOLD", 40.0),
            verification_beta=_env_float("VERIFICATION_BETA", 0.05),
            operator_role=role,
            telemetry_path=root / "data" / "ue_sessions.json",
            topology_path=root / "data" / "network_slices.json",
            audit_log_path=root / "logs" / "audit.jsonl",
            use_mock_llm=(provider == "mock"),
        )
