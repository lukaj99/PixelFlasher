"""Pure dataclasses for tool results, pre/post conditions, and risk tiers."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RiskTier(enum.Enum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    severity: RiskTier = RiskTier.INFO


@dataclass
class PreCondition:
    checks: list[CheckResult]
    mode: str = "all_must_pass"


@dataclass
class PostCondition:
    checks: list[CheckResult]
    on_failure: str = "warn"


@dataclass
class ToolResult:
    success: bool
    data: Any = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    dry_run: bool = False
    preflight_checks: list[CheckResult] = field(default_factory=list)
    postcondition_checks: list[CheckResult] = field(default_factory=list)
    execution_time_ms: int = 0
    command: str | None = None
    rollback_performed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict. Non-serializable values are stringified."""
        data = self.data
        if data is not None:
            try:
                # Quick check: if json.dumps succeeds, keep the original value.
                import json
                json.dumps(data)
            except (TypeError, ValueError):
                data = str(data)
        return {
            "success": self.success,
            "data": data,
            "error": self.error,
            "warnings": self.warnings,
            "dry_run": self.dry_run,
            "preflight_checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "detail": c.detail,
                    "severity": c.severity.value,
                }
                for c in self.preflight_checks
            ],
            "postcondition_checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "detail": c.detail,
                    "severity": c.severity.value,
                }
                for c in self.postcondition_checks
            ],
            "execution_time_ms": self.execution_time_ms,
            "command": self.command,
            "rollback_performed": self.rollback_performed,
        }
