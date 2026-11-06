"""Remediation playbooks (``config/playbooks.yaml``)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment

from autoheal.config import load_yaml
from autoheal.models import AlarmType

_expr_env = Environment()

STEP_KINDS = {"netconf_config", "netconf_rpc", "rest", "verify", "wait"}


@dataclass
class Step:
    action: str
    params: dict[str, Any]
    target: str = "device"  # device | peer
    description: str = ""
    when: str | None = None  # skip the step unless this expression is true
    _when_fn: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.when:
            self._when_fn = _expr_env.compile_expression(self.when)

    def enabled(self, ctx: dict[str, Any]) -> bool:
        if self._when_fn is None:
            return True
        try:
            return bool(self._when_fn(**ctx))
        except Exception:
            return False

    def describe(self) -> str:
        if self.description:
            return self.description
        p = self.params
        if self.action == "netconf_config":
            return f"NETCONF edit-config '{p['template']}' (confirmed commit)"
        if self.action == "netconf_rpc":
            return f"NETCONF rpc '{p['rpc']}'"
        if self.action == "rest":
            return f"REST {p.get('method', 'POST').upper()} {p.get('endpoint', 'device')}{p['path']}"
        if self.action == "verify":
            cond = (f"== {p['expect']}" if "expect" in p else
                    f"<= {p['max']}" if "max" in p else f">= {p.get('min')}")
            return f"verify {p['probe']} {cond} (within {p.get('timeout', 30)}s)"
        if self.action == "wait":
            return f"wait {p['seconds']}s"
        return self.action


@dataclass
class Playbook:
    name: str
    root_cause: AlarmType
    steps: list[Step]
    description: str = ""
    when: str | None = None
    min_confidence: float = 0.0
    requires_approval: bool = False
    hold_down: float = 0.0
    outcome: str = "healed"  # healed | mitigated
    follow_up: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    suppress_alarms: list[AlarmType] = field(default_factory=list)
    _when_fn: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.when:
            self._when_fn = _expr_env.compile_expression(self.when)
        if self.outcome not in ("healed", "mitigated"):
            raise ValueError(f"playbook {self.name}: outcome must be healed|mitigated")

    def applies(self, root_cause: AlarmType, ctx: dict[str, Any]) -> bool:
        if root_cause != self.root_cause:
            return False
        if self._when_fn is None:
            return True
        try:
            return bool(self._when_fn(**ctx))
        except Exception:
            return False


def parse_playbooks(data: dict[str, Any]) -> list[Playbook]:
    books = []
    for pb in data.get("playbooks") or []:
        match = pb.get("match") or {}
        steps = []
        for s in pb.get("steps") or []:
            s = dict(s)
            action = s.pop("action")
            if action not in STEP_KINDS:
                raise ValueError(f"playbook {pb['name']}: unknown step action {action!r}")
            target = s.pop("target", "device")
            if target not in ("device", "peer"):
                raise ValueError(f"playbook {pb['name']}: target must be device|peer")
            description = s.pop("description", "")
            when = s.pop("when", None)
            steps.append(Step(action, s, target, description, when))
        books.append(
            Playbook(
                name=pb["name"],
                root_cause=AlarmType(match["root_cause"]),
                when=match.get("when"),
                steps=steps,
                description=pb.get("description", ""),
                min_confidence=float(pb.get("min_confidence", 0.0)),
                requires_approval=bool(pb.get("requires_approval", False)),
                hold_down=float(pb.get("hold_down", 0.0)),
                outcome=pb.get("outcome", "healed"),
                follow_up=pb.get("follow_up", ""),
                params=pb.get("params") or {},
                suppress_alarms=[AlarmType(t) for t in pb.get("suppress_alarms") or []],
            )
        )
    return books


def load_playbooks(path: str | Path) -> list[Playbook]:
    return parse_playbooks(load_yaml(path))


def select_playbook(playbooks: list[Playbook], root_cause: AlarmType, ctx: dict[str, Any]) -> Playbook | None:
    for pb in playbooks:
        if pb.applies(root_cause, {**ctx, "params": pb.params}):
            return pb
    return None
