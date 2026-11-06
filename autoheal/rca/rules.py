"""Correlation rules.

A rule says: an alarm of type ``root`` explains alarms of the listed types when a
topology ``relation`` holds between the two (optionally filtered by a ``when``
expression evaluated against ``root`` and ``symptom``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment

from autoheal.config import load_yaml
from autoheal.models import Alarm, AlarmType
from autoheal.topology import Topology

Relation = Callable[[Alarm, Alarm, Topology], bool]

_expr_env = Environment()


def _same_resource(root: Alarm, s: Alarm, topo: Topology) -> bool:
    return root.device == s.device and root.resource == s.resource


def _same_device(root: Alarm, s: Alarm, topo: Topology) -> bool:
    return root.device == s.device


def _same_link(root: Alarm, s: Alarm, topo: Topology) -> bool:
    a, b = topo.link_of_alarm(root), topo.link_of_alarm(s)
    return a is not None and b is not None and a.id == b.id


def _facing_device(root: Alarm, s: Alarm, topo: Topology) -> bool:
    """Symptom sits on a neighbor and points at the root's device (interface/session facing it)."""
    return s.device != root.device and topo.peer_device_of_alarm(s) == root.device


def _downstream(root: Alarm, s: Alarm, topo: Topology) -> bool:
    return s.device in topo.downstream(root.device)


def _isolated_by_link(root: Alarm, s: Alarm, topo: Topology) -> bool:
    """Symptom device is cut off from management because the root's link is down."""
    link = topo.link_of_alarm(root)
    return link is not None and s.device in topo.isolated_by_link(link)


RELATIONS: dict[str, Relation] = {
    "same_resource": _same_resource,
    "same_device": _same_device,
    "same_link": _same_link,
    "facing_device": _facing_device,
    "downstream": _downstream,
    "isolated_by_link": _isolated_by_link,
}


@dataclass
class Explains:
    type: str  # AlarmType value or "*"
    relation: str
    when: str | None = None
    _when_fn: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.relation not in RELATIONS:
            raise ValueError(f"unknown relation {self.relation!r}; valid: {sorted(RELATIONS)}")
        if self.type != "*":
            AlarmType(self.type)  # validate
        if self.when:
            self._when_fn = _expr_env.compile_expression(self.when)

    def matches(self, root: Alarm, symptom: Alarm, topo: Topology) -> bool:
        if self.type != "*" and symptom.type.value != self.type:
            return False
        if not RELATIONS[self.relation](root, symptom, topo):
            return False
        if self._when_fn is not None:
            return bool(self._when_fn(root=root.model_dump(), symptom=symptom.model_dump()))
        return True


@dataclass
class Rule:
    name: str
    root: AlarmType
    priority: int = 50
    confidence: float = 0.8
    min_symptoms: int = 0
    description: str = ""
    explains: list[Explains] = field(default_factory=list)
    when: str | None = None  # condition on the root alarm itself
    _when_fn: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.when:
            self._when_fn = _expr_env.compile_expression(self.when)

    def applies_to(self, root: Alarm) -> bool:
        if root.type != self.root:
            return False
        return self._when_fn is None or bool(self._when_fn(root=root.model_dump()))

    def explains_alarm(self, root: Alarm, symptom: Alarm, topo: Topology) -> str | None:
        """Return the relation name if this rule (rooted at ``root``) explains ``symptom``."""
        if symptom.fingerprint == root.fingerprint or not self.applies_to(root):
            return None
        for e in self.explains:
            if e.matches(root, symptom, topo):
                return e.relation
        return None


def load_rules(path: str | Path) -> list[Rule]:
    return parse_rules(load_yaml(path))


def parse_rules(data: dict[str, Any]) -> list[Rule]:
    rules = []
    for r in data.get("rules") or []:
        rules.append(
            Rule(
                name=r["name"],
                root=AlarmType(r["root"]),
                priority=int(r.get("priority", 50)),
                confidence=float(r.get("confidence", 0.8)),
                min_symptoms=int(r.get("min_symptoms", 0)),
                description=r.get("description", ""),
                when=r.get("when"),
                explains=[Explains(**e) for e in r.get("explains") or []],
            )
        )
    names = [r.name for r in rules]
    if len(names) != len(set(names)):
        raise ValueError("duplicate rule names in RCA rules")
    return rules
