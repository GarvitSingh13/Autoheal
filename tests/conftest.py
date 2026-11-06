from __future__ import annotations

from pathlib import Path

import pytest

from autoheal.models import Alarm, AlarmType, Severity
from autoheal.rca.rules import load_rules
from autoheal.remediation.playbooks import load_playbooks
from autoheal.topology import Topology

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"


@pytest.fixture(scope="session")
def topology() -> Topology:
    return Topology.load(CONFIG / "topology.yaml")


@pytest.fixture(scope="session")
def rules():
    return load_rules(CONFIG / "rca_rules.yaml")


@pytest.fixture(scope="session")
def playbooks():
    return load_playbooks(CONFIG / "playbooks.yaml")


def alarm(device: str, atype: str, resource: str = "", clear: bool = False, ts: float | None = None,
          **attrs) -> Alarm:
    kwargs = {"timestamp": ts} if ts is not None else {}
    return Alarm(device=device, type=AlarmType(atype), resource=resource,
                 severity=Severity.CLEAR if clear else Severity.MAJOR, attributes=attrs, source="test", **kwargs)
