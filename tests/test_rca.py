from __future__ import annotations

import asyncio

import pytest

from autoheal.config import RcaSettings
from autoheal.models import AlarmType, IncidentStatus, Remediation, RemediationStatus
from autoheal.rca.engine import RcaEngine
from tests.conftest import alarm


class Collect:
    def __init__(self):
        self.events = []

    async def __call__(self, inc):
        self.events.append(inc)

    def latest(self):
        out = {}
        for inc in self.events:
            out[inc.id] = inc
        return out

    def open(self):
        return [i for i in self.latest().values() if i.status == IncidentStatus.OPEN]


@pytest.fixture
def engine(topology, rules):
    sink = Collect()
    eng = RcaEngine(RcaSettings(correlation_window=0.05, residual_grace=0.1), topology, rules, sink)
    eng.sink = sink
    return eng


async def feed(engine, *alarms):
    for a in alarms:
        await engine.handle_alarm(a)
    await asyncio.sleep(0.1)


# ------------------------------------------------------------------ topology
def test_topology_relations(topology):
    assert str(topology.peer("core1", "ge-0/0/0")) == "core2:ge-0/0/0"
    assert topology.interface_for_neighbor("agg2", "10.0.7.2") == "ge-0/0/3"
    assert topology.owner_of_ip("10.0.7.2").device == "edge2"
    assert topology.downstream("agg2") == {"edge2"}
    assert topology.downstream("agg1") == set()
    link = topology.link_at("agg2", "ge-0/0/3")
    assert topology.isolated_by_link(link) == {"edge2"}
    assert topology.isolated_by_link(topology.link_at("core1", "ge-0/0/0")) == set()


# ---------------------------------------------------------------------- RCA
async def test_admin_down_storm_collapses_to_one_incident(engine):
    await feed(engine,
               alarm("core1", "LINK_DOWN", "ge-0/0/0"),
               alarm("core1", "OSPF_NEIGHBOR_DOWN", "ge-0/0/0"),
               alarm("core1", "BGP_SESSION_DOWN", "10.0.0.2", reason="transport-down"),
               alarm("core2", "INTERFACE_ADMIN_DOWN", "ge-0/0/0"),
               alarm("core2", "OSPF_NEIGHBOR_DOWN", "ge-0/0/0"),
               alarm("core2", "BGP_SESSION_DOWN", "10.0.0.1", reason="transport-down"))
    incidents = engine.sink.open()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.root_cause.type == AlarmType.INTERFACE_ADMIN_DOWN and inc.device == "core2"
    assert inc.rule == "interface-admin-down"
    assert len(inc.symptoms) == 5
    assert inc.confidence == pytest.approx(0.95)


async def test_node_failure_explains_neighbors_and_downstream(engine):
    await feed(engine,
               alarm("core1", "LINK_DOWN", "ge-0/0/2"),
               alarm("core2", "LINK_DOWN", "ge-0/0/2"),
               alarm("edge1", "LINK_DOWN", "ge-0/0/1"),
               alarm("core1", "BGP_SESSION_DOWN", "10.0.2.2", reason="transport-down"),
               alarm("agg2", "DEVICE_UNREACHABLE", "mgmt"),
               alarm("edge2", "DEVICE_UNREACHABLE", "mgmt"))
    incidents = engine.sink.open()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.rule == "node-failure" and inc.device == "agg2"
    assert {s.device for s in inc.symptoms} == {"core1", "core2", "edge1", "edge2"}


async def test_unreachable_without_corroboration_has_low_confidence(engine):
    await feed(engine, alarm("edge1", "DEVICE_UNREACHABLE", "mgmt"))
    inc = engine.sink.open()[0]
    assert inc.rule == "node-failure"
    assert inc.confidence < 0.7  # below remediation threshold -> escalate, don't power-cycle


async def test_late_alarm_attaches_to_open_incident(engine):
    await feed(engine, alarm("agg1", "INTERFACE_ADMIN_DOWN", "ge-0/0/2"))
    assert len(engine.sink.open()) == 1
    await feed(engine, alarm("edge1", "LINK_DOWN", "ge-0/0/0"))
    incidents = engine.sink.open()
    assert len(incidents) == 1 and len(incidents[0].symptoms) == 1


async def test_late_root_supersedes_earlier_incidents(engine):
    await feed(engine, alarm("core1", "LINK_DOWN", "ge-0/0/2"))
    first = engine.sink.open()
    assert len(first) == 1 and first[0].rule == "physical-link-failure"
    await feed(engine, alarm("agg2", "DEVICE_UNREACHABLE", "mgmt"))
    latest = engine.sink.latest()
    assert latest[first[0].id].status == IncidentStatus.SUPERSEDED
    open_ = engine.sink.open()
    assert len(open_) == 1 and open_[0].rule == "node-failure"
    assert latest[first[0].id].superseded_by == open_[0].id


async def test_root_clear_clears_incident_and_reanalyses_residual(engine):
    await feed(engine,
               alarm("core2", "INTERFACE_ADMIN_DOWN", "ge-0/0/1"),
               alarm("agg1", "BGP_SESSION_DOWN", "10.0.3.1", reason="hold-timer-expired"))
    inc = engine.sink.open()[0]
    assert len(inc.symptoms) == 1
    await feed(engine, alarm("core2", "INTERFACE_ADMIN_DOWN", "ge-0/0/1", clear=True))
    latest = engine.sink.latest()
    assert latest[inc.id].status == IncidentStatus.CLEARED
    assert engine.sink.open() == []  # residual symptom gets a grace period first
    await asyncio.sleep(0.25)
    reopened = engine.sink.open()
    assert len(reopened) == 1
    assert reopened[0].root_cause.type == AlarmType.BGP_SESSION_DOWN
    assert reopened[0].rule == "bgp-session-failure"


async def test_duplicates_are_counted_not_reanalysed(engine):
    a = alarm("edge1", "HIGH_CPU", "cpu", process="telemetryd")
    await feed(engine, a, alarm("edge1", "HIGH_CPU", "cpu", process="telemetryd"))
    assert len(engine.sink.open()) == 1
    assert engine.stats["deduplicated"] == 1


async def test_intended_admin_down_is_ignored(engine):
    await feed(engine, alarm("core1", "INTERFACE_ADMIN_DOWN", "ge-0/0/9"))
    assert engine.sink.open() == []
    assert engine.stats["suppressed_by_intent"] == 1


async def test_transient_alarm_cleared_inside_window_is_dropped(engine):
    await engine.handle_alarm(alarm("agg1", "LINK_DOWN", "ge-0/0/2"))
    await engine.handle_alarm(alarm("agg1", "LINK_DOWN", "ge-0/0/2", clear=True))
    await asyncio.sleep(0.1)
    assert engine.sink.events == []


async def test_bgp_admin_shutdown_side_is_chosen_as_root(engine):
    await feed(engine,
               alarm("agg2", "BGP_SESSION_DOWN", "10.0.4.1", reason="peer-closed", ts=1.0),
               alarm("core2", "BGP_SESSION_DOWN", "10.0.4.2", reason="admin-shutdown", ts=2.0))
    inc = engine.sink.open()[0]
    assert inc.device == "core2" and inc.rule == "bgp-neighbor-admin-down"


async def test_change_induced_alarms_are_suppressed(engine):
    rem = Remediation(incident_id="inc-x", device="agg1", root_cause="LINK_DOWN", resource="ge-0/0/2",
                      status=RemediationStatus.RUNNING, suppressions=["agg1|INTERFACE_ADMIN_DOWN|ge-0/0/2"])
    engine.handle_remediation(rem)
    await feed(engine, alarm("agg1", "INTERFACE_ADMIN_DOWN", "ge-0/0/2"))
    assert engine.sink.events == []
    assert engine.stats["suppressed_by_change"] == 1
