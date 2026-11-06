from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from autoheal.api.app import create_api
from autoheal.api.projector import Projector
from autoheal.bus import Topics
from autoheal.bus.memory import MemoryBus
from autoheal.config import BusSettings, Settings
from autoheal.models import Alarm, AlarmType, Incident, Remediation, RemediationStatus
from autoheal.store import Store


class RecordingBus(MemoryBus):
    def __init__(self):
        super().__init__(BusSettings(backend="memory"))
        self.sent = []

    async def _publish(self, topic, data, key):
        self.sent.append((topic, data))
        await super()._publish(topic, data, key)


@pytest.fixture
def api(topology):
    bus, store = RecordingBus(), Store(":memory:")
    projector = Projector(store, bus)
    app = create_api(Settings(), bus, store, topology)
    return TestClient(app), bus, store, projector


def test_ingest_single_and_batch(api):
    client, bus, *_ = api
    r = client.post("/api/alarms", json={"device": "core1", "type": "LINK_DOWN", "resource": "ge-0/0/0"})
    assert r.status_code == 202 and r.json() == {"accepted": 1}
    r = client.post("/api/alarms", json=[{"device": "core1", "type": "HIGH_CPU", "resource": "cpu"},
                                         {"device": "core2", "type": "BGP_SESSION_DOWN", "resource": "10.0.0.1"}])
    assert r.json() == {"accepted": 2}
    assert [t for t, _ in bus.sent] == [Topics.ALARMS] * 3
    assert client.post("/api/alarms", json={"device": "x", "type": "NOT_A_TYPE"}).status_code == 422


async def test_projection_topology_and_approval_guard(api):
    client, bus, store, projector = api
    root = Alarm(device="agg2", type=AlarmType.DEVICE_UNREACHABLE, resource="mgmt")
    await projector.handle(Topics.ALARMS, root.model_dump(mode="json"))
    inc = Incident(root_cause=root, rule="node-failure", confidence=0.9)
    await projector.handle(Topics.INCIDENTS, inc.model_dump(mode="json"))
    rem = Remediation(incident_id=inc.id, device="agg2", root_cause="DEVICE_UNREACHABLE",
                      status=RemediationStatus.PENDING_APPROVAL, playbook="power-cycle-unresponsive-node")
    await projector.handle(Topics.REMEDIATIONS, rem.model_dump(mode="json"))

    topo = client.get("/api/topology").json()
    status = {d["name"]: d["status"] for d in topo["devices"]}
    assert status["agg2"] == "unreachable" and status["core1"] == "ok"
    assert all(l["status"] == "down" for l in topo["links"] if "agg2" in l["id"])

    incidents = client.get("/api/incidents").json()
    assert incidents[0]["remediation"]["status"] == "pending_approval"

    assert client.post(f"/api/remediations/{rem.id}/approve", json={"user": "me"}).status_code == 202
    assert bus.sent[-1][0] == Topics.COMMANDS and bus.sent[-1][1]["user"] == "me"

    # stale snapshot is ignored; a finished remediation can no longer be approved
    rem.status, rem.version = RemediationStatus.HEALED, rem.version + 1
    await projector.handle(Topics.REMEDIATIONS, rem.model_dump(mode="json"))
    old = rem.model_copy(update={"status": RemediationStatus.RUNNING, "version": 1})
    await projector.handle(Topics.REMEDIATIONS, old.model_dump(mode="json"))
    assert store.remediation(rem.id)["status"] == "healed"
    assert client.post(f"/api/remediations/{rem.id}/approve").status_code == 409


def test_resync_reassertions_are_not_counted(api):
    _, _, store, _ = api
    first = Alarm(device="agg1", type=AlarmType.LINK_DOWN, resource="ge-0/0/2")
    again = Alarm(device="agg1", type=AlarmType.LINK_DOWN, resource="ge-0/0/2", attributes={"resync": True})
    assert store.put_alarm(first) is True
    assert store.put_alarm(again) is False
    assert store.summary()["alarms_total"] == 1
    assert len(store.alarms()) == 1
