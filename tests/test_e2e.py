"""End-to-end: lab simulator (real NETCONF/SSH + RESTCONF + PDU) + full platform
(collector -> RCA -> remediator -> API) on the in-memory bus.

Each scenario injects a fault into the simulator, waits for the platform to diagnose
and act, then checks the *device state* in the simulator, not just platform records.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import yaml

from autoheal.config import Settings, expand_env
from autoheal.runner import Platform
from autoheal.topology import Topology
from simulator.server import Simulator

pytestmark = pytest.mark.asyncio(loop_scope="module")

CONFIG = Path(__file__).resolve().parent.parent / "config"
PORT_OFFSET = 1000  # NETCONF on 9301.., simulator API on 9300, so a running lab is not disturbed
SIM_API = 8300 + PORT_OFFSET


def _test_topology(tmp: Path) -> Path:
    data = yaml.safe_load(expand_env((CONFIG / "topology.yaml").read_text()))
    for name, dev in data["devices"].items():
        dev["host"] = "127.0.0.1"
        dev["netconf_port"] += PORT_OFFSET
        dev["restconf_url"] = f"http://127.0.0.1:{SIM_API}/devices/{name}/restconf"
    path = tmp / "topology.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def lab(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("lab")
    topo_path = _test_topology(tmp)
    sim = Simulator(Topology.load(topo_path), host="127.0.0.1", api_port=SIM_API, boot_time=2.0)
    sim.start()
    settings = Settings.model_validate({
        "bus": {"backend": "memory"},
        "api": {"db_path": str(tmp / "autoheal.db")},
        "collector": {"reconnect_interval": 1, "resync_interval": 30, "connect_timeout": 3},
        "rca": {"correlation_window": 2.0, "residual_grace": 5.0},
        "remediation": {"mode": "auto", "confirm_timeout": 60, "approval_timeout": 60},
        "endpoints": {"pdu": {"base_url": f"http://127.0.0.1:{SIM_API}/pdu", "username": "admin",
                              "password": "admin"}},
        "lab": {"simulator_url": f"http://127.0.0.1:{SIM_API}"},
        "paths": {"topology": str(topo_path), "rules": str(CONFIG / "rca_rules.yaml"),
                  "playbooks": str(CONFIG / "playbooks.yaml"), "vendors_dir": str(CONFIG / "vendors")},
    })
    platform = Platform(settings, {"collector", "rca", "remediator", "api"})
    await platform.start()
    deadline = time.time() + 20
    while not all(w.connected for w in platform.collector.workers):
        assert time.time() < deadline, "collector did not connect to all simulated devices"
        await asyncio.sleep(0.2)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=platform.app), base_url="http://api")
    yield sim, platform, client
    await client.aclose()
    await platform.stop()
    sim.stop()


async def wait_for(predicate, timeout: float, what: str):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        await asyncio.sleep(0.25)
    raise AssertionError(f"timed out waiting for {what}")


def remediation_for(platform, device: str | None, root: str, statuses: set[str], after: float):
    """First remediation for ``root`` (on ``device``, or any device if None) created after ``after``."""
    for rem in platform.remediator.engine.records.values():
        if (device is None or rem.device == device) and rem.root_cause == root \
                and rem.status.value in statuses and rem.created_at >= after:
            return rem
    return None


async def network_healthy(sim, platform, timeout: float = 30):
    """Wait until the simulator has no faults and RCA holds no open incidents."""
    def ok():
        snap = sim.net.snapshot()
        links_up = all(s["oper"] == "up" for d in snap.values() if d["powered"]
                       for n, s in d["ifaces"].items() if n != "ge-0/0/9")
        return links_up and not sim.net.faults and not platform.rca.engine.incidents
    await wait_for(ok, timeout, "network to return to healthy")


TERMINAL = {"healed", "mitigated", "failed", "escalated", "no_playbook", "rejected", "cancelled", "expired"}


async def test_admin_shutdown_is_healed_with_full_correlation(lab):
    sim, platform, client = lab
    t0 = time.time()
    sim.net.inject("admin_shutdown", "core2", interface="ge-0/0/1")  # core2 <-> agg1
    rem = await wait_for(lambda: remediation_for(platform, "core2", "INTERFACE_ADMIN_DOWN", TERMINAL, t0), 40,
                         "admin-shutdown remediation")
    assert rem.status.value == "healed", rem.reason
    assert rem.playbook == "restore-admin-shutdown"
    assert sim.net.snapshot()["core2"]["ifaces"]["ge-0/0/1"]["admin"] == "up"
    inc = (await client.get(f"/api/incidents/{rem.incident_id}")).json()
    assert inc["rule"] == "interface-admin-down"
    # far-end link + OSPF and BGP on both ends = 5 symptoms folded into one incident
    assert len(inc["symptoms"]) == 5, [s["type"] + "@" + s["device"] for s in inc["symptoms"]]
    await network_healthy(sim, platform)


async def test_hung_link_is_bounced(lab):
    sim, platform, _ = lab
    t0 = time.time()
    sim.net.inject("link_hang", "agg1", interface="ge-0/0/2")  # agg1 <-> edge1
    rem = await wait_for(lambda: remediation_for(platform, None, "LINK_DOWN", TERMINAL, t0), 45, "link bounce")
    assert rem.status.value == "healed", rem.reason
    assert rem.playbook == "bounce-hung-link"
    assert sim.net.snapshot()["agg1"]["ifaces"]["ge-0/0/2"]["oper"] == "up"
    assert platform.rca.engine.stats["suppressed_by_change"] >= 1  # the bounce's own admin-down was not a new fault
    await network_healthy(sim, platform)


async def test_fiber_cut_fails_safely_and_rolls_back(lab):
    sim, platform, _ = lab
    t0 = time.time()
    fault = sim.net.inject("fiber_cut", "core1", interface="ge-0/0/1")  # core1 <-> agg1
    rem = await wait_for(lambda: remediation_for(platform, None, "LINK_DOWN", TERMINAL, t0), 60,
                         "fiber-cut remediation outcome")
    assert rem.status.value == "failed"
    assert "cancel-commit" in rem.reason
    # rollback restored the original (enabled) config on whichever end was bounced
    assert sim.net.snapshot()[rem.device]["ifaces"][rem.resource]["admin"] == "up"
    sim.net.repair(fault["id"])
    await network_healthy(sim, platform)


async def test_stuck_bgp_is_cleared(lab):
    sim, platform, _ = lab
    t0 = time.time()
    sim.net.inject("bgp_stuck", "edge1", neighbor="10.0.6.1")
    rem = await wait_for(lambda: remediation_for(platform, None, "BGP_SESSION_DOWN", TERMINAL, t0), 40, "bgp clear")
    assert rem.status.value == "healed", rem.reason
    assert rem.playbook == "clear-stuck-bgp-session"
    assert sim.net.snapshot()["edge1"]["bgp"]["10.0.6.1"]["state"] == "established"
    await network_healthy(sim, platform)


async def test_bgp_neighbor_drift_is_reverted(lab):
    sim, platform, _ = lab
    t0 = time.time()
    sim.net.inject("bgp_neighbor_shutdown", "core2", neighbor="10.0.4.2")
    rem = await wait_for(lambda: remediation_for(platform, "core2", "BGP_SESSION_DOWN", TERMINAL, t0), 40,
                         "bgp neighbor re-enable")
    assert rem.status.value == "healed", rem.reason
    assert rem.playbook == "re-enable-bgp-neighbor"
    assert sim.net.snapshot()["core2"]["bgp"]["10.0.4.2"]["state"] == "established"
    await network_healthy(sim, platform)


async def test_runaway_process_restarted_over_restconf(lab):
    sim, platform, _ = lab
    t0 = time.time()
    sim.net.inject("cpu_runaway", "edge1", process="telemetryd")
    rem = await wait_for(lambda: remediation_for(platform, "edge1", "HIGH_CPU", TERMINAL, t0), 40, "cpu fix")
    assert rem.status.value == "healed", rem.reason
    assert rem.steps[0].kind == "rest" and "HTTP 204" in rem.steps[0].detail
    assert sim.net.snapshot()["edge1"]["cpu"] < 70
    await network_healthy(sim, platform)


async def test_crc_errors_are_mitigated_by_cost_out(lab):
    sim, platform, client = lab
    t0 = time.time()
    fault = sim.net.inject("crc_errors", "agg2", interface="ge-0/0/2")  # agg2 <-> edge1
    rem = await wait_for(lambda: remediation_for(platform, "agg2", "HIGH_ERROR_RATE", TERMINAL, t0), 40, "cost-out")
    assert rem.status.value == "mitigated", rem.reason
    assert "edge1:ge-0/0/1" in rem.follow_up
    snap = sim.net.snapshot()
    assert snap["agg2"]["ospf"]["ge-0/0/2"]["cost"] == 65535
    assert snap["edge1"]["ospf"]["ge-0/0/1"]["cost"] == 65535
    sim.net.repair(fault["id"])
    await network_healthy(sim, platform)


async def test_node_failure_needs_approval_then_power_cycles(lab):
    sim, platform, client = lab
    t0 = time.time()
    sim.net.inject("power_off", "agg2")
    rem = await wait_for(lambda: remediation_for(platform, "agg2", "DEVICE_UNREACHABLE", {"pending_approval"}, t0),
                         40, "approval request")
    inc = (await client.get(f"/api/incidents/{rem.incident_id}")).json()
    assert inc["rule"] == "node-failure"
    assert "edge2" in inc["affected_devices"]  # single-homed behind agg2 -> downstream
    await wait_for(lambda: platform.store.remediation(rem.id), 5, "remediation in read model")
    r = await client.post(f"/api/remediations/{rem.id}/approve", json={"user": "noc-oncall"})
    assert r.status_code == 202, r.text
    done = await wait_for(lambda: remediation_for(platform, "agg2", "DEVICE_UNREACHABLE", TERMINAL, t0), 60,
                          "power cycle")
    assert done.status.value == "healed", done.reason
    assert done.approved_by == "noc-oncall"
    assert sim.net.snapshot()["agg2"]["powered"]
    await network_healthy(sim, platform, timeout=40)


async def test_api_summary_and_topology(lab):
    _, platform, client = lab
    summary = (await client.get("/api/summary")).json()
    assert summary["auto_healed"] >= 6
    assert summary["alarms_total"] > summary["incidents_total"]  # correlation reduced noise
    topo = (await client.get("/api/topology")).json()
    assert {d["status"] for d in topo["devices"]} <= {"ok", "degraded"}
    assert (await client.get("/metrics")).status_code == 200
