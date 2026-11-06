from __future__ import annotations

from lxml import etree

from autoheal.api.app import alertmanager_to_alarms
from autoheal.collector.normalizer import SimNormalizer
from autoheal.config import RemediationSettings
from autoheal.models import AlarmType
from autoheal.remediation.engine import _satisfied
from autoheal.remediation.guardrails import Guardrails
from autoheal.remediation.playbooks import select_playbook
from simulator.datastore import apply_edit, subtree_filter


def test_playbook_selection_respects_conditions(topology, playbooks):
    ctx = topology.context_for("core2", "ge-0/0/0", AlarmType.INTERFACE_ADMIN_DOWN)
    assert select_playbook(playbooks, AlarmType.INTERFACE_ADMIN_DOWN, ctx).name == "restore-admin-shutdown"
    spare = topology.context_for("core1", "ge-0/0/9", AlarmType.INTERFACE_ADMIN_DOWN)
    assert select_playbook(playbooks, AlarmType.INTERFACE_ADMIN_DOWN, spare) is None

    bgp = topology.context_for("core2", "10.0.4.2", AlarmType.BGP_SESSION_DOWN)
    assert select_playbook(playbooks, AlarmType.BGP_SESSION_DOWN,
                           {**bgp, "attributes": {"reason": "admin-shutdown"}}).name == "re-enable-bgp-neighbor"
    assert select_playbook(playbooks, AlarmType.BGP_SESSION_DOWN,
                           {**bgp, "attributes": {"reason": "hold-timer-expired"}}).name == "clear-stuck-bgp-session"
    assert select_playbook(playbooks, AlarmType.BGP_SESSION_DOWN,
                           {**bgp, "attributes": {"reason": "transport-down"}}) is None

    cpu = topology.context_for("edge1", "cpu", AlarmType.HIGH_CPU)
    assert select_playbook(playbooks, AlarmType.HIGH_CPU,
                           {**cpu, "attributes": {"process": "telemetryd"}}).name == "restart-runaway-process"
    assert select_playbook(playbooks, AlarmType.HIGH_CPU, {**cpu, "attributes": {"process": "rpd"}}) is None


def test_context_resolves_peer_and_ips(topology):
    ctx = topology.context_for("agg2", "10.0.7.2", AlarmType.BGP_SESSION_DOWN)
    assert ctx["interface"] == "ge-0/0/3"
    assert ctx["peer_device"] == "edge2" and ctx["peer_interface"] == "ge-0/0/0"
    assert ctx["local_ip"] == "10.0.7.1" and ctx["peer_ip"] == "10.0.7.2"


def test_guardrails(topology):
    cfg = RemediationSettings(max_actions_per_device_per_hour=3)
    cfg.flap_limit.count = 2
    cfg.circuit_breaker.max_actions = 5
    g = Guardrails(cfg, topology)
    key = "agg1|LINK_DOWN|ge-0/0/2"
    assert g.check("agg1", key) is None
    g.record("agg1", key)
    g.record("agg1", key)
    assert "flap guard" in g.check("agg1", key)
    g.record("agg1", "agg1|HIGH_CPU|cpu")
    assert "rate limit" in g.check("agg1", "agg1|BGP_SESSION_DOWN|10.0.5.2")
    for dev in ("core1", "core2"):
        g.record(dev, f"{dev}|x|y")
    assert "circuit breaker" in g.check("edge1", "edge1|x|y")
    cfg2 = RemediationSettings(excluded_devices=["edge2"])
    assert "excluded" in Guardrails(cfg2, topology).check("edge2", "k")


def test_verify_conditions():
    assert _satisfied("UP", {"expect": "up"})
    assert _satisfied("idle", {"expect": ["established", "idle"]})
    assert not _satisfied(None, {"expect": "up"})
    assert _satisfied("12.5", {"max": 70})
    assert not _satisfied(95.0, {"max": 70})
    assert _satisfied(True, {"expect": True})
    assert _satisfied("65535", {"expect": "65535"})


def test_normalizer_interface_states():
    n = SimNormalizer()
    xml = ('<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><eventTime>x</eventTime>'
           '<interface-state-change xmlns="urn:autoheal:sim:events"><name>ge-0/0/1</name>'
           '<admin-status>up</admin-status><oper-status>down</oper-status></interface-state-change></notification>')
    out = n.from_notification("r1", xml)
    assert [(a.type.value, raised) for a, raised in out] == [("LINK_DOWN", True), ("INTERFACE_ADMIN_DOWN", False)]
    admin = xml.replace("<admin-status>up", "<admin-status>down")
    assert [(a.type.value, r) for a, r in n.from_notification("r1", admin)] == [("INTERFACE_ADMIN_DOWN", True)]


def test_alertmanager_mapping():
    payload = {"alerts": [
        {"status": "firing", "labels": {"alertname": "BGPSessionDown", "device": "core1", "neighbor": "10.0.0.2",
                                        "severity": "critical"}, "annotations": {"summary": "bgp down"}},
        {"status": "resolved", "labels": {"alertname": "HighCPU", "instance": "edge1:9100"}},
    ]}
    a, b = alertmanager_to_alarms(payload)
    assert a.type == AlarmType.BGP_SESSION_DOWN and a.resource == "10.0.0.2" and a.severity.value == "critical"
    assert b.device == "edge1" and b.type == AlarmType.HIGH_CPU and b.is_clear and b.resource == "cpu"


NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
IF = "urn:ietf:params:xml:ns:yang:ietf-interfaces"


def _ds(inner: str):
    return etree.fromstring(f'<data xmlns="{NC}">{inner}</data>')


def test_edit_config_merge_and_delete():
    ds = _ds(f'<interfaces xmlns="{IF}"><interface><name>a</name><enabled>true</enabled></interface>'
             f'<interface><name>b</name><enabled>true</enabled></interface></interfaces>')
    cfg = etree.fromstring(f'<config xmlns="{NC}"><interfaces xmlns="{IF}"><interface><name>b</name>'
                           f'<enabled>false</enabled></interface></interfaces></config>')
    new = apply_edit(ds, cfg)
    vals = {i.findtext(f"{{{IF}}}name"): i.findtext(f"{{{IF}}}enabled") for i in new.iter(f"{{{IF}}}interface")}
    assert vals == {"a": "true", "b": "false"}
    delete = etree.fromstring(f'<config xmlns="{NC}" xmlns:nc="{NC}"><interfaces xmlns="{IF}">'
                              f'<interface nc:operation="delete"><name>a</name></interface></interfaces></config>')
    names = [i.findtext(f"{{{IF}}}name") for i in apply_edit(new, delete).iter(f"{{{IF}}}interface")]
    assert names == ["b"]


def test_subtree_filter_content_match():
    ds = _ds(f'<interfaces xmlns="{IF}"><interface><name>a</name><enabled>true</enabled></interface>'
             f'<interface><name>b</name><enabled>false</enabled></interface></interfaces>')
    flt = etree.fromstring(f'<filter xmlns="{NC}"><interfaces xmlns="{IF}"><interface><name>b</name>'
                           f'</interface></interfaces></filter>')
    out = subtree_filter(ds, flt)
    names = [i.findtext(f"{{{IF}}}name") for i in out.iter(f"{{{IF}}}interface")]
    assert names == ["b"]
    assert out.find(f".//{{{IF}}}enabled").text == "false"
