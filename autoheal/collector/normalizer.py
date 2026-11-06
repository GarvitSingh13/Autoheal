"""Turn vendor-specific NETCONF notifications and state snapshots into normalized alarms.

Each normalizer yields alarm *assertions*: ``(Alarm, raised: bool)``. The collector
diffs assertions against what it last reported, so only changes reach the bus.

The ``sim`` normalizer understands the lab simulator's event model. Adding a real
platform means adding a normalizer for its notifications (e.g. ietf-interfaces
``interface-state-change`` / openconfig telemetry) and registering it in NORMALIZERS.
"""

from __future__ import annotations

from typing import Iterable

from lxml import etree

from autoheal.models import Alarm, AlarmType, Severity

Assertion = tuple[Alarm, bool]

IF_NS = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
RT_NS = "urn:autoheal:sim:routing"
SYS_NS = "urn:autoheal:sim:system"
EV_NS = "urn:autoheal:sim:events"
NOTIF_NS = "urn:ietf:params:xml:ns:netconf:notification:1.0"

SEVERITY = {
    AlarmType.LINK_DOWN: Severity.CRITICAL,
    AlarmType.INTERFACE_ADMIN_DOWN: Severity.MAJOR,
    AlarmType.BGP_SESSION_DOWN: Severity.MAJOR,
    AlarmType.OSPF_NEIGHBOR_DOWN: Severity.MAJOR,
    AlarmType.HIGH_CPU: Severity.MINOR,
    AlarmType.HIGH_ERROR_RATE: Severity.MINOR,
    AlarmType.DEVICE_UNREACHABLE: Severity.CRITICAL,
}


def make(device: str, atype: AlarmType, resource: str, raised: bool, source: str,
         message: str = "", **attrs) -> Assertion:
    alarm = Alarm(source=source, device=device, resource=resource, type=atype,
                  severity=SEVERITY.get(atype, Severity.MAJOR) if raised else Severity.CLEAR,
                  message=message, attributes=attrs)
    return alarm, raised


def _why(reason: str) -> str:
    return f" ({reason})" if reason else ""


def _t(el, path: str, ns: dict[str, str]) -> str:
    found = el.find(path, ns)
    return (found.text or "").strip() if found is not None and found.text else ""


class SimNormalizer:
    CPU_THRESHOLD = 85.0
    ERROR_RATE_THRESHOLD = 100.0
    ns = {"if": IF_NS, "rt": RT_NS, "sys": SYS_NS, "ev": EV_NS}

    # -------------------------------------------------------- notifications
    def from_notification(self, device: str, xml: str | bytes) -> list[Assertion]:
        root = etree.fromstring(xml.encode() if isinstance(xml, str) else xml)
        out: list[Assertion] = []
        for ev in root:
            if not isinstance(ev.tag, str) or etree.QName(ev).namespace != EV_NS:
                continue
            name = etree.QName(ev).localname
            if name == "interface-state-change":
                out += self._interface(device, _t(ev, "ev:name", self.ns), _t(ev, "ev:admin-status", self.ns),
                                       _t(ev, "ev:oper-status", self.ns), "netconf-notification")
            elif name == "ospf-adjacency-change":
                iface, state = _t(ev, "ev:interface", self.ns), _t(ev, "ev:state", self.ns)
                out.append(make(device, AlarmType.OSPF_NEIGHBOR_DOWN, iface, state != "full", "netconf-notification",
                                f"OSPF adjacency on {iface} {state}", state=state))
            elif name == "bgp-session-state-change":
                nbr, state = _t(ev, "ev:neighbor", self.ns), _t(ev, "ev:state", self.ns)
                reason = _t(ev, "ev:reason", self.ns)
                out.append(make(device, AlarmType.BGP_SESSION_DOWN, nbr, state != "established",
                                "netconf-notification", f"BGP session to {nbr} {state}{_why(reason)}",
                                state=state, reason=reason))
            elif name == "cpu-threshold":
                util, proc = _t(ev, "ev:utilization", self.ns), _t(ev, "ev:process", self.ns)
                out.append(make(device, AlarmType.HIGH_CPU, "cpu", _t(ev, "ev:status", self.ns) == "raised",
                                "netconf-notification", f"CPU {util}% (top process {proc})",
                                utilization=float(util or 0), process=proc))
            elif name == "interface-error-rate":
                iface, rate = _t(ev, "ev:name", self.ns), _t(ev, "ev:rate", self.ns)
                out.append(make(device, AlarmType.HIGH_ERROR_RATE, iface, _t(ev, "ev:status", self.ns) == "raised",
                                "netconf-notification", f"input errors {rate}/s on {iface}",
                                rate=float(rate or 0)))
        return out

    # ------------------------------------------------------------ snapshots
    state_filter = None  # full <get>

    def from_state(self, device: str, data) -> list[Assertion]:
        out: list[Assertion] = []
        for iface in data.iterfind(".//if:interfaces/if:interface", self.ns):
            name = _t(iface, "if:name", self.ns)
            out += self._interface(device, name, _t(iface, "if:admin-status", self.ns),
                                   _t(iface, "if:oper-status", self.ns), "netconf-resync")
            rate = _t(iface, "if:statistics/sys:in-error-rate", self.ns)
            if rate:
                r = float(rate)
                out.append(make(device, AlarmType.HIGH_ERROR_RATE, name, r > self.ERROR_RATE_THRESHOLD,
                                "netconf-resync", f"input errors {rate}/s on {name}", rate=r))
        for oi in data.iterfind(".//rt:routing/rt:ospf/rt:interface", self.ns):
            state = _t(oi, "rt:adjacency-state", self.ns)
            if state:
                name = _t(oi, "rt:name", self.ns)
                out.append(make(device, AlarmType.OSPF_NEIGHBOR_DOWN, name, state != "full", "netconf-resync",
                                f"OSPF adjacency on {name} {state}", state=state))
        for nb in data.iterfind(".//rt:routing/rt:bgp/rt:neighbor", self.ns):
            state = _t(nb, "rt:session-state", self.ns)
            if state:
                addr, reason = _t(nb, "rt:address", self.ns), _t(nb, "rt:last-error", self.ns)
                out.append(make(device, AlarmType.BGP_SESSION_DOWN, addr, state != "established", "netconf-resync",
                                f"BGP session to {addr} {state}{_why(reason)}", state=state, reason=reason))
        cpu = data.find(".//sys:system-state/sys:cpu-utilization", self.ns)
        if cpu is not None and cpu.text:
            util = float(cpu.text)
            procs = sorted(data.iterfind(".//sys:system-state/sys:processes/sys:process", self.ns),
                           key=lambda p: -float(_t(p, "sys:cpu", self.ns) or 0))
            top = _t(procs[0], "sys:name", self.ns) if procs else ""
            out.append(make(device, AlarmType.HIGH_CPU, "cpu", util > self.CPU_THRESHOLD, "netconf-resync",
                            f"CPU {util:g}% (top process {top})", utilization=util, process=top))
        return out

    @staticmethod
    def _interface(device: str, name: str, admin: str, oper: str, source: str) -> Iterable[Assertion]:
        if admin == "down":
            return [make(device, AlarmType.INTERFACE_ADMIN_DOWN, name, True, source,
                         f"{name} administratively down")]
        if oper == "down":
            return [make(device, AlarmType.LINK_DOWN, name, True, source, f"{name} operationally down"),
                    make(device, AlarmType.INTERFACE_ADMIN_DOWN, name, False, source)]
        return [make(device, AlarmType.LINK_DOWN, name, False, source, f"{name} up"),
                make(device, AlarmType.INTERFACE_ADMIN_DOWN, name, False, source)]


NORMALIZERS = {"sim": SimNormalizer()}


def normalizer_for(vendor: str):
    if vendor not in NORMALIZERS:
        raise KeyError(f"no alarm normalizer for vendor '{vendor}'")
    return NORMALIZERS[vendor]
