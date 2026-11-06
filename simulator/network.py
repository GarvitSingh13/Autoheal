"""Simulated multi-vendor-agnostic routed network.

Every device has a real XML running/candidate datastore. Operational state is *derived*
from configuration plus injected physical faults, across devices:

    oper-status(dev:if)  = powered(dev) & enabled(dev:if) & powered(peer) & enabled(peer:if) & link healthy
    OSPF adjacency       = OSPF configured on both ends & interface oper-up
    BGP session          = neighbor enabled both sides & underlying link oper-up & not stuck
    management reachable = in-band path from the management root over oper-up links

After any change the network recomputes state, diffs it, and emits NETCONF
notifications to subscribed sessions — so a config pushed by the platform really does
bring a link (and its routing sessions) back, and a power-off really does drop sessions.
"""

from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import itertools
import logging
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

from lxml import etree

from autoheal.topology import Endpoint, Topology
from simulator.datastore import NC_NS, EditError, apply_edit

log = logging.getLogger("simulator")

IF_NS = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
IP_NS = "urn:ietf:params:xml:ns:yang:ietf-ip"
RT_NS = "urn:autoheal:sim:routing"
SYS_NS = "urn:autoheal:sim:system"
EV_NS = "urn:autoheal:sim:events"
NOTIF_NS = "urn:ietf:params:xml:ns:netconf:notification:1.0"
NS = {"nc": NC_NS, "if": IF_NS, "rt": RT_NS, "sys": SYS_NS}

CPU_THRESHOLD = 85.0
ERROR_RATE_THRESHOLD = 100.0
CRC_ERROR_RATE = 450.0
BGP_RESET_SECONDS = 2.0
DEFAULT_PROCESSES = {"rpd": 4.0, "mgd": 2.0, "snmpd": 1.0, "sshd": 1.0, "telemetryd": 2.0}

FAULT_TYPES = {
    "admin_shutdown": "Operator mistake: interface shut down in running config (fields: device, interface)",
    "link_hang": "Transceiver/autoneg hang: link down until the interface is bounced (device, interface)",
    "fiber_cut": "Physical cut: link down until repaired (device, interface)",
    "bgp_stuck": "BGP session wedged (hold-timer expired) until cleared (device, neighbor)",
    "bgp_neighbor_shutdown": "Operator mistake: BGP neighbor disabled in running config (device, neighbor)",
    "cpu_runaway": "Runaway process pins the control-plane CPU until restarted (device, process)",
    "crc_errors": "Dirty optic: CRC errors on an interface until repaired (device, interface)",
    "power_off": "Device loses power until power-cycled via the PDU (device)",
}


@dataclass
class Fault:
    id: str
    type: str
    device: str
    interface: str | None = None
    neighbor: str | None = None
    process: str | None = None
    created_at: float = field(default_factory=time.time)
    link_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class PendingConfirm:
    snapshot: Any
    session_id: int
    timer: threading.Timer


class SimDevice:
    def __init__(self, name: str, running):
        self.name = name
        self.running = running
        self.candidate = copy.deepcopy(running)
        self.powered = True
        self.booting = False
        self.locks: dict[str, int] = {}
        self.confirm: PendingConfirm | None = None
        self.processes = dict(DEFAULT_PROCESSES)
        self.base_cpu = 8.0 + zlib.crc32(name.encode()) % 8


def _el(parent, ns: str, tag: str, text: Any = None):
    nsmap = None if etree.QName(parent).namespace == ns else {None: ns}
    e = etree.SubElement(parent, f"{{{ns}}}{tag}", nsmap=nsmap)
    if text is not None:
        e.text = str(text).lower() if isinstance(text, bool) else str(text)
    return e


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Network:
    def __init__(self, topology: Topology, boot_time: float = 5.0):
        self.topo = topology
        self.boot_time = boot_time
        self.lock = threading.RLock()
        self.devices = {name: SimDevice(name, self._initial_config(name)) for name in topology.devices}
        self.faults: dict[str, Fault] = {}
        self.resetting: dict[tuple[str, str], float] = {}  # (device, neighbor) -> until
        self._ids = itertools.count(1)
        self.subscribers: dict[str, list[Callable[[str], None]]] = {n: [] for n in self.devices}
        self.session_closers: dict[str, dict[int, Callable[[], None]]] = {n: {} for n in self.devices}
        self.state = self._compute()
        self.events_emitted = 0

    # ------------------------------------------------------------ config model
    def _initial_config(self, name: str):
        dev = self.topo.devices[name]
        data = etree.Element(f"{{{NC_NS}}}data", nsmap={None: NC_NS})
        ifs = _el(data, IF_NS, "interfaces")
        for iface in dev.interfaces.values():
            ie = _el(ifs, IF_NS, "interface")
            _el(ie, IF_NS, "name", iface.name)
            _el(ie, IF_NS, "description", iface.description or "")
            _el(ie, IF_NS, "enabled", iface.intended_enabled)
            if iface.ip is not None:
                v4 = _el(ie, IP_NS, "ipv4")
                addr = _el(v4, IP_NS, "address")
                _el(addr, IP_NS, "ip", iface.ip.ip)
                _el(addr, IP_NS, "prefix-length", iface.ip.network.prefixlen)
        rt = _el(data, RT_NS, "routing")
        ospf = _el(rt, RT_NS, "ospf")
        _el(ospf, RT_NS, "area", "0.0.0.0")
        bgp = _el(rt, RT_NS, "bgp")
        _el(bgp, RT_NS, "local-as", dev.asn or 65000)
        for iface in dev.interfaces.values():
            peer = self.topo.peer(name, iface.name)
            if peer is None:
                continue
            if iface.ospf:
                oi = _el(ospf, RT_NS, "interface")
                _el(oi, RT_NS, "name", iface.name)
                _el(oi, RT_NS, "cost", iface.ospf_cost)
            pif = self.topo.devices[peer.device].interfaces[peer.interface]
            if iface.ip is not None and pif.ip is not None:
                nb = _el(bgp, RT_NS, "neighbor")
                _el(nb, RT_NS, "address", pif.ip.ip)
                _el(nb, RT_NS, "remote-as", self.topo.devices[peer.device].asn or 65000)
                _el(nb, RT_NS, "description", f"{peer.device} via {iface.name}")
                _el(nb, RT_NS, "enabled", True)
        sysc = _el(data, SYS_NS, "system")
        _el(sysc, SYS_NS, "hostname", name)
        return data

    def validate(self, name: str, tree) -> None:
        hw = set(self.topo.devices[name].interfaces)
        for ie in tree.iterfind("if:interfaces/if:interface", NS):
            iname = ie.findtext("if:name", namespaces=NS)
            if iname not in hw:
                raise EditError("invalid-value", f"interface {iname!r} does not exist on {name}")
            en = ie.findtext("if:enabled", namespaces=NS)
            if en is not None and en not in ("true", "false"):
                raise EditError("invalid-value", f"enabled must be true|false, got {en!r}")
        for oi in tree.iterfind("rt:routing/rt:ospf/rt:interface", NS):
            if oi.findtext("rt:name", namespaces=NS) not in hw:
                raise EditError("invalid-value", f"OSPF interface {oi.findtext('rt:name', namespaces=NS)!r} unknown")
            cost = oi.findtext("rt:cost", namespaces=NS)
            if cost is not None and (not cost.isdigit() or not 1 <= int(cost) <= 65535):
                raise EditError("invalid-value", f"OSPF cost must be 1..65535, got {cost!r}")
        for nb in tree.iterfind("rt:routing/rt:bgp/rt:neighbor", NS):
            try:
                ipaddress.IPv4Address(nb.findtext("rt:address", namespaces=NS) or "")
            except ValueError:
                raise EditError("invalid-value", "BGP neighbor address must be an IPv4 address")

    @staticmethod
    def _iface_enabled(cfg, iface: str) -> bool:
        for ie in cfg.iterfind("if:interfaces/if:interface", NS):
            if ie.findtext("if:name", namespaces=NS) == iface:
                return (ie.findtext("if:enabled", namespaces=NS) or "true") == "true"
        return False

    @staticmethod
    def _ospf_ifaces(cfg) -> dict[str, int]:
        out = {}
        for oi in cfg.iterfind("rt:routing/rt:ospf/rt:interface", NS):
            if (oi.findtext("rt:enabled", namespaces=NS) or "true") == "true":
                out[oi.findtext("rt:name", namespaces=NS)] = int(oi.findtext("rt:cost", namespaces=NS) or 10)
        return out

    @staticmethod
    def _bgp_neighbors(cfg) -> dict[str, bool]:
        return {nb.findtext("rt:address", namespaces=NS): (nb.findtext("rt:enabled", namespaces=NS) or "true") == "true"
                for nb in cfg.iterfind("rt:routing/rt:bgp/rt:neighbor", NS)}

    # ------------------------------------------------------------ state model
    def _link_faulted(self, link_id: str) -> bool:
        return any(f.link_id == link_id and f.type in ("fiber_cut", "link_hang") for f in self.faults.values())

    def _compute(self) -> dict[str, dict[str, Any]]:
        now = time.time()
        st: dict[str, dict[str, Any]] = {}
        oper: dict[tuple[str, str], bool] = {}
        for name, dev in self.devices.items():
            for iname in self.topo.devices[name].interfaces:
                up = dev.powered and self._iface_enabled(dev.running, iname)
                link = self.topo.link_at(name, iname)
                if up and link is not None:
                    peer = link.other(Endpoint(name, iname))
                    pdev = self.devices[peer.device]
                    up = (pdev.powered and self._iface_enabled(pdev.running, peer.interface)
                          and not self._link_faulted(link.id))
                oper[(name, iname)] = up

        reachable: set[str] = set()
        root = self.topo.mgmt_root
        if root and self.devices[root].powered:
            frontier = [root]
            reachable.add(root)
            while frontier:
                cur = frontier.pop()
                for iname in self.topo.devices[cur].interfaces:
                    if not oper[(cur, iname)]:
                        continue
                    peer = self.topo.peer(cur, iname)
                    if peer and peer.device not in reachable:
                        reachable.add(peer.device)
                        frontier.append(peer.device)

        for name, dev in self.devices.items():
            if not dev.powered:
                st[name] = {"powered": False, "reachable": False, "ifaces": {}, "ospf": {}, "bgp": {}, "cpu": None}
                continue
            ifaces = {}
            for iname in self.topo.devices[name].interfaces:
                rate = CRC_ERROR_RATE if any(
                    f.type == "crc_errors" and f.device == name and f.interface == iname
                    for f in self.faults.values()) else 0.0
                ifaces[iname] = {"admin": "up" if self._iface_enabled(dev.running, iname) else "down",
                                 "oper": "up" if oper[(name, iname)] else "down", "error_rate": rate}
            ospf = {}
            local_ospf = self._ospf_ifaces(dev.running)
            for iname, cost in local_ospf.items():
                peer = self.topo.peer(name, iname)
                peer_ospf = self._ospf_ifaces(self.devices[peer.device].running) if peer else {}
                full = oper.get((name, iname), False) and peer is not None and peer.interface in peer_ospf
                ospf[iname] = {"state": "full" if full else "down", "cost": cost}
            bgp = {}
            for nbr, enabled in self._bgp_neighbors(dev.running).items():
                bgp[nbr] = self._bgp_state(name, nbr, enabled, oper, now)
            procs = dict(dev.processes)
            for f in self.faults.values():
                if f.type == "cpu_runaway" and f.device == name:
                    procs[f.process] = procs.get(f.process, 0.0) + 85.0
            cpu = min(99.0, dev.base_cpu + sum(procs.values()))
            st[name] = {"powered": True, "reachable": name in reachable, "ifaces": ifaces, "ospf": ospf,
                        "bgp": bgp, "cpu": round(cpu, 1), "processes": procs}
        return st

    def _bgp_state(self, name: str, nbr: str, enabled: bool, oper, now: float) -> dict[str, str]:
        if not enabled:
            return {"state": "idle", "reason": "admin-shutdown"}
        local_if = self.topo.interface_for_neighbor(name, nbr)
        owner = self.topo.owner_of_ip(nbr)
        if local_if is None or owner is None:
            return {"state": "idle", "reason": "peer-unreachable"}
        if not oper.get((name, local_if), False):
            return {"state": "idle", "reason": "transport-down"}
        my_ip = str(self.topo.devices[name].interfaces[local_if].ip.ip)
        peer_cfg = self._bgp_neighbors(self.devices[owner.device].running)
        if not peer_cfg.get(my_ip, False):
            return {"state": "active", "reason": "peer-closed"}
        for f in self.faults.values():
            if f.type == "bgp_stuck" and ((f.device == name and f.neighbor == nbr) or
                                          (f.device == owner.device and f.neighbor == my_ip)):
                return {"state": "idle", "reason": "hold-timer-expired"}
        for key in ((name, nbr), (owner.device, my_ip)):
            if self.resetting.get(key, 0) > now:
                return {"state": "active", "reason": "session-reset"}
        return {"state": "established", "reason": ""}

    # ------------------------------------------------------- recompute + events
    def recompute(self) -> None:
        """Recompute state, emit notifications for changes, drop sessions of unreachable devices."""
        to_close: list[Callable[[], None]] = []
        with self.lock:
            # A bounce (admin down) clears a hung link.
            for fid, f in list(self.faults.items()):
                if f.type == "link_hang":
                    link = self.topo.link_at(f.device, f.interface)
                    if link and any(not self._iface_enabled(self.devices[ep.device].running, ep.interface)
                                    for ep in (link.a, link.b)):
                        log.info("fault %s (link_hang %s) cleared by interface bounce", fid, link.id)
                        del self.faults[fid]
            old, new = self.state, self._compute()
            self.state = new
            for name in self.devices:
                for ev in self._diff(name, old[name], new[name]):
                    self._notify(name, ev)
                if not new[name]["reachable"] and self.session_closers[name]:
                    to_close.extend(self.session_closers[name].values())
        for close in to_close:
            try:
                close()
            except Exception:
                pass

    def _diff(self, name: str, old: dict, new: dict) -> list[str]:
        if not new["powered"]:
            return []
        evs = []
        for iname, s in new["ifaces"].items():
            o = old["ifaces"].get(iname) if old["powered"] else None
            if o is None or (o["admin"], o["oper"]) != (s["admin"], s["oper"]):
                if o is None and s["oper"] == "up":
                    pass  # boot-up: nothing to report
                else:
                    evs.append(self._ev("interface-state-change", name=iname, **{"admin-status": s["admin"],
                                                                                  "oper-status": s["oper"]}))
            o_rate = o["error_rate"] if o else 0.0
            if (o_rate > ERROR_RATE_THRESHOLD) != (s["error_rate"] > ERROR_RATE_THRESHOLD):
                evs.append(self._ev("interface-error-rate", name=iname, rate=s["error_rate"],
                                    status="raised" if s["error_rate"] > ERROR_RATE_THRESHOLD else "cleared"))
        for iname, s in new["ospf"].items():
            o = old["ospf"].get(iname) if old["powered"] else None
            if (o["state"] if o else "full") != s["state"]:
                evs.append(self._ev("ospf-adjacency-change", interface=iname, state=s["state"]))
        for nbr, s in new["bgp"].items():
            o = old["bgp"].get(nbr) if old["powered"] else None
            was_up = (o["state"] == "established") if o else True
            if was_up != (s["state"] == "established"):
                evs.append(self._ev("bgp-session-state-change", neighbor=nbr, state=s["state"], reason=s["reason"]))
        o_cpu = old["cpu"] if old["powered"] else 0.0
        if (o_cpu > CPU_THRESHOLD) != (new["cpu"] > CPU_THRESHOLD):
            top = max(new["processes"], key=new["processes"].get)
            evs.append(self._ev("cpu-threshold", utilization=new["cpu"], process=top,
                                status="raised" if new["cpu"] > CPU_THRESHOLD else "cleared"))
        return evs

    @staticmethod
    def _ev(kind: str, **fields) -> str:
        n = etree.Element(f"{{{NOTIF_NS}}}notification", nsmap={None: NOTIF_NS})
        _el(n, NOTIF_NS, "eventTime", _now_iso())
        body = etree.SubElement(n, f"{{{EV_NS}}}{kind}", nsmap={None: EV_NS})
        for k, v in fields.items():
            _el(body, EV_NS, k, v)
        return etree.tostring(n, encoding="unicode")

    def _notify(self, name: str, xml: str) -> None:
        self.events_emitted += 1
        for push in list(self.subscribers[name]):
            push(xml)

    # -------------------------------------------------------------- NETCONF ops
    def get_config(self, name: str, source: str = "running"):
        with self.lock:
            dev = self.devices[name]
            return copy.deepcopy(dev.candidate if source == "candidate" else dev.running)

    def get_state(self, name: str):
        """Config + operational state (what NETCONF <get> returns)."""
        with self.lock:
            dev, st = self.devices[name], self.state[name]
            data = copy.deepcopy(dev.running)
            if not st["powered"]:
                return data
            for ie in data.iterfind("if:interfaces/if:interface", NS):
                s = st["ifaces"].get(ie.findtext("if:name", namespaces=NS))
                if not s:
                    continue
                _el(ie, IF_NS, "admin-status", s["admin"])
                _el(ie, IF_NS, "oper-status", s["oper"])
                stats = _el(ie, IF_NS, "statistics")
                _el(stats, IF_NS, "in-errors", int(s["error_rate"] * 60))
                _el(stats, SYS_NS, "in-error-rate", s["error_rate"])
            for oi in data.iterfind("rt:routing/rt:ospf/rt:interface", NS):
                s = st["ospf"].get(oi.findtext("rt:name", namespaces=NS))
                if s:
                    _el(oi, RT_NS, "adjacency-state", s["state"])
            for nb in data.iterfind("rt:routing/rt:bgp/rt:neighbor", NS):
                s = st["bgp"].get(nb.findtext("rt:address", namespaces=NS))
                if s:
                    _el(nb, RT_NS, "session-state", s["state"])
                    _el(nb, RT_NS, "last-error", s["reason"])
            ss = _el(data, SYS_NS, "system-state")
            _el(ss, SYS_NS, "cpu-utilization", st["cpu"])
            procs = _el(ss, SYS_NS, "processes")
            for pname, pcpu in st["processes"].items():
                p = _el(procs, SYS_NS, "process")
                _el(p, SYS_NS, "name", pname)
                _el(p, SYS_NS, "cpu", pcpu)
            return data

    def _check_lock(self, name: str, target: str, session_id: int) -> None:
        holder = self.devices[name].locks.get(target)
        if holder is not None and holder != session_id:
            raise EditError("in-use", f"{target} datastore is locked by session {holder}")

    def edit_config(self, name: str, target: str, config, default_op: str, session_id: int) -> None:
        with self.lock:
            dev = self.devices[name]
            self._check_lock(name, target, session_id)
            current = dev.candidate if target == "candidate" else dev.running
            new = apply_edit(current, config, default_op)
            self.validate(name, new)
            if target == "candidate":
                dev.candidate = new
                return
            dev.running = new
            dev.candidate = copy.deepcopy(new)
        log.info("%s: running config edited directly by session %d", name, session_id)
        self.recompute()

    def lock_ds(self, name: str, target: str, session_id: int) -> None:
        with self.lock:
            dev = self.devices[name]
            holder = dev.locks.get(target)
            if holder is not None and holder != session_id:
                raise EditError("lock-denied", f"lock held by session {holder}")
            if target == "candidate" and session_id != holder and \
                    etree.tostring(dev.candidate) != etree.tostring(dev.running):
                raise EditError("lock-denied", "candidate has uncommitted changes")
            dev.locks[target] = session_id

    def unlock_ds(self, name: str, target: str, session_id: int) -> None:
        with self.lock:
            dev = self.devices[name]
            if dev.locks.get(target) != session_id:
                raise EditError("operation-failed", f"{target} not locked by this session")
            del dev.locks[target]

    def discard_changes(self, name: str) -> None:
        with self.lock:
            dev = self.devices[name]
            dev.candidate = copy.deepcopy(dev.running)

    def validate_ds(self, name: str, source: str) -> None:
        with self.lock:
            self.validate(name, self.get_config(name, source))

    def commit(self, name: str, session_id: int, confirmed: bool, timeout: int) -> None:
        with self.lock:
            dev = self.devices[name]
            self._check_lock(name, "running", session_id)
            self.validate(name, dev.candidate)
            if confirmed:
                if dev.confirm is None:
                    snapshot = copy.deepcopy(dev.running)
                else:
                    dev.confirm.timer.cancel()
                    snapshot = dev.confirm.snapshot
                timer = threading.Timer(timeout, self._confirm_expired, args=(name,))
                timer.daemon = True
                dev.confirm = PendingConfirm(snapshot, session_id, timer)
                timer.start()
                log.info("%s: confirmed commit by session %d (rollback in %ss unless confirmed)",
                         name, session_id, timeout)
            elif dev.confirm is not None:
                dev.confirm.timer.cancel()
                dev.confirm = None
                log.info("%s: confirmed commit confirmed by session %d", name, session_id)
            else:
                log.info("%s: commit by session %d", name, session_id)
            dev.running = copy.deepcopy(dev.candidate)
        self.recompute()

    def cancel_commit(self, name: str) -> None:
        with self.lock:
            dev = self.devices[name]
            if dev.confirm is None:
                raise EditError("operation-failed", "no confirmed commit is in progress")
            self._rollback_confirm(dev, "cancel-commit")
        self.recompute()

    def _rollback_confirm(self, dev: SimDevice, why: str) -> None:
        dev.confirm.timer.cancel()
        dev.running = dev.confirm.snapshot
        dev.candidate = copy.deepcopy(dev.running)
        dev.confirm = None
        log.warning("%s: configuration rolled back (%s)", dev.name, why)

    def _confirm_expired(self, name: str) -> None:
        with self.lock:
            dev = self.devices[name]
            if dev.confirm is None:
                return
            self._rollback_confirm(dev, "confirm timeout expired")
        self.recompute()

    def session_closed(self, name: str, session_id: int) -> None:
        with self.lock:
            dev = self.devices[name]
            held = [k for k, v in dev.locks.items() if v == session_id]
            for ds in held:
                del dev.locks[ds]
            if "candidate" in held and (dev.confirm is None or dev.confirm.session_id != session_id):
                dev.candidate = copy.deepcopy(dev.running)  # RFC 6241 7.5: uncommitted changes discarded
            self.session_closers[name].pop(session_id, None)
            pending = dev.confirm is not None and dev.confirm.session_id == session_id
            if pending:
                self._rollback_confirm(dev, f"session {session_id} closed before confirming")
        if pending:
            self.recompute()

    # ------------------------------------------------------------ device RPCs
    def clear_bgp(self, name: str, neighbor: str) -> None:
        with self.lock:
            if neighbor not in self._bgp_neighbors(self.devices[name].running):
                raise EditError("invalid-value", f"no BGP neighbor {neighbor} on {name}")
            owner = self.topo.owner_of_ip(neighbor)
            local_if = self.topo.interface_for_neighbor(name, neighbor)
            my_ip = str(self.topo.devices[name].interfaces[local_if].ip.ip) if local_if else None
            for fid, f in list(self.faults.items()):
                if f.type == "bgp_stuck" and ((f.device == name and f.neighbor == neighbor) or
                                              (owner and f.device == owner.device and f.neighbor == my_ip)):
                    del self.faults[fid]
                    log.info("fault %s cleared by clear bgp on %s", fid, name)
            until = time.time() + BGP_RESET_SECONDS
            self.resetting[(name, neighbor)] = until
        self.recompute()
        t = threading.Timer(BGP_RESET_SECONDS + 0.1, self.recompute)
        t.daemon = True
        t.start()

    def restart_process(self, name: str, process: str) -> None:
        with self.lock:
            dev = self.devices[name]
            if process not in dev.processes and not any(
                    f.type == "cpu_runaway" and f.device == name and f.process == process for f in self.faults.values()):
                raise EditError("invalid-value", f"no process {process!r} on {name}")
            for fid, f in list(self.faults.items()):
                if f.type == "cpu_runaway" and f.device == name and f.process == process:
                    del self.faults[fid]
                    log.info("fault %s cleared: %s restarted on %s", fid, process, name)
        self.recompute()

    # ------------------------------------------------------------------- power
    def power(self, name: str, action: str) -> dict[str, Any]:
        with self.lock:
            dev = self.devices[name]
            for fid, f in list(self.faults.items()):
                if f.type == "power_off" and f.device == name and action in ("on", "cycle"):
                    del self.faults[fid]
            if action in ("off", "cycle"):
                dev.powered = False
            if dev.confirm is not None:
                dev.confirm.timer.cancel()
                dev.confirm = None
            dev.locks.clear()
            dev.candidate = copy.deepcopy(dev.running)
            booting = action in ("on", "cycle") and not dev.booting and not dev.powered
            if booting:
                dev.booting = True
        self.recompute()
        if booting:
            t = threading.Timer(self.boot_time, self._booted, args=(name,))
            t.daemon = True
            t.start()
        return {"device": name, "action": action, "boot_time": self.boot_time if booting else 0}

    def _booted(self, name: str) -> None:
        with self.lock:
            dev = self.devices[name]
            dev.powered, dev.booting = True, False
        log.info("%s: boot complete", name)
        self.recompute()

    def is_reachable(self, name: str) -> bool:
        with self.lock:
            return self.state[name]["reachable"]

    # ------------------------------------------------------------------ faults
    def inject(self, ftype: str, device: str, interface: str | None = None, neighbor: str | None = None,
               process: str | None = None) -> dict[str, Any]:
        if ftype not in FAULT_TYPES:
            raise ValueError(f"unknown fault type {ftype!r}; valid: {', '.join(FAULT_TYPES)}")
        if device not in self.devices:
            raise ValueError(f"unknown device {device!r}")
        topo_dev = self.topo.devices[device]
        if ftype in ("admin_shutdown", "link_hang", "fiber_cut", "crc_errors"):
            if not interface or interface not in topo_dev.interfaces:
                raise ValueError(f"{ftype} needs a valid interface on {device}: {', '.join(topo_dev.interfaces)}")
        if ftype in ("bgp_stuck", "bgp_neighbor_shutdown"):
            nbrs = self._bgp_neighbors(self.devices[device].running)
            if not neighbor or neighbor not in nbrs:
                raise ValueError(f"{ftype} needs a BGP neighbor of {device}: {', '.join(nbrs)}")

        if ftype == "admin_shutdown":
            self._config_change(device, f'<interfaces xmlns="{IF_NS}"><interface><name>{interface}</name>'
                                        f'<enabled>false</enabled></interface></interfaces>')
            return {"applied": "config-change", "type": ftype, "device": device, "interface": interface}
        if ftype == "bgp_neighbor_shutdown":
            self._config_change(device, f'<routing xmlns="{RT_NS}"><bgp><neighbor><address>{neighbor}</address>'
                                        f'<enabled>false</enabled></neighbor></bgp></routing>')
            return {"applied": "config-change", "type": ftype, "device": device, "neighbor": neighbor}
        if ftype == "power_off":
            fault = Fault(f"f{next(self._ids)}", ftype, device)
            with self.lock:
                self.faults[fault.id] = fault
            self.power(device, "off")
            return fault.as_dict()

        fault = Fault(f"f{next(self._ids)}", ftype, device, interface, neighbor,
                      process or ("telemetryd" if ftype == "cpu_runaway" else None))
        if interface:
            link = self.topo.link_at(device, interface)
            fault.link_id = link.id if link else None
        with self.lock:
            self.faults[fault.id] = fault
        log.info("fault injected: %s", fault.as_dict())
        self.recompute()
        return fault.as_dict()

    def _config_change(self, device: str, inner: str) -> None:
        cfg = etree.fromstring(f'<config xmlns="{NC_NS}">{inner}</config>')
        with self.lock:
            dev = self.devices[device]
            dev.running = apply_edit(dev.running, cfg)
            dev.candidate = copy.deepcopy(dev.running)
        log.info("config change on %s (simulated operator action)", device)
        self.recompute()

    def repair(self, fault_id: str) -> dict[str, Any]:
        with self.lock:
            fault = self.faults.get(fault_id)
            if fault is None:
                raise KeyError(fault_id)
            if fault.type == "power_off":
                pass
            else:
                del self.faults[fault_id]
        if fault.type == "power_off":
            self.power(fault.device, "on")
        else:
            self.recompute()
        return {"repaired": fault.as_dict()}

    def list_faults(self) -> list[dict[str, Any]]:
        with self.lock:
            return [f.as_dict() for f in self.faults.values()]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.state)
