"""Network topology / source of truth.

The topology answers the questions root cause analysis needs: which interface is at
the other end of a link, which link a BGP session rides on, which devices lose
management reachability when a node fails. It also stores intent (whether an
interface *should* be enabled), which the platform uses to tell drift from design.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import networkx as nx

from autoheal.config import load_yaml
from autoheal.models import INTERFACE_ALARMS, Alarm, AlarmType


@dataclass
class Interface:
    name: str
    ip: ipaddress.IPv4Interface | None = None
    description: str = ""
    intended_enabled: bool = True
    ospf: bool = True
    ospf_cost: int = 10


@dataclass
class Device:
    name: str
    host: str = "127.0.0.1"
    netconf_port: int = 830
    vendor: str = "sim"
    role: str = ""
    asn: int | None = None
    restconf_url: str | None = None
    pdu_outlet: str | None = None
    position: tuple[float, float] | None = None
    tags: list[str] = field(default_factory=list)
    interfaces: dict[str, Interface] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "netconf_port": self.netconf_port,
            "vendor": self.vendor,
            "role": self.role,
            "asn": self.asn,
            "restconf_url": self.restconf_url,
            "pdu_outlet": self.pdu_outlet,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class Endpoint:
    device: str
    interface: str

    def __str__(self) -> str:
        return f"{self.device}:{self.interface}"


@dataclass(frozen=True)
class Link:
    a: Endpoint
    b: Endpoint

    @property
    def id(self) -> str:
        return "--".join(sorted([str(self.a), str(self.b)]))

    def other(self, ep: Endpoint) -> Endpoint:
        return self.b if ep == self.a else self.a

    def devices(self) -> tuple[str, str]:
        return self.a.device, self.b.device


class Topology:
    def __init__(self, devices: dict[str, Device], links: list[Link], mgmt_root: str | None = None):
        self.devices = devices
        self.links = links
        self.mgmt_root = mgmt_root or (next(iter(devices)) if devices else None)
        self._by_endpoint: dict[Endpoint, Link] = {}
        for link in links:
            for ep in (link.a, link.b):
                if ep.device not in devices:
                    raise ValueError(f"link {link.id} references unknown device {ep.device}")
                devices[ep.device].interfaces.setdefault(ep.interface, Interface(ep.interface))
                self._by_endpoint[ep] = link
        self.graph = nx.MultiGraph()
        self.graph.add_nodes_from(devices)
        for link in links:
            self.graph.add_edge(link.a.device, link.b.device, key=link.id)

    # ----------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: str | Path) -> "Topology":
        return cls.from_dict(load_yaml(path))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Topology":
        devices: dict[str, Device] = {}
        for name, d in (data.get("devices") or {}).items():
            d = d or {}
            ifaces = {}
            for iname, idata in (d.get("interfaces") or {}).items():
                idata = idata or {}
                ifaces[iname] = Interface(
                    name=iname,
                    ip=ipaddress.IPv4Interface(idata["ip"]) if idata.get("ip") else None,
                    description=idata.get("description", ""),
                    intended_enabled=bool(idata.get("enabled", True)),
                    ospf=bool(idata.get("ospf", True)),
                    ospf_cost=int(idata.get("ospf_cost", 10)),
                )
            pos = d.get("position")
            devices[name] = Device(
                name=name,
                host=str(d.get("host", "127.0.0.1")),
                netconf_port=int(d.get("netconf_port", 830)),
                vendor=d.get("vendor", "sim"),
                role=d.get("role", ""),
                asn=d.get("asn"),
                restconf_url=d.get("restconf_url"),
                pdu_outlet=str(d["pdu_outlet"]) if d.get("pdu_outlet") is not None else None,
                position=(float(pos[0]), float(pos[1])) if pos else None,
                tags=list(d.get("tags") or []),
                interfaces=ifaces,
            )
        links = []
        for entry in data.get("links") or []:
            a, b = (entry["a"], entry["b"]) if isinstance(entry, dict) else entry
            links.append(Link(_parse_ep(a), _parse_ep(b)))
        return cls(devices, links, data.get("mgmt_root"))

    # ----------------------------------------------------------------- queries
    def link_at(self, device: str, interface: str) -> Link | None:
        return self._by_endpoint.get(Endpoint(device, interface))

    def peer(self, device: str, interface: str) -> Endpoint | None:
        link = self.link_at(device, interface)
        return link.other(Endpoint(device, interface)) if link else None

    def owner_of_ip(self, ip: str) -> Endpoint | None:
        addr = ipaddress.IPv4Address(ip)
        for dev in self.devices.values():
            for iface in dev.interfaces.values():
                if iface.ip is not None and iface.ip.ip == addr:
                    return Endpoint(dev.name, iface.name)
        return None

    def interface_for_neighbor(self, device: str, neighbor_ip: str) -> str | None:
        """Local interface on ``device`` sharing a subnet with ``neighbor_ip``."""
        try:
            addr = ipaddress.IPv4Address(neighbor_ip)
        except ValueError:
            return None
        dev = self.devices.get(device)
        if not dev:
            return None
        for iface in dev.interfaces.values():
            if iface.ip is not None and addr in iface.ip.network and addr != iface.ip.ip:
                return iface.name
        return None

    def link_of_alarm(self, alarm: Alarm) -> Link | None:
        if alarm.type in INTERFACE_ALARMS:
            return self.link_at(alarm.device, alarm.resource)
        if alarm.type == AlarmType.BGP_SESSION_DOWN:
            iface = self.interface_for_neighbor(alarm.device, alarm.resource)
            return self.link_at(alarm.device, iface) if iface else None
        return None

    def peer_device_of_alarm(self, alarm: Alarm) -> str | None:
        link = self.link_of_alarm(alarm)
        if link:
            a, b = link.devices()
            return b if a == alarm.device else a
        if alarm.type == AlarmType.BGP_SESSION_DOWN:
            owner = self.owner_of_ip(alarm.resource) if _is_ip(alarm.resource) else None
            return owner.device if owner else None
        return None

    def neighbors(self, device: str) -> set[str]:
        return set(self.graph.neighbors(device)) if device in self.graph else set()

    def downstream(self, device: str) -> set[str]:
        """Devices that lose their path to the management root if ``device`` fails."""
        if device not in self.graph or not self.mgmt_root:
            return set()
        if device == self.mgmt_root:
            return set(self.devices) - {device}
        g = self.graph.copy()
        g.remove_node(device)
        return set(g.nodes) - nx.node_connected_component(g, self.mgmt_root)

    def isolated_by_link(self, link: Link) -> set[str]:
        """Devices that lose their path to the management root if ``link`` fails."""
        if not self.mgmt_root:
            return set()
        g = self.graph.copy()
        g.remove_edge(link.a.device, link.b.device, key=link.id)
        return set(g.nodes) - nx.node_connected_component(g, self.mgmt_root)

    def context_for(self, device: str, resource: str, alarm_type: AlarmType) -> dict[str, Any]:
        """Template variables derived from topology for an alarm on device/resource."""
        ctx: dict[str, Any] = {"device": device, "interface": None, "neighbor": None,
                               "peer_device": None, "peer_interface": None}
        dev = self.devices.get(device)
        ctx["device_info"] = dev.as_dict() if dev else {"name": device}
        if alarm_type in INTERFACE_ALARMS:
            ctx["interface"] = resource
        elif alarm_type == AlarmType.BGP_SESSION_DOWN:
            ctx["neighbor"] = resource
            ctx["interface"] = self.interface_for_neighbor(device, resource)
        if ctx["interface"]:
            peer = self.peer(device, ctx["interface"])
            if peer:
                ctx["peer_device"], ctx["peer_interface"] = peer.device, peer.interface
                pdev = self.devices[peer.device].interfaces.get(peer.interface)
                if pdev and pdev.ip is not None:
                    ctx["peer_ip"] = str(pdev.ip.ip)
            iface = dev.interfaces.get(ctx["interface"]) if dev else None
            if iface and iface.ip is not None:
                ctx["local_ip"] = str(iface.ip.ip)
            ctx["intent"] = {"enabled": iface.intended_enabled if iface else True,
                             "ospf_cost": iface.ospf_cost if iface else 10}
        else:
            ctx["intent"] = {}
        return ctx

    def to_dict(self) -> dict[str, Any]:
        return {
            "mgmt_root": self.mgmt_root,
            "devices": [
                {**d.as_dict(), "position": list(d.position) if d.position else None,
                 "interfaces": [{"name": i.name, "ip": str(i.ip) if i.ip else None,
                                 "description": i.description, "enabled": i.intended_enabled}
                                for i in d.interfaces.values()]}
                for d in self.devices.values()
            ],
            "links": [{"id": l.id, "a": str(l.a), "b": str(l.b)} for l in self.links],
        }

    def iter_interfaces(self) -> Iterable[tuple[Device, Interface]]:
        for dev in self.devices.values():
            for iface in dev.interfaces.values():
                yield dev, iface


def _parse_ep(text: str) -> Endpoint:
    device, _, interface = str(text).partition(":")
    if not interface:
        raise ValueError(f"link endpoint must be 'device:interface', got {text!r}")
    return Endpoint(device, interface)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False
