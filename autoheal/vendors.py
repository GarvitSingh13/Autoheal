"""Vendor profiles.

Playbooks are vendor-neutral: they reference template, RPC and probe *names*. A vendor
profile (``config/vendors/<vendor>.yaml``) maps those names to the device's actual
YANG payloads (NETCONF XML) and state paths (subtree filter + XPath, or RESTCONF path).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from autoheal.config import load_yaml

_env = Environment(undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True, autoescape=False)


def render(template: str, ctx: dict[str, Any]) -> str:
    return _env.from_string(template).render(**ctx).strip()


def render_obj(obj: Any, ctx: dict[str, Any]) -> Any:
    """Render every string inside a JSON-like structure."""
    if isinstance(obj, str):
        return render(obj, ctx)
    if isinstance(obj, list):
        return [render_obj(v, ctx) for v in obj]
    if isinstance(obj, dict):
        return {render(k, ctx): render_obj(v, ctx) for k, v in obj.items()}
    return obj


@dataclass
class Probe:
    name: str
    kind: str  # netconf_get | netconf_get_config | restconf_get | builtin
    filter: str | None = None
    xpath: str | None = None
    path: str | None = None
    json_path: str | None = None


@dataclass
class VendorProfile:
    name: str
    namespaces: dict[str, str] = field(default_factory=dict)
    templates: dict[str, str] = field(default_factory=dict)
    rpcs: dict[str, str] = field(default_factory=dict)
    probes: dict[str, Probe] = field(default_factory=dict)

    def config(self, name: str, ctx: dict[str, Any]) -> str:
        if name not in self.templates:
            raise KeyError(f"vendor '{self.name}' has no config template '{name}'")
        return render(self.templates[name], ctx)

    def rpc(self, name: str, ctx: dict[str, Any]) -> str:
        if name not in self.rpcs:
            raise KeyError(f"vendor '{self.name}' has no rpc '{name}'")
        return render(self.rpcs[name], ctx)

    def probe(self, name: str) -> Probe:
        if name == "device_reachable":
            return Probe(name, "builtin")
        if name not in self.probes:
            raise KeyError(f"vendor '{self.name}' has no probe '{name}'")
        return self.probes[name]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VendorProfile":
        probes = {}
        for pname, p in (data.get("probes") or {}).items():
            (kind, spec), = p.items()
            probes[pname] = Probe(name=pname, kind=kind, **spec)
        return cls(
            name=data["name"],
            namespaces=data.get("namespaces") or {},
            templates=data.get("templates") or {},
            rpcs=data.get("rpcs") or {},
            probes=probes,
        )


def load_vendors(directory: str | Path) -> dict[str, VendorProfile]:
    profiles = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        prof = VendorProfile.from_dict(load_yaml(path))
        profiles[prof.name] = prof
    return profiles
