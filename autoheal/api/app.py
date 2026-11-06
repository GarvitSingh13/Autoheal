"""REST API + dashboard.

* Ingest: ``POST /api/alarms`` (generic JSON) and ``POST /api/alarms/alertmanager``
  (Prometheus Alertmanager webhook) publish to the ``alarms`` topic.
* Read model: incidents, remediations, alarms, topology with live status, summary KPIs.
* Control: approve / reject remediations awaiting approval (published to ``commands``).
* Lab: proxy to the network simulator's fault-injection API when configured.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

import httpx
from fastapi import Body, FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from autoheal import __version__
from autoheal.bus import Bus, Topics
from autoheal.config import Settings
from autoheal.models import Alarm, AlarmType, Command, Severity
from autoheal.store import Store
from autoheal.topology import Topology

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"


class AlarmIn(BaseModel):
    device: str
    type: AlarmType = AlarmType.GENERIC
    resource: str = ""
    severity: Severity = Severity.MAJOR
    message: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    source: str = "rest"


class Decision(BaseModel):
    user: str = "operator"
    comment: str = ""


# Alertmanager alertname -> alarm type, for rules that don't set an explicit alarm_type label.
ALERTNAME_MAP = {
    "interfacedown": AlarmType.LINK_DOWN,
    "linkdown": AlarmType.LINK_DOWN,
    "interfaceadmindown": AlarmType.INTERFACE_ADMIN_DOWN,
    "bgpsessiondown": AlarmType.BGP_SESSION_DOWN,
    "bgppeerdown": AlarmType.BGP_SESSION_DOWN,
    "ospfneighbordown": AlarmType.OSPF_NEIGHBOR_DOWN,
    "highcpu": AlarmType.HIGH_CPU,
    "cpuhigh": AlarmType.HIGH_CPU,
    "interfaceerrors": AlarmType.HIGH_ERROR_RATE,
    "higherrorrate": AlarmType.HIGH_ERROR_RATE,
    "targetdown": AlarmType.DEVICE_UNREACHABLE,
    "deviceunreachable": AlarmType.DEVICE_UNREACHABLE,
}


def alertmanager_to_alarms(payload: dict[str, Any]) -> list[Alarm]:
    out = []
    for a in payload.get("alerts") or []:
        labels, ann = a.get("labels") or {}, a.get("annotations") or {}
        device = labels.get("device") or labels.get("instance", "").split(":")[0]
        if not device:
            continue
        explicit = labels.get("alarm_type")
        atype = AlarmType(explicit) if explicit in AlarmType.__members__ else \
            ALERTNAME_MAP.get(labels.get("alertname", "").lower().replace("_", ""), AlarmType.GENERIC)
        resource = labels.get("resource") or labels.get("interface") or labels.get("neighbor") or \
            ("mgmt" if atype == AlarmType.DEVICE_UNREACHABLE else "cpu" if atype == AlarmType.HIGH_CPU else "")
        sev = labels.get("severity", "major").lower()
        severity = Severity.CLEAR if a.get("status") == "resolved" else \
            (Severity(sev) if sev in Severity._value2member_map_ else Severity.MAJOR)
        out.append(Alarm(source="alertmanager", device=device, type=atype, resource=resource, severity=severity,
                         message=ann.get("summary") or ann.get("description") or labels.get("alertname", ""),
                         attributes={k: v for k, v in labels.items()
                                     if k not in ("device", "instance", "severity", "alarm_type")}))
    return out


def create_api(settings: Settings, bus: Bus, store: Store, topology: Topology,
               status_fn: Callable[[], dict[str, Any]] | None = None) -> FastAPI:
    app = FastAPI(title="Autonomous Network Healing Platform", version=__version__)

    # ----------------------------------------------------------------- ingest
    @app.post("/api/alarms", status_code=202, tags=["ingest"])
    async def ingest_alarm(body: AlarmIn | list[AlarmIn]):
        items = body if isinstance(body, list) else [body]
        for item in items:
            await bus.publish(Topics.ALARMS, Alarm(**item.model_dump()), key=item.device)
        return {"accepted": len(items)}

    @app.post("/api/alarms/alertmanager", status_code=202, tags=["ingest"])
    async def ingest_alertmanager(payload: dict[str, Any] = Body(...)):
        alarms = alertmanager_to_alarms(payload)
        for alarm in alarms:
            await bus.publish(Topics.ALARMS, alarm, key=alarm.device)
        return {"accepted": len(alarms)}

    # ------------------------------------------------------------------ reads
    @app.get("/api/health", tags=["ops"])
    async def health():
        return {"status": "ok", "version": __version__, "bus": settings.bus.backend,
                "mode": settings.remediation.mode, "components": status_fn() if status_fn else {}}

    @app.get("/api/summary", tags=["read"])
    async def summary():
        return {**store.summary(), "mode": settings.remediation.mode}

    @app.get("/api/alarms", tags=["read"])
    async def list_alarms(active: bool = True, limit: int = Query(500, le=5000)):
        return store.alarms(active_only=active, limit=limit)

    @app.get("/api/alarms/log", tags=["read"])
    async def alarm_log(limit: int = Query(200, le=5000)):
        return store.alarm_log(limit)

    @app.get("/api/incidents", tags=["read"])
    async def list_incidents(status: str | None = None, limit: int = Query(200, le=2000)):
        incidents = store.incidents(status, limit)
        for inc in incidents:
            inc["remediation"] = store.remediation_for(inc["id"])
        return incidents

    @app.get("/api/incidents/{inc_id}", tags=["read"])
    async def get_incident(inc_id: str):
        inc = store.incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        inc["remediation"] = store.remediation_for(inc_id)
        return inc

    @app.get("/api/remediations", tags=["read"])
    async def list_remediations(status: str | None = None, limit: int = Query(200, le=2000)):
        return store.remediations(status, limit)

    @app.get("/api/remediations/{rem_id}", tags=["read"])
    async def get_remediation(rem_id: str):
        rem = store.remediation(rem_id)
        if not rem:
            raise HTTPException(404, "remediation not found")
        return rem

    @app.get("/api/topology", tags=["read"])
    async def get_topology():
        return topology_status(topology, store.alarms(active_only=True, limit=5000))

    # ---------------------------------------------------------------- control
    async def _decide(rem_id: str, command: str, decision: Decision):
        rem = store.remediation(rem_id)
        if not rem:
            raise HTTPException(404, "remediation not found")
        if rem["status"] != "pending_approval":
            raise HTTPException(409, f"remediation is {rem['status']}, not pending_approval")
        cmd = Command(command=command, remediation_id=rem_id, user=decision.user, comment=decision.comment)
        await bus.publish(Topics.COMMANDS, cmd, key=rem["incident_id"])
        return {"submitted": command, "remediation_id": rem_id}

    @app.post("/api/remediations/{rem_id}/approve", status_code=202, tags=["control"])
    async def approve(rem_id: str, decision: Decision = Body(default_factory=Decision)):
        return await _decide(rem_id, "approve", decision)

    @app.post("/api/remediations/{rem_id}/reject", status_code=202, tags=["control"])
    async def reject(rem_id: str, decision: Decision = Body(default_factory=Decision)):
        return await _decide(rem_id, "reject", decision)

    # -------------------------------------------------------------------- lab
    async def _lab(method: str, path: str, json: Any = None):
        if not settings.lab.simulator_url:
            raise HTTPException(404, "lab simulator not configured (settings.lab.simulator_url)")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.request(method, settings.lab.simulator_url.rstrip("/") + path, json=json)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"simulator unreachable: {exc}")
        if r.status_code >= 400:
            raise HTTPException(r.status_code, r.json().get("detail", r.text) if r.content else r.reason_phrase)
        return r.json()

    @app.get("/api/lab/faults", tags=["lab"])
    async def lab_faults():
        return await _lab("GET", "/faults")

    @app.post("/api/lab/faults", tags=["lab"])
    async def lab_inject(fault: dict[str, Any] = Body(...)):
        return await _lab("POST", "/faults", fault)

    @app.delete("/api/lab/faults/{fault_id}", tags=["lab"])
    async def lab_repair(fault_id: str):
        return await _lab("DELETE", f"/faults/{fault_id}")

    # ------------------------------------------------------------------- misc
    @app.get("/metrics", tags=["ops"])
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    return app


def topology_status(topology: Topology, active_alarms: list[dict[str, Any]]) -> dict[str, Any]:
    data = topology.to_dict()
    by_device: dict[str, list[dict]] = {}
    for a in active_alarms:
        if a["type"] == "INTERFACE_ADMIN_DOWN":
            dev = topology.devices.get(a["device"])
            iface = dev.interfaces.get(a["resource"]) if dev else None
            if iface is not None and not iface.intended_enabled:
                continue  # shut by design (e.g. a spare port): not a problem

        by_device.setdefault(a["device"], []).append(a)
    for dev in data["devices"]:
        alarms = by_device.get(dev["name"], [])
        types = {a["type"] for a in alarms}
        dev["status"] = ("unreachable" if "DEVICE_UNREACHABLE" in types else
                         "degraded" if alarms else "ok")
        dev["alarm_count"] = len(alarms)
    for link in data["links"]:
        status = "up"
        for end in (link["a"], link["b"]):
            device, _, iface = end.partition(":")
            for a in by_device.get(device, []):
                if a["resource"] != iface:
                    continue
                if a["type"] in ("LINK_DOWN", "INTERFACE_ADMIN_DOWN"):
                    status = "down"
                elif a["type"] == "HIGH_ERROR_RATE" and status == "up":
                    status = "degraded"
        for end in (link["a"], link["b"]):
            device = end.partition(":")[0]
            if any(a["type"] == "DEVICE_UNREACHABLE" for a in by_device.get(device, [])):
                status = "down"
        link["status"] = status
    return data
