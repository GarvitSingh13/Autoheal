"""Lab simulator process: NETCONF servers for every device + an HTTP API exposing

* ``/faults``                       fault injection (the "chaos" console)
* ``/devices/{dev}/restconf/...``   per-device RESTCONF (RFC 8040-style JSON)
* ``/pdu/outlets/...``              out-of-band smart PDU (power control)
* ``/state``                        computed network state (debugging)
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from typing import Any

import paramiko
import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from autoheal.topology import Topology
from simulator.datastore import EditError
from simulator.netconf_server import NetconfServer
from simulator.network import FAULT_TYPES, Network

log = logging.getLogger("simulator")
basic = HTTPBasic()


def create_sim_api(net: Network, username: str = "admin", password: str = "admin") -> FastAPI:
    app = FastAPI(title="autoheal lab network simulator")

    def auth(creds: HTTPBasicCredentials = Depends(basic)) -> None:
        if not (secrets.compare_digest(creds.username, username) and secrets.compare_digest(creds.password, password)):
            raise HTTPException(401, "bad credentials", headers={"WWW-Authenticate": "Basic"})

    def device_up(dev: str) -> None:
        if dev not in net.devices:
            raise HTTPException(404, f"unknown device {dev}")
        if not net.is_reachable(dev):
            raise HTTPException(503, f"{dev} is not reachable")

    # -------------------------------------------------------------- faults
    @app.get("/health")
    def health():
        return {"status": "ok", "devices": len(net.devices), "events_emitted": net.events_emitted}

    @app.get("/faults")
    def faults():
        return {"active": net.list_faults(), "catalog": FAULT_TYPES,
                "devices": {name: {"interfaces": list(d.interfaces), "neighbors": [
                    str(net.topo.devices[p.device].interfaces[p.interface].ip.ip)
                    for i in d.interfaces if (p := net.topo.peer(name, i)) is not None
                    and net.topo.devices[p.device].interfaces[p.interface].ip is not None]}
                    for name, d in net.topo.devices.items()}}

    @app.post("/faults")
    def inject(body: dict[str, Any] = Body(...)):
        try:
            return net.inject(body.get("type", ""), body.get("device", ""), body.get("interface"),
                              body.get("neighbor"), body.get("process"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.delete("/faults/{fault_id}")
    def repair(fault_id: str):
        try:
            return net.repair(fault_id)
        except KeyError:
            raise HTTPException(404, f"no active fault {fault_id}")

    @app.get("/state")
    def state():
        return net.snapshot()

    # ------------------------------------------------------------ RESTCONF
    @app.get("/devices/{dev}/restconf/data/autoheal-sim-system:system-state", dependencies=[Depends(auth)])
    def system_state(dev: str):
        device_up(dev)
        st = net.snapshot()[dev]
        return {"autoheal-sim-system:system-state": {
            "cpu-utilization": st["cpu"],
            "process": [{"name": n, "cpu": c} for n, c in st["processes"].items()]}}

    @app.get("/devices/{dev}/restconf/data/ietf-interfaces:interfaces", dependencies=[Depends(auth)])
    def interfaces(dev: str):
        device_up(dev)
        st = net.snapshot()[dev]
        return {"ietf-interfaces:interfaces": {"interface": [
            {"name": n, "enabled": s["admin"] == "up", "admin-status": s["admin"], "oper-status": s["oper"]}
            for n, s in st["ifaces"].items()]}}

    @app.post("/devices/{dev}/restconf/operations/autoheal-sim-ops:restart-process",
              dependencies=[Depends(auth)], status_code=204)
    def restart_process(dev: str, body: dict[str, Any] = Body(...)):
        device_up(dev)
        name = (body.get("input") or {}).get("name") or ""
        try:
            net.restart_process(dev, name)
        except EditError as exc:
            raise HTTPException(400, exc.message)
        return Response(status_code=204)

    @app.post("/devices/{dev}/restconf/operations/autoheal-sim-ops:clear-bgp-neighbor",
              dependencies=[Depends(auth)], status_code=204)
    def clear_bgp(dev: str, body: dict[str, Any] = Body(...)):
        device_up(dev)
        try:
            net.clear_bgp(dev, (body.get("input") or {}).get("address") or "")
        except EditError as exc:
            raise HTTPException(400, exc.message)
        return Response(status_code=204)

    # ----------------------------------------------------------------- PDU
    def outlet_device(outlet: str) -> str:
        for name, d in net.topo.devices.items():
            if d.pdu_outlet == outlet:
                return name
        raise HTTPException(404, f"no device on outlet {outlet}")

    @app.get("/pdu/outlets", dependencies=[Depends(auth)])
    def outlets():
        snap = net.snapshot()
        return [{"outlet": d.pdu_outlet, "device": n, "powered": snap[n]["powered"]}
                for n, d in net.topo.devices.items() if d.pdu_outlet]

    @app.get("/pdu/outlets/{outlet}", dependencies=[Depends(auth)])
    def outlet(outlet: str):
        dev = outlet_device(outlet)
        return {"outlet": outlet, "device": dev, "powered": net.snapshot()[dev]["powered"]}

    @app.post("/pdu/outlets/{outlet}/{action}", dependencies=[Depends(auth)], status_code=202)
    def power(outlet: str, action: str):
        if action not in ("on", "off", "cycle"):
            raise HTTPException(400, "action must be on|off|cycle")
        return net.power(outlet_device(outlet), action)

    return app


class Simulator:
    """Embeddable simulator (used by ``autoheal sim`` and by the integration tests)."""

    def __init__(self, topology: Topology, host: str = "0.0.0.0", api_port: int = 8300, boot_time: float = 5.0,
                 username: str = "admin", password: str = "admin"):
        self.net = Network(topology, boot_time)
        self.host, self.api_port = host, api_port
        key = paramiko.RSAKey.generate(2048)
        self.servers = [NetconfServer(self.net, name, host, dev.netconf_port, key, username, password)
                        for name, dev in topology.devices.items()]
        self.app = create_sim_api(self.net, username, password)
        self._uvicorn: uvicorn.Server | None = None

    def start(self, background_api: bool = True) -> None:
        for s in self.servers:
            s.start()
        config = uvicorn.Config(self.app, host=self.host, port=self.api_port, log_level="warning")
        self._uvicorn = uvicorn.Server(config)
        if background_api:
            threading.Thread(target=self._uvicorn.run, daemon=True, name="sim-api").start()
            for _ in range(100):
                if self._uvicorn.started:
                    break
                time.sleep(0.05)
        else:
            log.info("simulator API on http://%s:%d", self.host, self.api_port)
            self._uvicorn.run()

    def stop(self) -> None:
        for s in self.servers:
            s.stop()
        if self._uvicorn:
            self._uvicorn.should_exit = True


def main(topology_path: str, host: str, api_port: int, boot_time: float) -> None:
    sim = Simulator(Topology.load(topology_path), host, api_port, boot_time)
    log.info("simulating %d devices, %d links", len(sim.net.devices), len(sim.net.topo.links))
    sim.start(background_api=False)
    sim.stop()
