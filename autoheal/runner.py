"""Process assembly: run any subset of components in one process.

``all`` runs collector + rca + remediator + api together (single host / demo). In a
distributed deployment run each component as its own process; they only share Kafka.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

import uvicorn

from autoheal.bus import create_bus
from autoheal.config import Settings
from autoheal.topology import Topology

log = logging.getLogger(__name__)

COMPONENTS = ("collector", "rca", "remediator", "api")


class Platform:
    """Wires components to a bus. Construct, then ``await start()`` / ``await stop()``."""

    def __init__(self, settings: Settings, components: set[str]):
        unknown = components - set(COMPONENTS)
        if unknown:
            raise ValueError(f"unknown component(s): {', '.join(sorted(unknown))}")
        self.settings = settings
        self.components = components
        self.topology = Topology.load(settings.paths.topology)
        self.bus = create_bus(settings.bus)
        self.rca = self.remediator = self.collector = self.store = self.app = None

        if "rca" in components:
            from autoheal.rca.service import RcaService

            self.rca = RcaService(settings, self.bus, self.topology)
        if "remediator" in components:
            from autoheal.remediation.service import RemediationService

            self.remediator = RemediationService(settings, self.bus, self.topology)
        if "api" in components:
            from autoheal.api.app import create_api
            from autoheal.api.projector import Projector
            from autoheal.store import Store

            self.store = Store(settings.api.db_path)
            Projector(self.store, self.bus)
            self.app = create_api(settings, self.bus, self.store, self.topology, self.status)
        if "collector" in components:
            from autoheal.collector.netconf_listener import NetconfCollector

            self.collector = NetconfCollector(settings, self.bus, self.topology)

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"running": sorted(self.components)}
        if self.collector:
            out["collector"] = self.collector.status()
        if self.rca:
            eng = self.rca.engine
            out["rca"] = {**eng.stats, "active_alarms": len(eng.active), "open_incidents": len(eng.incidents)}
        return out

    async def start(self) -> None:
        await self.bus.start()
        if self.collector:
            await self.collector.start()
        log.info("platform started: %s (bus=%s, remediation mode=%s)", ", ".join(sorted(self.components)),
                 self.settings.bus.backend, self.settings.remediation.mode)

    async def stop(self) -> None:
        if self.collector:
            await self.collector.stop()
        if self.remediator:
            await self.remediator.stop()
        await self.bus.stop()


async def run(settings: Settings, components: set[str]) -> None:
    platform = Platform(settings, components)
    await platform.start()
    try:
        if platform.app is not None:
            server = uvicorn.Server(uvicorn.Config(platform.app, host=settings.api.host, port=settings.api.port,
                                                   log_level=settings.log_level.lower(), access_log=False))
            log.info("API/dashboard on http://%s:%d", settings.api.host, settings.api.port)
            await server.serve()
        else:
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
            await stop.wait()
    finally:
        await platform.stop()
