"""Remediation service: consumes ``incidents`` + ``commands``, publishes ``remediations``."""

from __future__ import annotations

from autoheal.bus import Bus, Topics
from autoheal.config import Settings
from autoheal.models import Command, Incident, Remediation
from autoheal.remediation.engine import RemediationEngine
from autoheal.remediation.playbooks import load_playbooks
from autoheal.topology import Topology
from autoheal.vendors import load_vendors


class RemediationService:
    def __init__(self, settings: Settings, bus: Bus, topology: Topology):
        self.bus = bus
        self.engine = RemediationEngine(
            settings,
            topology,
            load_playbooks(settings.paths.playbooks),
            load_vendors(settings.paths.vendors_dir),
            self._publish,
        )
        bus.subscribe([Topics.INCIDENTS, Topics.COMMANDS], self._on_message, group="remediator")

    async def _publish(self, rem: Remediation) -> None:
        await self.bus.publish(Topics.REMEDIATIONS, rem, key=rem.incident_id)

    async def _on_message(self, topic: str, data: dict) -> None:
        if topic == Topics.INCIDENTS:
            await self.engine.handle_incident(Incident.model_validate(data))
        elif topic == Topics.COMMANDS:
            await self.engine.handle_command(Command.model_validate(data))

    async def stop(self) -> None:
        await self.engine.shutdown()
