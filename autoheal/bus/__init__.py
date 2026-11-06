"""Event bus abstraction.

Production deployments use Kafka (:class:`KafkaBus`). The in-memory backend
(:class:`MemoryBus`) runs everything in one process for demos and tests.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from pydantic import BaseModel

from autoheal.config import BusSettings

log = logging.getLogger(__name__)

Handler = Callable[[str, dict[str, Any]], Awaitable[None]]


class Topics:
    """Logical topic names; the physical Kafka topic is ``<prefix>.<name>``."""

    ALARMS = "alarms"  # normalized Alarm events (raise + clear), key = device
    INCIDENTS = "incidents"  # Incident snapshots published by RCA, key = incident id
    REMEDIATIONS = "remediations"  # Remediation snapshots published by the remediator
    COMMANDS = "commands"  # operator commands (approve / reject)

    ALL = (ALARMS, INCIDENTS, REMEDIATIONS, COMMANDS)


@dataclass
class Subscription:
    topics: list[str]
    handler: Handler
    group: str
    from_beginning: bool = False


class Bus(abc.ABC):
    def __init__(self, settings: BusSettings):
        self.settings = settings
        self._subs: list[Subscription] = []

    def subscribe(self, topics: list[str], handler: Handler, group: str, from_beginning: bool = False) -> None:
        """Register a handler. Must be called before :meth:`start`."""
        self._subs.append(Subscription(list(topics), handler, group, from_beginning))

    async def publish(self, topic: str, payload: BaseModel | dict[str, Any], key: str | None = None) -> None:
        data = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
        await self._publish(topic, data, key)

    @abc.abstractmethod
    async def _publish(self, topic: str, data: dict[str, Any], key: str | None) -> None: ...

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...


def create_bus(settings: BusSettings) -> Bus:
    if settings.backend == "memory":
        from autoheal.bus.memory import MemoryBus

        return MemoryBus(settings)
    from autoheal.bus.kafka import KafkaBus

    return KafkaBus(settings)
