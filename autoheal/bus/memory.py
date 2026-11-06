"""In-process bus with Kafka-like semantics: every consumer group sees every message,
messages within a group are delivered sequentially and in order."""

from __future__ import annotations

import asyncio
import copy
import logging
from typing import Any

from autoheal.bus import Bus, Subscription

log = logging.getLogger(__name__)


class MemoryBus(Bus):
    def __init__(self, settings):
        super().__init__(settings)
        self._queues: list[tuple[Subscription, asyncio.Queue]] = []
        self._tasks: list[asyncio.Task] = []
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._started = False

    async def start(self) -> None:
        for sub in self._subs:
            q: asyncio.Queue = asyncio.Queue()
            if sub.from_beginning:
                for topic in sub.topics:
                    for msg in self._history.get(topic, []):
                        q.put_nowait((topic, copy.deepcopy(msg)))
            self._queues.append((sub, q))
            self._tasks.append(asyncio.create_task(self._consume(sub, q), name=f"bus:{sub.group}"))
        self._started = True

    async def _consume(self, sub: Subscription, q: asyncio.Queue) -> None:
        while True:
            topic, msg = await q.get()
            try:
                await sub.handler(topic, msg)
            except Exception:  # a bad message must not kill the consumer
                log.exception("handler %s failed on %s message", sub.group, topic)
            finally:
                q.task_done()

    async def _publish(self, topic: str, data: dict[str, Any], key: str | None) -> None:
        self._history.setdefault(topic, []).append(data)
        for sub, q in self._queues:
            if topic in sub.topics:
                q.put_nowait((topic, copy.deepcopy(data)))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
