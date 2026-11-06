"""Kafka bus built on aiokafka.

* Producer: idempotent, ``acks=all``, JSON values, string keys (keys keep all events of a
  device / incident on one partition, preserving order).
* Consumers: one consumer per subscription, offsets committed only after the handler
  succeeds (at-least-once). Handlers are idempotent (snapshots carry a ``version``).
* ``from_beginning`` subscriptions (read-model projections) consume without a consumer
  group and replay the retained topic on every start, so each API replica rebuilds its
  own state and a deleted database is reconstructed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import KafkaConnectionError, TopicAlreadyExistsError

from autoheal.bus import Bus, Subscription, Topics

log = logging.getLogger(__name__)


class KafkaBus(Bus):
    def __init__(self, settings):
        super().__init__(settings)
        self._producer: AIOKafkaProducer | None = None
        self._consumers: list[AIOKafkaConsumer] = []
        self._tasks: list[asyncio.Task] = []

    def topic(self, name: str) -> str:
        return f"{self.settings.topic_prefix}.{name}"

    def _logical(self, physical: str) -> str:
        prefix = f"{self.settings.topic_prefix}."
        return physical[len(prefix):] if physical.startswith(prefix) else physical

    async def _ensure_topics(self) -> None:
        admin = AIOKafkaAdminClient(bootstrap_servers=self.settings.bootstrap_servers)
        await admin.start()
        try:
            existing = set(await admin.list_topics())
            wanted = [
                NewTopic(
                    name=self.topic(t),
                    num_partitions=self.settings.partitions,
                    replication_factor=self.settings.replication_factor,
                )
                for t in Topics.ALL
                if self.topic(t) not in existing
            ]
            if wanted:
                try:
                    await admin.create_topics(wanted)
                    log.info("created kafka topics: %s", ", ".join(t.name for t in wanted))
                except TopicAlreadyExistsError:
                    pass
        finally:
            await admin.close()

    async def start(self) -> None:
        for attempt in range(1, 31):
            try:
                await self._ensure_topics()
                break
            except (KafkaConnectionError, OSError) as exc:
                log.warning("kafka not reachable at %s (attempt %d): %s", self.settings.bootstrap_servers, attempt, exc)
                await asyncio.sleep(2)
        else:
            raise RuntimeError(f"cannot reach Kafka at {self.settings.bootstrap_servers}")

        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.bootstrap_servers,
            acks="all",
            enable_idempotence=True,
            value_serializer=lambda v: json.dumps(v).encode(),
            key_serializer=lambda k: k.encode() if k is not None else None,
            linger_ms=5,
        )
        await self._producer.start()

        for sub in self._subs:
            consumer = AIOKafkaConsumer(
                *[self.topic(t) for t in sub.topics],
                bootstrap_servers=self.settings.bootstrap_servers,
                group_id=None if sub.from_beginning else f"{self.settings.group_id}.{sub.group}",
                enable_auto_commit=False,
                auto_offset_reset="earliest" if sub.from_beginning else "latest",
                value_deserializer=lambda v: json.loads(v.decode()),
            )
            await consumer.start()
            self._consumers.append(consumer)
            self._tasks.append(asyncio.create_task(self._consume(sub, consumer), name=f"kafka:{sub.group}"))
        log.info("kafka bus started (%s)", self.settings.bootstrap_servers)

    async def _consume(self, sub: Subscription, consumer: AIOKafkaConsumer) -> None:
        async for msg in consumer:
            try:
                await sub.handler(self._logical(msg.topic), msg.value)
            except Exception:
                log.exception("handler %s failed on %s offset %s", sub.group, msg.topic, msg.offset)
            if not sub.from_beginning:
                await consumer.commit()

    async def _publish(self, topic: str, data: dict[str, Any], key: str | None) -> None:
        assert self._producer is not None, "bus not started"
        await self._producer.send_and_wait(self.topic(topic), data, key=key)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for c in self._consumers:
            await c.stop()
        if self._producer:
            await self._producer.stop()
