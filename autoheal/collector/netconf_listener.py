"""NETCONF alarm collector.

One worker thread per device keeps a NETCONF session with an RFC 5277 notification
subscription open:

* on connect: ``create-subscription``, then a full state resync (``<get>``) so alarms
  raised while we were away are not missed;
* notifications are normalized into alarms; only *changes* are published;
* periodically resyncs (re-asserting active alarms, so a restarted RCA rebuilds state);
* losing the session or failing to connect N times raises ``DEVICE_UNREACHABLE``;
  reconnecting clears it.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time

from autoheal.bus import Bus, Topics
from autoheal.collector.normalizer import Assertion, make, normalizer_for
from autoheal.config import Settings
from autoheal.models import Alarm, AlarmType
from autoheal.remediation.drivers.netconf import connect
from autoheal.topology import Device, Topology

log = logging.getLogger(__name__)


class DeviceWorker(threading.Thread):
    def __init__(self, device: Device, collector: "NetconfCollector"):
        super().__init__(name=f"collector:{device.name}", daemon=True)
        self.device = device
        self.c = collector
        self.normalizer = normalizer_for(device.vendor)
        self.raised: dict[str, Alarm] = {}  # fingerprints we last reported as raised
        self.unreachable = False
        self.connected = False

    def _emit(self, alarm: Alarm) -> None:
        self.c.emit(alarm)

    def _apply(self, assertions: list[Assertion], reassert: bool = False) -> None:
        for alarm, raised in assertions:
            fp = alarm.fingerprint
            if raised and (fp not in self.raised or reassert):
                if reassert and fp in self.raised:
                    alarm.attributes["resync"] = True
                self.raised[fp] = alarm
                self._emit(alarm)
            elif not raised and fp in self.raised:
                del self.raised[fp]
                self._emit(alarm)

    def _resync(self, m, reassert: bool = False) -> None:
        reply = m.get(filter=("subtree", self.normalizer.state_filter) if self.normalizer.state_filter else None)
        self._apply(self.normalizer.from_state(self.device.name, reply.data_ele), reassert)

    def _set_unreachable(self, value: bool, why: str = "") -> None:
        if value == self.unreachable:
            return
        self.unreachable = value
        alarm, raised = make(self.device.name, AlarmType.DEVICE_UNREACHABLE, "mgmt", value, "collector",
                             f"NETCONF management session unavailable: {why}" if value else "management restored")
        self._emit(alarm)

    def run(self) -> None:
        cfg = self.c.settings.collector
        failures = 0
        while not self.c.stopping.is_set():
            try:
                m = connect(self.device, self.c.settings.credentials.netconf, cfg.connect_timeout)
            except Exception as exc:
                failures += 1
                log.debug("%s: connect failed (%d): %s", self.device.name, failures, exc)
                if failures >= cfg.unreachable_after_failures:
                    self._set_unreachable(True, str(exc) or type(exc).__name__)
                self.c.stopping.wait(cfg.reconnect_interval if failures > 1 else 0.5)
                continue
            failures = 0
            self._set_unreachable(False)
            try:
                # Subscribe before the resync so nothing that happens in between is missed.
                m.create_subscription()
                self._resync(m)
                self.connected = True
                log.info("%s: subscribed to NETCONF notifications", self.device.name)
                last_resync = time.monotonic()
                while not self.c.stopping.is_set() and m.connected:
                    n = m.take_notification(block=True, timeout=1)
                    if n is not None:
                        self._apply(self.normalizer.from_notification(self.device.name, n.notification_xml))
                    if time.monotonic() - last_resync >= cfg.resync_interval:
                        self._resync(m, reassert=True)
                        last_resync = time.monotonic()
            except Exception as exc:
                log.info("%s: session error: %s", self.device.name, exc)
            finally:
                self.connected = False
                try:
                    if m.connected:
                        m.close_session()
                except Exception:
                    pass
            if not self.c.stopping.is_set():
                log.warning("%s: NETCONF session lost", self.device.name)
                failures = 1  # a dropped session counts as the first failure; reconnect immediately


class NetconfCollector:
    def __init__(self, settings: Settings, bus: Bus, topology: Topology):
        self.settings = settings
        self.bus = bus
        self.topology = topology
        self.stopping = threading.Event()
        self.workers: list[DeviceWorker] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    def emit(self, alarm: Alarm) -> None:
        assert self.loop is not None
        log.info("alarm %s %s", "CLEAR" if alarm.is_clear else alarm.severity.value.upper(), alarm.label())
        fut = asyncio.run_coroutine_threadsafe(self.bus.publish(Topics.ALARMS, alarm, key=alarm.device), self.loop)
        try:
            fut.result(timeout=10)
        except Exception as exc:
            log.error("failed to publish alarm %s: %s", alarm.label(), exc)

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        for dev in self.topology.devices.values():
            worker = DeviceWorker(dev, self)
            worker.start()
            self.workers.append(worker)
        log.info("collector watching %d device(s)", len(self.workers))

    async def stop(self) -> None:
        self.stopping.set()
        for w in self.workers:
            await asyncio.to_thread(w.join, 5)

    def status(self) -> dict[str, dict]:
        return {w.device.name: {"connected": w.connected, "unreachable": w.unreachable,
                                "active_alarms": len(w.raised)} for w in self.workers}
