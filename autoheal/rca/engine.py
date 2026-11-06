"""Topology-aware root cause analysis.

Algorithm
---------
1. **Dedup** – an alarm whose fingerprint (device|type|resource) is already active is
   counted, not re-analysed (alarm-storm suppression).
2. **Intent filter** – an interface that is administratively down *by design* is not a fault.
3. **Late attach** – a new alarm explained by the root of an already-open incident joins it.
4. **Windowed correlation** – remaining alarms are buffered for ``correlation_window``
   seconds, then a greedy set-cover picks root causes: for each candidate alarm and each
   rule rooted at its type, count the alarms (and open incidents) it explains; the best
   (priority, coverage, earliest) candidate becomes an incident root and its explained
   alarms become symptoms. Open incidents whose root is explained by the new root are
   *superseded* (e.g. link-down incidents opened before a node was declared unreachable).
5. **Change-induced suppression** – alarms a running remediation is expected to cause
   (declared by the playbook, e.g. INTERFACE_ADMIN_DOWN during an interface bounce) are
   ignored while it runs and for a short grace period afterwards.
6. **Clear handling** – when an incident's root alarm clears the incident clears; symptoms
   still active after ``residual_grace`` are re-analysed (e.g. a BGP session that did not
   recover with its link becomes its own incident).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from autoheal.config import RcaSettings
from autoheal.models import (
    TERMINAL_REMEDIATION,
    Alarm,
    AlarmType,
    Incident,
    IncidentStatus,
    Remediation,
    RemediationStatus,
    now,
)
from autoheal.rca.rules import Rule
from autoheal.topology import Topology

log = logging.getLogger(__name__)

Publisher = Callable[[Incident], Awaitable[None]]

SUPPRESSION_GRACE = 15.0  # seconds a remediation's expected alarms stay suppressed after it ends


class RcaEngine:
    def __init__(self, settings: RcaSettings, topology: Topology, rules: list[Rule], publish: Publisher):
        self.settings = settings
        self.topology = topology
        self.rules = sorted(rules, key=lambda r: -r.priority)
        self.rules_by_root: dict[AlarmType, list[Rule]] = {}
        for r in self.rules:
            self.rules_by_root.setdefault(r.root, []).append(r)
        self.rule_by_name = {r.name: r for r in self.rules}
        self._publish = publish
        self.active: dict[str, Alarm] = {}
        self.owner: dict[str, str] = {}  # alarm fingerprint -> incident id
        self.incidents: dict[str, Incident] = {}  # open incidents only
        self.pending: dict[str, Alarm] = {}
        self._flush_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self.suppressed: dict[str, float] = {}  # fingerprint -> expiry timestamp
        self._residual_tasks: set[asyncio.Task] = set()
        self.stats = {"alarms": 0, "deduplicated": 0, "suppressed_by_intent": 0,
                      "suppressed_by_change": 0, "incidents": 0}

    def handle_remediation(self, rem: Remediation) -> None:
        if rem.status == RemediationStatus.RUNNING:
            for fp in rem.suppressions:
                self.suppressed[fp] = float("inf")
        elif rem.status in TERMINAL_REMEDIATION:
            until = now() + SUPPRESSION_GRACE
            for fp in rem.suppressions:
                if fp in self.suppressed:
                    self.suppressed[fp] = until

    def _is_suppressed(self, fp: str) -> bool:
        expiry = self.suppressed.get(fp)
        if expiry is None:
            return False
        if expiry < now():
            del self.suppressed[fp]
            return False
        return True

    # ------------------------------------------------------------------ input
    async def handle_alarm(self, alarm: Alarm) -> None:
        async with self._lock:
            if alarm.is_clear:
                await self._handle_clear(alarm)
            else:
                await self._handle_raise(alarm)

    async def _handle_raise(self, alarm: Alarm) -> None:
        fp = alarm.fingerprint
        self.stats["alarms"] += 1
        if fp in self.active:
            if not alarm.attributes.get("resync"):
                existing = self.active[fp]
                existing.attributes["occurrences"] = int(existing.attributes.get("occurrences", 1)) + 1
                self.stats["deduplicated"] += 1
            return
        if self._is_suppressed(fp):
            self.stats["suppressed_by_change"] += 1
            log.info("ignoring %s: expected side effect of a running remediation", alarm.label())
            return
        if self._expected_by_intent(alarm):
            self.stats["suppressed_by_intent"] += 1
            log.info("ignoring %s: matches intended state", alarm.label())
            return
        self.active[fp] = alarm

        for inc in list(self.incidents.values()):
            rule = self.rule_by_name.get(inc.rule)
            relation = rule.explains_alarm(inc.root_cause, alarm, self.topology) if rule else None
            if relation:
                inc.symptoms.append(alarm)
                self.owner[fp] = inc.id
                inc.explanation = self._explain(inc.root_cause, rule, [(s, self._relation(rule, inc.root_cause, s)) for s in inc.symptoms])
                self._update_affected(inc)
                await self._emit(inc)
                log.info("%s attached to incident %s (%s)", alarm.label(), inc.id, relation)
                return

        self.pending[fp] = alarm
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_after_window())

    async def _handle_clear(self, alarm: Alarm) -> None:
        fp = alarm.fingerprint
        self.active.pop(fp, None)
        if self.pending.pop(fp, None) is not None:
            log.info("%s cleared within the correlation window (transient)", alarm.label())
            return
        inc_id = self.owner.pop(fp, None)
        inc = self.incidents.get(inc_id) if inc_id else None
        if inc is None:
            return
        if inc.root_cause.fingerprint == fp:
            inc.status = IncidentStatus.CLEARED
            inc.cleared_at = now()
            del self.incidents[inc.id]
            residual = [s for s in inc.symptoms if s.fingerprint in self.active]
            for s in residual:
                self.owner.pop(s.fingerprint, None)
            await self._emit(inc)
            log.info("incident %s cleared (root %s cleared)%s", inc.id, inc.root_cause.label(),
                     f"; {len(residual)} symptom(s) still active, re-analysing after "
                     f"{self.settings.residual_grace:g}s grace" if residual else "")
            if residual:
                self._residual_tasks.add(asyncio.create_task(self._reanalyse_later(residual)))
        else:
            if fp not in inc.cleared_symptoms:
                inc.cleared_symptoms.append(fp)
            await self._emit(inc)

    async def _reanalyse_later(self, residual: list[Alarm]) -> None:
        """Symptoms that outlive their root get time to recover (e.g. BGP reconverging after a
        link returns) before they are treated as faults of their own."""
        await asyncio.sleep(self.settings.residual_grace)
        async with self._lock:
            still = [a for a in residual if self.active.get(a.fingerprint) is a and a.fingerprint not in self.owner]
            for a in still:
                self.pending[a.fingerprint] = a
            if still:
                log.info("%d symptom(s) persisted after their root cleared; re-analysing", len(still))
                await self.flush()
        self._residual_tasks.discard(asyncio.current_task())

    # ------------------------------------------------------------ correlation
    async def _flush_after_window(self) -> None:
        await asyncio.sleep(self.settings.correlation_window)
        async with self._lock:
            await self.flush()

    async def flush(self) -> None:
        pool = [a for a in self.pending.values() if a.fingerprint in self.active]
        self.pending.clear()
        while pool:
            best = None
            for cand in pool:
                for rule in self.rules_by_root.get(cand.type, []):
                    if not rule.applies_to(cand):
                        continue
                    explained = [(s, rel) for s in pool
                                 if (rel := rule.explains_alarm(cand, s, self.topology))]
                    superseded = [inc for inc in self.incidents.values()
                                  if rule.explains_alarm(cand, inc.root_cause, self.topology)]
                    coverage = len(explained) + sum(i.alarm_count for i in superseded)
                    key = (rule.priority, coverage, -cand.timestamp, cand.fingerprint)
                    if best is None or key > best[0]:
                        best = (key, cand, rule, explained, superseded)
            if best is None:
                break
            _, root, rule, explained, superseded = best
            inc = await self._open_incident(root, rule, explained, superseded)
            taken = {root.fingerprint, *(s.fingerprint for s, _ in explained)}
            pool = [a for a in pool if a.fingerprint not in taken]
            log.info("incident %s: root %s via rule %s explains %d alarm(s), confidence %.2f",
                     inc.id, root.label(), rule.name, inc.alarm_count - 1, inc.confidence)

        for alarm in pool:  # no rule is rooted at these alarm types
            inc = Incident(root_cause=alarm, rule="standalone", confidence=self.settings.standalone_confidence,
                           explanation=f"{alarm.label()}: no correlation rule applies; treated as its own root cause.")
            self._update_affected(inc)
            self.incidents[inc.id] = inc
            self.owner[alarm.fingerprint] = inc.id
            self.stats["incidents"] += 1
            await self._emit(inc)

    async def _open_incident(self, root: Alarm, rule: Rule, explained: list[tuple[Alarm, str]],
                             superseded: list[Incident]) -> Incident:
        symptoms = [(s, rel) for s, rel in explained]
        for old in superseded:
            symptoms.append((old.root_cause, rule.explains_alarm(root, old.root_cause, self.topology) or "superseded"))
            symptoms.extend((s, rule.explains_alarm(root, s, self.topology) or "superseded")
                            for s in old.symptoms if s.fingerprint in self.active)
        confidence = rule.confidence if len(symptoms) >= rule.min_symptoms else round(rule.confidence * 0.6, 3)
        inc = Incident(root_cause=root, rule=rule.name, confidence=confidence,
                       symptoms=[s for s, _ in symptoms],
                       explanation=self._explain(root, rule, symptoms))
        if len(symptoms) < rule.min_symptoms:
            inc.explanation += (f" Confidence reduced: rule expects at least {rule.min_symptoms} "
                                f"corroborating alarm(s), saw {len(symptoms)}.")
        self._update_affected(inc)
        self.incidents[inc.id] = inc
        for a in (root, *inc.symptoms):
            self.owner[a.fingerprint] = inc.id
        self.stats["incidents"] += 1
        for old in superseded:
            old.status = IncidentStatus.SUPERSEDED
            old.superseded_by = inc.id
            self.incidents.pop(old.id, None)
            await self._emit(old)
            log.info("incident %s superseded by %s", old.id, inc.id)
        await self._emit(inc)
        return inc

    # ---------------------------------------------------------------- helpers
    def _expected_by_intent(self, alarm: Alarm) -> bool:
        if alarm.type != AlarmType.INTERFACE_ADMIN_DOWN:
            return False
        dev = self.topology.devices.get(alarm.device)
        iface = dev.interfaces.get(alarm.resource) if dev else None
        return iface is not None and not iface.intended_enabled

    def _relation(self, rule: Rule, root: Alarm, s: Alarm) -> str:
        return rule.explains_alarm(root, s, self.topology) or "superseded"

    @staticmethod
    def _explain(root: Alarm, rule: Rule, symptoms: list[tuple[Alarm, str]]) -> str:
        text = f"Root cause: {root.label()} (rule '{rule.name}')."
        if rule.description:
            text += f" {rule.description}"
        if symptoms:
            parts = [f"{s.label()} [{rel}]" for s, rel in symptoms]
            text += f" Explains {len(symptoms)} downstream alarm(s): " + "; ".join(parts) + "."
        return text

    def _update_affected(self, inc: Incident) -> None:
        devs = {inc.root_cause.device, *(s.device for s in inc.symptoms)}
        inc.affected_devices = sorted(devs)

    async def _emit(self, inc: Incident) -> None:
        inc.updated_at = now()
        inc.version += 1
        await self._publish(inc.model_copy(deep=True))
