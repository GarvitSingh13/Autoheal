# AutoHeal: Autonomous Network Healing Platform

**Problem:** manual intervention delays network recovery.
**Solution:** a self-healing loop of **alarms → root cause analysis → automatic reconfiguration over NETCONF/REST**, built on **Kafka** and deployed on **Ubuntu**.

```
 devices ──NETCONF notifications (RFC 5277)──┐
 Prometheus Alertmanager / any tool ──REST──┤
                                            ▼
                                   ┌──────────────────┐   autoheal.alarms
                                   │    collector     │ ─────────────────────┐
                                   └──────────────────┘                      ▼
                                                                    ┌──────────────────┐
                                                                    │  RCA engine      │ topology-aware
                                                                    │  (correlation)   │ correlation rules
                                                                    └──────────────────┘
                                                                             │ autoheal.incidents
                                                                             ▼
   NETCONF edit-config + commit confirmed ◄──┐                      ┌──────────────────┐
   RESTCONF / REST (device, PDU, ...)    ◄───┴──────────────────────│  remediator      │ playbooks +
                                                                    │  (guarded)       │ guardrails
                                                                    └──────────────────┘
                                                                             │ autoheal.remediations
                                                                             ▼
                                   operator ◄── dashboard / REST API ── read model (SQLite)
                                       └── approve / reject ──► autoheal.commands
```

Everything between components goes over Kafka topics, so each component can run as
its own process (and be restarted, scaled or replaced on its own).

## What it does

| Fault | What the platform sees | Root cause it infers | What it does |
|---|---|---|---|
| Interface shut by mistake | 5–6 alarms (far-end link down, OSPF + BGP on both ends, maybe an isolated device) | `INTERFACE_ADMIN_DOWN` (config drift vs. intent) | NETCONF: re-enable, verify interface + BGP, confirm |
| Hung transceiver / autoneg | link down both ends + routing alarms | `LINK_DOWN` (physical-link-failure) | NETCONF: bounce interface, verify. If the link stays down it rolls back and escalates as a physical fault |
| BGP session wedged | BGP down on both peers, link healthy | `BGP_SESSION_DOWN` (hold-timer-expired) | NETCONF RPC: soft-clear the session, verify Established |
| BGP neighbor disabled | BGP down on both peers | `BGP_SESSION_DOWN` on the side with `admin-shutdown` | NETCONF: re-enable neighbor, verify |
| Runaway process | `HIGH_CPU` | control-plane overload | RESTCONF: restart the process (never `rpd`), verify CPU < 70% |
| Dirty optic | `HIGH_ERROR_RATE` | degraded link | NETCONF: OSPF cost-out on both ends. Outcome is *mitigated*, with a follow-up task for a human |
| Device dead | neighbors' links/sessions down, downstream devices unreachable | `DEVICE_UNREACHABLE` (node-failure) | REST: power-cycle via the out-of-band PDU, **after operator approval**, then verify reachability |

### Root cause analysis
- **Dedup** of repeated alarms, plus an **intent filter**: an interface shut by design is not a fault.
- **Windowed, topology-aware correlation.** Rules in [config/rca_rules.yaml](config/rca_rules.yaml) say that alarm type X explains alarm type Y when a topology relation holds (`same_link`, `facing_device`, `downstream`, `isolated_by_link`, ...). A greedy set-cover picks the roots: highest priority first, then most explained.
- **Late arrivals** join an open incident. **Superseding** happens when a later alarm explains the roots of earlier incidents, for example a node declared unreachable after its links were reported down.
- **Confidence scoring.** A diagnosis without corroboration (an unreachable device whose neighbors see nothing wrong) gets lower confidence, and automation won't act on it.
- **Change-induced suppression.** Alarms a running playbook causes itself, such as the admin-down during an interface bounce, are not treated as new faults.
- **Residual re-analysis.** When a root clears, symptoms that persist beyond a grace period become incidents of their own.

### Safe automation
- **Commit-confirmed.** Every NETCONF change is `lock → edit-config(candidate) → validate → commit confirmed`, and is confirmed only after every verify step passes. On failure the platform sends `cancel-commit`. If the platform itself dies mid-change, the device rolls back on its own. Running-only devices get a snapshot that is restored on failure.
- **Verification.** Probes poll real device state (XPath over NETCONF `<get>`, or RESTCONF JSON) until the expected value appears or the timeout passes.
- **Guardrails** ([guardrails.py](autoheal/remediation/guardrails.py)):
  - a minimum RCA confidence
  - device exclusions (`no-auto-heal` tag)
  - a flap guard (the same fault fixed N times means the fix isn't holding, so a human takes over)
  - a per-device rate limit
  - a network-wide circuit breaker
  - one change at a time per device
- **Modes:** `auto`, `approval` (every action waits for an operator) or `dry_run` (records the rendered payloads and sends nothing). Individual playbooks can also require approval, as power-cycling does.
- **Hold-down** before acting on flappy faults, cancelled if the fault clears by itself.
- **Escalation** to a Slack/Teams-compatible webhook on failure, escalation, a pending approval or a mitigation.

## Quick start (local, no Kafka)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

autoheal sim &                       # lab network: 6 routers on NETCONF :8301-8306, API :8300
autoheal run all --bus memory        # collector + RCA + remediator + API in one process
open http://localhost:8080           # dashboard
```

Break something and watch it heal, either from the dashboard's **Lab** panel or the CLI:

```bash
autoheal inject admin_shutdown --device core2 --interface ge-0/0/1
autoheal inject link_hang      --device agg1  --interface ge-0/0/2
autoheal inject bgp_stuck      --device edge1 --neighbor 10.0.6.1
autoheal inject cpu_runaway    --device edge1 --process telemetryd
autoheal inject crc_errors     --device agg2  --interface ge-0/0/2
autoheal inject power_off      --device agg2          # approve the power-cycle in the dashboard
autoheal inject fiber_cut      --device core1 --interface ge-0/0/1   # bounce fails -> rollback + escalate
autoheal faults                 # list active faults
autoheal repair f3              # fix a physical fault
```

## Deploy on Ubuntu

**Docker Compose** (Kafka in KRaft mode, each component in its own container, plus the simulator):

```bash
docker compose up -d --build
# dashboard: http://<host>:8080   simulator API: http://<host>:8300/docs
```

**Bare metal / VM with systemd** (Ubuntu 22.04 / 24.04):

```bash
sudo ./deploy/install_ubuntu.sh --with-kafka --with-simulator   # full lab on one box
sudo ./deploy/install_ubuntu.sh                                  # platform only, use your Kafka
```

This installs to `/opt/autoheal` with config in `/etc/autoheal`. It sets up the units
`autoheal-{collector,rca,remediator,api}` under `autoheal.target`, an optional `kafka`
unit, and an optional `autoheal-simulator` unit.
Logs: `journalctl -u 'autoheal-*' -f`.

Run a single RCA instance per alarm stream, because correlation needs a global view. The API's
SQLite store is a projection of the Kafka topics and rebuilds itself if deleted.

## Pointing it at real devices

1. **Topology** ([config/topology.yaml](config/topology.yaml)): devices (host, NETCONF port, vendor, RESTCONF URL, PDU outlet), interface IPs, links, intent and the management root.
2. **Vendor profile** (`config/vendors/<vendor>.yaml`): maps playbook template, RPC and probe *names* to your YANG payloads. [openconfig.yaml](config/vendors/openconfig.yaml) is a starting point. It has not been tested against hardware, so validate the paths for your platform.
3. **Alarm normalizer** ([normalizer.py](autoheal/collector/normalizer.py)): turns your platform's notifications into normalized alarms. Alternatively, feed alarms from an existing NMS through `POST /api/alarms` or the Alertmanager webhook.
4. **Credentials** in `/etc/autoheal/autoheal.env` (`NETCONF_USER`, `NETCONF_PASSWORD`, ...).
5. Run `autoheal check`, start in `--mode dry_run`, review what it *would* do, then move to `approval` and finally to `auto`.

## REST API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/alarms` | ingest one alarm or a list (`device`, `type`, `resource`, `severity`, ...) |
| POST | `/api/alarms/alertmanager` | Prometheus Alertmanager webhook receiver |
| GET | `/api/incidents[?status=open]`, `/api/incidents/{id}` | incidents with RCA explanation + remediation |
| GET | `/api/remediations`, `/api/remediations/{id}` | remediation records with per-step results |
| POST | `/api/remediations/{id}/approve` · `/reject` | operator decision |
| GET | `/api/topology` | topology with live device and link status |
| GET | `/api/summary` | KPIs: noise reduction, heal rate, mean time to heal |
| GET | `/api/alarms[?active=true]`, `/api/alarms/log` | alarm state and history |
| GET | `/metrics` | Prometheus metrics |
| GET | `/docs` | OpenAPI UI |

## Project layout

```
autoheal/
  collector/     NETCONF notification listener + vendor normalizers
  rca/           correlation rules + engine + service
  remediation/   playbooks, engine, guardrails, notifier, NETCONF/REST drivers
  api/           FastAPI app, projector (read model + metrics), dashboard
  bus/           Kafka (aiokafka) and in-memory backends
  topology.py    source of truth + graph queries
  vendors.py     vendor profiles (templates / RPCs / probes)
simulator/       lab network: NETCONF-over-SSH servers, RESTCONF, PDU, fault injection
config/          settings, topology, RCA rules, playbooks, vendor profiles
deploy/          Ubuntu installer + systemd units
tests/           unit tests + end-to-end tests against the simulator
```

## Tests

```bash
pytest -q          # unit tests + end-to-end runs against the simulator (~1.5 min)
```

The end-to-end suite starts the simulator (real NETCONF over SSH) and the full platform,
injects every fault type, and asserts on the **device state in the simulator**: interfaces
back up, BGP Established, OSPF cost changed, device powered on. It also checks the
records the platform kept.

## The lab simulator

[simulator/](simulator/) emulates the network from `topology.yaml`. Every device has
real candidate/running XML datastores, and operational state is *derived* from configuration
plus injected physical faults, across devices. A link is up only if both ends are
enabled and powered and the link is healthy. BGP needs both neighbors configured over an up
link. Management reachability follows in-band paths from the management root. So a
config pushed by the platform really restores service, and a power-off really drops sessions.
It implements NETCONF base:1.0 over SSH: get/get-config with subtree filters, edit-config,
lock, commit confirmed with timeout rollback (also on session loss), cancel-commit,
validate, notifications. It also offers per-device RESTCONF, a smart-PDU API, and a fault
injection API.
