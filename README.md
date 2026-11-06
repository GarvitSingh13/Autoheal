# AutoHeal: Autonomous Network Self-Healing Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![NETCONF](https://img.shields.io/badge/Protocol-NETCONF%20%2F%20RESTCONF-orange)](https://datatracker.ietf.org/doc/html/rfc6241)
[![Kafka](https://img.shields.io/badge/Event%20Bus-Apache%20Kafka%20(KRaft)-black?logo=apachekafka)](https://kafka.apache.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

AutoHeal is a closed-loop network automation platform designed to eliminate human intervention delays during network incidents. It continuously ingests real-time telemetry, suppresses alarm storms using topology-aware graph correlation, and automatically reconfigures routers over NETCONF/REST with safety rollback guarantees.

---

## Problem and Solution

* **The Problem:** When a single link or transceiver hangs, 20 to 50 redundant alarms flood the Network Operations Center (NOC) simultaneously (BGP drops, OSPF neighbor down, ping failures). Diagnosing and fixing this manually takes 30 to 45 minutes of downtime.
* **The Solution:** AutoHeal executes an autonomous **Observe -> Diagnose -> Guard -> Repair -> Verify** closed-loop cycle in under 8 seconds:

```
  Simulated / Real Routers (NETCONF RFC 5277 / REST)
  Prometheus Alertmanager / External Tools
                         │
                         ▼
               ┌──────────────────┐
               │    Collector     │  Ingests notifications & normalizes alarm fields
               └──────────────────┘
                         │  topic: autoheal.alarms
                         ▼
               ┌──────────────────┐
               │    RCA Engine    │  Topology-aware correlation (NetworkX + Greedy Set-Cover)
               └──────────────────┘  Deduplication, confidence scoring & intent filtering
                         │  topic: autoheal.incidents
                         ▼
               ┌──────────────────┐
               │    Remediator    │  Guarded playbook execution (NETCONF commit-confirmed)
               └──────────────────┘  Auto-rollback on failure & safety guardrails
                         │  topic: autoheal.remediations
                         ▼
        ┌───────────────────────────────────┐
        │       NOC Dashboard & Read Model  │  FastAPI + SQLite projection, Prometheus /metrics,
        │       (http://localhost:8080)     │  real-time SVG topology & human approval controls
        └───────────────────────────────────┘
```

---

## Fault and Remediation Matrix

| Failure Scenario | Alarms Detected | Inferred Root Cause | Automated Remediation |
|---|---|---|---|
| **Interface Shut by Mistake** | 4-6 alarms (far-end link down, OSPF + BGP both ends) | `INTERFACE_ADMIN_DOWN` (config drift) | NETCONF: re-enable interface, verify routing convergence, confirm. |
| **Transceiver / Autoneg Hang** | Link down both ends + routing loss | `LINK_DOWN` (physical-link-failure) | NETCONF: bounce interface. If link remains down, rolls back and escalates. |
| **BGP Session Wedged** | BGP Down on both peers, physical link healthy | `BGP_SESSION_DOWN` (hold-timer-expired) | NETCONF RPC: soft-clear BGP session, verify `Established` state. |
| **BGP Neighbor Disabled** | BGP down on peers, one peer admin-down | `BGP_SESSION_DOWN` on disabled peer | NETCONF: re-enable neighbor configuration, verify BGP peering. |
| **Runaway Process / High CPU** | `HIGH_CPU` telemetry | Control-plane overload | RESTCONF: restart offending process (safeguarded: never `rpd`), verify CPU < 70%. |
| **Degraded Link / Bad Optic** | `HIGH_ERROR_RATE` (CRC errors) | Degraded optical link | NETCONF: OSPF cost-out on both ends to route traffic away, marks mitigated. |
| **Dead Device / Node Crash** | All neighbors down, downstream unreachable | `DEVICE_UNREACHABLE` (node failure) | REST: Power-cycle via smart PDU after operator approval, verify reachability. |

---

## Safety Guardrails and Rollback Guarantees

AutoHeal implements enterprise-grade safety mechanisms to ensure automation never worsens an outage:

1. **Commit-Confirmed Rollback:** Every NETCONF transaction executes `lock -> edit-config(candidate) -> validate -> commit confirmed`. If verification fails or the controller disconnects mid-change, the router rolls back automatically.
2. **Human-in-the-Loop Approval:** Destructive actions (such as power-cycling a router via smart PDU) pause and wait for one-click operator confirmation in the dashboard.
3. **Flap Guard:** If the same fault recurs 3 times within an hour, AutoHeal locks out automation on that port and escalates to a human engineer.
4. **Rate Limits & Circuit Breaker:** Restricts maximum actions per device per hour and features a network-wide circuit breaker.
5. **Intent Filtering:** Interfaces shut intentionally by design (such as spare ports) are filtered out and never treated as faults.
6. **Execution Modes:** Configurable as `auto` (fully autonomous), `approval` (every action requires human confirmation), or `dry_run` (logs planned changes without touching devices).

---

## Quick Start Guide

AutoHeal includes an embedded lab network simulating 6 routers (`core1`, `core2`, `agg1`, `agg2`, `edge1`, `edge2`) with real NETCONF-over-SSH servers, RESTCONF, and smart PDU emulation.

### Option 1: Local Native Run (No Docker or Kafka Required)

The platform provides a high-performance in-memory event bus (`--bus memory`) for local development, testing, and demonstrations.

#### On Windows (PowerShell):
```powershell
# 1. Clone & enter repository
git clone https://github.com/GarvitSingh13/Autoheal.git
cd Autoheal

# 2. Set up virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 3. Start Terminal 1: Lab Network Simulator (Ports 8301-8306 & API 8300)
autoheal sim

# 4. Start Terminal 2: AutoHeal Engine & Dashboard
.\.venv\Scripts\Activate.ps1
autoheal run all --bus memory
```

#### On Linux / macOS (Bash):
```bash
# 1. Set up virtual environment & dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Start the simulator in background & run platform
autoheal sim &
autoheal run all --bus memory
```

Access the NOC Dashboard in your browser: **http://localhost:8080**

---

### Option 2: Docker Compose (Full Stack with Apache Kafka)

Run the production microservice architecture with Apache Kafka (in KRaft mode, without ZooKeeper):

```bash
docker compose up -d --build
```
* **NOC Dashboard:** http://localhost:8080
* **Simulator API Docs:** http://localhost:8300/docs

---

## Chaos Testing: Fault Injection

You can trigger failures directly from the **LAB: INJECT A FAULT** controls on the web dashboard, or via the command line:

```bash
# 1. Accidental administrative port shutdown (config drift)
autoheal inject admin_shutdown --device core2 --interface ge-0/0/1

# 2. Transceiver / link hang
autoheal inject link_hang --device agg1 --interface ge-0/0/2

# 3. Wedged BGP peering session
autoheal inject bgp_stuck --device edge1 --neighbor 10.0.6.1

# 4. Runaway telemetry process consuming CPU
autoheal inject cpu_runaway --device edge1 --process telemetryd

# 5. Bad optical fiber with high CRC error rate
autoheal inject crc_errors --device agg2 --interface ge-0/0/2

# 6. Dead router (triggers operator approval prompt on dashboard)
autoheal inject power_off --device agg2

# View active faults or clear them manually:
autoheal faults
autoheal repair <fault_id>
```

---

## REST API and Telemetry

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/alarms` | Ingest external alarm payload (`device`, `type`, `resource`, `severity`). |
| `POST` | `/api/alarms/alertmanager` | Webhook receiver for Prometheus Alertmanager. |
| `GET` | `/api/incidents` | List incidents with correlated symptoms and RCA diagnosis. |
| `GET` | `/api/remediations` | View playbook execution logs with per-step verification results. |
| `POST` | `/api/remediations/{id}/approve` | Operator approval for pending remediation actions. |
| `POST` | `/api/remediations/{id}/reject` | Operator rejection of pending remediation actions. |
| `GET` | `/api/topology` | Network topology graph with real-time link and device health status. |
| `GET` | `/api/summary` | Real-time NOC KPIs: noise reduction, heal rate, and MTTH. |
| `GET` | `/metrics` | Prometheus metrics scrape endpoint. |
| `GET` | `/docs` | Interactive OpenAPI documentation. |

---

## Project Structure

```text
autoheal/
├── autoheal/
│   ├── collector/        # NETCONF RFC 5277 listener & vendor alarm normalizers
│   ├── rca/              # Topology-aware graph correlation & greedy set-cover engine
│   ├── remediation/      # Playbook runner, NETCONF/REST drivers, guardrails & notifier
│   ├── api/              # FastAPI application, SQLite projector & NOC SVG dashboard
│   ├── bus/              # Decoupled event bus (Kafka & in-memory implementations)
│   ├── topology.py       # Network topology graph model (NetworkX)
│   └── models.py         # Pydantic schemas (Alarms, Incidents, Remediations)
├── simulator/            # Lab testbed: NETCONF-over-SSH router daemons, RESTCONF & PDU
├── config/
│   ├── topology.yaml     # Source of truth: devices, links, IP addressing & intent
│   ├── rca_rules.yaml    # Topology correlation rules for root cause identification
│   ├── playbooks.yaml    # Declarative multi-step remediation playbooks
│   └── vendors/          # Vendor-specific YANG RPCs, templates, and state probes
├── deploy/               # Ubuntu 22.04/24.04 automated systemd installation scripts
├── tests/                # Automated pytest unit & end-to-end integration test suite
├── Dockerfile            # Container definition for platform microservices
└── docker-compose.yml    # Full multi-container stack with Apache Kafka in KRaft mode
```

---

## Automated Test Suite

Run the full automated test suite (32 unit and end-to-end tests):

```bash
# Run unit tests only
pytest tests/ -k "not e2e" -q

# Run end-to-end integration tests against real NETCONF router daemons
pytest tests/test_e2e.py -q
```

The end-to-end test suite spins up virtual NETCONF-over-SSH servers for every device, injects each failure scenario, and validates operational convergence (interfaces up, BGP Established, OSPF cost mitigated, and device power restored).

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).
