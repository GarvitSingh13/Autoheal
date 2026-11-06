"""Command line entry point.

    autoheal run [all|collector|rca|remediator|api ...]   run platform components
    autoheal sim                                          run the lab network simulator
    autoheal check                                        validate configuration files
    autoheal inject <fault> --device D [...]              inject a fault into the simulator
    autoheal faults / repair <id>                         list / clear simulator faults
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

import httpx

from autoheal.config import load_settings


def _setup_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    for noisy in ("ncclient", "paramiko", "aiokafka", "httpx", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # ncclient logs a full traceback for every refused connection (e.g. while probing a
    # rebooting device); the collector/remediator report those failures themselves.
    logging.getLogger("ncclient.transport.ssh").setLevel(logging.CRITICAL)


def cmd_run(args) -> int:
    from autoheal.runner import COMPONENTS, run

    settings = load_settings(args.config)
    if args.bus:
        settings.bus.backend = args.bus
    if args.mode:
        settings.remediation.mode = args.mode
    _setup_logging(settings.log_level)
    comps = set(COMPONENTS) if "all" in args.components else set(args.components)
    try:
        asyncio.run(run(settings, comps))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_sim(args) -> int:
    from simulator.server import main as sim_main

    _setup_logging(args.log_level)
    sim_main(args.topology, args.host, args.api_port, args.boot_time)
    return 0


def cmd_check(args) -> int:
    from autoheal.models import AlarmType
    from autoheal.rca.rules import load_rules
    from autoheal.remediation.playbooks import load_playbooks
    from autoheal.topology import Topology
    from autoheal.vendors import load_vendors

    settings = load_settings(args.config)
    topo = Topology.load(settings.paths.topology)
    rules = load_rules(settings.paths.rules)
    books = load_playbooks(settings.paths.playbooks)
    vendors = load_vendors(settings.paths.vendors_dir)
    problems = []
    for dev in topo.devices.values():
        if dev.vendor not in vendors:
            problems.append(f"device {dev.name}: no vendor profile '{dev.vendor}'")
    in_use = {d.vendor for d in topo.devices.values()} & set(vendors)
    for pb in books:
        for step in pb.steps:
            for vname, prof in ((v, vendors[v]) for v in sorted(in_use)):
                p = step.params
                if step.action == "netconf_config" and p["template"] not in prof.templates:
                    problems.append(f"playbook {pb.name}: vendor {vname} lacks template {p['template']}")
                if step.action == "netconf_rpc" and p["rpc"] not in prof.rpcs:
                    problems.append(f"playbook {pb.name}: vendor {vname} lacks rpc {p['rpc']}")
                if step.action == "verify" and p["probe"] != "device_reachable" and p["probe"] not in prof.probes:
                    problems.append(f"playbook {pb.name}: vendor {vname} lacks probe {p['probe']}")
                if step.action == "rest" and p.get("endpoint", "device") not in ("device", *settings.endpoints):
                    problems.append(f"playbook {pb.name}: REST endpoint {p['endpoint']} not in settings.endpoints")
    uncovered = {t.value for t in AlarmType} - {r.root.value for r in rules} - {"GENERIC"}
    print(f"topology : {len(topo.devices)} devices, {len(topo.links)} links (mgmt root {topo.mgmt_root})")
    print(f"rules    : {len(rules)} ({', '.join(r.name for r in rules)})")
    print(f"playbooks: {len(books)} ({', '.join(b.name for b in books)})")
    print(f"vendors  : {', '.join(f'{v} (in use)' if v in in_use else v for v in vendors)}")
    if uncovered:
        print(f"note     : no RCA rule rooted at {', '.join(sorted(uncovered))} (handled as standalone)")
    for p in problems:
        print(f"PROBLEM  : {p}")
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


def _sim_url(args) -> str:
    if args.sim:
        return args.sim.rstrip("/")
    url = load_settings(args.config).lab.simulator_url
    if not url:
        sys.exit("simulator URL unknown: pass --sim or set lab.simulator_url")
    return url.rstrip("/")


def cmd_inject(args) -> int:
    body = {"type": args.fault, "device": args.device}
    for key in ("interface", "neighbor", "process"):
        if getattr(args, key):
            body[key] = getattr(args, key)
    r = httpx.post(f"{_sim_url(args)}/faults", json=body, timeout=10)
    print(json.dumps(r.json(), indent=2))
    return 0 if r.status_code < 400 else 1


def cmd_faults(args) -> int:
    r = httpx.get(f"{_sim_url(args)}/faults", timeout=10)
    print(json.dumps(r.json(), indent=2))
    return 0


def cmd_repair(args) -> int:
    r = httpx.delete(f"{_sim_url(args)}/faults/{args.fault_id}", timeout=10)
    print(json.dumps(r.json(), indent=2))
    return 0 if r.status_code < 400 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="autoheal", description="Autonomous Network Healing Platform")
    ap.add_argument("-c", "--config", default=None, help="settings file (default config/settings.yaml or $AUTOHEAL_CONFIG)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="run platform components")
    p.add_argument("components", nargs="*", default=["all"],
                   choices=["all", "collector", "rca", "remediator", "api"])
    p.add_argument("--bus", choices=["kafka", "memory"], help="override bus backend")
    p.add_argument("--mode", choices=["auto", "approval", "dry_run"], help="override remediation mode")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("sim", help="run the lab network simulator (NETCONF + RESTCONF + PDU)")
    p.add_argument("--topology", default="config/topology.yaml")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--api-port", type=int, default=8300)
    p.add_argument("--boot-time", type=float, default=5.0, help="seconds a power-cycled device takes to boot")
    p.add_argument("--log-level", default="INFO")
    p.set_defaults(fn=cmd_sim)

    p = sub.add_parser("check", help="validate topology, rules, playbooks and vendor profiles")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("inject", help="inject a fault into the simulator")
    p.add_argument("fault", choices=["admin_shutdown", "link_hang", "fiber_cut", "bgp_stuck",
                                     "bgp_neighbor_shutdown", "cpu_runaway", "crc_errors", "power_off"])
    p.add_argument("--device", required=True)
    p.add_argument("--interface")
    p.add_argument("--neighbor")
    p.add_argument("--process")
    p.add_argument("--sim", help="simulator URL (default settings.lab.simulator_url)")
    p.set_defaults(fn=cmd_inject)

    p = sub.add_parser("faults", help="list active simulator faults")
    p.add_argument("--sim")
    p.set_defaults(fn=cmd_faults)

    p = sub.add_parser("repair", help="clear a simulator fault")
    p.add_argument("fault_id")
    p.add_argument("--sim")
    p.set_defaults(fn=cmd_repair)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
