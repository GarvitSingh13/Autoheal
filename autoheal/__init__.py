"""Autonomous Network Healing Platform.

Pipeline: alarms (NETCONF notifications / REST webhooks) -> Kafka -> topology-aware
root cause analysis -> policy-guarded remediation playbooks executed over
NETCONF (confirmed commit) and REST/RESTCONF -> verification -> heal or escalate.
"""

__version__ = "1.0.0"
