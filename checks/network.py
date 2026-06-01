"""checks/network.py – Network policy coverage checks."""

from __future__ import annotations
from checks.rbac import Finding


class NetworkPolicyChecker:
    """
    CIS controls covered:
      5.3.2  Ensure that all Namespaces have Network Policies defined
    """

    def run(self, namespace: str | None = None) -> list[Finding]:
        from kubernetes import client
        v1       = client.CoreV1Api()
        net_v1   = client.NetworkingV1Api()
        findings: list[Finding] = []

        namespaces = (
            [type("NS", (), {"metadata": type("M", (), {"name": namespace})()})()]
            if namespace else
            v1.list_namespace().items
        )

        for ns_obj in namespaces:
            ns = ns_obj.metadata.name
            if ns in ("kube-system", "kube-public", "kube-node-lease"):
                continue
            policies = net_v1.list_namespaced_network_policy(ns).items
            if not policies:
                findings.append(Finding(
                    control_id  = "CIS-5.3.2",
                    title       = "Namespace has no NetworkPolicy",
                    status      = "FAIL",
                    detail      = f"Namespace '{ns}' has no NetworkPolicy defined — all traffic is permitted.",
                    remediation = "Define at least a default-deny NetworkPolicy and explicitly allow only required traffic.",
                    namespace   = ns,
                    tags        = ["network-policy", "network"],
                ))
            else:
                findings.append(Finding(
                    control_id  = "CIS-5.3.2",
                    title       = "Namespace has NetworkPolicy",
                    status      = "PASS",
                    detail      = f"Namespace '{ns}' has {len(policies)} NetworkPolicy/s defined.",
                    remediation = "",
                    namespace   = ns,
                    tags        = ["network-policy"],
                ))
        return findings
