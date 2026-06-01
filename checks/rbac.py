"""checks/rbac.py – CIS Kubernetes Benchmark: RBAC checks."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    control_id:   str
    title:        str
    status:       str          # PASS | FAIL | WARN | INFO
    detail:       str
    remediation:  str
    resource:     str = ""
    namespace:    str = ""
    tags:         list[str] = field(default_factory=list)


class RBACChecker:
    """
    CIS controls covered:
      5.1.1  Ensure that cluster-admin role is only used where required
      5.1.2  Minimise access to secrets
      5.1.3  Minimise wildcard use in Roles and ClusterRoles
      5.1.6  Ensure that default service accounts are not bound to active roles
    """

    def run(self, namespace: str | None = None) -> list[Finding]:
        from kubernetes import client
        rbac   = client.RbacAuthorizationV1Api()
        findings: list[Finding] = []

        # 5.1.1 – cluster-admin bindings
        findings += self._check_cluster_admin(rbac)

        # 5.1.2 & 5.1.3 – wildcard / secrets access in ClusterRoles
        findings += self._check_clusterrole_permissions(rbac)

        # 5.1.6 – default service account bindings
        findings += self._check_default_sa_bindings(rbac, namespace)

        return findings

    # ── helpers ──────────────────────────────────────────────────────────────

    def _check_cluster_admin(self, rbac) -> list[Finding]:
        findings = []
        for crb in rbac.list_cluster_role_binding().items:
            if crb.role_ref.name != "cluster-admin":
                continue
            subjects = crb.subjects or []
            for sub in subjects:
                if sub.kind == "ServiceAccount":
                    findings.append(Finding(
                        control_id  = "CIS-5.1.1",
                        title       = "Service account bound to cluster-admin",
                        status      = "FAIL",
                        detail      = f"ServiceAccount '{sub.namespace}/{sub.name}' has cluster-admin via '{crb.metadata.name}'.",
                        remediation = "Remove the cluster-admin binding and grant only the minimum required permissions.",
                        resource    = crb.metadata.name,
                        tags        = ["rbac", "privilege-escalation"],
                    ))
                elif sub.kind in ("User", "Group") and sub.name not in ("system:masters",):
                    findings.append(Finding(
                        control_id  = "CIS-5.1.1",
                        title       = "Non-system principal bound to cluster-admin",
                        status      = "WARN",
                        detail      = f"{sub.kind} '{sub.name}' has cluster-admin via '{crb.metadata.name}'.",
                        remediation = "Audit whether this principal genuinely requires cluster-wide admin access.",
                        resource    = crb.metadata.name,
                        tags        = ["rbac"],
                    ))
        if not findings:
            findings.append(Finding(
                control_id  = "CIS-5.1.1",
                title       = "cluster-admin bindings",
                status      = "PASS",
                detail      = "No unexpected cluster-admin bindings found.",
                remediation = "",
                tags        = ["rbac"],
            ))
        return findings

    def _check_clusterrole_permissions(self, rbac) -> list[Finding]:
        findings = []
        for cr in rbac.list_cluster_role().items:
            name = cr.metadata.name
            if name.startswith("system:"):
                continue
            rules = cr.rules or []
            for rule in rules:
                resources = rule.resources or []
                verbs      = rule.verbs or []
                # 5.1.3 wildcard
                if "*" in resources or "*" in verbs:
                    findings.append(Finding(
                        control_id  = "CIS-5.1.3",
                        title       = "Wildcard permission in ClusterRole",
                        status      = "FAIL",
                        detail      = f"ClusterRole '{name}' uses wildcard in resources={resources} or verbs={verbs}.",
                        remediation = "Replace wildcards with explicit resource and verb lists.",
                        resource    = name,
                        tags        = ["rbac", "least-privilege"],
                    ))
                # 5.1.2 secrets access
                if "secrets" in resources and any(v in verbs for v in ("get", "list", "watch", "*")):
                    findings.append(Finding(
                        control_id  = "CIS-5.1.2",
                        title       = "ClusterRole grants access to Secrets",
                        status      = "WARN",
                        detail      = f"ClusterRole '{name}' can read Secrets (verbs: {verbs}).",
                        remediation = "Restrict Secret access to the minimum required namespaces and principals.",
                        resource    = name,
                        tags        = ["rbac", "secrets"],
                    ))
        return findings

    def _check_default_sa_bindings(self, rbac, namespace) -> list[Finding]:
        findings = []
        bindings = (
            rbac.list_namespaced_role_binding(namespace).items
            if namespace else
            rbac.list_role_binding_for_all_namespaces().items
        )
        for rb in bindings:
            for sub in (rb.subjects or []):
                if sub.kind == "ServiceAccount" and sub.name == "default":
                    findings.append(Finding(
                        control_id  = "CIS-5.1.6",
                        title       = "Default service account has active role binding",
                        status      = "FAIL",
                        detail      = f"RoleBinding '{rb.metadata.namespace}/{rb.metadata.name}' binds role '{rb.role_ref.name}' to the default SA.",
                        remediation = "Create dedicated service accounts for workloads and remove bindings from the default SA.",
                        resource    = rb.metadata.name,
                        namespace   = rb.metadata.namespace or "",
                        tags        = ["rbac", "service-account"],
                    ))
        return findings
