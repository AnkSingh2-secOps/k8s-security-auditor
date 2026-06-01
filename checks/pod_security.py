"""checks/pod_security.py - CIS Kubernetes Benchmark: Pod security checks."""

from __future__ import annotations
from checks.rbac import Finding


class PodSecurityChecker:
    """
    CIS controls covered:
      5.2.1  Prefer not running containers as root
      5.2.2  Do not admit privileged containers
      5.2.3  Do not allow containers to share the host process ID namespace
      5.2.4  Do not allow containers to share the host IPC namespace
      5.2.5  Do not allow containers to use the host network namespace
      5.2.6  Minimise the admission of containers with allowPrivilegeEscalation
      5.2.9  Minimise the admission of containers with added capabilities
      5.4.1  Containers without resource limits
    """

    def run(self, namespace: str | None = None) -> list[Finding]:
        from kubernetes import client
        v1 = client.CoreV1Api()
        pods = (
            v1.list_namespaced_pod(namespace).items
            if namespace else
            v1.list_pod_for_all_namespaces().items
        )
        findings: list[Finding] = []
        for pod in pods:
            ns   = pod.metadata.namespace
            name = pod.metadata.name
            spec = pod.spec
            if not spec:
                continue

            # Host-level flags
            if spec.host_pid:
                findings.append(self._f("CIS-5.2.3", "Pod shares hostPID", "FAIL",
                    f"Pod '{ns}/{name}' has hostPID=true.",
                    "Set hostPID: false in the pod spec.", name, ns, ["host-pid"]))
            if spec.host_ipc:
                findings.append(self._f("CIS-5.2.4", "Pod shares hostIPC", "FAIL",
                    f"Pod '{ns}/{name}' has hostIPC=true.",
                    "Set hostIPC: false in the pod spec.", name, ns, ["host-ipc"]))
            if spec.host_network:
                findings.append(self._f("CIS-5.2.5", "Pod uses host network", "FAIL",
                    f"Pod '{ns}/{name}' has hostNetwork=true.",
                    "Set hostNetwork: false unless explicitly required.", name, ns, ["host-network"]))

            for ctr in (spec.containers or []) + (spec.init_containers or []):
                cname  = ctr.name
                label  = f"{ns}/{name}/{cname}"
                sc     = ctr.security_context

                if sc:
                    if sc.privileged:
                        findings.append(self._f("CIS-5.2.2", "Privileged container", "FAIL",
                            f"Container '{label}' runs with privileged=true.",
                            "Remove privileged flag; grant only required capabilities.", name, ns, ["privileged"]))
                    if sc.run_as_user == 0 or (sc.run_as_non_root is False):
                        findings.append(self._f("CIS-5.2.1", "Container running as root", "WARN",
                            f"Container '{label}' runs as root (runAsUser=0 or runAsNonRoot=false).",
                            "Set runAsNonRoot: true and specify a non-zero runAsUser.", name, ns, ["root"]))
                    if sc.allow_privilege_escalation is not False:
                        findings.append(self._f("CIS-5.2.6", "allowPrivilegeEscalation not disabled", "WARN",
                            f"Container '{label}' does not explicitly set allowPrivilegeEscalation=false.",
                            "Add allowPrivilegeEscalation: false to the container's securityContext.", name, ns, ["privesc"]))
                    caps = sc.capabilities
                    if caps and caps.add:
                        findings.append(self._f("CIS-5.2.9", "Container adds Linux capabilities", "WARN",
                            f"Container '{label}' adds capabilities: {caps.add}.",
                            "Drop all capabilities and add only what is strictly required.", name, ns, ["capabilities"]))
                else:
                    findings.append(self._f("CIS-5.2.1", "No securityContext defined", "WARN",
                        f"Container '{label}' has no securityContext.",
                        "Define a securityContext with runAsNonRoot, allowPrivilegeEscalation=false, and capabilities.drop=['ALL'].",
                        name, ns, ["no-secctx"]))

                # Resource limits
                res = ctr.resources
                if not res or not res.limits:
                    findings.append(self._f("CIS-5.4.1", "Container missing resource limits", "WARN",
                        f"Container '{label}' has no resource limits.",
                        "Set CPU and memory limits to prevent resource exhaustion.", name, ns, ["resource-limits"]))

        return findings

    @staticmethod
    def _f(cid, title, status, detail, remediation, resource, ns, tags) -> Finding:
        return Finding(
            control_id=cid, title=title, status=status, detail=detail,
            remediation=remediation, resource=resource, namespace=ns, tags=tags
        )
