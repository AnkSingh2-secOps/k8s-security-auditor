"""checks/secrets.py - Secrets and service account token checks."""

from __future__ import annotations
from checks.rbac import Finding


class SecretsChecker:
    """
    CIS controls covered:
      5.1.6  Avoid auto-mounting service account tokens
      5.4.2  Containers should not expose sensitive information in environment variables
    """

    _SENSITIVE_PATTERNS = (
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "access_key", "private_key", "credentials",
    )

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

            # Auto-mounted service account token
            if spec.automount_service_account_token is not False:
                findings.append(Finding(
                    control_id  = "CIS-5.1.6",
                    title       = "Service account token auto-mounted",
                    status      = "WARN",
                    detail      = f"Pod '{ns}/{name}' does not explicitly disable automountServiceAccountToken.",
                    remediation = "Set automountServiceAccountToken: false on the pod spec (or service account) if the application does not need API access.",
                    resource    = name,
                    namespace   = ns,
                    tags        = ["service-account", "secrets"],
                ))

            # Sensitive env var names with literal values
            for ctr in (spec.containers or []) + (spec.init_containers or []):
                for env in (ctr.env or []):
                    if env.value and any(p in (env.name or "").lower() for p in self._SENSITIVE_PATTERNS):
                        findings.append(Finding(
                            control_id  = "CIS-5.4.2",
                            title       = "Potentially sensitive env var with plain-text value",
                            status      = "FAIL",
                            detail      = f"Container '{ns}/{name}/{ctr.name}' has env var '{env.name}' with a literal value (not a Secret ref).",
                            remediation = "Store credentials in Kubernetes Secrets or an external vault and reference them via secretKeyRef or a mounted volume.",
                            resource    = name,
                            namespace   = ns,
                            tags        = ["secrets", "credentials"],
                        ))

        return findings
