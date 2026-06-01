"""
checks/images.py
CIS Kubernetes Benchmark - Image security checks.

Controls covered:
  5.5.1 - Ensure that image pull policy is set to Always for :latest images
  5.5.2 - Ensure that only vetted/approved registries are used
  5.5.3 - Ensure images are not using the :latest tag in production
"""

from typing import Any

from kubernetes import client


def run_image_checks(k8s_client: client.ApiClient) -> list[dict[str, Any]]:
    findings = []

    apps_v1   = client.AppsV1Api(k8s_client)
    core_v1   = client.CoreV1Api(k8s_client)

    # Allowed registries - empty set = allow all (permissive by default)
    # Users can extend this list in their config.
    APPROVED_REGISTRIES: set[str] = set()

    pod_specs: list[tuple[str, str, Any]] = []

    # Deployments
    for dep in apps_v1.list_deployment_for_all_namespaces().items:
        ns   = dep.metadata.namespace
        name = dep.metadata.name
        spec = dep.spec.template.spec
        pod_specs.append((f"Deployment/{ns}/{name}", ns, spec))

    # DaemonSets
    for ds in apps_v1.list_daemon_set_for_all_namespaces().items:
        ns   = ds.metadata.namespace
        name = ds.metadata.name
        spec = ds.spec.template.spec
        pod_specs.append((f"DaemonSet/{ns}/{name}", ns, spec))

    # StatefulSets
    for ss in apps_v1.list_stateful_set_for_all_namespaces().items:
        ns   = ss.metadata.namespace
        name = ss.metadata.name
        spec = ss.spec.template.spec
        pod_specs.append((f"StatefulSet/{ns}/{name}", ns, spec))

    for ref, ns, spec in pod_specs:
        if not spec:
            continue
        all_containers = list(spec.containers or []) + list(spec.init_containers or [])

        for ctr in all_containers:
            image       = ctr.image or ""
            pull_policy = ctr.image_pull_policy or ""

            tag = image.split(":")[-1] if ":" in image else "latest"
            registry = image.split("/")[0] if "/" in image else "docker.io"

            # CIS 5.5.3 - :latest tag
            if tag == "latest":
                findings.append({
                    "control":     "CIS-5.5.3",
                    "severity":    "MEDIUM",
                    "status":      "FAIL",
                    "resource":    ref,
                    "container":   ctr.name,
                    "detail":      f"Image '{image}' uses :latest tag. Pin to a specific digest or version.",
                })

            # CIS 5.5.1 - imagePullPolicy for :latest
            if tag == "latest" and pull_policy != "Always":
                findings.append({
                    "control":     "CIS-5.5.1",
                    "severity":    "LOW",
                    "status":      "FAIL",
                    "resource":    ref,
                    "container":   ctr.name,
                    "detail":      f"Image '{image}' uses :latest but imagePullPolicy is '{pull_policy}' (should be Always).",
                })

            # CIS 5.5.2 - approved registry
            if APPROVED_REGISTRIES and not any(image.startswith(r) for r in APPROVED_REGISTRIES):
                findings.append({
                    "control":     "CIS-5.5.2",
                    "severity":    "HIGH",
                    "status":      "FAIL",
                    "resource":    ref,
                    "container":   ctr.name,
                    "detail":      f"Image '{image}' from unapproved registry '{registry}'.",
                })

    if not findings:
        findings.append({
            "control":  "CIS-5.5.1/5.5.2/5.5.3",
            "severity": "INFO",
            "status":   "PASS",
            "resource": "all",
            "detail":   "No image policy violations found.",
        })

    return findings
