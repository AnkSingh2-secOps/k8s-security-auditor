"""
checks/admission.py
Detects whether admission controllers are active:
  - OPA/Gatekeeper (CRDs + controller pod presence)
  - Kyverno (CRDs + controller pod presence)
  - Kubernetes native PodSecurity admission (labels on namespaces)

CIS Kubernetes Benchmark context: 5.7.1 - Create administrative boundaries
  between resources using namespaces; general best practice for admission control.
"""

from typing import Any

from kubernetes import client


def run_admission_checks(k8s_client: client.ApiClient) -> list[dict[str, Any]]:
    findings = []

    ext_api  = client.ApiextensionsV1Api(k8s_client)
    core_v1  = client.CoreV1Api(k8s_client)

    crds = {crd.metadata.name for crd in ext_api.list_custom_resource_definition().items}

    # OPA / Gatekeeper
    gatekeeper_crds = {
        "constrainttemplatepodstatuses.status.gatekeeper.sh",
        "constrainttemplates.templates.gatekeeper.sh",
        "configs.config.gatekeeper.sh",
    }
    if gatekeeper_crds & crds:
        gk_pod = _find_pod(core_v1, label_selector="control-plane=controller-manager",
                           name_fragment="gatekeeper")
        status = "ACTIVE" if gk_pod else "CRDs present, controller pod NOT found"
        findings.append({
            "control":  "AdmissionControl",
            "severity": "INFO",
            "status":   "PASS" if gk_pod else "WARN",
            "resource": "cluster",
            "detail":   f"OPA/Gatekeeper: {status}",
        })
    else:
        findings.append({
            "control":  "AdmissionControl",
            "severity": "WARN",
            "status":   "FAIL",
            "resource": "cluster",
            "detail":   "OPA/Gatekeeper not detected. Consider deploying a policy engine.",
        })

    # Kyverno
    kyverno_crds = {
        "clusterpolicies.kyverno.io",
        "policies.kyverno.io",
        "clusteradmissionreports.kyverno.io",
    }
    if kyverno_crds & crds:
        kv_pod = _find_pod(core_v1, label_selector="app.kubernetes.io/name=kyverno",
                           name_fragment="kyverno")
        status = "ACTIVE" if kv_pod else "CRDs present, controller pod NOT found"
        findings.append({
            "control":  "AdmissionControl",
            "severity": "INFO",
            "status":   "PASS" if kv_pod else "WARN",
            "resource": "cluster",
            "detail":   f"Kyverno: {status}",
        })

    # Native PodSecurity admission (PSA)
    namespaces = core_v1.list_namespace().items
    psa_enforced = [
        ns.metadata.name
        for ns in namespaces
        if ns.metadata.labels and any(
            k.startswith("pod-security.kubernetes.io/enforce") for k in ns.metadata.labels
        )
    ]
    if psa_enforced:
        findings.append({
            "control":  "AdmissionControl",
            "severity": "INFO",
            "status":   "PASS",
            "resource": "cluster",
            "detail":   f"Native PodSecurity Admission (PSA) enforce labels found on "
                        f"{len(psa_enforced)} namespace(s): {', '.join(psa_enforced[:5])}",
        })
    else:
        findings.append({
            "control":  "AdmissionControl",
            "severity": "WARN",
            "status":   "WARN",
            "resource": "cluster",
            "detail":   "No PodSecurity Admission enforce labels found on any namespace.",
        })

    return findings


def _find_pod(core_v1: client.CoreV1Api, label_selector: str, name_fragment: str) -> bool:
    try:
        pods = core_v1.list_pod_for_all_namespaces(label_selector=label_selector).items
        if pods:
            return True
        # Fallback: name fragment search
        all_pods = core_v1.list_pod_for_all_namespaces().items
        return any(name_fragment in (p.metadata.name or "") for p in all_pods)
    except Exception:
        return False
