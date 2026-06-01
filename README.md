# K8s Security Auditor

CIS Kubernetes Benchmark security auditor. Connects to a live cluster, runs a suite of security checks across RBAC, pod security, network policies, and secrets management, and produces a structured HTML, JSON, or Markdown report.

---

## Usage

```bash
pip install -r requirements.txt

# Audit all namespaces (uses ~/.kube/config or in-cluster config)
python audit.py --output report.html

# Audit a specific namespace
python audit.py --namespace production --output report.html

# Custom kubeconfig path
python audit.py --kubeconfig /path/to/kubeconfig --format json --output report.json

# Markdown output
python audit.py --format markdown --output report.md
```

Exit code is `1` if any FAIL findings are present, `0` otherwise — suitable for CI/CD gates.

---

## CIS Controls covered

| Control ID | Description |
|-----------|-------------|
| CIS-5.1.1 | Cluster-admin bindings audit |
| CIS-5.1.2 | Minimise access to Secrets in ClusterRoles |
| CIS-5.1.3 | Wildcard permissions in Roles and ClusterRoles |
| CIS-5.1.6 | Default service account bindings + token auto-mount |
| CIS-5.2.1 | Containers running as root |
| CIS-5.2.2 | Privileged containers |
| CIS-5.2.3 | hostPID sharing |
| CIS-5.2.4 | hostIPC sharing |
| CIS-5.2.5 | hostNetwork sharing |
| CIS-5.2.6 | allowPrivilegeEscalation not disabled |
| CIS-5.2.9 | Containers with added Linux capabilities |
| CIS-5.3.2 | Namespaces missing NetworkPolicy |
| CIS-5.4.1 | Containers without resource limits |
| CIS-5.4.2 | Sensitive environment variables with plain-text values |

---

## Output

**HTML report** — colour-coded table with FAIL / WARN / PASS per control, remediation guidance, and affected resources.

**Summary line (stderr):**
```
[*] Summary: {'FAIL': 3, 'WARN': 12, 'PASS': 8}
```

---

## Project structure

```
k8s-security-auditor/
├── audit.py                # CLI entry point
├── checks/
│   ├── rbac.py             # RBAC checks (CIS 5.1.x)
│   ├── pod_security.py     # Pod security checks (CIS 5.2.x)
│   ├── network.py          # Network policy checks (CIS 5.3.x)
│   └── secrets.py          # Secrets & SA token checks (CIS 5.4.x)
├── report/
│   └── reporter.py         # HTML / JSON / Markdown report renderer
└── requirements.txt
```

---

## Requirements

- Python 3.10+
- `kubernetes` (official Python client)
- A valid kubeconfig or in-cluster service account
