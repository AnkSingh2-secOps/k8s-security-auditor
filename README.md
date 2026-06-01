# K8s Security Auditor

Connects to a live Kubernetes cluster and runs a suite of security checks against CIS Kubernetes Benchmark controls. Covers RBAC, pod security, network policies, secrets handling, image hygiene, and admission controller posture. Outputs HTML, JSON, or Markdown reports.

## Usage

```bash
pip install -r requirements.txt

# Audit all namespaces
python audit.py --output report.html

# Specific namespace, JSON output
python audit.py --namespace production --output-format json --output report.json

# Custom kubeconfig
python audit.py --kubeconfig /path/to/kubeconfig --output report.html

# Compare against a previous run (diff mode)
python audit.py --output current.json --output-format json
python audit.py --diff baseline.json --output current.json
```

Exit code is 1 if any FAIL findings are present, 0 otherwise. This lets you gate CI/CD pipelines on audit results.

## CIS controls covered

| Control | Description |
|---------|-------------|
| CIS-5.1.1 | Cluster-admin role bindings |
| CIS-5.1.2 | Access to Secrets in ClusterRoles |
| CIS-5.1.3 | Wildcard permissions in Roles and ClusterRoles |
| CIS-5.1.6 | Default service account bindings |
| CIS-5.2.1 | Containers running as root |
| CIS-5.2.2 | Privileged containers |
| CIS-5.2.3 | hostPID sharing |
| CIS-5.2.4 | hostIPC sharing |
| CIS-5.2.5 | hostNetwork sharing |
| CIS-5.2.6 | allowPrivilegeEscalation not disabled |
| CIS-5.2.9 | Added Linux capabilities |
| CIS-5.3.2 | Namespaces missing NetworkPolicy |
| CIS-5.4.1 | Containers without resource limits |
| CIS-5.4.2 | Plaintext secrets in environment variables |
| CIS-5.5.1 | imagePullPolicy not set to Always for latest images |
| CIS-5.5.3 | Images using the :latest tag |
| AdmCtrl | OPA/Gatekeeper, Kyverno, PodSecurity admission detection |

## Output

HTML report: colour-coded table per control with FAIL/WARN/PASS status, remediation notes, and affected resources.

JSON output: machine-readable findings list, suitable for ingestion into a SIEM or storage as a baseline for diff mode.

Diff mode: compares a previous JSON run against the current one and reports new failures (regressions), fixed findings, and persisting issues with a trend summary.

## Requirements

- Python 3.10+
- kubernetes (official Python client)
- A valid kubeconfig or in-cluster service account
