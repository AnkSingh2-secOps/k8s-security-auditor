"""
k8s-security-auditor · audit.py
CLI entry point.

Usage:
    python audit.py
    python audit.py --namespace production
    python audit.py --output report.html
    python audit.py --kubeconfig /path/to/kubeconfig --output report.json --format json
"""

import argparse
import sys

from checks.rbac          import RBACChecker
from checks.pod_security  import PodSecurityChecker
from checks.network       import NetworkPolicyChecker
from checks.secrets       import SecretsChecker
from report.reporter      import Reporter


def main():
    parser = argparse.ArgumentParser(
        description="CIS Kubernetes Benchmark security auditor."
    )
    parser.add_argument("--kubeconfig", default=None,
                        help="Path to kubeconfig (defaults to in-cluster or ~/.kube/config).")
    parser.add_argument("--namespace", "-n", default=None,
                        help="Audit a specific namespace only (default: all namespaces).")
    parser.add_argument("--output", "-o", default=None,
                        help="Write report to this file (default: stdout).")
    parser.add_argument("--format", choices=["html", "json", "markdown"],
                        default="html", help="Report format (default: html).")
    args = parser.parse_args()

    try:
        from kubernetes import config as k8s_config, client
        if args.kubeconfig:
            k8s_config.load_kube_config(config_file=args.kubeconfig)
        else:
            try:
                k8s_config.load_incluster_config()
            except k8s_config.ConfigException:
                k8s_config.load_kube_config()
    except Exception as exc:
        print(f"[ERROR] Could not load kubeconfig: {exc}", file=sys.stderr)
        sys.exit(1)

    namespace = args.namespace
    findings  = []

    print("[*] Running RBAC checks...",             file=sys.stderr)
    findings += RBACChecker().run(namespace)

    print("[*] Running pod security checks...",      file=sys.stderr)
    findings += PodSecurityChecker().run(namespace)

    print("[*] Running network policy checks...",    file=sys.stderr)
    findings += NetworkPolicyChecker().run(namespace)

    print("[*] Running secrets/configuration checks...", file=sys.stderr)
    findings += SecretsChecker().run(namespace)

    reporter = Reporter(findings)
    report   = reporter.render(fmt=args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[+] Report written to: {args.output}", file=sys.stderr)
    else:
        print(report)

    totals   = reporter.summary()
    failures = totals.get("FAIL", 0)
    print(f"\n[*] Summary: {totals}", file=sys.stderr)
    sys.exit(1 if failures > 0 else 0)


if __name__ == "__main__":
    main()
