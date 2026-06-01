"""
k8s-security-auditor · audit.py  (v2)
CLI entry point.

Usage:
    python audit.py
    python audit.py --namespace production
    python audit.py --output report.html
    python audit.py --kubeconfig /path/to/kubeconfig --output report.json --output-format json
    python audit.py --output report.json --output-format json  # save baseline
    python audit.py --diff baseline.json --output report.json  # compare to baseline
"""

import argparse
import json
import sys
from pathlib import Path

from checks.rbac          import RBACChecker
from checks.pod_security  import PodSecurityChecker
from checks.network       import NetworkPolicyChecker
from checks.secrets       import SecretsChecker
from checks.images        import run_image_checks
from checks.admission     import run_admission_checks
from core.diff            import diff_audits, format_diff_markdown
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
    parser.add_argument("--output-format", choices=["html", "json", "markdown"],
                        default="html", help="Report format (default: html).")
    parser.add_argument("--diff", default=None, metavar="BASELINE_JSON",
                        help="Compare a previous JSON audit report against this run.")
    parser.add_argument("--skip-images",    action="store_true",
                        help="Skip image registry/tag checks.")
    parser.add_argument("--skip-admission", action="store_true",
                        help="Skip admission controller detection checks.")
    args = parser.parse_args()

    try:
        from kubernetes import config as k8s_config, client as k8s_client_module
        if args.kubeconfig:
            k8s_config.load_kube_config(config_file=args.kubeconfig)
        else:
            try:
                k8s_config.load_incluster_config()
            except k8s_config.ConfigException:
                k8s_config.load_kube_config()
        k8s_api_client = k8s_client_module.ApiClient()
    except Exception as exc:
        print(f"[ERROR] Could not load kubeconfig: {exc}", file=sys.stderr)
        sys.exit(1)

    namespace = args.namespace
    findings  = []

    print("[*] Running RBAC checks...",                  file=sys.stderr)
    findings += RBACChecker().run(namespace)

    print("[*] Running pod security checks...",           file=sys.stderr)
    findings += PodSecurityChecker().run(namespace)

    print("[*] Running network policy checks...",         file=sys.stderr)
    findings += NetworkPolicyChecker().run(namespace)

    print("[*] Running secrets/configuration checks...",  file=sys.stderr)
    findings += SecretsChecker().run(namespace)

    if not args.skip_images:
        print("[*] Running image security checks...",     file=sys.stderr)
        findings += run_image_checks(k8s_api_client)

    if not args.skip_admission:
        print("[*] Detecting admission controllers...",   file=sys.stderr)
        findings += run_admission_checks(k8s_api_client)

    reporter = Reporter(findings)

    # ── Diff mode ─────────────────────────────────────────────────────────────
    if args.diff:
        # First save current run as JSON so diff can read it
        tmp_path = Path(args.output or "audit-current.json")
        tmp_path.write_text(
            json.dumps({"findings": findings}, indent=2), encoding="utf-8"
        )
        baseline_path = Path(args.diff)
        if not baseline_path.exists():
            print(f"[ERROR] Baseline file not found: {baseline_path}", file=sys.stderr)
            sys.exit(1)
        diff = diff_audits(baseline_path, tmp_path)
        diff_md = format_diff_markdown(diff)
        print(diff_md)
        if args.output:
            Path(args.output).with_suffix(".diff.md").write_text(diff_md, encoding="utf-8")
            print(f"[+] Diff report -> {Path(args.output).with_suffix('.diff.md')}", file=sys.stderr)
        sys.exit(0)

    report = reporter.render(fmt=args.output_format)

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
