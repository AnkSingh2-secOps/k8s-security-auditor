"""
core/diff.py
Compares two JSON audit reports (current vs baseline) and surfaces:
  - New failures (regressions)
  - Fixed findings (improvements)
  - Unchanged failures (persisting issues)

Usage:
    python audit.py --baseline baseline.json --output-format json > current.json
    python audit.py --diff baseline.json --input current.json
"""

import json
from pathlib import Path
from typing import Any


def _finding_key(finding: dict) -> str:
    """Stable key for deduplication across runs."""
    return "|".join([
        finding.get("control", ""),
        finding.get("resource", ""),
        finding.get("container", ""),
        finding.get("detail", ""),
    ])


def load_findings_from_report(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # Support both {"findings": [...]} and [...]
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def diff_audits(baseline_path: Path, current_path: Path) -> dict[str, Any]:
    baseline_findings = load_findings_from_report(baseline_path)
    current_findings  = load_findings_from_report(current_path)

    baseline_fails = {
        _finding_key(f): f
        for f in baseline_findings
        if f.get("status") in ("FAIL", "WARN")
    }
    current_fails = {
        _finding_key(f): f
        for f in current_findings
        if f.get("status") in ("FAIL", "WARN")
    }

    new_failures   = {k: v for k, v in current_fails.items()  if k not in baseline_fails}
    fixed          = {k: v for k, v in baseline_fails.items() if k not in current_fails}
    persisting     = {k: v for k, v in current_fails.items()  if k in baseline_fails}

    return {
        "baseline_path":       str(baseline_path),
        "current_path":        str(current_path),
        "baseline_fail_count": len(baseline_fails),
        "current_fail_count":  len(current_fails),
        "new_failures":        list(new_failures.values()),
        "fixed_findings":      list(fixed.values()),
        "persisting_failures": list(persisting.values()),
        "trend":               _trend(len(baseline_fails), len(current_fails)),
    }


def _trend(baseline_count: int, current_count: int) -> str:
    if current_count > baseline_count:
        delta = current_count - baseline_count
        return f"WORSE (+{delta} new failure(s))"
    if current_count < baseline_count:
        delta = baseline_count - current_count
        return f"IMPROVED (-{delta} failure(s) fixed)"
    return "NO CHANGE"


def format_diff_markdown(diff: dict[str, Any]) -> str:
    lines = [
        "# Kubernetes Audit Diff Report",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Baseline failures | {diff['baseline_fail_count']} |",
        f"| Current failures  | {diff['current_fail_count']} |",
        f"| Trend             | **{diff['trend']}** |",
        f"| New failures      | {len(diff['new_failures'])} |",
        f"| Fixed findings    | {len(diff['fixed_findings'])} |",
        f"| Persisting        | {len(diff['persisting_failures'])} |",
        "",
    ]

    if diff["new_failures"]:
        lines += ["## New Failures (Regressions)", ""]
        for f in diff["new_failures"]:
            lines.append(f"- **[{f['control']}]** `{f['resource']}` – {f['detail']}")
        lines.append("")

    if diff["fixed_findings"]:
        lines += ["## Fixed Findings", ""]
        for f in diff["fixed_findings"]:
            lines.append(f"- **[{f['control']}]** `{f['resource']}` – {f['detail']}")
        lines.append("")

    if diff["persisting_failures"]:
        lines += ["## Persisting Failures", ""]
        for f in diff["persisting_failures"]:
            sev = f.get("severity", "")
            lines.append(f"- **[{f['control']}]** `{sev}` `{f['resource']}` – {f['detail']}")
        lines.append("")

    return "\n".join(lines)
