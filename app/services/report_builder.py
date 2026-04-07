"""Build markdown and JSON reports from analysis data."""

from __future__ import annotations

import json
from app.models.repo_analysis import RepoAnalysis


def build_markdown(analysis: RepoAnalysis) -> str:
    """Generate the markdown audit report."""
    lines: list[str] = []
    lines.append("# Audit Copilot Review\n")

    # Repo info
    lines.append("## Repo")
    lines.append(f"- URL: {analysis.repo_url}")
    lines.append(f"- Ref: {analysis.ref}")
    lines.append(f"- Commit: {analysis.commit}")
    lines.append(f"- Solidity files: {analysis.solidity_files}")
    lines.append(f"- Total files scanned: {analysis.files_scanned}")
    lines.append("")

    # High-level summary
    lines.append("## High-Level Summary")
    lines.append(f"- Contracts found: {len(analysis.contracts)}")
    lines.append(f"- Functions found: {len(analysis.functions)}")
    lines.append(f"- Risk flags raised: {len(analysis.risk_flags)}")

    # Count by severity
    sev_counts: dict[str, int] = {}
    for flag in analysis.risk_flags:
        sev_counts[flag.severity] = sev_counts.get(flag.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low"]:
        if sev in sev_counts:
            lines.append(f"  - {sev}: {sev_counts[sev]}")
    lines.append("")

    # Top risk flags
    high_flags = [f for f in analysis.risk_flags if f.severity in ("critical", "high")]
    if high_flags:
        lines.append("## Top Risk Flags")
        lines.append("*Source: Heuristic flag*")
        lines.append("")
        for i, flag in enumerate(high_flags[:20], 1):
            lines.append(f"{i}. **[{flag.severity.upper()}] {flag.category}** — "
                         f"`{flag.contract}.{flag.function}`")
            lines.append(f"   - {flag.evidence}")
            for check in flag.manual_validation:
                lines.append(f"   - [ ] {check}")
        lines.append("")

    # Contracts
    lines.append("## Contracts")
    for c in analysis.contracts:
        lines.append(f"### {c.name}")
        lines.append(f"- File: `{c.file_path}`")
        lines.append(f"- Kind: {c.kind}")
        if c.inherits:
            lines.append(f"- Inherits: {', '.join(c.inherits)}")
        lines.append(f"- Functions: {len(c.functions)}")
        lines.append(f"- State variables: {len(c.state_vars)}")
        lines.append(f"- Review priority: {c.review_priority}")
        if c.ai_summary:
            lines.append(f"- AI-generated review note *(manual validation required)*: {c.ai_summary}")
        lines.append("")

    # Functions requiring manual review
    flagged_fns = [f for f in analysis.functions if f.risk_tags]
    if flagged_fns:
        lines.append("## Functions Requiring Manual Review")
        lines.append("*Source: Heuristic flag*")
        lines.append("")
        for fn in flagged_fns:
            lines.append(f"### `{fn.contract}.{fn.signature}`")
            lines.append(f"- File: `{fn.file_path}`")
            lines.append(f"- Visibility: {fn.visibility}")
            lines.append(f"- Risk buckets: {', '.join(fn.risk_tags)}")
            if fn.ai_summary:
                lines.append(f"- AI-generated review note *(manual validation required)*: {fn.ai_summary}")
            if fn.manual_checks:
                lines.append("- Manual checks:")
                for check in fn.manual_checks:
                    lines.append(f"  - [ ] {check}")
            lines.append("")

    # All risk flags
    if analysis.risk_flags:
        lines.append("## All Risk Flags")
        lines.append("*Source: Heuristic flag*")
        lines.append("")
        for flag in analysis.risk_flags:
            lines.append(f"### [{flag.severity.upper()}] {flag.category} — `{flag.contract}.{flag.function}`")
            lines.append(f"- Evidence: {flag.evidence}")
            lines.append(f"- Explanation: {flag.explanation}")
            lines.append(f"- Source: {flag.source}")
            if flag.manual_validation:
                lines.append("- Manual validation required:")
                for step in flag.manual_validation:
                    lines.append(f"  - [ ] {step}")
            lines.append("")

    # Value Movement Review (replaces Fund Flow Analysis)
    vm = analysis.value_movements
    if vm.edges:
        lines.append("## Value Movement Review")
        lines.append("*Source: Parsed fact*")
        lines.append("")
        for s in vm.summary:
            lines.append(f"- {s}")
        lines.append("")
        lines.append("### Value Movement Edges")
        lines.append("| Contract | Function | Direction | Asset | Destination | "
                      "Caller Influenced | Access Controlled | Manual Checks |")
        lines.append("|----------|----------|-----------|-------|-------------|"
                      "-------------------|-------------------|---------------|")
        for edge in vm.edges:
            checks_str = "; ".join(edge.manual_checks[:2]) if edge.manual_checks else ""
            lines.append(
                f"| `{edge.contract}` | `{edge.function}` | {edge.direction} | "
                f"{edge.asset_type} | {edge.destination_hint or '-'} | "
                f"{'Yes' if edge.caller_influenced else 'No'} | "
                f"{'Yes' if edge.access_controlled else 'No'} | "
                f"{checks_str} |"
            )
        lines.append("")

    # Review Properties Checklist (replaces Invariant Analysis)
    rp = analysis.review_properties
    if rp.properties:
        lines.append("## Review Properties Checklist")
        lines.append("*Source: Heuristic flag + AI-generated review note*")
        lines.append("")
        for s in rp.summary:
            lines.append(f"*{s}*")
        lines.append("")
        for i, prop in enumerate(rp.properties, 1):
            lines.append(f"### Property {i}: {prop.statement}")
            lines.append(f"- Kind: {prop.kind}")
            lines.append(f"- Rationale: {prop.rationale}")
            lines.append(f"- Confidence: {prop.confidence}")
            lines.append(f"- Source type: {prop.source_type}")
            if prop.confidence_basis:
                lines.append(f"- Confidence basis: {prop.confidence_basis}")
            if prop.evidence_refs:
                lines.append(f"- Evidence: {', '.join(f'`{r}`' for r in prop.evidence_refs)}")
            if prop.related_functions:
                lines.append(f"- Related functions: {', '.join(f'`{f}`' for f in prop.related_functions)}")
            if prop.manual_checks:
                lines.append("- Manual validation required:")
                for check in prop.manual_checks:
                    lines.append(f"  - [ ] {check}")
            lines.append("")

    # Risk Scenarios for Manual Validation (replaces Attack Surface Analysis)
    rs = analysis.risk_scenarios
    if rs.scenarios:
        lines.append("## Risk Scenarios for Manual Validation")
        lines.append("*Source: AI-generated review note*")
        lines.append("")
        for s in rs.summary:
            lines.append(f"*{s}*")
        lines.append("")

        # Group by severity
        for sev in ["high", "medium", "low"]:
            sev_scenarios = [s for s in rs.scenarios if s.severity_hint == sev]
            if not sev_scenarios:
                continue
            lines.append(f"### {sev.upper()} Priority Scenarios")
            for scenario in sev_scenarios:
                lines.append(f"#### {scenario.title}")
                lines.append(f"- Category: {scenario.category}")
                lines.append(f"- Source type: {scenario.source_type}")
                if scenario.confidence_basis:
                    lines.append(f"- Confidence basis: {scenario.confidence_basis}")
                if scenario.evidence_refs:
                    lines.append(f"- Evidence: {', '.join(f'`{r}`' for r in scenario.evidence_refs)}")
                lines.append(f"- Why it matters: {scenario.why_it_matters}")
                if scenario.affected_functions:
                    lines.append(f"- Affected: {', '.join(f'`{f}`' for f in scenario.affected_functions)}")
                lines.append(f"- Risky assumption: {scenario.risky_assumption}")
                if scenario.manual_validation_steps:
                    lines.append("- Manual validation required:")
                    for step in scenario.manual_validation_steps:
                        lines.append(f"  - [ ] {step}")
                if scenario.remediation_themes:
                    lines.append("- Remediation themes:")
                    for theme in scenario.remediation_themes:
                        lines.append(f"  - {theme}")
                lines.append("")

    # Notes
    if analysis.notes:
        lines.append("## Notes")
        for note in analysis.notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Audit Copilot. All AI outputs require manual validation.*")
    lines.append("")
    lines.append("**Label key:** Every item is labeled as one of: "
                  "Parsed fact | Heuristic flag | AI-generated review note | Manual validation required")
    return "\n".join(lines)


def build_json(analysis: RepoAnalysis) -> str:
    """Return the full analysis as formatted JSON."""
    return analysis.model_dump_json(indent=2)


def build_csv_findings(analysis: RepoAnalysis) -> str:
    """Return risk flags as CSV."""
    header = "severity,category,contract,function,file_path,evidence,source"
    rows = [header]
    for f in analysis.risk_flags:
        evidence = f.evidence.replace('"', '""')
        rows.append(
            f'{f.severity},{f.category},{f.contract},{f.function},'
            f'{f.file_path},"{evidence}",{f.source}'
        )
    return "\n".join(rows)
