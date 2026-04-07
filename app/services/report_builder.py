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
            lines.append(f"- AI summary *(manual validation required)*: {c.ai_summary}")
        lines.append("")

    # Functions requiring manual review
    flagged_fns = [f for f in analysis.functions if f.risk_tags]
    if flagged_fns:
        lines.append("## Functions Requiring Manual Review")
        for fn in flagged_fns:
            lines.append(f"### `{fn.contract}.{fn.signature}`")
            lines.append(f"- File: `{fn.file_path}`")
            lines.append(f"- Visibility: {fn.visibility}")
            lines.append(f"- Risk buckets: {', '.join(fn.risk_tags)}")
            if fn.ai_summary:
                lines.append(f"- AI summary *(manual validation required)*: {fn.ai_summary}")
            if fn.manual_checks:
                lines.append("- Manual checks:")
                for check in fn.manual_checks:
                    lines.append(f"  - [ ] {check}")
            lines.append("")

    # All risk flags
    if analysis.risk_flags:
        lines.append("## All Risk Flags")
        for flag in analysis.risk_flags:
            lines.append(f"### [{flag.severity.upper()}] {flag.category} — `{flag.contract}.{flag.function}`")
            lines.append(f"- Evidence: {flag.evidence}")
            lines.append(f"- Explanation: {flag.explanation}")
            lines.append(f"- Source: {flag.source}")
            if flag.manual_validation:
                lines.append("- Validation steps:")
                for step in flag.manual_validation:
                    lines.append(f"  - [ ] {step}")
            lines.append("")

    # Fund Flow Analysis
    ff = analysis.fund_flows
    if ff.edges:
        lines.append("## Fund Flow Analysis")
        lines.append("")
        if ff.entry_points:
            lines.append("### Value Entry Points (money IN)")
            for ep in ff.entry_points:
                lines.append(f"- `{ep}`")
            lines.append("")
        if ff.exit_points:
            lines.append("### Value Exit Points (money OUT)")
            for ep in ff.exit_points:
                marker = " **[UNGUARDED]**" if ep in ff.unguarded_exits else ""
                lines.append(f"- `{ep}`{marker}")
            lines.append("")
        if ff.unguarded_exits:
            lines.append("### Unguarded Exit Points")
            for ue in ff.unguarded_exits:
                lines.append(f"- `{ue}` — no access control detected on value outflow")
            lines.append("")
        lines.append("### Flow Edges")
        lines.append("| From | To | Mechanism | Token | Recipient | Guarded | Reentrancy Safe |")
        lines.append("|------|----|-----------|-------|-----------|---------|-----------------|")
        for edge in ff.edges:
            src = f"{edge.source_contract}.{edge.source_function}" if edge.source_function else edge.source_contract
            sink = f"{edge.sink_contract}.{edge.sink_function}" if edge.sink_function else edge.sink_contract
            lines.append(
                f"| `{src}` | `{sink}` | {edge.mechanism} | "
                f"{edge.token} | {edge.recipient} | "
                f"{'Yes' if edge.guarded else 'No'} | "
                f"{'Yes' if edge.reentrancy_safe else 'No'} |"
            )
        lines.append("")

    # Invariant Analysis
    inv = analysis.invariants
    if inv.invariants:
        lines.append("## Invariant Analysis")
        lines.append(f"*{inv.summary}*")
        lines.append("")
        for i, invariant in enumerate(inv.invariants, 1):
            threatened = " **THREATENED**" if invariant.threatened_by else ""
            lines.append(f"### Invariant {i}: {invariant.description}{threatened}")
            lines.append(f"- Kind: {invariant.kind}")
            lines.append(f"- Confidence: {invariant.confidence}")
            lines.append(f"- Evidence: {invariant.evidence}")
            if invariant.threatened_by:
                lines.append(f"- Threatened by: {', '.join(f'`{t}`' for t in invariant.threatened_by)}")
            if invariant.manual_checks:
                lines.append("- Manual checks:")
                for check in invariant.manual_checks:
                    lines.append(f"  - [ ] {check}")
            lines.append("")

    # Attack Surface Analysis
    atk = analysis.attack_surface
    if atk.paths:
        lines.append("## Attack Surface Analysis")
        lines.append(f"*{atk.summary}*")
        lines.append("")

        # Group by severity
        for sev in ["critical", "high", "medium", "low"]:
            sev_paths = [p for p in atk.paths if p.severity == sev]
            if not sev_paths:
                continue
            lines.append(f"### {sev.upper()} Severity Paths")
            for path in sev_paths:
                lines.append(f"#### [{path.id}] {path.title}")
                lines.append(f"- Category: {path.risk_category}")
                lines.append(f"- Affected: {', '.join(f'`{f}`' for f in path.affected_functions)}")
                lines.append(f"- Consequence: {path.consequence}")
                lines.append(f"- Likelihood: {path.likelihood}")
                if path.preconditions:
                    lines.append("- Preconditions:")
                    for pre in path.preconditions:
                        lines.append(f"  - {pre}")
                lines.append(f"- Why concerning: {path.why_concerning}")
                lines.append(f"- Existing mitigations: {path.what_prevents_it}")
                if path.validation_steps:
                    lines.append("- Validation steps:")
                    for step in path.validation_steps:
                        lines.append(f"  - [ ] {step}")
                lines.append("")

    # Notes
    if analysis.notes:
        lines.append("## Notes")
        for note in analysis.notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Audit Copilot. All AI outputs require manual validation.*")
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
