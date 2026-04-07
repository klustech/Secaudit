"""Gradio frontend for Audit Copilot — lightweight iPad-friendly UI."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import gradio as gr
import httpx

# Allow importing from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.safety_filter import sanitize_text, sanitize_dict

API_BASE = "http://localhost:8000"


def start_analysis(repo_url: str, ref: str, docs_url: str, scope_notes: str):
    """Submit a repo for analysis and poll until complete."""
    if not repo_url.strip():
        return "Please enter a GitHub repo URL.", "", "", "", "", ""

    payload = {
        "repo_url": repo_url.strip(),
        "ref": ref.strip() or "main",
        "docs_url": docs_url.strip(),
        "scope_notes": scope_notes.strip(),
    }

    try:
        resp = httpx.post(f"{API_BASE}/analyze", json=payload, timeout=30.0)
        resp.raise_for_status()
        result = resp.json()
        job_id = result["job_id"]
    except Exception as e:
        return f"Error starting analysis: {e}", "", "", "", "", ""

    # Poll for completion
    status = {}
    for _ in range(120):  # up to ~4 minutes
        time.sleep(2)
        try:
            status_resp = httpx.get(f"{API_BASE}/jobs/{job_id}", timeout=10.0)
            status = status_resp.json()
            if status["status"] in ("completed", "error"):
                break
        except Exception:
            continue

    if status.get("status") == "error":
        return f"Analysis failed: {status.get('error', 'unknown error')}", "", "", "", "", ""

    # Fetch results
    try:
        summary_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/summary", timeout=10.0)
        summary = json.dumps(sanitize_dict(summary_resp.json()), indent=2)

        report_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/report.md", timeout=10.0)
        report_md = sanitize_text(report_resp.text)

        flags_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/flags", timeout=10.0)
        flags_data = flags_resp.json().get("flags", [])
        flags_table = sanitize_text(_flags_to_table(flags_data))

        # Fetch new analysis tabs
        vm_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/value-movements", timeout=10.0)
        vm_table = sanitize_text(_value_movements_to_table(vm_resp.json().get("edges", [])))

        rp_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/review-properties", timeout=10.0)
        rp_md = sanitize_text(_review_properties_to_md(rp_resp.json().get("properties", [])))

        rs_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/risk-scenarios", timeout=10.0)
        rs_md = sanitize_text(_risk_scenarios_to_md(rs_resp.json().get("scenarios", [])))

        return summary, report_md, flags_table, vm_table, rp_md, rs_md, job_id
    except Exception as e:
        return f"Error fetching results: {e}", "", "", "", "", "", job_id


def _flags_to_table(flags: list[dict]) -> str:
    """Format flags as a markdown table."""
    if not flags:
        return "No risk flags found."
    lines = ["| Severity | Category | Contract | Function | Evidence |",
             "|----------|----------|----------|----------|----------|"]
    for f in flags:
        lines.append(
            f"| {f['severity']} | {f['category']} | {f['contract']} | "
            f"{f['function']} | {f['evidence'][:80]} |"
        )
    return "\n".join(lines)


def _value_movements_to_table(edges: list[dict]) -> str:
    """Format value movement edges as a markdown table."""
    if not edges:
        return "No value movements detected."
    lines = [
        "| Contract | Function | Direction | Asset | Destination | "
        "Caller Influenced | Access Controlled | Manual Checks |",
        "|----------|----------|-----------|-------|-------------|"
        "-------------------|-------------------|---------------|",
    ]
    for e in edges:
        checks = "; ".join(e.get("manual_checks", [])[:2])
        lines.append(
            f"| {e.get('contract', '')} | {e.get('function', '')} | "
            f"{e.get('direction', '')} | {e.get('asset_type', '')} | "
            f"{e.get('destination_hint', '-') or '-'} | "
            f"{'Yes' if e.get('caller_influenced') else 'No'} | "
            f"{'Yes' if e.get('access_controlled') else 'No'} | "
            f"{checks} |"
        )
    return "\n".join(lines)


def _review_properties_to_md(properties: list[dict]) -> str:
    """Format review properties as markdown cards."""
    if not properties:
        return "No review properties inferred."
    lines: list[str] = []
    for i, p in enumerate(properties, 1):
        lines.append(f"### Property {i}: {p.get('statement', '')}")
        lines.append(f"- **Kind:** {p.get('kind', '')}")
        lines.append(f"- **Rationale:** {p.get('rationale', '')}")
        lines.append(f"- **Confidence:** {p.get('confidence', '')}")
        related = p.get("related_functions", [])
        if related:
            lines.append(f"- **Related functions:** {', '.join(f'`{f}`' for f in related)}")
        checks = p.get("manual_checks", [])
        if checks:
            lines.append("- **Manual checks:**")
            for c in checks:
                lines.append(f"  - [ ] {c}")
        lines.append("")
    return "\n".join(lines)


def _risk_scenarios_to_md(scenarios: list[dict]) -> str:
    """Format risk scenarios as markdown cards."""
    if not scenarios:
        return "No risk scenarios generated."
    lines: list[str] = []
    for s in scenarios:
        lines.append(f"### {s.get('title', '')}")
        lines.append(f"- **Category:** {s.get('category', '')}")
        lines.append(f"- **Severity hint:** {s.get('severity_hint', '')}")
        lines.append(f"- **Why it matters:** {s.get('why_it_matters', '')}")
        affected = s.get("affected_functions", [])
        if affected:
            lines.append(f"- **Affected functions:** {', '.join(f'`{f}`' for f in affected)}")
        lines.append(f"- **Risky assumption:** {s.get('risky_assumption', '')}")
        steps = s.get("manual_validation_steps", [])
        if steps:
            lines.append("- **Manual validation steps:**")
            for step in steps:
                lines.append(f"  - [ ] {step}")
        themes = s.get("remediation_themes", [])
        if themes:
            lines.append("- **Remediation themes:**")
            for t in themes:
                lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)


def download_report(job_id: str):
    """Download the markdown report."""
    if not job_id:
        return None
    try:
        resp = httpx.get(f"{API_BASE}/jobs/{job_id}/report.md", timeout=10.0)
        path = f"/tmp/audit_report_{job_id}.md"
        with open(path, "w") as f:
            f.write(resp.text)
        return path
    except Exception:
        return None


# --- Build UI ---

with gr.Blocks(title="Audit Copilot", theme=gr.themes.Soft()) as demo:
    gr.Markdown("# Audit Copilot\nSmart contract audit assistant for manual reviewers.")

    with gr.Row():
        with gr.Column(scale=2):
            repo_url = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/owner/repo")
            ref = gr.Textbox(label="Branch / Commit", value="main")
            docs_url = gr.Textbox(label="Docs URL (optional)", placeholder="https://docs.example.com")
            scope_notes = gr.Textbox(label="Scope Notes (optional)", lines=3,
                                     placeholder="Focus on the Vault contract...")
            analyze_btn = gr.Button("Analyze Repo", variant="primary")

    job_id_state = gr.State("")

    with gr.Tabs():
        with gr.Tab("Summary"):
            summary_output = gr.Code(label="Analysis Summary", language="json")
        with gr.Tab("Report"):
            report_output = gr.Markdown(label="Markdown Report")
        with gr.Tab("Risk Flags"):
            flags_output = gr.Markdown(label="Risk Flags")
        with gr.Tab("Value Movements"):
            vm_output = gr.Markdown(label="Value Movements")
        with gr.Tab("Review Properties"):
            rp_output = gr.Markdown(label="Review Properties")
        with gr.Tab("Risk Scenarios"):
            rs_output = gr.Markdown(label="Risk Scenarios")
        with gr.Tab("Export"):
            gr.Markdown("Download the analysis report:")
            download_btn = gr.Button("Download Markdown Report")
            download_file = gr.File(label="Report File")

    analyze_btn.click(
        fn=start_analysis,
        inputs=[repo_url, ref, docs_url, scope_notes],
        outputs=[summary_output, report_output, flags_output, vm_output, rp_output, rs_output, job_id_state],
    )

    download_btn.click(
        fn=download_report,
        inputs=[job_id_state],
        outputs=[download_file],
    )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
