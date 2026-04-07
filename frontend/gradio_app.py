"""Gradio frontend for Audit Copilot — lightweight iPad-friendly UI."""

from __future__ import annotations

import json
import time

import gradio as gr
import httpx

API_BASE = "http://localhost:8000"


def start_analysis(repo_url: str, ref: str, docs_url: str, scope_notes: str):
    """Submit a repo for analysis and poll until complete."""
    if not repo_url.strip():
        return "Please enter a GitHub repo URL.", "", "", ""

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
        return f"Error starting analysis: {e}", "", "", ""

    # Poll for completion
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
        return f"Analysis failed: {status.get('error', 'unknown error')}", "", "", ""

    # Fetch results
    try:
        summary_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/summary", timeout=10.0)
        summary = json.dumps(summary_resp.json(), indent=2)

        report_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/report.md", timeout=10.0)
        report_md = report_resp.text

        flags_resp = httpx.get(f"{API_BASE}/jobs/{job_id}/flags", timeout=10.0)
        flags_data = flags_resp.json().get("flags", [])
        flags_table = _flags_to_table(flags_data)

        return summary, report_md, flags_table, job_id
    except Exception as e:
        return f"Error fetching results: {e}", "", "", job_id


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
        with gr.Tab("Export"):
            gr.Markdown("Download the analysis report:")
            download_btn = gr.Button("Download Markdown Report")
            download_file = gr.File(label="Report File")

    analyze_btn.click(
        fn=start_analysis,
        inputs=[repo_url, ref, docs_url, scope_notes],
        outputs=[summary_output, report_output, flags_output, job_id_state],
    )

    download_btn.click(
        fn=download_report,
        inputs=[job_id_state],
        outputs=[download_file],
    )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
