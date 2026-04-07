"""Tests for the report builder."""

from app.models.repo_analysis import RepoAnalysis
from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.services.report_builder import build_markdown, build_csv_findings


def _make_analysis() -> RepoAnalysis:
    return RepoAnalysis(
        job_id="test123",
        repo_url="https://github.com/test/repo",
        ref="main",
        files_scanned=10,
        solidity_files=3,
        contracts=[
            ContractInfo(name="Vault", file_path="src/Vault.sol", kind="contract"),
        ],
        functions=[
            FunctionInfo(
                contract="Vault",
                file_path="src/Vault.sol",
                name="withdraw",
                signature="withdraw(uint256)",
                visibility="external",
                risk_tags=["funds-flow", "access-control"],
            ),
        ],
        risk_flags=[
            RiskFlag(
                severity="high",
                category="funds-flow",
                contract="Vault",
                function="withdraw",
                evidence="Token transfer in withdraw",
                explanation="Moves funds",
                manual_validation=["Check reentrancy"],
            ),
        ],
    )


def test_markdown_contains_header():
    analysis = _make_analysis()
    md = build_markdown(analysis)
    assert "# Audit Copilot Review" in md
    assert "Vault" in md
    assert "withdraw" in md


def test_markdown_contains_risk_flags():
    analysis = _make_analysis()
    md = build_markdown(analysis)
    assert "funds-flow" in md
    assert "Check reentrancy" in md


def test_csv_has_header_and_rows():
    analysis = _make_analysis()
    csv = build_csv_findings(analysis)
    lines = csv.strip().split("\n")
    assert len(lines) == 2  # header + 1 flag
    assert "severity" in lines[0]
    assert "high" in lines[1]
