"""Tests for the file scanner module."""

from pathlib import Path
import tempfile

from app.services.file_scanner import scan_files, detect_language_mix


def _make_tree(tmp: Path):
    """Create a minimal test file tree."""
    (tmp / "src").mkdir()
    (tmp / "src" / "Vault.sol").write_text("pragma solidity ^0.8.0;")
    (tmp / "src" / "Token.sol").write_text("pragma solidity ^0.8.0;")
    (tmp / "README.md").write_text("# Test")
    (tmp / "foundry.toml").write_text("[profile.default]")
    (tmp / "node_modules").mkdir()
    (tmp / "node_modules" / "dep.sol").write_text("ignored")


def test_scan_finds_solidity():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_tree(root)
        result = scan_files(root)
        assert len(result["solidity"]) == 2
        assert len(result["docs"]) == 1
        assert len(result["configs"]) == 1


def test_scan_ignores_node_modules():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_tree(root)
        result = scan_files(root)
        sol_names = [p.name for p in result["solidity"]]
        assert "dep.sol" not in sol_names


def test_language_mix():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_tree(root)
        mix = detect_language_mix(root)
        assert ".sol" in mix
        assert mix[".sol"] == 2
