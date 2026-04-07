"""Tests for the regex-based Solidity parser."""

import tempfile
from pathlib import Path

from app.services.solidity_parser import parse_file

SAMPLE_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IVault {
    function deposit(uint256 amount) external;
}

contract Vault is IVault {
    address public owner;
    mapping(address => uint256) public balances;
    IERC20 public token;
    bool public paused;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    error InsufficientBalance();

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) revert InsufficientBalance();
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function sweepETH() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok);
    }
}
"""


def test_parse_finds_contracts():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        contracts, functions = parse_file(Path(f.name))

    names = [c.name for c in contracts]
    assert "IVault" in names
    assert "Vault" in names


def test_parse_finds_functions():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        contracts, functions = parse_file(Path(f.name))

    fn_names = [fn.name for fn in functions]
    assert "deposit" in fn_names
    assert "withdraw" in fn_names
    assert "pause" in fn_names
    assert "sweepETH" in fn_names


def test_parse_detects_inheritance():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        contracts, _ = parse_file(Path(f.name))

    vault = [c for c in contracts if c.name == "Vault"][0]
    assert "IVault" in vault.inherits


def test_parse_detects_events_and_errors():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        contracts, _ = parse_file(Path(f.name))

    vault = [c for c in contracts if c.name == "Vault"][0]
    assert "Deposited" in vault.events
    assert "InsufficientBalance" in vault.custom_errors


def test_parse_detects_token_actions():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        _, functions = parse_file(Path(f.name))

    deposit_fns = [fn for fn in functions if fn.name == "deposit" and fn.contract == "Vault"]
    assert len(deposit_fns) == 1
    assert "transferFrom" in deposit_fns[0].token_actions

    withdraw_fn = [fn for fn in functions if fn.name == "withdraw"][0]
    assert "transfer" in withdraw_fn.token_actions


def test_parse_detects_external_calls():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(SAMPLE_SOL)
        f.flush()
        _, functions = parse_file(Path(f.name))

    sweep_fn = [fn for fn in functions if fn.name == "sweepETH"][0]
    assert len(sweep_fn.external_calls) > 0
