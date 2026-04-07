"""Tests for repo fetcher URL parsing."""

import pytest
from app.services.repo_fetcher import parse_github_url


def test_parse_valid_url():
    owner, repo = parse_github_url("https://github.com/OpenZeppelin/openzeppelin-contracts")
    assert owner == "OpenZeppelin"
    assert repo == "openzeppelin-contracts"


def test_parse_url_with_git_suffix():
    owner, repo = parse_github_url("https://github.com/owner/repo.git")
    assert owner == "owner"
    assert repo == "repo"


def test_parse_url_with_trailing_slash():
    owner, repo = parse_github_url("https://github.com/owner/repo/")
    assert owner == "owner"
    assert repo == "repo"


def test_invalid_url_raises():
    with pytest.raises(ValueError):
        parse_github_url("https://gitlab.com/owner/repo")


def test_not_a_url_raises():
    with pytest.raises(ValueError):
        parse_github_url("not a url at all")
