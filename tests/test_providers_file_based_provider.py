# pyright: reportPrivateUsage=false
# ruff: noqa: PLC2701

"""Tests for FileProvider base class and contract for subclasses."""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from fflgs.core import RuleGroup
from fflgs.providers._file_provider import FileProvider


@pytest.fixture
def sample_flags() -> list[dict[str, Any]]:
    """Sample flag data for testing."""
    return [
        {
            "name": "flag1",
            "description": "First flag",
            "rules_strategy": "ALL",
            "rule_groups": [
                {
                    "operator": "AND",
                    "active": True,
                    "rules": [
                        {
                            "operator": "AND",
                            "active": True,
                            "conditions": [
                                {
                                    "ctx_attr": "user.role",
                                    "operator": "EQUALS",
                                    "value": "admin",
                                    "active": True,
                                }
                            ],
                        }
                    ],
                }
            ],
            "enabled": True,
            "version": 1,
        },
        {
            "name": "flag2",
            "description": None,
            "rules_strategy": "ANY",
            "rule_groups": [],
            "enabled": False,
            "version": 2,
        },
    ]


@pytest.fixture
def file_with_flags(sample_flags: list[dict[str, Any]]):
    """Create a temporary file with sample flags."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(sample_flags, f)
        f.flush()
        yield f.name


class FileProviderContractTests:  # noqa: PLR0904
    """Base contract tests that all FileProvider subclasses should pass.

    Subclasses should define:
    - provider_class: Class to test
    - get_sample_file(): Fixture returning path to file with sample flags
    - get_invalid_file_error_match(): Regex pattern for provider-specific parse error
    """

    # To be overridden by subclasses
    provider_class: type[FileProvider]
    get_sample_file: pytest.fixture  # pyright: ignore[reportGeneralTypeIssues]
    get_invalid_file_error_match: str = "Invalid"

    # Initialization Tests

    def test_init_file_not_found(self) -> None:
        """Test FileNotFoundError is raised for non-existent files."""
        with pytest.raises(FileNotFoundError, match="File not found"):
            self.provider_class("/nonexistent/path/to/file")

    def test_init_negative_cache_ttl(self, file_with_flags: str) -> None:
        """Test ValueError is raised for negative cache TTL."""
        with pytest.raises(ValueError, match="cache_ttl_seconds must be non-negative"):
            self.provider_class(file_with_flags, cache_ttl_seconds=-1)

    def test_init_cache_enabled_default(self, file_with_flags: str) -> None:
        """Test cache is enabled by default."""
        provider = self.provider_class(file_with_flags)
        assert provider._cache_enabled is True
        assert provider._cache_ttl_seconds is None

    def test_init_cache_disabled(self, file_with_flags: str) -> None:
        """Test cache can be disabled with TTL=0."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=0)
        assert provider._cache_enabled is False

    def test_init_cache_with_ttl(self, file_with_flags: str) -> None:
        """Test cache can have specific TTL."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=60)
        assert provider._cache_enabled is True
        assert provider._cache_ttl_seconds == 60

    # Cache Validation Tests

    def test_cache_invalid_before_load(self, file_with_flags: str) -> None:
        """Test cache is invalid before first load."""
        provider = self.provider_class(file_with_flags)
        assert provider._is_cache_valid() is False

    def test_cache_valid_after_load_infinite_ttl(self, file_with_flags: str) -> None:
        """Test cache is valid after load with infinite TTL."""
        provider = self.provider_class(file_with_flags)
        provider._load_flags()
        assert provider._is_cache_valid() is True

    def test_cache_valid_after_load_within_ttl(self, file_with_flags: str) -> None:
        """Test cache is valid within TTL window."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=10)
        provider._load_flags()
        assert provider._is_cache_valid() is True

    def test_cache_invalid_after_ttl_expiry(self, file_with_flags: str) -> None:
        """Test cache becomes invalid after TTL expiry using mocked time."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=10)
        provider._load_flags()
        assert provider._is_cache_valid() is True

        # Mock time to advance past TTL without sleeping
        with mock.patch("fflgs.providers._file_provider.time") as mock_time:
            current_time = time.time()
            mock_time.time.return_value = current_time + 11  # Advance 11 seconds
            assert provider._is_cache_valid() is False

    def test_cache_always_invalid_when_disabled(self, file_with_flags: str) -> None:
        """Test cache is always invalid when disabled."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=0)
        provider._load_flags()
        assert provider._is_cache_valid() is False

    # Flag Loading Tests

    def test_load_flags_returns_dict(self, file_with_flags: str) -> None:
        """Test _load_flags returns a dictionary."""
        provider = self.provider_class(file_with_flags)
        flags = provider._load_flags()
        assert isinstance(flags, dict)

    def test_load_flags_contains_all_flags(self, sample_flags: list[dict[str, Any]], file_with_flags: str) -> None:
        """Test _load_flags loads all flags from file."""
        provider = self.provider_class(file_with_flags)
        flags = provider._load_flags()
        assert len(flags) == len(sample_flags)
        for flag_data in sample_flags:
            assert flag_data["name"] in flags

    def test_load_flags_cache_hit(self, file_with_flags: str) -> None:
        """Test _load_flags returns cached result on cache hit."""
        provider = self.provider_class(file_with_flags)
        flags1 = provider._load_flags()
        flags2 = provider._load_flags()
        assert flags1 is flags2

    def test_load_flags_cache_miss_after_ttl(self, file_with_flags: str) -> None:
        """Test _load_flags reloads after TTL expiry using mocked time."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=10)
        flags1 = provider._load_flags()
        assert provider._is_cache_valid()

        # Mock time to advance past TTL
        with mock.patch("fflgs.providers._file_provider.time") as mock_time:
            current_time = time.time()
            mock_time.time.return_value = current_time + 11  # Advance 11 seconds
            flags2 = provider._load_flags()  # Should reload due to expired cache

        assert flags1 is not flags2  # Different objects due to reload
        assert flags1.keys() == flags2.keys()  # But same flag names

    def test_load_flags_no_cache_when_disabled(self, file_with_flags: str) -> None:
        """Test _load_flags doesn't cache when caching disabled."""
        provider = self.provider_class(file_with_flags, cache_ttl_seconds=0)
        provider._load_flags()
        assert len(provider._flags_cache) == 0

    # File Validation Tests

    def test_load_flags_file_read_error(self, file_with_flags: str) -> None:
        """Test ValueError when file becomes unreadable during load."""
        provider = self.provider_class(file_with_flags)
        # Make file unreadable
        os.chmod(file_with_flags, 0o000)
        try:
            with pytest.raises(ValueError, match="Failed to read file"):
                provider._load_flags()
        finally:
            # Restore permissions for cleanup
            os.chmod(file_with_flags, 0o644)

    def test_load_flags_not_list(self) -> None:
        """Test ValueError when file is not a list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"flag": {}}, f)
            f.flush()
            path = f.name

        provider = self.provider_class(path)
        with pytest.raises(ValueError, match="Expected list"):
            provider._load_flags()
        Path(path).unlink()

    def test_load_flags_flag_not_dict(self) -> None:
        """Test ValueError when flag is not a dict."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(["not a dict"], f)
            f.flush()
            path = f.name

        provider = self.provider_class(path)
        with pytest.raises(ValueError, match="must be an object"):
            provider._load_flags()
        Path(path).unlink()

    def test_load_flags_invalid_flag_structure(self) -> None:
        """Test ValueError on deserialization error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump([{"name": "bad_flag"}], f)
            f.flush()
            path = f.name

        provider = self.provider_class(path)
        with pytest.raises(ValueError, match="Failed to deserialize flag"):
            provider._load_flags()
        Path(path).unlink()

    # Get Flag Tests

    def test_get_flag_existing(self, file_with_flags: str, sample_flags: list[dict[str, Any]]) -> None:
        """Test _get_flag returns existing flag."""
        provider = self.provider_class(file_with_flags)
        first_flag_name = sample_flags[0]["name"]
        flag = provider._get_flag(first_flag_name)
        assert flag is not None
        assert flag.name == first_flag_name

    def test_get_flag_nonexistent(self, file_with_flags: str) -> None:
        """Test _get_flag returns None for nonexistent flag."""
        provider = self.provider_class(file_with_flags)
        flag = provider._get_flag("nonexistent_flag_xyz")
        assert flag is None

    def test_get_flag_multiple(self, file_with_flags: str, sample_flags: list[dict[str, Any]]) -> None:
        """Test _get_flag can retrieve different flags."""
        provider = self.provider_class(file_with_flags)
        flag1 = provider._get_flag(sample_flags[0]["name"])
        flag2 = provider._get_flag(sample_flags[1]["name"])

        assert flag1 is not None
        assert flag2 is not None
        assert flag1.name == sample_flags[0]["name"]
        assert flag2.name == sample_flags[1]["name"]

    # Deserialization Tests

    def test_deserialize_simple_flag(self, file_with_flags: str, sample_flags: list[dict[str, Any]]) -> None:
        """Test flag deserialization includes all fields."""
        provider = self.provider_class(file_with_flags)
        flag_data = sample_flags[0]
        flag = provider._get_flag(flag_data["name"])

        assert flag is not None
        assert flag.name == flag_data["name"]
        assert flag.description == flag_data.get("description")
        assert flag.rules_strategy == flag_data["rules_strategy"]
        assert flag.enabled == flag_data["enabled"]
        assert flag.version == flag_data["version"]

    def test_deserialize_flag_with_null_description(
        self, file_with_flags: str, sample_flags: list[dict[str, Any]]
    ) -> None:
        """Test flag deserialization handles null description."""
        provider = self.provider_class(file_with_flags)
        # Find a flag with null description, or skip
        flag_with_null = next((f for f in sample_flags if f.get("description") is None), None)
        if flag_with_null is None:
            pytest.skip("No flag with null description in fixtures")

        flag = provider._get_flag(flag_with_null["name"])

        assert flag is not None
        assert flag.description is None

    def test_deserialize_nested_structure(self, file_with_flags: str, sample_flags: list[dict[str, Any]]) -> None:
        """Test deserialization of complete flag structure."""
        provider = self.provider_class(file_with_flags)
        flag_data = sample_flags[0]
        flag = provider._get_flag(flag_data["name"])

        assert flag is not None
        # Only test if flag has rule groups
        if flag_data.get("rule_groups"):
            assert len(flag.rule_groups) == len(flag_data["rule_groups"])
            rule_group = flag.rule_groups[0]
            assert isinstance(rule_group, RuleGroup)


class _ConcreteFileProvider(FileProvider):
    """Concrete implementation of FileProvider for testing."""

    def _parse_file(self) -> Any:
        """Parse JSON file for testing."""
        with open(self._file_path, encoding="utf-8") as f:
            return json.load(f)


class TestFileProviderDirect(FileProviderContractTests):
    """Contract tests for FileProvider base class using concrete implementation."""

    provider_class = _ConcreteFileProvider

    @pytest.fixture
    def sample_flags(self) -> list[dict[str, Any]]:
        """Provide sample flags for contract tests."""
        return [
            {
                "name": "flag1",
                "description": "First flag",
                "rules_strategy": "ALL",
                "rule_groups": [
                    {
                        "operator": "AND",
                        "active": True,
                        "rules": [
                            {
                                "operator": "AND",
                                "active": True,
                                "conditions": [
                                    {
                                        "ctx_attr": "user.role",
                                        "operator": "EQUALS",
                                        "value": "admin",
                                        "active": True,
                                    }
                                ],
                            }
                        ],
                    }
                ],
                "enabled": True,
                "version": 1,
            },
            {
                "name": "flag2",
                "description": None,
                "rules_strategy": "ANY",
                "rule_groups": [],
                "enabled": False,
                "version": 2,
            },
        ]

    @pytest.fixture
    def file_with_flags(self, sample_flags: list[dict[str, Any]]):
        """Create a temporary JSON file with sample flags."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_flags, f)
            f.flush()
            yield f.name
