# pyright: reportPrivateUsage=false

import json
import tempfile
from typing import Any

import pytest

from fflgs.core import FeatureFlagsProviderError
from fflgs.providers.json import JSONProvider, JSONProviderAsync
from tests.test_provider_contract import ProviderContractTests, ProviderContractTestsAsync
from tests.test_providers_file_based_provider import FileProviderContractTests


@pytest.fixture
def sample_flags_json() -> list[dict[str, Any]]:
    return [
        {
            "name": "webhooks",
            "description": "Enable webhooks feature",
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
                                    "ctx_attr": "user.plan",
                                    "operator": "IN",
                                    "value": ["pro", "enterprise"],
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
            "name": "analytics",
            "description": None,
            "rules_strategy": "ANY",
            "rule_groups": [
                {
                    "operator": "OR",
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
    ]


@pytest.fixture
def json_file(sample_flags_json: list[dict[str, Any]]):
    """Create a temporary JSON file with sample flags"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(sample_flags_json, f)
        f.flush()
        yield f.name


class TestJSONFileProviderContract(FileProviderContractTests):
    """Contract tests for JSONProvider."""

    provider_class = JSONProvider

    @pytest.fixture
    def sample_flags(self, sample_flags_json: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Provide sample flags for contract tests."""
        return sample_flags_json

    @pytest.fixture
    def file_with_flags(self, sample_flags_json: list[dict[str, Any]]):
        """Create a temporary JSON file with sample flags."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(sample_flags_json, f)
            f.flush()
            yield f.name


class TestJSONProviderContract(ProviderContractTests):
    """Contract tests for JSONProvider."""

    @pytest.fixture
    def provider_instance(self, json_file: str) -> JSONProvider:
        """Provide a JSONProvider with test flags."""
        return JSONProvider(json_file)

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Override with actual test flag name."""
        return "webhooks"


class TestJSONProviderAsyncContract(ProviderContractTestsAsync):
    """Contract tests for JSONProviderAsync."""

    @pytest.fixture
    def provider_instance(self, json_file: str) -> JSONProviderAsync:
        """Provide a JSONProviderAsync with test flags."""
        return JSONProviderAsync(json_file)

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Override with actual test flag name."""
        return "webhooks"


class TestJSONProviderFormatSpecific:
    """Format-specific tests for JSONProvider."""

    def test_invalid_json_syntax(self) -> None:
        """Test JSONProvider raises FeatureFlagsProviderError for invalid JSON syntax."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{invalid json]")
            f.flush()
            path = f.name

            provider = JSONProvider(path)
            with pytest.raises(FeatureFlagsProviderError, match="Invalid JSON"):
                provider.get_flag("any_flag")

    def test_json_with_trailing_comma(self) -> None:
        """Test JSONProvider raises FeatureFlagsProviderError for JSON with trailing comma."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write('[\n  {"name": "test"},\n]')
            f.flush()
            path = f.name

            provider = JSONProvider(path)
            with pytest.raises(FeatureFlagsProviderError, match="Invalid JSON"):
                provider.get_flag("any_flag")
