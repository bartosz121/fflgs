import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from fflgs.core import Condition, FeatureFlagsProviderError, Flag, Rule, RuleGroup
from fflgs.providers.yaml import YAMLProvider, YAMLProviderAsync
from tests.test_provider_contract import ProviderContractTests, ProviderContractTestsAsync
from tests.test_providers_file_based_provider import FileProviderContractTests


@pytest.fixture
def simple_flag() -> Flag:
    """Fixture for a simple test flag."""
    return Flag(
        name="test_flag",
        description="A test flag",
        rules_strategy="ALL",
        rule_groups=[
            RuleGroup(
                operator="AND",
                rules=[
                    Rule(
                        operator="AND",
                        conditions=[
                            Condition("user.role", "EQUALS", "admin", active=True),
                        ],
                        active=True,
                    ),
                ],
                active=True,
            ),
        ],
        enabled=True,
        version=1,
    )


@pytest.fixture
def yaml_file_with_simple_flag(simple_flag: Flag):
    """Fixture that creates a temporary YAML file with a simple flag."""
    flag_data: dict[str, object] = {
        "name": simple_flag.name,
        "description": simple_flag.description,
        "rules_strategy": simple_flag.rules_strategy,
        "rule_groups": [
            {
                "operator": rg.operator,
                "rules": [
                    {
                        "operator": r.operator,
                        "conditions": [
                            {
                                "ctx_attr": c.ctx_attr,
                                "operator": c.operator,
                                "value": c.value,
                                "active": c.active,
                            }
                            for c in r.conditions
                        ],
                        "active": r.active,
                    }
                    for r in rg.rules
                ],
                "active": rg.active,
            }
            for rg in simple_flag.rule_groups
        ],
        "enabled": simple_flag.enabled,
        "version": simple_flag.version,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump([flag_data], f)
        f.flush()
        path = f.name
        yield path
    Path(path).unlink()


@pytest.fixture
def sample_flags_yaml() -> list[dict[str, Any]]:
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


class TestYAMLProviderFileContract(FileProviderContractTests):
    """File-based contract tests for YAMLProvider."""

    provider_class = YAMLProvider

    @pytest.fixture
    def sample_flags(self, sample_flags_yaml: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Provide sample flags for contract tests."""
        return sample_flags_yaml

    @pytest.fixture
    def file_with_flags(self, sample_flags_yaml: list[dict[str, Any]]):
        """Create a temporary YAML file with sample flags."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            yaml.dump(sample_flags_yaml, f)
            f.flush()
            yield f.name


class TestYAMLProviderContract(ProviderContractTests):
    """Contract tests for YAMLProvider."""

    @pytest.fixture
    def provider_instance(self, yaml_file_with_simple_flag: str) -> YAMLProvider:
        """Provide a YAMLProvider with test flags."""
        return YAMLProvider(yaml_file_with_simple_flag)

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Override with actual test flag name."""
        return "test_flag"


class TestYAMLProviderAsyncContract(ProviderContractTestsAsync):
    """Contract tests for YAMLProviderAsync."""

    @pytest.fixture
    def provider_instance(self, yaml_file_with_simple_flag: str) -> YAMLProviderAsync:
        """Provide a YAMLProviderAsync with test flags."""
        return YAMLProviderAsync(yaml_file_with_simple_flag)

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Override with actual test flag name."""
        return "test_flag"


class TestYAMLProviderFormatSpecific:
    """Format-specific tests for YAMLProvider."""

    def test_invalid_yaml_syntax(self) -> None:
        """Test YAMLProvider raises FeatureFlagsProviderError for invalid YAML syntax."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            # Tab in YAML value is technically valid, use invalid syntax instead
            f.write("- name: test\n  description: |\n   invalid")
            f.flush()
            path = f.name

            provider = YAMLProvider(path)
            with pytest.raises(FeatureFlagsProviderError, match=r"Invalid YAML|Failed to load"):
                provider.get_flag("any_flag")

    def test_yaml_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("")
            f.flush()
            path = f.name

            provider = YAMLProvider(path)
            # Empty YAML parses as None, which should trigger validation error
            with pytest.raises(FeatureFlagsProviderError, match=r"Expected list|Failed to load"):
                provider.get_flag("any_flag")
