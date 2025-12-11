# pyright: reportPrivateUsage=false

"""Contract tests for all FeatureFlagsProvider implementations."""

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from fflgs.providers.protocol import FeatureFlagsProvider, FeatureFlagsProviderAsync


class ProviderContractTests:
    """Contract tests that all FeatureFlagsProvider implementations must pass.

    Subclasses should define:
    - provider_instance: Fixture returning a provider with test flags loaded
    - test_flag_name: Fixture returning the name of a test flag in the provider
    """

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Return the name of a test flag to use in tests. Override if needed."""
        return "flag1"

    def test_get_flag_existing(self, provider_instance: "FeatureFlagsProvider", test_flag_name: str) -> None:
        """Test get_flag returns Flag object for existing flag."""
        flag = provider_instance.get_flag(test_flag_name)
        assert flag is not None
        assert flag.name == test_flag_name

    def test_get_flag_nonexistent(self, provider_instance: "FeatureFlagsProvider") -> None:
        """Test get_flag returns None for nonexistent flag."""
        flag = provider_instance.get_flag("nonexistent_flag_xyz")
        assert flag is None

    def test_get_flag_preserves_state(self, provider_instance: "FeatureFlagsProvider", test_flag_name: str) -> None:
        """Test get_flag returns flag with intact attributes."""
        flag = provider_instance.get_flag(test_flag_name)
        assert flag is not None
        assert hasattr(flag, "name")
        assert hasattr(flag, "description")
        assert hasattr(flag, "enabled")
        assert hasattr(flag, "version")
        assert hasattr(flag, "rules_strategy")
        assert hasattr(flag, "rule_groups")


class ProviderContractTestsAsync:
    """Contract tests that all FeatureFlagsProviderAsync implementations must pass.

    Subclasses should define:
    - provider_instance: Fixture returning an async provider with test flags loaded
    - test_flag_name: Fixture returning the name of a test flag in the provider
    """

    @pytest.fixture
    def test_flag_name(self) -> str:
        """Return the name of a test flag to use in tests. Override if needed."""
        return "flag1"

    @pytest.mark.asyncio
    async def test_get_flag_existing(self, provider_instance: "FeatureFlagsProviderAsync", test_flag_name: str) -> None:
        """Test async get_flag returns Flag object for existing flag."""
        flag = await provider_instance.get_flag(test_flag_name)
        assert flag is not None
        assert flag.name == test_flag_name

    @pytest.mark.asyncio
    async def test_get_flag_nonexistent(self, provider_instance: "FeatureFlagsProviderAsync") -> None:
        """Test async get_flag returns None for nonexistent flag."""
        flag = await provider_instance.get_flag("nonexistent_flag_xyz")
        assert flag is None

    @pytest.mark.asyncio
    async def test_get_flag_preserves_state(
        self, provider_instance: "FeatureFlagsProviderAsync", test_flag_name: str
    ) -> None:
        """Test async get_flag returns flag with intact attributes."""
        flag = await provider_instance.get_flag(test_flag_name)
        assert flag is not None
        assert hasattr(flag, "name")
        assert hasattr(flag, "description")
        assert hasattr(flag, "enabled")
        assert hasattr(flag, "version")
        assert hasattr(flag, "rules_strategy")
        assert hasattr(flag, "rule_groups")
