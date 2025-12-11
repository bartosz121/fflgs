# pyright: reportPrivateUsage=false

import asyncio

import pytest

from fflgs.core import Condition, Flag, Rule, RuleGroup
from fflgs.providers.memory import InMemoryProvider, InMemoryProviderAsync
from tests.test_provider_contract import ProviderContractTests, ProviderContractTestsAsync


@pytest.fixture
def in_memory_provider_with_test_flags() -> InMemoryProvider:
    """Create an in-memory provider with test flags."""
    provider = InMemoryProvider()
    flag = Flag(
        name="flag1",
        description="First flag",
        rules_strategy="ALL",
        rule_groups=[],
        enabled=True,
        version=1,
    )
    provider.add_flag(flag)
    return provider


@pytest.fixture
def in_memory_provider_async_with_test_flags() -> InMemoryProviderAsync:
    """Create an async in-memory provider with test flags."""
    provider = InMemoryProviderAsync()
    flag = Flag(
        name="flag1",
        description="First flag",
        rules_strategy="ALL",
        rule_groups=[],
        enabled=True,
        version=1,
    )
    provider.add_flag(flag)
    return provider


class TestInMemoryProviderContract(ProviderContractTests):
    """Contract tests for InMemoryProvider."""

    @pytest.fixture
    def provider_instance(self, in_memory_provider_with_test_flags: InMemoryProvider) -> InMemoryProvider:
        """Provide an InMemoryProvider with test flags."""
        return in_memory_provider_with_test_flags


class TestInMemoryProviderAsyncContract(ProviderContractTestsAsync):
    """Contract tests for InMemoryProviderAsync."""

    @pytest.fixture
    def provider_instance(
        self, in_memory_provider_async_with_test_flags: InMemoryProviderAsync
    ) -> InMemoryProviderAsync:
        """Provide an InMemoryProviderAsync with test flags."""
        return in_memory_provider_async_with_test_flags


class TestInMemoryProvider:
    """Test InMemoryProvider"""

    def test_initialization(self) -> None:
        """Test provider initializes with empty flags dict"""
        provider = InMemoryProvider()
        assert provider._flags == {}

    def test_add_flag_single(self) -> None:
        """Test adding a single flag to the provider"""
        provider = InMemoryProvider()
        flag = Flag(
            name="test_flag",
            description="A test flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        assert "test_flag" in provider._flags
        assert provider._flags["test_flag"] is flag

    def test_add_flag_multiple(self) -> None:
        """Test adding multiple flags to the provider"""
        provider = InMemoryProvider()
        flag1 = Flag(
            name="flag1",
            description="First flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="flag2",
            description="Second flag",
            rules_strategy="ANY",
            rule_groups=[],
            enabled=False,
            version=1,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        assert len(provider._flags) == 2
        assert provider._flags["flag1"] is flag1
        assert provider._flags["flag2"] is flag2

    def test_add_flag_overwrite(self) -> None:
        """Test that adding a flag with same name overwrites the previous one"""
        provider = InMemoryProvider()
        flag1 = Flag(
            name="test_flag",
            description="First version",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="test_flag",
            description="Second version",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=2,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        assert len(provider._flags) == 1
        assert provider._flags["test_flag"] is flag2
        assert provider._flags["test_flag"].version == 2

    def test_get_flag_existing(self) -> None:
        """Test retrieving an existing flag"""
        provider = InMemoryProvider()
        flag = Flag(
            name="existing_flag",
            description="An existing flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        result = provider.get_flag("existing_flag")
        assert result
        assert result is flag
        assert result.name == "existing_flag"

    def test_get_flag_nonexistent(self) -> None:
        """Test retrieving a non-existent flag returns None"""
        provider = InMemoryProvider()
        result = provider.get_flag("nonexistent")
        assert result is None

    def test_get_flag_after_overwrite(self) -> None:
        """Test that get_flag returns the latest version after overwrite"""
        provider = InMemoryProvider()
        flag1 = Flag(
            name="test_flag",
            description="v1",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="test_flag",
            description="v2",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=2,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        result = provider.get_flag("test_flag")
        assert result
        assert result.version == 2
        assert result.enabled is False

    def test_get_flag_with_complex_rules(self) -> None:
        """Test storing and retrieving a flag with complex rule groups"""
        provider = InMemoryProvider()
        flag = Flag(
            name="complex_flag",
            description="Flag with complex rules",
            rules_strategy="ANY",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[
                                Condition(
                                    ctx_attr="age",
                                    operator="GREATER_THAN",
                                    value=18,
                                    active=True,
                                )
                            ],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        result = provider.get_flag("complex_flag")
        assert result
        assert result is flag
        assert len(result.rule_groups) == 1
        assert len(result.rule_groups[0].rules) == 1

    def test_get_flag_empty_provider(self) -> None:
        """Test get_flag on empty provider"""
        provider = InMemoryProvider()
        assert provider.get_flag("any_flag") is None

    def test_add_flag_preserves_flag_state(self) -> None:
        """Test that adding a flag preserves all flag attributes"""
        provider = InMemoryProvider()
        flag = Flag(
            name="preserved_flag",
            description="Check preservation",
            rules_strategy="NONE",
            rule_groups=[],
            enabled=False,
            version=42,
        )
        provider.add_flag(flag)
        result = provider.get_flag("preserved_flag")
        assert result
        assert result.name == "preserved_flag"
        assert result.description == "Check preservation"
        assert result.rules_strategy == "NONE"
        assert result.enabled is False
        assert result.version == 42


class TestInMemoryProviderAsync:
    """Test asynchronous InMemoryProviderAsync"""

    def test_initialization(self) -> None:
        """Test async provider initializes with empty flags dict"""
        provider = InMemoryProviderAsync()
        assert provider._flags == {}

    def test_add_flag_single(self) -> None:
        """Test adding a single flag to the async provider"""
        provider = InMemoryProviderAsync()
        flag = Flag(
            name="test_flag",
            description="A test flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        assert "test_flag" in provider._flags
        assert provider._flags["test_flag"] is flag

    def test_add_flag_multiple(self) -> None:
        """Test adding multiple flags to the async provider"""
        provider = InMemoryProviderAsync()
        flag1 = Flag(
            name="flag1",
            description="First flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="flag2",
            description="Second flag",
            rules_strategy="ANY",
            rule_groups=[],
            enabled=False,
            version=1,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        assert len(provider._flags) == 2
        assert provider._flags["flag1"] is flag1
        assert provider._flags["flag2"] is flag2

    def test_add_flag_overwrite(self) -> None:
        """Test that adding a flag with same name overwrites previous one in async provider"""
        provider = InMemoryProviderAsync()
        flag1 = Flag(
            name="test_flag",
            description="First version",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="test_flag",
            description="Second version",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=2,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        assert len(provider._flags) == 1
        assert provider._flags["test_flag"] is flag2

    @pytest.mark.asyncio
    async def test_get_flag_existing(self) -> None:
        """Test async retrieving an existing flag"""
        provider = InMemoryProviderAsync()
        flag = Flag(
            name="existing_flag",
            description="An existing flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        result = await provider.get_flag("existing_flag")
        assert result
        assert result is flag
        assert result.name == "existing_flag"

    @pytest.mark.asyncio
    async def test_get_flag_nonexistent(self) -> None:
        """Test async retrieving a non-existent flag returns None"""
        provider = InMemoryProviderAsync()
        result = await provider.get_flag("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_flag_after_overwrite(self) -> None:
        """Test async get_flag returns the latest version after overwrite"""
        provider = InMemoryProviderAsync()
        flag1 = Flag(
            name="test_flag",
            description="v1",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="test_flag",
            description="v2",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=2,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)
        result = await provider.get_flag("test_flag")
        assert result
        assert result.version == 2
        assert result.enabled is False

    @pytest.mark.asyncio
    async def test_get_flag_with_complex_rules(self) -> None:
        """Test async storing and retrieving a flag with complex rule groups"""
        provider = InMemoryProviderAsync()
        flag = Flag(
            name="complex_flag",
            description="Flag with complex rules",
            rules_strategy="ANY",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[
                                Condition(
                                    ctx_attr="age",
                                    operator="GREATER_THAN",
                                    value=18,
                                    active=True,
                                )
                            ],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=1,
        )
        provider.add_flag(flag)
        result = await provider.get_flag("complex_flag")
        assert result
        assert result is flag
        assert len(result.rule_groups) == 1

    @pytest.mark.asyncio
    async def test_get_flag_empty_provider(self) -> None:
        """Test async get_flag on empty provider"""
        provider = InMemoryProviderAsync()
        result = await provider.get_flag("any_flag")
        assert result is None

    @pytest.mark.asyncio
    async def test_add_flag_preserves_flag_state(self) -> None:
        """Test that adding a flag preserves all flag attributes in async provider"""
        provider = InMemoryProviderAsync()
        flag = Flag(
            name="preserved_flag",
            description="Check preservation",
            rules_strategy="NONE",
            rule_groups=[],
            enabled=False,
            version=42,
        )
        provider.add_flag(flag)
        result = await provider.get_flag("preserved_flag")
        assert result
        assert result.name == "preserved_flag"
        assert result.description == "Check preservation"
        assert result.rules_strategy == "NONE"
        assert result.enabled is False
        assert result.version == 42

    @pytest.mark.asyncio
    async def test_multiple_concurrent_gets(self) -> None:
        """Test concurrent async flag retrieval"""
        provider = InMemoryProviderAsync()
        flag1 = Flag(
            name="flag1",
            description="First",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )
        flag2 = Flag(
            name="flag2",
            description="Second",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=False,
            version=1,
        )
        provider.add_flag(flag1)
        provider.add_flag(flag2)

        # Simulate concurrent gets
        result1, result2, result_none = await asyncio.gather(
            provider.get_flag("flag1"),
            provider.get_flag("flag2"),
            provider.get_flag("nonexistent"),
        )

        assert result1 is flag1
        assert result2 is flag2
        assert result_none is None


class TestProviderConsistency:
    """Test consistency between sync and async providers"""

    @pytest.mark.asyncio
    async def test_flag_storage_consistency(self) -> None:
        """Test that sync and async providers handle flags consistently"""
        sync_provider = InMemoryProvider()
        async_provider = InMemoryProviderAsync()

        flag = Flag(
            name="consistency_test",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[],
            enabled=True,
            version=1,
        )

        sync_provider.add_flag(flag)
        async_provider.add_flag(flag)

        sync_result = sync_provider.get_flag("consistency_test")
        async_result = await async_provider.get_flag("consistency_test")

        assert sync_result is flag
        assert async_result is flag
