# pyright: reportPrivateUsage=false
# ruff: noqa: PLC2701

import asyncio
import threading
import time
from unittest import mock

import pytest

from fflgs.cache._cache import CachedFeatureFlags, CachedFeatureFlagsAsync
from fflgs.cache._utils import generate_cache_key
from fflgs.cache.memory import InMemoryStorage
from fflgs.core import Condition, FeatureFlags, FeatureFlagsAsync, Flag, Rule, RuleGroup
from fflgs.providers.memory import InMemoryProvider, InMemoryProviderAsync


@pytest.fixture
def simple_flag() -> Flag:
    """Create a simple test flag"""
    return Flag(
        name="test_flag",
        description="Test flag",
        rules_strategy="ALL",
        rule_groups=[
            RuleGroup(
                operator="AND",
                rules=[
                    Rule(
                        operator="AND",
                        conditions=[
                            Condition("pro", "EQUALS", "user.plan", active=True),
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


@pytest.fixture
def provider_with_flag(simple_flag: Flag) -> InMemoryProvider:
    """Create a provider with a test flag"""
    provider = InMemoryProvider()
    provider.add_flag(simple_flag)
    return provider


def _create_mock_ff(simple_flag: Flag, spec: type = FeatureFlags) -> mock.MagicMock:
    """Helper to create mock FeatureFlags with provider returning simple_flag"""
    mock_provider = mock.MagicMock()
    mock_provider.get_flag.return_value = simple_flag
    mock_ff = mock.MagicMock(spec=spec)
    mock_ff._provider = mock_provider
    return mock_ff


def _create_mock_ff_async(simple_flag: Flag, spec: type = FeatureFlagsAsync) -> mock.AsyncMock:
    """Helper to create mock FeatureFlagsAsync with async provider returning simple_flag"""
    mock_provider = mock.AsyncMock()
    mock_provider.get_flag.return_value = simple_flag
    mock_ff = mock.AsyncMock(spec=spec)
    mock_ff._provider = mock_provider
    return mock_ff


class TestCachedFeatureFlags:
    """Test synchronous CachedFeatureFlags wrapper"""

    def test_initialization(self, provider_with_flag: InMemoryProvider) -> None:
        """Test CachedFeatureFlags initialization"""
        ff = FeatureFlags(provider_with_flag)
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(ff, storage, default_ttl=10)

        assert cached_ff._ff is ff
        assert cached_ff._storage is storage
        assert cached_ff._default_ttl == 10
        assert cached_ff._ttl_per_flag == {}

    def test_initialization_with_ttl_per_flag(self, provider_with_flag: InMemoryProvider) -> None:
        """Test CachedFeatureFlags initialization with per-flag TTLs"""
        ff = FeatureFlags(provider_with_flag)
        storage = InMemoryStorage()
        ttl_per_flag = {"flag1": 5, "flag2": 20}
        cached_ff = CachedFeatureFlags(ff, storage, default_ttl=10, ttl_per_flag=ttl_per_flag)

        assert cached_ff._ttl_per_flag == ttl_per_flag

    def test_is_enabled_cache_miss_then_hit(self, simple_flag: Flag) -> None:
        """Test cache miss followed by cache hit.

        Verifies:
        - First call: underlying FeatureFlags.is_enabled called (cache miss)
        - Second call: underlying NOT called, result returned from cache (cache hit)
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # First call - cache miss
        result1 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1  # Underlying called

        # Second call - cache hit
        result2 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is True
        assert mock_ff.is_enabled.call_count == 1  # NOT called again - result from cache

    def test_is_enabled_different_contexts(self, simple_flag: Flag) -> None:
        """Test that different contexts are cached separately.

        Verifies:
        - Same flag, different contexts = different cache keys
        - Both underlying calls are executed (different cache entries)
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx1 = {"user": {"plan": "pro"}}
        ctx2 = {"user": {"plan": "free"}}

        # Call with context 1
        result1 = cached_ff.is_enabled("test_flag", ctx=ctx1)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Call with context 2 - different cache key
        result2 = cached_ff.is_enabled("test_flag", ctx=ctx2)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 2  # Called again for different context

        # Call with context 1 again - should hit cache
        result3 = cached_ff.is_enabled("test_flag", ctx=ctx1)
        assert result3 is True
        assert mock_ff.is_enabled.call_count == 2  # NOT called again - cache hit for ctx1

    def test_cache_key_stored_correctly(self, simple_flag: Flag) -> None:
        """Test that cache key is stored correctly in storage.

        Verifies:
        - After is_enabled call, correct key exists in storage
        - Storage contains the cached result
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}
        cached_ff.is_enabled("test_flag", ctx=ctx)

        # Verify cache key is in storage
        cache_key = generate_cache_key("test_flag", simple_flag.version, ctx)
        assert storage.get(cache_key) is True

    def test_is_enabled_respects_ttl(self, simple_flag: Flag) -> None:
        """Test that TTL is respected.

        Verifies:
        - First call: cache miss, underlying called
        - Before TTL expires: cache hit, underlying not called
        - After TTL expires: cache miss, underlying called again
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=1)

        ctx = {"user": {"plan": "pro"}}

        # First call - cache miss
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Second call immediately - cache hit
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Wait for TTL expiration
        time.sleep(1.1)

        # Third call - cache expired, cache miss
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

    def test_is_enabled_respects_per_flag_ttl(self, simple_flag: Flag) -> None:
        """Test that per-flag TTL overrides default TTL.

        Verifies:
        - Per-flag TTL takes precedence over default
        - Expiration happens according to per-flag TTL, not default
        - Default TTL works independently for flags without per-flag TTL
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10, ttl_per_flag={"test_flag": 1})

        ctx = {"user": {"plan": "pro"}}

        # Test per-flag TTL (1 second)
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Cache hit before per-flag TTL expires
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Test default TTL (10 seconds) with another flag
        cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

        # Cache hit for other_flag before default TTL expires
        cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

        # Wait for per-flag TTL expiration (but not default)
        time.sleep(1.1)

        # test_flag cache expired, underlying called
        cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 3

        # other_flag still cached with default TTL, underlying not called
        cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 3

    def test_caches_false_results(self, simple_flag: Flag) -> None:
        """Test that False results are cached.

        Verifies:
        - Negative results (False) are cached, not just True
        - Second call with False cached returns cached value
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "free"}}

        # First call
        result1 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is False
        assert mock_ff.is_enabled.call_count == 1

        # Second call - should hit cache
        result2 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 1  # NOT called again

    def test_is_enabled_with_none_context(self, simple_flag: Flag) -> None:
        """Test caching with None context.

        Verifies:
        - None context is properly handled and cached
        - Cache hit occurs with None context repeated
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        # First call with None context
        cached_ff.is_enabled("test_flag", ctx=None)
        assert mock_ff.is_enabled.call_count == 1

        # Second call - cache hit
        cached_ff.is_enabled("test_flag", ctx=None)
        assert mock_ff.is_enabled.call_count == 1

    def test_is_enabled_passes_through_error_handlers(self, simple_flag: Flag) -> None:
        """Test that error handler parameters are passed through to wrapped instance.

        Verifies:
        - Error handler kwargs are forwarded to underlying FeatureFlags.is_enabled
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Call with error handler overrides
        cached_ff.is_enabled(
            "nonexistent_flag",
            ctx=ctx,
            on_flag_not_found="return_false",
        )

        # Verify parameters were passed through
        mock_ff.is_enabled.assert_called_once_with(
            "nonexistent_flag",
            ctx=ctx,
            on_flag_not_found="return_false",
            on_evaluation_error=None,
            on_provider_error=None,
        )

    def test_clear_cache_all(self, simple_flag: Flag) -> None:
        """Test clearing entire cache.

        Verifies:
        - clear_cache() with no args clears storage
        - Cache is empty after clear
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Cache a result
        cached_ff.is_enabled("test_flag", ctx=ctx)
        cache_key = generate_cache_key("test_flag", simple_flag.version, ctx)
        assert storage.get(cache_key) is True

        # Clear cache
        cached_ff.clear_cache()

        # Verify cache is cleared
        assert storage.get(cache_key) is None

    def test_caching_with_multiple_flags(self, simple_flag: Flag) -> None:
        """Test caching with multiple different flags.

        Verifies:
        - Each flag has independent cache entries
        - Multiple flags can be cached simultaneously
        - Cache hits/misses work correctly across flags
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False, True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Call flag1
        result1 = cached_ff.is_enabled("flag1", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Call flag2 - different cache entry
        result2 = cached_ff.is_enabled("flag2", ctx=ctx)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 2

        # Call flag1 again - cache hit
        result3 = cached_ff.is_enabled("flag1", ctx=ctx)
        assert result3 is True
        assert mock_ff.is_enabled.call_count == 2  # NOT called

        # Call flag2 again - cache hit
        result4 = cached_ff.is_enabled("flag2", ctx=ctx)
        assert result4 is False
        assert mock_ff.is_enabled.call_count == 2  # NOT called

    def test_concurrent_cache_access(self, simple_flag: Flag) -> None:
        """Test concurrent access to cache is thread-safe.

        Verifies:
        - Multiple threads can access cache without corruption
        - Call count reflects correct number of underlying calls
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}
        results = []
        lock = threading.Lock()

        def reader() -> None:
            for _ in range(50):
                result = cached_ff.is_enabled("test_flag", ctx=ctx)
                with lock:
                    results.append(result)  # pyright: ignore[reportUnknownMemberType]

        threads = [threading.Thread(target=reader) for _ in range(3)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # All results should be True (cached value)
        assert all(results)  # pyright: ignore[reportUnknownArgumentType]
        # Only one call to underlying (first one, rest from cache)
        assert mock_ff.is_enabled.call_count == 1

    def test_provider_error_fallback_to_underlying(self, simple_flag: Flag) -> None:
        """Test that provider error causes fallback to underlying FeatureFlags.

        Verifies:
        - When provider.get_flag raises exception, caching is skipped
        - Error is logged and call is delegated to underlying FeatureFlags
        - Underlying is_enabled receives all parameters correctly
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Make provider.get_flag raise an exception
        mock_ff._provider.get_flag.side_effect = Exception("Provider error")

        # Call should delegate to underlying and return its result
        result = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result is False  # Returns what underlying returned

        # Verify underlying was called with correct parameters
        mock_ff.is_enabled.assert_called_once_with(
            "test_flag",
            ctx=ctx,
            on_flag_not_found=None,
            on_evaluation_error=None,
            on_provider_error=None,
        )

    def test_clear_cache_with_specific_key(self, simple_flag: Flag) -> None:
        """Test clearing specific cache key.

        Verifies:
        - clear_cache(cache_key) clears only that specific key
        - Other cache entries remain intact
        """
        mock_ff = _create_mock_ff(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=10)

        ctx1 = {"user": {"plan": "pro"}}
        ctx2 = {"user": {"plan": "free"}}

        # Cache two different results
        cached_ff.is_enabled("test_flag", ctx=ctx1)
        cached_ff.is_enabled("test_flag", ctx=ctx2)

        cache_key1 = generate_cache_key("test_flag", simple_flag.version, ctx1)
        cache_key2 = generate_cache_key("test_flag", simple_flag.version, ctx2)

        assert storage.get(cache_key1) is True
        assert storage.get(cache_key2) is False

        # Clear only cache_key1
        cached_ff.clear_cache(cache_key=cache_key1)

        # Verify only cache_key1 is cleared
        assert storage.get(cache_key1) is None
        assert storage.get(cache_key2) is False  # Still cached


class TestCachedFeatureFlagsAsync:
    """Test asynchronous CachedFeatureFlagsAsync wrapper"""

    @pytest.mark.asyncio
    async def test_initialization(self) -> None:
        """Test CachedFeatureFlagsAsync initialization"""
        provider = InMemoryProviderAsync()
        ff = FeatureFlagsAsync(provider)
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(ff, storage, default_ttl=10)

        assert cached_ff._ff is ff
        assert cached_ff._storage is storage
        assert cached_ff._default_ttl == 10
        assert cached_ff._ttl_per_flag == {}

    @pytest.mark.asyncio
    async def test_initialization_with_ttl_per_flag(self) -> None:
        """Test CachedFeatureFlagsAsync initialization with per-flag TTLs"""
        provider = InMemoryProviderAsync()
        ff = FeatureFlagsAsync(provider)
        storage = InMemoryStorage()
        ttl_per_flag = {"flag1": 5, "flag2": 20}
        cached_ff = CachedFeatureFlagsAsync(ff, storage, default_ttl=10, ttl_per_flag=ttl_per_flag)

        assert cached_ff._ttl_per_flag == ttl_per_flag

    @pytest.mark.asyncio
    async def test_is_enabled_cache_miss_then_hit(self, simple_flag: Flag) -> None:
        """Test async cache miss followed by cache hit.

        Verifies:
        - First call: underlying FeatureFlagsAsync.is_enabled called (cache miss)
        - Second call: underlying NOT called, result returned from cache (cache hit)
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # First call - cache miss
        result1 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Second call - cache hit
        result2 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is True
        assert mock_ff.is_enabled.call_count == 1  # NOT called again

    @pytest.mark.asyncio
    async def test_is_enabled_different_contexts(self, simple_flag: Flag) -> None:
        """Test that different contexts are cached separately (async).

        Verifies:
        - Same flag, different contexts = different cache keys
        - Both underlying calls are executed (different cache entries)
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx1 = {"user": {"plan": "pro"}}
        ctx2 = {"user": {"plan": "free"}}

        # Call with context 1
        result1 = await cached_ff.is_enabled("test_flag", ctx=ctx1)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Call with context 2 - different cache key
        result2 = await cached_ff.is_enabled("test_flag", ctx=ctx2)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 2  # Called again for different context

    @pytest.mark.asyncio
    async def test_is_enabled_respects_ttl(self, simple_flag: Flag) -> None:
        """Test that TTL is respected (async).

        Verifies:
        - First call: cache miss, underlying called
        - Before TTL expires: cache hit, underlying not called
        - After TTL expires: cache miss, underlying called again
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=1)

        ctx = {"user": {"plan": "pro"}}

        # First call - cache miss
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Second call - cache hit
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Wait for TTL expiration
        await asyncio.sleep(1.1)

        # Third call - cache expired
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

    @pytest.mark.asyncio
    async def test_is_enabled_respects_per_flag_ttl_async(self, simple_flag: Flag) -> None:
        """Test that per-flag TTL overrides default TTL (async).

        Verifies:
        - Per-flag TTL takes precedence over default
        - Expiration happens according to per-flag TTL, not default
        - Default TTL works independently for flags without per-flag TTL
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10, ttl_per_flag={"test_flag": 1})

        ctx = {"user": {"plan": "pro"}}

        # Test per-flag TTL (1 second)
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Cache hit before per-flag TTL expires
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 1

        # Test default TTL (10 seconds) with another flag
        await cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

        # Cache hit for other_flag before default TTL expires
        await cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 2

        # Wait for per-flag TTL expiration (but not default)
        await asyncio.sleep(1.1)

        # test_flag cache expired, underlying called
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 3

        # other_flag still cached with default TTL, underlying not called
        await cached_ff.is_enabled("other_flag", ctx=ctx)
        assert mock_ff.is_enabled.call_count == 3

    @pytest.mark.asyncio
    async def test_cache_key_stored_correctly(self, simple_flag: Flag) -> None:
        """Test that cache key is stored correctly in storage (async).

        Verifies:
        - After is_enabled call, correct key exists in storage
        - Storage contains the cached result
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}
        await cached_ff.is_enabled("test_flag", ctx=ctx)

        # Verify cache key is in storage (includes version)
        cache_key = generate_cache_key("test_flag", simple_flag.version, ctx)
        assert storage.get(cache_key) is True

    @pytest.mark.asyncio
    async def test_caches_false_results(self, simple_flag: Flag) -> None:
        """Test that False results are cached (async).

        Verifies:
        - Negative results (False) are cached
        - Second call with False cached returns cached value
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "free"}}

        # First call
        result1 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is False
        assert mock_ff.is_enabled.call_count == 1

        # Second call - should hit cache
        result2 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 1

    @pytest.mark.asyncio
    async def test_is_enabled_with_none_context_async(self, simple_flag: Flag) -> None:
        """Test caching with None context (async).

        Verifies:
        - None context is properly handled and cached
        - Cache hit occurs with None context repeated
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        # First call with None context
        await cached_ff.is_enabled("test_flag", ctx=None)
        assert mock_ff.is_enabled.call_count == 1

        # Second call - cache hit
        await cached_ff.is_enabled("test_flag", ctx=None)
        assert mock_ff.is_enabled.call_count == 1

    @pytest.mark.asyncio
    async def test_is_enabled_passes_through_error_handlers_async(self, simple_flag: Flag) -> None:
        """Test that error handler parameters are passed through to wrapped instance (async).

        Verifies:
        - Error handler kwargs are forwarded to underlying FeatureFlagsAsync.is_enabled
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Call with error handler overrides
        await cached_ff.is_enabled(
            "nonexistent_flag",
            ctx=ctx,
            on_flag_not_found="return_false",
        )

        # Verify parameters were passed through
        mock_ff.is_enabled.assert_called_once_with(
            "nonexistent_flag",
            ctx=ctx,
            on_flag_not_found="return_false",
            on_evaluation_error=None,
            on_provider_error=None,
        )

    @pytest.mark.asyncio
    async def test_clear_cache_all(self, simple_flag: Flag) -> None:
        """Test clearing entire cache (async).

        Verifies:
        - clear_cache() with no args clears storage
        - Cache is empty after clear
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Cache a result
        await cached_ff.is_enabled("test_flag", ctx=ctx)
        cache_key = generate_cache_key("test_flag", simple_flag.version, ctx)
        assert storage.get(cache_key) is True

        # Clear cache
        cached_ff.clear_cache()

        # Verify cache is cleared
        assert storage.get(cache_key) is None

    @pytest.mark.asyncio
    async def test_caching_with_multiple_flags(self, simple_flag: Flag) -> None:
        """Test caching with multiple different flags (async).

        Verifies:
        - Each flag has independent cache entries
        - Multiple flags can be cached simultaneously
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False, True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Call flag1
        result1 = await cached_ff.is_enabled("flag1", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Call flag2 - different cache entry
        result2 = await cached_ff.is_enabled("flag2", ctx=ctx)
        assert result2 is False
        assert mock_ff.is_enabled.call_count == 2

        # Call flag1 again - cache hit
        result3 = await cached_ff.is_enabled("flag1", ctx=ctx)
        assert result3 is True
        assert mock_ff.is_enabled.call_count == 2

        # Call flag2 again - cache hit
        result4 = await cached_ff.is_enabled("flag2", ctx=ctx)
        assert result4 is False
        assert mock_ff.is_enabled.call_count == 2

    @pytest.mark.asyncio
    async def test_concurrent_cache_access_async(self, simple_flag: Flag) -> None:
        """Test concurrent access to cache is safe in async context.

        Verifies:
        - Multiple concurrent tasks can access cache without corruption
        - Call count reflects correct number of underlying calls
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = True
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}
        results = []

        async def reader() -> None:
            for _ in range(50):
                result = await cached_ff.is_enabled("test_flag", ctx=ctx)
                results.append(result)  # pyright: ignore[reportUnknownMemberType]

        # Run concurrent tasks
        tasks = [reader() for _ in range(3)]
        await asyncio.gather(*tasks)

        # All results should be True (cached value)
        assert all(results)  # pyright: ignore[reportUnknownArgumentType]
        # Only one call to underlying (first one, rest from cache)
        assert mock_ff.is_enabled.call_count == 1

    @pytest.mark.asyncio
    async def test_provider_error_fallback_to_underlying_async(self, simple_flag: Flag) -> None:
        """Test that provider error causes fallback to underlying FeatureFlagsAsync.

        Verifies:
        - When provider.get_flag raises exception, caching is skipped (async)
        - Error is logged and call is delegated to underlying FeatureFlagsAsync
        - Underlying is_enabled receives all parameters correctly
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.return_value = False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx = {"user": {"plan": "pro"}}

        # Make provider.get_flag raise an exception
        mock_ff._provider.get_flag.side_effect = Exception("Provider error")

        # Call should delegate to underlying and return its result
        result = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result is False  # Returns what underlying returned

        # Verify underlying was called with correct parameters
        mock_ff.is_enabled.assert_called_once_with(
            "test_flag",
            ctx=ctx,
            on_flag_not_found=None,
            on_evaluation_error=None,
            on_provider_error=None,
        )

    @pytest.mark.asyncio
    async def test_clear_cache_with_specific_key_async(self, simple_flag: Flag) -> None:
        """Test clearing specific cache key (async).

        Verifies:
        - clear_cache(cache_key) clears only that specific key (async)
        - Other cache entries remain intact
        """
        mock_ff = _create_mock_ff_async(simple_flag)
        mock_ff.is_enabled.side_effect = [True, False]
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=10)

        ctx1 = {"user": {"plan": "pro"}}
        ctx2 = {"user": {"plan": "free"}}

        # Cache two different results
        await cached_ff.is_enabled("test_flag", ctx=ctx1)
        await cached_ff.is_enabled("test_flag", ctx=ctx2)

        cache_key1 = generate_cache_key("test_flag", simple_flag.version, ctx1)
        cache_key2 = generate_cache_key("test_flag", simple_flag.version, ctx2)

        assert storage.get(cache_key1) is True
        assert storage.get(cache_key2) is False

        # Clear only cache_key1
        cached_ff.clear_cache(cache_key=cache_key1)

        # Verify only cache_key1 is cleared
        assert storage.get(cache_key1) is None
        assert storage.get(cache_key2) is False  # Still cached


class TestVersionInvalidation:
    """Test cache invalidation based on flag version changes"""

    def test_version_change_invalidates_cache(self) -> None:
        """Test that changing flag version invalidates cache.

        Verifies:
        - Cache is stored with version in the key
        - When flag version changes, old cache is bypassed
        - Underlying is called again with new version
        """
        flag_v1 = Flag(
            name="test_flag",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[Condition(1, "EQUALS", "user.id", active=True)],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=1,
        )

        flag_v2 = Flag(
            name="test_flag",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[Condition(2, "EQUALS", "user.id", active=True)],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=2,  # Version changed
        )

        mock_ff = mock.MagicMock(spec=FeatureFlags)
        mock_ff.is_enabled.side_effect = [True, False]  # v1 returns True, v2 returns False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlags(mock_ff, storage, default_ttl=100)

        ctx = {"user": {"id": 1}}

        # Set up provider to return v1 initially
        mock_provider = mock.MagicMock()
        mock_provider.get_flag.return_value = flag_v1
        mock_ff._provider = mock_provider

        # First call with v1
        result1 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Second call with v1 - cache hit
        result2 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is True
        assert mock_ff.is_enabled.call_count == 1  # Not called again

        # Change flag version in provider
        mock_provider.get_flag.return_value = flag_v2

        # Third call with v2 - should bypass cache (different version)
        result3 = cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result3 is False
        assert mock_ff.is_enabled.call_count == 2  # Called again for new version

    @pytest.mark.asyncio
    async def test_version_change_invalidates_cache_async(self) -> None:
        """Test that changing flag version invalidates cache (async).

        Verifies:
        - Cache is stored with version in the key (async)
        - When flag version changes, old cache is bypassed
        - Underlying is called again with new version
        """
        flag_v1 = Flag(
            name="test_flag",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[Condition(1, "EQUALS", "user.id", active=True)],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=1,
        )

        flag_v2 = Flag(
            name="test_flag",
            description="Test flag",
            rules_strategy="ALL",
            rule_groups=[
                RuleGroup(
                    operator="AND",
                    rules=[
                        Rule(
                            operator="AND",
                            conditions=[Condition(2, "EQUALS", "user.id", active=True)],
                            active=True,
                        )
                    ],
                    active=True,
                )
            ],
            enabled=True,
            version=2,  # Version changed
        )

        mock_ff = _create_mock_ff_async(flag_v1)
        mock_ff.is_enabled.side_effect = [True, False]  # v1 returns True, v2 returns False
        storage = InMemoryStorage()
        cached_ff = CachedFeatureFlagsAsync(mock_ff, storage, default_ttl=100)

        ctx = {"user": {"id": 1}}

        # First call with v1
        result1 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result1 is True
        assert mock_ff.is_enabled.call_count == 1

        # Second call with v1 - cache hit
        result2 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result2 is True
        assert mock_ff.is_enabled.call_count == 1  # Not called again

        # Change flag version in provider
        mock_ff._provider.get_flag.return_value = flag_v2

        # Third call with v2 - should bypass cache (different version)
        result3 = await cached_ff.is_enabled("test_flag", ctx=ctx)
        assert result3 is False
        assert mock_ff.is_enabled.call_count == 2  # Called again for new version
