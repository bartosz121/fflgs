import logging
from collections.abc import Callable
from typing import Any

from fflgs.cache._utils import generate_cache_key
from fflgs.cache.protocol import Storage
from fflgs.core import FeatureFlags, FeatureFlagsAsync, FeatureFlagsProviderError, OnOption

logger = logging.getLogger(__name__)


class CachedFeatureFlags:
    """Feature flags evaluator with caching support.

    Wraps a FeatureFlags instance to cache evaluation results. Results are cached
    per flag name and context, with configurable TTL per flag or a default TTL.

    Thread-safe when using thread-safe Storage implementations (e.g., InMemoryStorage).

    Args:
        ff: The underlying FeatureFlags instance to wrap
        storage: Storage implementation for caching results
        default_ttl: Default time-to-live in seconds for cached results
        ttl_per_flag: Optional dict mapping flag names to custom TTL values (in seconds).
                     If a flag is in this dict, its custom TTL is used instead of default_ttl.

    Example:

        ```python
        provider = InMemoryProvider()
        ff = FeatureFlags(
            provider
        )
        cache_storage = InMemoryStorage()

        cached_ff = CachedFeatureFlags(
            ff,
            cache_storage,
            default_ttl=300,
            ttl_per_flag={
                "critical_flag": 60,
                "user_feature": 600,
            },
        )

        result = cached_ff.is_enabled(
            "user_feature",
            ctx={
                "user_id": 123
            },
        )
        ```
    """

    _ff: FeatureFlags
    _storage: Storage
    _default_ttl: int
    _ttl_per_flag: dict[str, int]
    _key_generator: Callable[[str, int, dict[str, Any] | None], str]

    def __init__(
        self,
        ff: FeatureFlags,
        storage: Storage,
        *,
        default_ttl: int,
        ttl_per_flag: dict[str, int] | None = None,
        key_generator: Callable[[str, int, dict[str, Any] | None], str] = generate_cache_key,
    ) -> None:
        """Initialize cached feature flags wrapper.

        Args:
            ff: Underlying FeatureFlags instance
            storage: Cache storage implementation
            default_ttl: Default TTL in seconds
            ttl_per_flag: Optional per-flag TTL overrides
        """
        self._ff = ff
        self._storage = storage
        self._default_ttl = default_ttl
        self._ttl_per_flag = ttl_per_flag or {}
        self._key_generator = key_generator

        logger.debug(
            "Initialized CachedFeatureFlags with default_ttl=%d, ttl_per_flag=%r",
            default_ttl,
            self._ttl_per_flag,
        )

    def _get_ttl(self, flag_name: str) -> int:
        """Get the appropriate TTL for a flag.

        Args:
            flag_name: Name of the flag

        Returns:
            Per-flag TTL if configured, otherwise default TTL
        """
        return self._ttl_per_flag.get(flag_name, self._default_ttl)

    def is_enabled(
        self,
        flag_name: str,
        *,
        ctx: dict[str, Any] | None = None,
        on_flag_not_found: OnOption | None = None,
        on_evaluation_error: OnOption | None = None,
        on_provider_error: OnOption | None = None,
    ) -> bool:
        """Check if a feature flag is enabled with caching.

        Results are cached using the flag name, version, and context. Subsequent calls
        with the same flag name, version, and context will return the cached result if
        it hasn't expired. When a flag's version changes, cached results are automatically
        invalidated.

        Args:
            flag_name: Name of the flag to check
            ctx: Context dictionary for evaluation
            on_flag_not_found: Override for missing flags
            on_evaluation_error: Override for evaluation errors
            on_provider_error: Override for provider exceptions

        Returns:
            True if flag is enabled, False otherwise
        """

        can_cache = True
        try:
            provider = self._ff._provider  # pyright: ignore[reportPrivateUsage]
            flag = provider.get_flag(flag_name)
        except (FeatureFlagsProviderError, Exception) as exc:
            logger.warning("Error while fetching flag %r: %s", flag_name, exc, exc_info=True)
            can_cache = False
            flag = None

        if not can_cache or flag is None:
            # No caching available or flag not found, delegate to underlying `FeatureFlags`
            return self._ff.is_enabled(
                flag_name,
                ctx=ctx,
                on_flag_not_found=on_flag_not_found,
                on_evaluation_error=on_evaluation_error,
                on_provider_error=on_provider_error,
            )

        cache_key = self._key_generator(flag_name, flag.version, ctx)

        cached_result = self._storage.get(cache_key)
        if cached_result is not None:
            logger.debug("Returning cached result for flag %r (version=%d)", flag_name, flag.version)
            return cached_result

        # Cache miss, evaluate flag and save result in cache
        result = self._ff.is_enabled(
            flag_name,
            ctx=ctx,
            on_flag_not_found=on_flag_not_found,
            on_evaluation_error=on_evaluation_error,
            on_provider_error=on_provider_error,
        )
        ttl = self._get_ttl(flag_name)
        self._storage.set(cache_key, result, ttl)

        return result

    def clear_cache(self, cache_key: str | None = None) -> None:
        """Clear cache entries.

        Args:
            cache_key: Specific cache key to clear, or None to clear entire cache.
        """
        self._storage.clear(cache_key)
        if cache_key is None:
            logger.debug("Cleared entire cache")
        else:
            logger.debug("Cleared cache key %r", cache_key)


class CachedFeatureFlagsAsync:
    """Asynchronous feature flags evaluator with caching support.

    Wraps a FeatureFlagsAsync instance to cache evaluation results. Results are cached
    per flag name and context, with configurable TTL per flag or a default TTL.

    Safe for concurrent access in async contexts (no locking needed).

    Args:
        ff: The underlying FeatureFlagsAsync instance to wrap
        storage: Storage implementation for caching results
        default_ttl: Default time-to-live in seconds for cached results
        ttl_per_flag: Optional dict mapping flag names to custom TTL values (in seconds).
                     If a flag is in this dict, its custom TTL is used instead of default_ttl.

    Example:
        ```python
        provider = InMemoryProviderAsync()
        ff = FeatureFlagsAsync(
            provider
        )
        cache_storage = InMemoryStorage()

        cached_ff = CachedFeatureFlagsAsync(
            ff,
            cache_storage,
            default_ttl=300,
            ttl_per_flag={
                "critical_flag": 60,
                "user_feature": 600,
            },
        )

        result = await cached_ff.is_enabled(
            "user_feature",
            ctx={
                "user_id": 123
            },
        )
        ```
    """

    _ff: FeatureFlagsAsync
    _storage: Storage
    _default_ttl: int
    _ttl_per_flag: dict[str, int]
    _key_generator: Callable[[str, int, dict[str, Any] | None], str]

    def __init__(
        self,
        ff: FeatureFlagsAsync,
        storage: Storage,
        *,
        default_ttl: int,
        ttl_per_flag: dict[str, int] | None = None,
        key_generator: Callable[[str, int, dict[str, Any] | None], str] = generate_cache_key,
    ) -> None:
        """Initialize cached async feature flags wrapper.

        Args:
            ff: Underlying FeatureFlagsAsync instance
            storage: Cache storage implementation
            default_ttl: Default TTL in seconds
            ttl_per_flag: Optional per-flag TTL overrides
        """
        self._ff = ff
        self._storage = storage
        self._default_ttl = default_ttl
        self._ttl_per_flag = ttl_per_flag or {}
        self._key_generator = key_generator

        logger.debug(
            "Initialized CachedFeatureFlagsAsync with default_ttl=%d, ttl_per_flag=%r",
            default_ttl,
            self._ttl_per_flag,
        )

    def _get_ttl(self, flag_name: str) -> int:
        """Get the appropriate TTL for a flag.

        Args:
            flag_name: Name of the flag

        Returns:
            Per-flag TTL if configured, otherwise default TTL
        """
        return self._ttl_per_flag.get(flag_name, self._default_ttl)

    async def is_enabled(
        self,
        flag_name: str,
        *,
        ctx: dict[str, Any] | None = None,
        on_flag_not_found: OnOption | None = None,
        on_evaluation_error: OnOption | None = None,
        on_provider_error: OnOption | None = None,
    ) -> bool:
        """Check if a feature flag is enabled with caching (async).

        Results are cached using the flag name, version, and context. Subsequent calls
        with the same flag name, version, and context will return the cached result if
        it hasn't expired. When a flag's version changes, cached results are automatically
        invalidated.

        Args:
            flag_name: Name of the flag to check
            ctx: Context dictionary for evaluation
            on_flag_not_found: Override for missing flags
            on_evaluation_error: Override for evaluation errors
            on_provider_error: Override for provider exceptions

        Returns:
            True if flag is enabled, False otherwise
        """

        can_cache = True
        try:
            provider = self._ff._provider  # pyright: ignore[reportPrivateUsage]
            flag = await provider.get_flag(flag_name)
        except (FeatureFlagsProviderError, Exception) as exc:
            logger.warning("Error while fetching flag %r: %s", flag_name, exc, exc_info=True)
            can_cache = False
            flag = None

        if not can_cache or flag is None:
            return await self._ff.is_enabled(
                flag_name,
                ctx=ctx,
                on_flag_not_found=on_flag_not_found,
                on_evaluation_error=on_evaluation_error,
                on_provider_error=on_provider_error,
            )

        cache_key = self._key_generator(flag_name, flag.version, ctx)

        cached_result = self._storage.get(cache_key)
        if cached_result is not None:
            logger.debug("Returning cached result for flag %r (version=%d)", flag_name, flag.version)
            return cached_result

        # Cache miss, evaluate flag and save result in cache
        result = await self._ff.is_enabled(
            flag_name,
            ctx=ctx,
            on_flag_not_found=on_flag_not_found,
            on_evaluation_error=on_evaluation_error,
            on_provider_error=on_provider_error,
        )
        ttl = self._get_ttl(flag_name)
        self._storage.set(cache_key, result, ttl)

        return result

    def clear_cache(self, cache_key: str | None = None) -> None:
        """Clear cache entries.

        Args:
            cache_key: Specific cache key to clear, or None to clear entire cache.
        """
        self._storage.clear(cache_key)
        if cache_key is None:
            logger.debug("Cleared entire cache")
        else:
            logger.debug("Cleared cache key %r", cache_key)
