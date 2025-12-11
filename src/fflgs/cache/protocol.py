from typing import Protocol


class Storage(Protocol):
    """Protocol for storing and retrieving cached flag evaluation results.

    Implementations must support TTL-based expiration of cached values.
    """

    def get(self, key: str) -> bool | None:
        """Retrieve a cached flag evaluation result.

        Args:
            key: Cache key (typically "flag_name:ctx_hash")

        Returns:
            Cached boolean result if key exists and hasn't expired, None otherwise
        """
        ...  # pragma: no cover

    def set(self, key: str, value: bool, ttl: int) -> None:  # noqa: FBT001
        """Store a flag evaluation result with a time-to-live.

        Args:
            key: Cache key (typically "flag_name:ctx_hash")
            value: Boolean result to cache
            ttl: Time-to-live in seconds
        """
        ...  # pragma: no cover

    def clear(self, key: str | None = None) -> None:
        """Clear cache entries.

        Args:
            key: Specific cache key to clear, or None to clear entire cache
        """
        ...  # pragma: no cover
