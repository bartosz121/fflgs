"""In-memory cache storage implementation with TTL support"""

import logging
import threading
import time

logger = logging.getLogger(__name__)


class InMemoryStorage:
    """In-memory cache storage with TTL-based expiration.

    Stores flag evaluation results with expiration timestamps. Expired entries
    are automatically filtered out on retrieval.
    """

    _cache: dict[str, tuple[bool, float]]
    _lock: threading.Lock

    def __init__(self) -> None:
        self._cache: dict[str, tuple[bool, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> bool | None:
        """Retrieve a cached value if it exists and hasn't expired.

        Args:
            key: Cache key

        Returns:
            Cached boolean value if key exists and TTL hasn't expired, None otherwise
        """
        with self._lock:
            if key not in self._cache:
                logger.debug("Cache miss for key %r", key)
                return None

            value, expiration = self._cache[key]
            if time.time() >= expiration:
                logger.debug("Cache expired for key %r", key)
                del self._cache[key]
                return None

            logger.debug("Cache hit for key %r", key)
            return value

    def set(self, key: str, value: bool, ttl: int) -> None:  # noqa: FBT001
        """Store a value with TTL-based expiration.

        Args:
            key: Cache key
            value: Boolean value to cache
            ttl: Time-to-live in seconds
        """
        expiration = time.time() + ttl
        with self._lock:
            self._cache[key] = (value, expiration)
            logger.debug("Cached key %r with TTL %d seconds", key, ttl)

    def clear(self, key: str | None = None) -> None:
        """Clear cache entries.

        Args:
            key: Specific cache key to clear, or None to clear entire cache
        """
        with self._lock:
            if key is None:
                self._cache.clear()
                logger.debug("Cleared entire cache")
            elif key in self._cache:
                del self._cache[key]
                logger.debug("Cleared cache key %r", key)
