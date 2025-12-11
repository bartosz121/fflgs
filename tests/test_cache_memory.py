# pyright: reportPrivateUsage=false
# ruff: noqa: PLC2701

import threading
import time

from fflgs.cache._utils import generate_cache_key
from fflgs.cache.memory import InMemoryStorage


class TestInMemoryStorage:
    """Test InMemoryStorage cache implementation"""

    def test_set_and_get(self) -> None:
        """Test basic set and get operations"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=10)
        assert storage.get("key1") is True

    def test_get_nonexistent_key(self) -> None:
        """Test getting a non-existent key returns None"""
        storage = InMemoryStorage()
        assert storage.get("nonexistent") is None

    def test_ttl_expiration(self) -> None:
        """Test that cached values expire after TTL"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=1)
        assert storage.get("key1") is True

        # Wait for expiration
        time.sleep(1.1)
        assert storage.get("key1") is None

    def test_set_overwrites_existing(self) -> None:
        """Test that setting a key multiple times overwrites"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=10)
        assert storage.get("key1") is True

        storage.set("key1", False, ttl=10)
        assert storage.get("key1") is False

    def test_clear_single_key(self) -> None:
        """Test clearing a single cache key"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=10)
        storage.set("key2", False, ttl=10)

        storage.clear("key1")
        assert storage.get("key1") is None
        assert storage.get("key2") is False

    def test_clear_all_keys(self) -> None:
        """Test clearing entire cache"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=10)
        storage.set("key2", False, ttl=10)

        storage.clear()
        assert storage.get("key1") is None
        assert storage.get("key2") is None

    def test_clear_nonexistent_key(self) -> None:
        """Test clearing a non-existent key doesn't raise error"""
        storage = InMemoryStorage()
        storage.clear("nonexistent")  # Should not raise

    def test_thread_safety_concurrent_access(self) -> None:
        """Test that storage is thread-safe for concurrent access"""
        storage = InMemoryStorage()
        storage.set("key1", True, ttl=10)

        results = []

        def reader() -> None:
            for _ in range(100):
                result = storage.get("key1")
                results.append(result)  # pyright: ignore[reportUnknownMemberType]

        def writer() -> None:
            for i in range(100):
                storage.set("key1", i % 2 == 0, ttl=10)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=writer),
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # All operations completed without deadlock/error
        assert len(results) == 200  # pyright: ignore[reportUnknownArgumentType]


class TestGenerateCacheKey:
    """Test cache key generation"""

    def test_deterministic_key_generation(self) -> None:
        """Test that the same inputs generate the same key"""
        ctx1 = {"user": "alice", "plan": "pro"}
        key1 = generate_cache_key("flag1", 1, ctx1)
        key2 = generate_cache_key("flag1", 1, ctx1)
        assert key1 == key2

    def test_different_contexts_different_keys(self) -> None:
        """Test that different contexts generate different keys"""
        ctx1 = {"user": "alice"}
        ctx2 = {"user": "bob"}
        key1 = generate_cache_key("flag1", 1, ctx1)
        key2 = generate_cache_key("flag1", 1, ctx2)
        assert key1 != key2

    def test_different_flags_different_keys(self) -> None:
        """Test that different flag names generate different keys"""
        ctx = {"user": "alice"}
        key1 = generate_cache_key("flag1", 1, ctx)
        key2 = generate_cache_key("flag2", 1, ctx)
        assert key1 != key2

    def test_none_context(self) -> None:
        """Test key generation with None context"""
        key = generate_cache_key("flag1", 1, None)
        assert key.startswith("flag1:1:")

    def test_empty_context(self) -> None:
        """Test key generation with empty context"""
        key = generate_cache_key("flag1", 1, {})
        assert key.startswith("flag1:1:")

    def test_nested_context(self) -> None:
        """Test key generation with nested context"""
        ctx = {"user": {"profile": {"role": "admin"}}}
        key = generate_cache_key("flag1", 1, ctx)
        assert key.startswith("flag1:1:")

    def test_non_json_serializable_values(self) -> None:
        """Test key generation with non-JSON-serializable values"""
        ctx = {"timestamp": object()}
        # Should not raise, should convert to string
        key = generate_cache_key("flag1", 1, ctx)
        assert key.startswith("flag1:1:")

    def test_key_format(self) -> None:
        """Test that generated keys have correct format"""
        ctx = {"test": "data"}
        key = generate_cache_key("my_flag", 1, ctx)
        assert key.startswith("my_flag:1:")
        parts = key.split(":")
        assert len(parts) == 3  # flag_name:version:hash
        assert parts[0] == "my_flag"
        assert parts[1] == "1"
        assert len(parts[2]) == 16  # SHA256 hash truncated to 16 chars

    def test_order_independent_context(self) -> None:
        """Test that context key order doesn't affect hash (uses sort_keys=True)"""
        ctx1 = {"a": 1, "b": 2, "c": 3}
        ctx2 = {"c": 3, "a": 1, "b": 2}
        key1 = generate_cache_key("flag", 1, ctx1)
        key2 = generate_cache_key("flag", 1, ctx2)
        assert key1 == key2

    def test_version_change_different_keys(self) -> None:
        """Test that different versions generate different keys"""
        ctx = {"user": "alice"}
        key1 = generate_cache_key("flag", 1, ctx)
        key2 = generate_cache_key("flag", 2, ctx)
        assert key1 != key2
