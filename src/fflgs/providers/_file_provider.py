import logging
import os
import time
from collections.abc import Callable
from typing import Any

from fflgs.core import Flag
from fflgs.providers._utils import deserialize_flag

logger = logging.getLogger(__name__)


class FileProvider:
    """Base file-based provider with configurable caching and file loading.

    Handles cache management and deserialization for any file-based flag provider.
    """

    _file_path: str
    _cache_enabled: bool
    _cache_ttl_seconds: int | None
    _flags_cache: dict[str, Flag]
    _last_load_time: float
    _flag_loads: Callable[[dict[str, Any]], Flag]

    def __init__(
        self,
        file_path: str,
        *,
        cache_ttl_seconds: int | None = None,
        flag_loads: Callable[[dict[str, Any]], Flag] = deserialize_flag,
    ) -> None:
        """Initialize the file-based provider.

        Args:
            file_path: Path to the file containing flags
            cache_ttl_seconds: Time-to-live for cached flags in seconds.
                - None (default): Cache indefinitely, never expire
                - 0: Disable caching
                - N > 0: Reload flags if cache is older than N seconds
            flag_loads: Callable to deserialize flag dictionaries

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If cache_ttl_seconds is negative
        """
        if not os.path.exists(file_path):
            msg = f"File not found: {file_path}"
            raise FileNotFoundError(msg)

        if cache_ttl_seconds is not None and cache_ttl_seconds < 0:
            msg = "cache_ttl_seconds must be non-negative"
            raise ValueError(msg)

        self._file_path = file_path
        self._cache_ttl_seconds = cache_ttl_seconds

        self._cache_enabled = self._cache_ttl_seconds != 0
        self._flags_cache = {}
        self._last_load_time = -1  # `-1` = never loaded, forces first load
        self._flag_loads = flag_loads

        logger.debug(
            "%s initialized, path: %s; cache_ttl: %s",
            self.__class__.__name__,
            self._file_path,
            self._cache_ttl_seconds,
        )

    def _is_cache_valid(self) -> bool:
        """Check if cached flags are still valid.

        Returns:
            True if cache exists and is still valid, False otherwise
        """
        if not self._cache_enabled:
            return False

        if self._last_load_time == -1:
            # Never loaded yet, need to load flags first
            return False

        if self._cache_ttl_seconds is None:
            # Infinite TTL - always valid after first load
            return True

        elapsed = time.time() - self._last_load_time
        is_valid = elapsed < self._cache_ttl_seconds
        logger.debug(
            "%s cache is %s, elapsed: %.2f, ttl: %s",
            self.__class__.__name__,
            is_valid,
            elapsed,
            self._cache_ttl_seconds,
        )
        return is_valid

    def _parse_file(self) -> Any:
        """Parse the file contents. Must be overridden by subclasses.

        Returns:
            Parsed data from the file

        Raises:
            ValueError: If file parsing fails
        """
        raise NotImplementedError

    def _load_flags(self) -> dict[str, Flag]:
        """Load and cache flags from file.

        Returns:
            Dictionary mapping flag names to Flag objects

        Raises:
            ValueError: If parsing is invalid or missing required fields
        """
        if self._is_cache_valid():
            return self._flags_cache

        try:
            data = self._parse_file()
        except OSError as exc:
            msg = f"Failed to read file {self._file_path}: {exc!s}"
            raise ValueError(msg) from exc

        if not isinstance(data, list):
            msg = f"Expected list in {self._file_path}, got {type(data).__name__}"
            raise ValueError(msg)

        flags_cache: dict[str, Flag] = {}
        for i, flag_data in enumerate(data):  # pyright: ignore[reportUnknownArgumentType, reportUnknownVariableType]
            try:
                if not isinstance(flag_data, dict):
                    msg = f"Flag #{i} must be an object (dict), got {type(flag_data).__name__}"  # pyright: ignore[reportUnknownArgumentType]
                    raise ValueError(msg)

                flag = self._flag_loads(flag_data)  # pyright: ignore[reportUnknownArgumentType]
                flags_cache[flag.name] = flag
                logger.debug("Loaded flag %r from file", flag.name)  # pyright: ignore[reportUnknownArgumentType]
            except (ValueError, KeyError, TypeError) as exc:
                msg = f"Failed to deserialize flag #{i}: {exc!s}"
                raise ValueError(msg) from exc

        if self._cache_enabled:
            self._flags_cache = flags_cache
            self._last_load_time = time.time()
            logger.debug("Cached %d flags from %r", len(flags_cache), self._file_path)

        return flags_cache

    def _get_flag(self, flag_name: str) -> Flag | None:
        """Get a flag by name from the file.

        Args:
            flag_name: Name of the flag to retrieve

        Returns:
            Flag object if found, None otherwise
        """
        flags = self._load_flags()
        return flags.get(flag_name)
