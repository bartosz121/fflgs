import json
import logging
from typing import Any

from fflgs.core import FeatureFlagsProviderError, Flag
from fflgs.providers._file_provider import FileProvider

logger = logging.getLogger(__name__)


class _JSONProvider(FileProvider):
    """JSON file provider"""

    def _parse_file(self) -> Any:
        """Parse JSON file.

        Returns:
            Parsed JSON data

        Raises:
            ValueError: If JSON is invalid
        """
        try:
            with open(self._file_path, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON in {self._file_path}: {exc!s}"
            raise ValueError(msg) from exc


class JSONProvider(_JSONProvider):
    """JSON provider for loading feature flags from a JSON file.

    Supports configurable caching with TTL support:

    ```python
    # Always reload from file
    provider = JSONProvider(
        "flags.json",
        cache_enabled=False,
    )

    # Cache indefinitely (default)
    provider = (
        JSONProvider(
            "flags.json"
        )
    )

    # Cache for 60 seconds, then reload
    provider = JSONProvider(
        "flags.json",
        cache_ttl_seconds=60,
    )
    ```
    """

    def get_flag(self, flag_name: str) -> Flag | None:
        """Get a flag by name from the JSON file.

        Args:
            flag_name: Name of the flag to retrieve

        Returns:
            Flag object if found, None otherwise

        Raises:
            FeatureFlagsProviderError: If JSON is invalid or deserialization fails
        """
        try:
            return self._get_flag(flag_name)
        except Exception as exc:
            msg = f"Failed to load flags from {self._file_path}: {exc!s}"
            raise FeatureFlagsProviderError(msg) from exc


class JSONProviderAsync(_JSONProvider):
    """Asynchronous JSON provider for loading feature flags from a JSON file.

    Supports configurable caching with TTL support:

    ```python
    # Always reload from file
    provider = JSONProviderAsync(
        "flags.json",
        cache_enabled=False,
    )

    # Cache indefinitely (default)
    provider = JSONProviderAsync(
        "flags.json"
    )

    # Cache for 60 seconds, then reload
    provider = JSONProviderAsync(
        "flags.json",
        cache_ttl_seconds=60,
    )
    ```
    """

    async def get_flag(self, flag_name: str) -> Flag | None:
        """Get a flag by name from the JSON file (async).

        Args:
            flag_name: Name of the flag to retrieve

        Returns:
            Flag object if found, None otherwise

        Raises:
            FeatureFlagsProviderError: If JSON is invalid or deserialization fails
        """
        try:
            return self._get_flag(flag_name)
        except Exception as exc:
            msg = f"Failed to load flags from {self._file_path}: {exc!s}"
            raise FeatureFlagsProviderError(msg) from exc
