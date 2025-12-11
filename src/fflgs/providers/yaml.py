import logging
from typing import Any

import yaml

from fflgs.core import FeatureFlagsProviderError, Flag
from fflgs.providers._file_provider import FileProvider

logger = logging.getLogger(__name__)


class _YAMLProvider(FileProvider):
    """YAML file provider"""

    def _parse_file(self) -> Any:
        """Parse YAML file.

        Returns:
            Parsed YAML data

        Raises:
            ValueError: If YAML is invalid
        """
        try:
            with open(self._file_path, encoding="utf-8") as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as exc:
            msg = f"Invalid YAML in {self._file_path}: {exc!s}"
            raise ValueError(msg) from exc


class YAMLProvider(_YAMLProvider):
    """YAML provider for loading feature flags from a YAML file.

    Supports configurable caching with TTL support:

    ```python
    # Always reload from file
    provider = YAMLProvider(
        "flags.yaml",
        cache_ttl_seconds=0,
    )

    # Cache indefinitely (default)
    provider = (
        YAMLProvider(
            "flags.yaml"
        )
    )

    # Cache for 60 seconds, then reload
    provider = YAMLProvider(
        "flags.yaml",
        cache_ttl_seconds=60,
    )
    ```
    """

    def get_flag(self, flag_name: str) -> Flag | None:
        """Get a flag by name from the YAML file.

        Args:
            flag_name: Name of the flag to retrieve

        Returns:
            Flag object if found, None otherwise

        Raises:
            FeatureFlagsProviderError: If YAML is invalid or deserialization fails
        """
        try:
            return self._get_flag(flag_name)
        except Exception as exc:
            msg = f"Failed to load flags from {self._file_path}: {exc!s}"
            raise FeatureFlagsProviderError(msg) from exc


class YAMLProviderAsync(_YAMLProvider):
    """Asynchronous YAML provider for loading feature flags from a YAML file.

    Supports configurable caching with TTL support:

    ```python
    # Always reload from file
    provider = YAMLProviderAsync(
        "flags.yaml",
        cache_ttl_seconds=0,
    )

    # Cache indefinitely (default)
    provider = YAMLProviderAsync(
        "flags.yaml"
    )

    # Cache for 60 seconds, then reload
    provider = YAMLProviderAsync(
        "flags.yaml",
        cache_ttl_seconds=60,
    )
    ```
    """

    async def get_flag(self, flag_name: str) -> Flag | None:
        """Get a flag by name from the YAML file (async).

        Args:
            flag_name: Name of the flag to retrieve

        Returns:
            Flag object if found, None otherwise

        Raises:
            FeatureFlagsProviderError: If YAML is invalid or deserialization fails
        """
        try:
            return self._get_flag(flag_name)
        except Exception as exc:
            msg = f"Failed to load flags from {self._file_path}: {exc!s}"
            raise FeatureFlagsProviderError(msg) from exc
