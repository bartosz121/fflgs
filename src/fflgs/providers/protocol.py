from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from fflgs.core import Flag


class FeatureFlagsProvider(Protocol):
    """Provider interface for feature flags.

    Implementations should raise FeatureFlagsProviderError for any errors encountered
    while fetching flags (network failures, database errors, invalid data, etc.).

    Example:
        try:
            flag = self.db.query_flag(flag_name)
            return flag
        except DatabaseError as exc:
            raise FeatureFlagsProviderError(f"Database error: {exc}") from exc
    """

    def get_flag(self, flag_name: str) -> "Flag | None": ...  # pragma: no cover


class FeatureFlagsProviderAsync(Protocol):
    """Asynchronous provider interface for feature flags.

    Implementations should raise FeatureFlagsProviderError for any errors encountered
    while fetching flags (network failures, database errors, invalid data, etc.).

    Example:
        try:
            flag = await self.db.query_flag(flag_name)
            return flag
        except DatabaseError as exc:
            raise FeatureFlagsProviderError(f"Database error: {exc}") from exc
    """

    async def get_flag(self, flag_name: str) -> "Flag | None": ...  # pragma: no cover
