from fflgs.core import Flag


class InMemoryProvider:
    """In-memory implementation of FeatureFlagsProvider"""

    _flags: dict[str, Flag]

    def __init__(self) -> None:
        self._flags: dict[str, Flag] = {}

    def add_flag(self, flag: Flag) -> None:
        self._flags[flag.name] = flag

    def get_flag(self, flag_name: str) -> Flag | None:
        return self._flags.get(flag_name)


class InMemoryProviderAsync:
    """In-memory implementation of FeatureFlagsProviderAsync"""

    _flags: dict[str, Flag]

    def __init__(self) -> None:
        self._flags: dict[str, Flag] = {}

    def add_flag(self, flag: Flag) -> None:
        self._flags[flag.name] = flag

    async def get_flag(self, flag_name: str) -> Flag | None:
        return self._flags.get(flag_name)
