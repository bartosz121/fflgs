from importlib.metadata import PackageNotFoundError, version

try:  # noqa: RUF067
    __version__ = version("fflgs")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"
finally:
    del version, PackageNotFoundError
