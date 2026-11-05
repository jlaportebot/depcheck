"""depcheck - A dependency health checker for Python projects."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("depcheck-cli")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.4.0"

__author__ = "jlaportebot"

__all__ = ["__author__", "__version__"]
