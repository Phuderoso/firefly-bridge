"""Public bridge API and the single runtime version source.

Lazy exports preserve the RC2 import surface without eagerly importing transport
or daemon modules (and without creating version/import cycles).
"""

from importlib import import_module
from typing import TYPE_CHECKING

__version__ = "0.4.0"
__all__ = ["Bridge", "Receipt", "__version__"]

if TYPE_CHECKING:
    from firefly_bridge.bridge import Bridge as Bridge
    from firefly_bridge.messages import Receipt as Receipt


def __getattr__(name):
    modules = {"Bridge": ".bridge", "Receipt": ".messages"}
    if name not in modules:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(modules[name], __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
