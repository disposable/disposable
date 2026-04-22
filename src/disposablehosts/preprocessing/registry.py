"""Preprocessor registry for dynamic loading of data preprocessors."""

import importlib
from functools import lru_cache
from types import ModuleType
from typing import Any, Callable, List, Optional, cast

PreprocessorFn = Callable[[bytes, Any], Optional[List[str]]]


def _import_preprocessor_module(module_name: str) -> ModuleType:
    """Import a preprocessor module by name."""
    return importlib.import_module(f"disposablehosts.preprocessing.{module_name}")


@lru_cache(maxsize=None)
def get_preprocessor(type_name: str) -> PreprocessorFn:
    """Get a preprocessor function by type name.

    Args:
        type_name: The source type name (e.g., 'json', 'html', 'file', 'sha1', 'ws').

    Returns:
        The preprocessor function for the given type.

    Raises:
        RuntimeError: If the preprocessor module doesn't export a valid function.
    """
    # Map source types to preprocessor module names
    type_map = {
        "json": "json",
        "list": "file",
        "file": "file",
        "whitelist": "file",
        "whitelist_file": "file",
        "greylist": "file",
        "greylist_file": "file",
        "html": "html",
        "sha1": "sha1",
        "ws": "websocket",
    }

    module_name = type_map.get(type_name)
    if not module_name:
        raise RuntimeError(f"Unknown preprocessor type: {type_name}")

    mod = _import_preprocessor_module(module_name)

    fn = getattr(mod, f"preprocess_{module_name}", None)
    if not callable(fn):
        raise RuntimeError(f"Preprocessor module preprocessing.{module_name} does not export callable 'preprocess_{module_name}'")

    return cast(PreprocessorFn, fn)
