"""Disposable email domain generator package."""

from importlib.metadata import version

from .cli import main
from .generator import disposableHostGenerator
from .remote_data import remoteData

__all__ = ["disposableHostGenerator", "main", "remoteData"]
__version__ = version("disposable")
