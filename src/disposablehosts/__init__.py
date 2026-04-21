"""Disposable email domain generator package."""

from .cli import main
from .generator import disposableHostGenerator
from .remote_data import remoteData

__all__ = ["disposableHostGenerator", "main", "remoteData"]
__version__ = "0.3.0"
