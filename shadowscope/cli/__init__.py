"""
CLI Framework for SHADOWSCOPE
Provides command-line interface using Typer and Rich.
"""

from .app import app
from .commands import *

__all__ = ["app"]
