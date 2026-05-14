from __future__ import annotations
import abc
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    success: bool
    data: Any = None
    error: Optional[str] = None
    raw_output: str = ""


class BaseTool(abc.ABC):
    """Abstract base for all scanner tools."""

    name: str = ""
    description: str = ""

    def __init__(self, scope_urls: list[str] | None = None):
        self.scope_urls = scope_urls or []

    def validate_scope(self, url: str) -> bool:
        if not self.scope_urls:
            return True
        return any(url.startswith(s) for s in self.scope_urls)

    @abc.abstractmethod
    async def run(self, target: str, **kwargs) -> ToolResult:
        ...


_REGISTRY: dict[str, type[BaseTool]] = {}


def register(cls: type[BaseTool]) -> type[BaseTool]:
    _REGISTRY[cls.name] = cls
    return cls


def get_tool(name: str) -> type[BaseTool] | None:
    return _REGISTRY.get(name)


def list_tools() -> list[str]:
    return list(_REGISTRY.keys())
