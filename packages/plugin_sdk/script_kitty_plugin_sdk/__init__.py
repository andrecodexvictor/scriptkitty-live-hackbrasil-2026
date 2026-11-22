from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

try:
    from pydantic import BaseModel
except ImportError:  # pragma: no cover - stdlib fallback when pydantic is absent
    class BaseModel:  # type: ignore[no-redef]
        """Lightweight BaseModel fallback supporting field validation and serialization."""

        def __init__(self, **data: Any) -> None:
            annotations = getattr(self.__class__, "__annotations__", {})
            for field_name in annotations:
                if field_name in data:
                    setattr(self, field_name, data[field_name])
                elif hasattr(self.__class__, field_name):
                    setattr(self, field_name, getattr(self.__class__, field_name))
                else:
                    raise TypeError(f"Missing required field '{field_name}' for {self.__class__.__name__}")
            for extra_key, extra_val in data.items():
                if extra_key not in annotations:
                    setattr(self, extra_key, extra_val)

        def model_dump(self) -> Dict[str, Any]:
            annotations = getattr(self.__class__, "__annotations__", {})
            return {field_name: getattr(self, field_name) for field_name in annotations}

        def dict(self) -> Dict[str, Any]:
            return self.model_dump()

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, self.__class__):
                return False
            return self.model_dump() == other.model_dump()


class PluginMetadata(BaseModel):
    name: str
    version: str
    author: str
    description: str
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH


class BaseScannerPlugin(ABC):
    """Abstract Base Class for community exposure & discovery scanners."""

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        pass

    @abstractmethod
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Executes passive discovery scan on target."""
        pass


class BaseValidatorPlugin(ABC):
    """Abstract Base Class for community vulnerability validators."""

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        pass

    @abstractmethod
    def validate(self, target: str, finding_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """Executes controlled verification flow."""
        pass


class PluginRegistry:
    """Central loader and manager for Script Kitty plugins."""

    ALLOWED_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}

    def __init__(self):
        self.scanners: Dict[str, BaseScannerPlugin] = {}
        self.validators: Dict[str, BaseValidatorPlugin] = {}

    def _validate_metadata(self, meta: PluginMetadata) -> None:
        if not meta.name or not meta.name.strip():
            raise ValueError("Plugin metadata.name must be non-empty")
        if meta.risk_level.upper() not in self.ALLOWED_RISK_LEVELS:
            raise ValueError(f"Unsupported plugin risk_level: {meta.risk_level}")

    def register_scanner(self, plugin: BaseScannerPlugin):
        if not isinstance(plugin, BaseScannerPlugin):
            raise TypeError("Scanner plugin must inherit from BaseScannerPlugin")
        meta = plugin.metadata
        self._validate_metadata(meta)
        self.scanners[meta.name] = plugin

    def register_validator(self, plugin: BaseValidatorPlugin):
        if not isinstance(plugin, BaseValidatorPlugin):
            raise TypeError("Validator plugin must inherit from BaseValidatorPlugin")
        meta = plugin.metadata
        self._validate_metadata(meta)
        self.validators[meta.name] = plugin

    def get_scanner(self, name: str) -> Optional[BaseScannerPlugin]:
        return self.scanners.get(name)

    def get_validator(self, name: str) -> Optional[BaseValidatorPlugin]:
        return self.validators.get(name)

    def list_plugins(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "scanners": [p.metadata.model_dump() for p in self.scanners.values()],
            "validators": [p.metadata.model_dump() for p in self.validators.values()],
        }


__all__ = [
    "PluginMetadata",
    "BaseScannerPlugin",
    "BaseValidatorPlugin",
    "PluginRegistry",
]
