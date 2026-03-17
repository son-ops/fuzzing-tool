from dataclasses import dataclass

@dataclass(frozen=True)
class InjectionPoint:
    kind: str
    key: str | None = None
    path: list | None = None
    index: int | None = None
