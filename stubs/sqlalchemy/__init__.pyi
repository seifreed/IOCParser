from typing import Generic, TypeVar

T = TypeVar("T")


class Engine:
    ...


def create_engine(url: str, future: bool = ...) -> Engine:
    ...


class MetaData:
    def create_all(self, engine: Engine) -> None: ...


class Boolean:
    ...


class DateTime:
    ...


class ForeignKey:
    def __init__(self, target: str) -> None: ...


class Integer:
    ...


class String:
    def __init__(self, length: int | None = None) -> None: ...


class Text:
    ...


class UniqueConstraint:
    def __init__(self, *columns: str, name: str | None = None) -> None: ...


class Select(Generic[T]):
    def where(self, *criteria: object) -> "Select[T]": ...


def select(entity: type[T]) -> Select[T]:
    ...
