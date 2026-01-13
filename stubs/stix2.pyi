from typing import Optional


class Indicator:
    pattern: str

    def __init__(
        self,
        *,
        name: str,
        pattern: str,
        pattern_type: str,
        valid_from: object,
        labels: list[str],
        description: Optional[str] = ...,
        indicator_types: Optional[list[str]] = ...,
        pattern_version: Optional[str] = ...,
        allow_custom: bool = ...,
        **kwargs: object,
    ) -> None: ...


class Bundle:
    def __init__(self, *, objects: list[Indicator], allow_custom: bool = ...) -> None: ...

    def serialize(self, pretty: bool = ...) -> str: ...
