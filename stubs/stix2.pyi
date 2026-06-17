
class Indicator:
    id: str
    type: str
    name: str
    pattern: str

    def __init__(
        self,
        *,
        name: str,
        pattern: str,
        pattern_type: str,
        valid_from: object,
        labels: list[str] | None = ...,
        description: str | None = ...,
        indicator_types: list[str] | None = ...,
        pattern_version: str | None = ...,
        allow_custom: bool = ...,
        **kwargs: object,
    ) -> None: ...


class Vulnerability:
    id: str
    type: str
    name: str

    def __init__(
        self,
        *,
        name: str,
        created: object = ...,
        modified: object = ...,
        external_references: list[dict[str, str]] | None = ...,
        description: str | None = ...,
        allow_custom: bool = ...,
        **kwargs: object,
    ) -> None: ...


class Bundle:
    def __init__(
        self, *, objects: list[Indicator | Vulnerability], allow_custom: bool = ...
    ) -> None: ...

    def serialize(self, pretty: bool = ...) -> str: ...
