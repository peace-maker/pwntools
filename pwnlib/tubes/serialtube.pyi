from typing import Any

from pwnlib.tubes.tube import tube

class serialtube(tube):
    def __init__(
        self,
        port: str | None = ...,
        baudrate: int = ...,
        convert_newlines: bool = ...,
        bytesize: int = ...,
        parity: str = ...,
        stopbits: int = ...,
        xonoff: bool = ...,
        rtscts: bool = ...,
        dsrdtr: bool = ...,
        *args: Any,
        **kwargs: Any
    ) -> None: ...
