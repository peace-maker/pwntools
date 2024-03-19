from collections.abc import Iterable, Mapping
from typing import Any, TextIO
from typing_extensions import TypeAlias, Literal

import logging

ValidLoglevel: TypeAlias = Literal[
        "CRITICAL",
        "ERROR",
        "WARNING",
        "WARN",
        "INFO",
        "DEBUG",
        "NOTSET",
        "critical",
        "error",
        "warning",
        "warn",
        "info",
        "debug",
        "notset",
    ]

class Progress:
    last_status: float
    rate: float

    def __init__(
        self,
        logger: Logger,
        msg: str,
        status: float,
        level: int,
        args: Iterable[Any],
        kwargs: Mapping[str, Any],
    ) -> None: ...

    def status(self, status: str, *args: Any, **kwargs: Any) -> None: ...
    def success(self, status: str = ..., *args: Any, **kwargs: Any) -> None: ...
    def failure(self, status: str = ..., *args: Any, **kwargs: Any) -> None: ...
    def __enter__(self) -> Progress: ...
    def __exit__(self, *args: Any) -> None: ...

class Logger:
    _logger: logging.Logger

    def __init__(self, logger: logging.Logger | None = ...) -> None: ...
    def progress(self, message: str, status: str = ..., *args: Any, **kwargs: Any) -> Progress: ...
    def waitfor(self, *args: Any, **kwargs: Any) -> Progress: ...
    def indented(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def success(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def failure(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def info_once(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def warning_once(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def warn_once(self, message: str, *args: Any, **kwargs: Any) -> None: ...

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def info(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def hexdump(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def maybe_hexdump(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def warning(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def warn(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def error(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def exception(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def critical(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def log(self, level: int, message: str, *args: Any, **kwargs: Any) -> None: ...

    def isEnabledFor(self, level: int) -> bool: ...
    def setLevel(self, level: int | ValidLoglevel) -> None: ...
    def addHandler(self, handler: logging.Handler) -> None: ...
    def removeHandler(self, handler: logging.Handler) -> None: ...

    @property
    def level(self) -> int: ...
    @level.setter
    def level(self, level: int | ValidLoglevel) -> None: ...

class _PwnlibLogRecord(logging.LogRecord):
    pwnlib_msgtype: str
    pwnlib_progress: Progress | None

class Handler(logging.StreamHandler): ...

class Formatter(logging.Formatter):
    indent: str
    nlindent: str

def getLogger(name: str) -> Logger: ...

class LogfileHandler(logging.FileHandler): ...

log_file: LogfileHandler
console: Handler
formatter: Formatter