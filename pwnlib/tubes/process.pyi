from typing import Any, AnyStr, Callable, IO
from subprocess import Popen

from pwnlib.elf.corefile import Corefile
from pwnlib.elf.elf import ELF
from pwnlib.tubes.tube import tube

class PTY: ...

STDOUT: int
PIPE: int

signal_names: dict[int, str]

class process(tube):
    STDOUT: int
    PIPE: int
    PTY: PTY

    _stop_noticed: int

    proc: Popen | None
    pty: int | None
    raw: bool
    aslr: bool
    _setuid: bool
    argv: list[bytes]
    executable: str
    env: dict[bytes | str, bytes | str]

    def __init__(
        self,
        argv: (
            AnyStr
            | bytearray
            | list[AnyStr | bytearray]
            | tuple[AnyStr | bytearray]
            | None
        ),
        shell: bool = ...,
        executable: str | None = ...,
        cwd: str | None = ...,
        env: dict[AnyStr, AnyStr] | None = ...,
        ignore_environ: bool | None = ...,
        stdin: int | PTY | None = ...,
        stdout: int | PTY | None = ...,
        stderr: int | PTY | None = ...,
        close_fds: bool = ...,
        preexec_fn: Callable[[], Any] | None = ...,
        raw: bool = ...,
        aslr: bool | None = ...,
        setuid: Any | None = ...,
        where: str = ...,
        display: str | None = ...,
        alarm: int | None = ...,
        creationflags: int = ...,
        *args: Any,
        **kwargs: Any
    ) -> None: ...
    @property
    def program(self) -> str: ...
    @property
    def cwd(self) -> str: ...
    def __getattr__(self, attr: str) -> Any: ...
    def kill(self) -> None: ...
    def poll(self, block: bool = ...) -> int: ...
    def communicate(self, stdin: Any | None) -> tuple[bytes | None, bytes | None]: ...
    def libs(self) -> dict[str, int]: ...
    @property
    def libc(self) -> ELF | None: ...
    @property
    def elf(self) -> ELF: ...
    @property
    def corefile(self) -> Corefile: ...
    def leak(self, address: int, count: int = ...) -> bytes: ...
    def readmem(self, address: int, count: int = ...) -> bytes: ...
    def writemem(self, address: int, data: bytes) -> None: ...
    @property
    def stdin(self) -> IO[Any] | None: ...
    @property
    def stdout(self) -> IO[Any] | None: ...
    @property
    def stderr(self) -> IO[Any] | None: ...
