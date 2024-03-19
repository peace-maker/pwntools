from socket import AddressFamily, SocketKind
from typing import Any

from pwnlib.tubes.remote import remote
from pwnlib.tubes.sock import sock

class listen(sock):
    lport: int
    lhost: str | None
    type: SocketKind | None
    family: AddressFamily | None
    protocol: int | None
    proto: int | None
    canonname: str | None
    sockaddr: tuple[str, int] | tuple[str, int, int, int] | None

    rhost: str | None
    rport: int | None

    def __init__(self, port: int = ..., bindaddr: str = ..., fam: int | str = ..., typ: int | str = ..., *args: Any, **kwargs: Any) -> None: ...
    def spawn_process(self, *args: Any, **kwargs: Any) -> None: ...
    def wait_for_connection(self) -> listen: ...
