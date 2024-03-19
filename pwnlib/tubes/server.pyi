import socket

from typing import Any, Callable
from socket import AddressFamily, SocketKind

from six.moves.queue import Queue

from pwnlib.tubes.remote import remote
from pwnlib.tubes.sock import sock, SupportedIPFamilies, SupportedSocketTypes

class server(sock):
    lport: int
    lhost: str | None
    type: SocketKind | None
    family: AddressFamily | None
    proto: int | None
    canonname: str | None
    sockaddr: tuple[str, int] | tuple[str, int, int, int] | None

    connections: Queue[remote]
    rhost: str | None
    rport: int | None

    def __init__(
        self,
        port: int = ...,
        bindaddr: str = ...,
        fam: int | SupportedIPFamilies = ...,
        typ: int | SupportedSocketTypes = ...,
        callback: Callable[[remote], None] = ...,
        blocking: bool = ...,
        *args: Any,
        **kwargs: Any
    ) -> None: ...

    def next_connection(self) -> remote: ...
    