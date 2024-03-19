from typing import Any
from socket import socket, AddressFamily, SocketKind

from pwnlib.tubes.sock import sock, SupportedIPFamilies, SupportedSocketTypes

class remote(sock):
    rhost: str | None
    rport: str | None
    type: SocketKind | None
    family: AddressFamily | None
    proto: int | None
    lhost: str | None
    lport: int | None

    def __init__(
        self,
        host: str,
        port: int,
        fam: int | SupportedIPFamilies = ...,
        typ: int | SupportedSocketTypes = ...,
        ssl: bool = ...,
        # TODO: Better SSLContext type
        ssl_context: Any = ...,
        ssl_args: dict[str, Any] = ...,
        sni: bool | str = ...,
        *args: Any,
        **kwargs: Any
    ) -> None: ...
    @classmethod
    def fromsocket(cls, socket: socket) -> remote: ...

class tcp(remote): ...
class udp(remote): ...
class connect(remote): ...
