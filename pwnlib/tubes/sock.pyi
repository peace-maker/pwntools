import socket

from typing_extensions import TypeAlias, Literal

from pwnlib.tubes.tube import tube

SupportedIPFamilies: TypeAlias = Literal[
    "any", "ipv4", "ipv6", "ip4", "ip6", "v4", "v6", "4", "6"
]
SupportedSocketTypes: TypeAlias = Literal["tcp", "udp"]

class sock(tube):
    sock: socket.socket | None
    closed: dict[Literal["recv", "send"], bool]

    @classmethod
    def _get_family(cls, fam: int | SupportedIPFamilies) -> int: ...
    @classmethod
    def _get_type(cls, typ: int | SupportedSocketTypes) -> int: ...
