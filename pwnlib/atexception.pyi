from typing import Callable
from typing_extensions import ParamSpec, TypeVar

_P = ParamSpec("_P")
_R = TypeVar("_R")

def register(func: Callable[_P, _R], *args: _P.args, **kwargs: _P.kwargs) -> int: ...
def unregister(func: int) -> None: ...
