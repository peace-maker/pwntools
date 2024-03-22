from pwnlib.term.term import width as width, height as height, output as output
from pwnlib.term.keymap import Keymap as Keymap

# TODO: getkey reexport
term_mode: bool

def can_init() -> bool: ...
def init() -> None: ...