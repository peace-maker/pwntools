import collections

class PwnlibArgs(collections.defaultdict[str, str]): ...

args: PwnlibArgs
term_mode: bool
env_prefix: str
free_form: bool

def initialize() -> None: ...
