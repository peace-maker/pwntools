from typing import Any, AnyStr

from pwnlib.context import LocalContext
from pwnlib.tubes.process import process

# TODO: adb.process return type?
@LocalContext
def run_assembly(assembly: AnyStr) -> process: ...
@LocalContext
def run_shellcode(bytes: bytes, **kw: Any) -> process: ...
# TODO: kwargs?
@LocalContext
def run_assembly_exitcode(assembly: AnyStr) -> int: ...
@LocalContext
def run_shellcode_exitcode(bytes: bytes) -> int: ...
