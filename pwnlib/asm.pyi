from typing import Any
from pwnlib.context import ContextType, LocalContext

def dpkg_search_for_binutils(arch: str, util: str) -> list[str]: ...
def print_binutils_instructions(util: str, context: ContextType) -> None: ...
def check_binutils_version(util: str) -> str: ...
@LocalContext
def which_binutils(util: str, check_version: bool = ...) -> str | None: ...
@LocalContext
def cpp(shellcode: str) -> str: ...

# TODO: overload return type for extract=True
@LocalContext
def make_elf_from_assembly(assembly: str, vma: int | None = ..., extract: bool = ..., shared: bool = ..., **kwargs: Any) -> bytes | str: ...
@LocalContext
def make_elf(data: bytes, vma: int | None = ..., strip: bool = ..., extract: bool = ..., shared: bool = ...) -> bytes | str: ...
@LocalContext
def make_macho_from_assembly(shellcode: str) -> str: ...
@LocalContext
def make_macho(data: str, is_shellcode: bool = ...) -> str: ...
@LocalContext
def asm(shellcode: str, vma: int = ..., extract: bool = ..., shared: bool = ...) -> bytes | str: ...
@LocalContext
def disasm(data: bytes, vma: int = ..., byte: bool = ..., offset: bool = ..., instructions: bool = ...) -> str: ...
