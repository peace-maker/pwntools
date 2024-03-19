class FileStructure:
    vars_: list[str]
    length: dict[str, int]

    flags: int | bytes
    _IO_read_ptr: int | bytes
    _IO_read_end: int | bytes
    _IO_read_base: int | bytes
    _IO_write_base: int | bytes
    _IO_write_ptr: int | bytes
    _IO_write_end: int | bytes
    _IO_buf_base: int | bytes
    _IO_buf_end: int | bytes
    _IO_save_base: int | bytes
    _IO_backup_base: int | bytes
    _IO_save_end: int | bytes
    markers: int | bytes
    chain: int | bytes
    fileno: int | bytes
    _flags2: int | bytes
    _old_offset: int | bytes
    _cur_column: int | bytes
    _vtable_offset: int | bytes
    _shortbuf: int | bytes
    unknown1: int | bytes
    _lock: int | bytes
    _offset: int | bytes
    _codecvt: int | bytes
    _wide_data: int | bytes
    unknown2: int | bytes
    vtable: int | bytes

    def __init__(self, null: int = ...) -> None: ...
    def __setattr__(self, item: str, value: int | bytes) -> None: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __bytes__(self) -> bytes: ...
    def struntil(self, v: str) -> bytes: ...
    def setdefault(self, null: int) -> None: ...
    def write(self, addr: int = ..., size: int = ...) -> bytes: ...
    def read(self, addr: int = ..., size: int = ...) -> bytes: ...
    def orange(self, io_list_all: int, vtable: int) -> bytes: ...
