"""
Common interface for accessing executable files.
This includes :class:`pwnlib.elf.ELF` and :class:`pwnlib.pe.PE`.
"""

from pwnlib.asm import disasm
from pwnlib.tubes.process import process

class dotdict(dict):
    """Wrapper to allow dotted access to dictionary elements.

    Is a real :class:`dict` object, but also serves up keys as attributes
    when reading attributes.

    Supports recursive instantiation for keys which contain dots.

    Example:

        >>> x = pwnlib.elf.elf.dotdict()
        >>> isinstance(x, dict)
        True
        >>> x['foo'] = 3
        >>> x.foo
        3
        >>> x['bar.baz'] = 4
        >>> x.bar.baz
        4
    """
    def __missing__(self, name):
        if isinstance(name, (bytes, bytearray)):
            name = packing._decode(name)
            return self[name]
        raise KeyError(name)

    def __getattr__(self, name):
        if name in self:
            return self[name]

        name_dot = name + '.'
        name_len = len(name_dot)
        subkeys = {k[name_len:]: self[k] for k in self if k.startswith(name_dot)}

        if subkeys:
            return dotdict(subkeys)
        raise AttributeError(name)

class Binary:
    @staticmethod
    def from_path(path, *k, **kw):
        """
        Returns an ELF or an PE object depending on the file type.
        """
        # Avoid cyclic imports :(
        from pwnlib.elf import ELF
        from pwnlib.pe import PE
        try:
            # Try loading it as an ELF first.
            return ELF(path, *k, **kw)
        except:
            return PE(path, *k, **kw)
    
    def _get_machine_arch(self):
        raise NotImplementedError

    @property
    def entry(self):
        raise NotImplementedError
    entrypoint = entry
    start      = entry

    @property
    def address(self):
        raise NotImplementedError
    
    @address.setter
    def address(self, new):
        raise NotImplementedError

    def process(self, argv=[], *a, **kw):
        """process(argv=[], *a, **kw) -> process

        Execute the binary with :class:`.process`.  Note that ``argv``
        is a list of arguments, and should not include ``argv[0]``.

        Arguments:
            argv(list): List of arguments to the binary
            *args: Extra arguments to :class:`.process`
            **kwargs: Extra arguments to :class:`.process`

        Returns:
            :class:`.process`
        """

        return process([self.path] + argv, *a, **kw)

    def disasm(self, address, n_bytes):
        """disasm(address, n_bytes) -> str

        Returns a string of disassembled instructions at
        the specified virtual memory address"""
        arch = self.arch
        if self.arch == 'arm' and address & 1:
            arch = 'thumb'
            address -= 1

        return disasm(self.read(address, n_bytes), vma=address, arch=arch, endian=self.endian)
    
    def search(self, needle, writable = False, executable = False):
        raise NotImplementedError
