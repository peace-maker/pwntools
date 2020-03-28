"""
Common interface for accessing executable files.

This includes :class:`pwnlib.elf.ELF` and :class:`pwnlib.pe.PE`.
"""

class dotdict(dict):
    """Wrapper to allow dotted access to dictionary elements.

    Is a real :class:`dict` object, but also serves up keys as attributes
    when reading attributes.

    Supports recursive instantiation for keys which contain dots.

    Example:

        >>> x = pwnlib.binary.dotdict()
        >>> isinstance(x, dict)
        True
        >>> x['foo'] = 3
        >>> x.foo
        3
        >>> x['bar.baz'] = 4
        >>> x.bar.baz
        4
    """
    def __getattr__(self, name):
        if name in self:
            return self[name]

        name_dot = name + '.'
        name_len = len(name_dot)
        subkeys = {k[name_len:]: self[k] for k in self if k.startswith(name_dot)}

        if subkeys:
            return dotdict(subkeys)

        return getattr(super(dotdict, self), name)

class Binary(object):
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
