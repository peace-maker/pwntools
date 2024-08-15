"""
Most exploitable CTF challenges on Windows are provided in the Portable Executable (``PE``) format.
This module allows to extract data such as function addresses, and ROP gadgets.
"""
from __future__ import absolute_import

from pwnlib.pe.pe import PE

__all__ = ['PE']
