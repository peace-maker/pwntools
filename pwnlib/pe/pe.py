from __future__ import absolute_import

import mmap
import os

from pefile import PE as PEFile
from pefile import DIRECTORY_ENTRY
from pefile import DLL_CHARACTERISTICS
from pefile import IMAGE_CHARACTERISTICS
from pefile import MACHINE_TYPE

from pwnlib.binary import Binary, dotdict
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.pe.pdb import PDB
from pwnlib.term import text

log = getLogger(__name__)

__all__ = ['PE']

class PE(PEFile, Binary):
    def __init__(self, path, checksec=True, load_pdb=True):
        super(PE,self).__init__(path)

        #: :class:`file`: Open handle to the PE file on disk
        self.file = open(path,'rb')

        #: :class:`str`: Path to the file
        self.path = os.path.abspath(path)

        #: :class:`str`: Architecture of the file (e.g. ``'i386'``, ``'arm'``).
        #:
        #: See: :attr:`.ContextType.arch`
        self.arch = self.get_machine_arch().lower()

        #: :class:`pwnlib.binary.dotdict` of ``name`` to ``address`` for all symbols in the PE
        self.symbols = dotdict()

        #: :class:`pwnlib.binary.dotdict` of ``name`` to ``address`` for all imports in the PE
        self.imports = dotdict()

        #: :class:`str`: Endianness of the file (e.g. ``'big'``, ``'little'``)
        self.endian = 'little'

        #: :class:`int`: Bit-ness of the file
        self.bits = 64
        if self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS['IMAGE_FILE_32BIT_MACHINE']:
            self.bits = 32
        
        #: :class:`int`: Pointer width, in bytes
        self.bytes = self.bits // 8

        # Is this a native binary?
        try:
            with context.local(arch=self.arch):
                #: Whether this PE should be able to run natively
                self.native = context.native
        except AttributeError:
            # The architecture may not be supported in pwntools
            self.native = False

        self._address = 0
        if self.OPTIONAL_HEADER:
            self._address = self.OPTIONAL_HEADER.ImageBase
        self.load_addr = self._address

        #: ``True`` if the PE is an executable
        self.executable = (self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE']) != 0

        #: ``True`` if the PE is a DLL
        self.library = (self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS['IMAGE_FILE_DLL']) != 0

        #: Operating system of the PE
        self.os = 'windows'

        #: Debugging information PDB of the PE.
        self.pdb = None
        if load_pdb:
            try:
                self.pdb = PDB.from_pefile(self, os.path.dirname(self.path))
            except Exception as e:
                log.warn('Error parsing PDB: %s', str(e))

        self._populate_symbols()

        if checksec:
            self._describe()

    def _populate_symbols(self):
        self.symbols['start'] = self.OPTIONAL_HEADER.ImageBase + self.OPTIONAL_HEADER.AddressOfEntryPoint
        
        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            for module in self.DIRECTORY_ENTRY_IMPORT:
                for symbol in module.imports:
                    # Ignore symbols imported by ordinal only.
                    if symbol.name:
                        self.symbols[str(symbol.name, 'utf-8')] = symbol.address
                        self.imports[str(symbol.name, 'utf-8')] = symbol.address

        if hasattr(self, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.DIRECTORY_ENTRY_EXPORT.symbols:
                # Ignore symbols exported by ordinal only.
                if symbol.name:
                    self.symbols[str(symbol.name, 'utf-8')] = symbol.address
        
        if self.pdb:
            try:
                dbg_symbols = self.pdb.populate_symbols(self.address)
                if dbg_symbols:
                    self.symbols.update(dbg_symbols)
                else:
                    log.warn('PDB file not loaded %s', self.pdb.filename)
            except Exception as e:
                log.debug('PDB file failed to load: %s', str(e))

    
    def _describe(self, *a, **kw):
        log.info_once(
            '%s\n%-18s%s-%s\n%s',
            repr(self.path),
            'Arch:',
            self.arch,
            self.bits,
            self.checksec(*a, **kw)
        )
    
    def __repr__(self):
        return "PE(%r)" % self.path

    def get_machine_arch(self):
        machine_type = MACHINE_TYPE[self.FILE_HEADER.Machine]
        return {
            'IMAGE_FILE_MACHINE_AMD64': 'amd64',
            'IMAGE_FILE_MACHINE_I386' :'i386',
            'IMAGE_FILE_MACHINE_ARM': 'arm',
            'IMAGE_FILE_MACHINE_POWERPC': 'powerpc',
            'IMAGE_FILE_MACHINE_IA64': 'ia64'
        }.get(machine_type, machine_type)
    
    @property
    def entry(self):
        """:class:`int`: Address of the entry point for the PE"""
        return self.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint = entry
    start      = entry

    @property
    def sym(self):
        """:class:`pwnlib.binary.dotdict`: Alias for :attr:`.PE.symbols`"""
        return self.symbols

    def section(self, name):
        """section(name) -> bytes

        Gets data for the named section

        Arguments:
            name(str): Name of the section

        Returns:
            :class:`str`: String containing the bytes for that section
        """
        if not self.sections:
            return None

        for section in self.sections:
            if section.get_name() == name:
                return section.get_data()
        return None

    @property
    def address(self):
        """:class:`int`: Address of the base image in memory of the PE.

        When updated, the addresses of the following fields are also updated:

        - :attr:`~.PE.symbols`
        - :attr:`~.PE.imports`

        Example:

            >>> calc = PE(which('calc.exe'))
            >>> execute = calc.symbols['ShellExecuteW']
            >>> calc.address += 0x1000
            >>> execute + 0x1000 == calc.symbols['ShellExecuteW']
            True
        """
        return self._address
    
    @address.setter
    def address(self, new):
        self.relocate_image(new)
        self._address = self.OPTIONAL_HEADER.ImageBase
        self._populate_symbols()

    def load_pdb(self, path):
        """
        Loads the debug symbols for this PE from the PDB file.
        """
        self.pdb = PDB(path, os.path.dirname(self.path))
        self._populate_symbols()

    @property
    def dynamicbase(self):
        """:class:`bool`: Whether the current binary can be relocated at load time."""

        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']) != 0

    @property
    def aslr(self):
        # Image has relocation information available and can be relocated.
        if (self.FILE_HEADER.Characteristics & IMAGE_CHARACTERISTICS['IMAGE_FILE_RELOCS_STRIPPED']) == 0 and self.dynamicbase:
            return True
        # Managed images always use ASLR.
        if self.dotnet:
            return True
        return False

    @property
    def dotnet(self):
        # Image is managed by the .NET runtime.
        return self.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']].VirtualAddress != 0

    @property
    def highentropyva(self):
        # Image can handle a high entropy 64-bit virtual address space.
        # Only consider it relevant if the binary uses ASLR as well.
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA']) != 0 \
                and self.aslr

    @property
    def nx(self):
        # Image is NX compatible.
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NX_COMPAT']) != 0 \
                or self.dotnet
    
    @property
    def seh(self):
        # Does not use structured exception (SE) handling. No SE handler may be called in this image. 
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NO_SEH']) == 0

    @property
    def canary(self):
        """:class:`bool`: Whether the current binary uses stack canaries."""

        if not hasattr(self, 'DIRECTORY_ENTRY_LOAD_CONFIG') or not self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
            return False

        if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size < 96:
            return False

        return self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie != 0

    @property
    def safeseh(self):
        # Image has a table of safe exception handlers.
        if not hasattr(self, 'DIRECTORY_ENTRY_LOAD_CONFIG') or not self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
            return False
        
        if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size < 112:
            return False

        # No point in checking for SafeSEH if the image has NO_SEH set in the first place.
        if not self.seh:
            return False

        return self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable != 0 \
                and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount != 0

    @property
    def forceintegrity(self):
        # Code Integrity checks are enforced
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY']) != 0

    @property
    def isolation(self):
        # Isolation aware, but do not isolate the image
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NO_ISOLATION']) == 0

    @property
    def cfg(self):
        # Image supports Control Flow Guard.
        return (self.OPTIONAL_HEADER.DllCharacteristics & DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_GUARD_CF']) != 0

    @property
    def rfg(self):
        # Image supports Return Flow Guard.
        if not hasattr(self, 'DIRECTORY_ENTRY_LOAD_CONFIG') or not self.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
            return False
        
        if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size < 148:
            return False
        
        GuardFlags = self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags
        # Module contains return flow instrumentation and metadata
        IMAGE_GUARD_RF_INSTRUMENTED = 0x00020000
        # Module requests that the OS enable return flow protection
        IMAGE_GUARD_RF_ENABLE = 0x00040000
        # Module requests that the OS enable return flow protection in strict mode
        IMAGE_GUARD_RF_STRICT = 0x00080000

        return (GuardFlags & IMAGE_GUARD_RF_INSTRUMENTED) != 0 \
                and ((GuardFlags & IMAGE_GUARD_RF_ENABLE) != 0 \
                    or (GuardFlags & IMAGE_GUARD_RF_STRICT) != 0)

    def checksec(self, color=True):
        """checksec(banner=True, color=True)

        Prints out information of the binary, similar to ``winchecksec``.

        Arguments:
            color(bool): Whether to use colored output.
        """
        red    = text.red if color else str
        green  = text.green if color else str

        res = []

        res.extend([
            "Stack:".ljust(18) + {
                True:  green("Canary found"),
                False: red("No canary found")
            }[self.canary],
            "NX:".ljust(18) + {
                True:  green("NX enabled"),
                False: red("NX disabled"),
            }[self.nx],
            "Dynamic Base:".ljust(18) + {
                True: green("Dynamic Base enabled"),
                False: red("Dynamic Base disabled")
            }[self.dynamicbase],
            "ASLR:".ljust(18) + {
                True: green("ASLR enabled"),
                False: red("No ASLR (%#x)" % self.address)
            }[self.aslr],
            "High Entropy VA:".ljust(18) + {
                True: green("High Entropy VA enabled"),
                False: red("High Entropy VA disabled")
            }[self.highentropyva],
            "SEH:".ljust(18) + {
                True: green("SEH enabled"),
                False: red("SEH disabled")
            }[self.seh],
            "SafeSEH:".ljust(18) + {
                True: green("SafeSEH enabled"),
                False: red("SafeSEH disabled")
            }[self.safeseh],
            "Force Integrity:".ljust(18) + {
                True: green("Force Integrity enabled"),
                False: red("Force Integrity disabled")
            }[self.forceintegrity],
            "Isolation:".ljust(18) + {
                True: green("Isolation enabled"),
                False: red("Isolation disabled")
            }[self.isolation],
            "CFG:".ljust(18) + {
                True: green("CFG enabled"),
                False: red("CFG disabled")
            }[self.cfg],
            "RFG:".ljust(18) + {
                True: green("RFG enabled"),
                False: red("RFG disabled")
            }[self.rfg],
            ".NET:".ljust(18) + {
                True: green("Managed"),
                False: red("Unmanaged")
            }[self.dotnet],
        ])

        return '\n'.join(res)

    @property
    def data(self):
        """:class:`str`: Raw data of the PE file.

        See:
            :meth:`get_data`
        """
        return self.get_data()

    def offset_to_vaddr(self, offset):
        """offset_to_vaddr(offset) -> int

        Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            `int`: Virtual address which corresponds to the file offset, or
            :const:`None`.

        Examples:

            This example shows that regardless of changes to the virtual
            address layout by modifying :attr:`.PE.address`, the offset
            for any given address doesn't change.

            >>> bash = PE('/bin/bash')
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        return self.OPTIONAL_HEADER.ImageBase + self.get_rva_from_offset(offset)
    
    def vaddr_to_offset(self, address):
        """vaddr_to_offset(address) -> int

        Translates the specified virtual address to a file offset

        Arguments:
            address(int): Virtual address to translate

        Returns:
            int: Offset within the PE file which corresponds to the address,
            or :const:`None`.

        Examples:
            >>> bash = PE(which('bash'))
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.address += 0x123456
            >>> bash.vaddr_to_offset(bash.address)
            0
            >>> bash.vaddr_to_offset(0) is None
            True
        """
        return self.get_offset_from_rva(address - self.OPTIONAL_HEADER.ImageBase)
    
    def read(self, address, count):
        return self.get_data(address, count)
