import os

from pdbparse.peinfo import get_debug_data, get_rsds, get_nb10
from pdbparse.symlookup import Lookup
from pdbparse.undname import undname

class PDB(object):
    def __init__(self, pdbpath, basepath):
        self.filename = pdbpath
        self.basepath = basepath
    
    @staticmethod
    def from_pefile(pe, basepath):
        pdb = PDB('', basepath)

        # pdbparse.peinfo.get_external_codeview() using already opened PE file.
        # Find which .pdb file is associated with the PE.
        dbgdata = get_debug_data(pe)
        if dbgdata[:4] == b'RSDS':
            (guid, filename) = get_rsds(dbgdata)
        elif dbgdata[:4] == b'NB10':
            (guid, filename) = get_nb10(dbgdata)
        else:
            raise TypeError(u'Invalid CodeView signature: [%s]' % dbgdata[:4])

        pdb.filename = filename
        return pdb

    def populate_symbols(self, base):
        if os.path.exists(self.filename):
            return self._populate_symbols(self.filename, base)
        
        # Try the same directory as the PE file.
        cwd_path = os.path.join(self.basepath, self.filename)
        if os.path.exists(cwd_path):
            return self._populate_symbols(cwd_path, base)
        return None

    def _populate_symbols(self, path, base):
        symbols = {}
        lookup = Lookup([(path, base)])
        for base, limit in lookup.addrs:
            module = lookup.addrs[base, limit]['name']
            addrs = lookup.addrs[base, limit]['addrs']
            for addr, name in addrs:
                symbols[undname(name)] = addr
        return symbols

