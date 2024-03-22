import sys
if sys.platform == 'win32':
    from pwnlib.term.windows_termcap import get as get
else:
    from pwnlib.term.unix_termcap import get as get
