import sys
if sys.platform == 'win32':
    from pwnlib.tubes.process_win import process, PTY, PIPE, STDOUT
else:
    from pwnlib.tubes.process_lin import process, PTY, PIPE, STDOUT
