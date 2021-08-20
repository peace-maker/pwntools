# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import logging
import os
import queue
import subprocess
import threading
import time

import windows
from windows.generated_def.winstructs import CREATE_SUSPENDED
from windows.generated_def import ntstatus

from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.tubes.tube import tube
from pwnlib.util.misc import which
from pwnlib.util.misc import normalize_argv_env

log = getLogger(__name__)

class PTY(object): pass
PTY=PTY()
STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE

ntstatus_names = {int(v):k for k,v in ntstatus.__dict__.items() if k.startswith('STATUS') and v}

class process(tube):
    r"""
    Spawns a new process, and wraps it with a tube for communication.

    Arguments:

        argv(list):
            List of arguments to pass to the spawned process.
        shell(bool):
            Set to `True` to interpret `argv` as a string
            to pass to the shell for interpretation instead of as argv.
        executable(str):
            Path to the binary to execute.  If :const:`None`, uses ``argv[0]``.
            Cannot be used with ``shell``.
        cwd(str):
            Working directory.  Uses the current working directory by default.
        env(dict):
            Environment variables.  By default, inherits from Python's environment.
        stdin(int):
            File object or file descriptor number to use for ``stdin``.
            By default, a pipe is used.  PTYs aren't supported.
        stdout(int):
            File object or file descriptor number to use for ``stdout``.
            By default, a pipe is used.
        stderr(int):
            File object or file descriptor number to use for ``stderr``.
            By default, ``STDOUT`` is used.
            May also be ``PIPE`` to use a separate pipe,
            although the :class:`pwnlib.tubes.tube.tube` wrapper will not be able to read this data.
        where(str):
            Where the process is running, used for logging purposes.
        display(list):
            List of arguments to display, instead of the main executable name.
    
    Based on https://github.com/masthoon/pwintools
    """

    STDOUT = STDOUT
    PIPE = PIPE

    #: Have we seen the process stop?  If so, this is a unix timestamp.
    _stop_noticed = 0

    def __init__(self, argv = None,
                 shell = False,
                 executable = None,
                 cwd = None,
                 env = None,
                 stdin  = PIPE,
                 stdout = PIPE,
                 stderr = STDOUT,
                 where = 'local',
                 display = None,
                 creationflags = 0,
                 *args,
                 **kwargs):
        super(process, self).__init__(*args,**kwargs)
        # Permit using context.binary
        if argv is None:
            if context.binary:
                argv = [context.binary.path]
            else:
                raise TypeError('Must provide argv or set context.binary')
        
        #: :class:`subprocess.Popen` object that backs this process
        self.proc = None

        if PTY in (stdin, stdout, stderr):
            raise NotImplementedError("ConPTY isn't implemented yet")

        # We need to keep a copy of the un-_validated environment for printing
        original_env = env

        if shell:
            executable_val, argv_val, env_val = executable, argv, env
        else:
            executable_val, argv_val, env_val = self._validate(cwd, executable, argv, env)
        
        #: Arguments passed on argv
        self.argv = argv_val

        #: Full path to the executable
        self.executable = executable_val

        #: Environment passed on envp
        self.env = os.environ if env is None else env_val

        if self.executable is None and not shell:
            self.executable = which(self.argv[0], path=self.env.get('PATH'))
        
        self._cwd = os.path.realpath(cwd or os.path.curdir)
        self.display    = display or self.executable
        self._imports   = None
        self._symbols   = None
        self._libs      = None
        self._offsets   = None

        message = "Starting %s process %r" % (where, self.display)

        if self.isEnabledFor(logging.DEBUG):
            if argv != [self.executable]: message += ' argv=%r ' % self.argv
            if original_env not in (os.environ, None):  message += ' env=%r ' % self.env

        with self.progress(message) as p:
            self.proc = subprocess.Popen(args = self.argv,
                                        shell = shell,
                                        executable = self.executable,
                                        cwd = cwd,
                                        env = self.env,
                                        stdin = stdin,
                                        stdout = stdout,
                                        stderr = stderr,
                                        creationflags = creationflags)

            p.success('pid %i' % self.pid)
        
        #: :class:`windows.winobject.process.WinProcess` object that provides insight into the process
        self.win_process = windows.winobject.process.WinProcess(pid=self.pid)

        self._read_thread = None
        self._read_queue = queue.Queue()
        if self.proc.stdout:
            # Read from stdout in a thread.
            self._read_thread = threading.Thread(target=_read_in_thread, args=(self._read_queue, self.proc.stdout))
            self._read_thread.daemon = True
            self._read_thread.start()
        
        if (creationflags & CREATE_SUSPENDED) == 0:
            self.wait_initialized()

    def check_initialized(self):
        # Accessing PEB until WinProcess is done initializing.
        try:
            self.peb.modules[1]
            return True
        except Exception as e:
            pass
        return False
    
    def wait_initialized(self):
        while not self.check_initialized() and not self.win_process.is_exit:
            time.sleep(0.05)
    
    @property
    def cwd(self):
        """Directory that the process is working in.

        Example:

            >>> p = process('cmd.exe')
            >>> p.sendline(b'cd %TEMP%')
            >>> p.sendline(b'echo AAA')
            >>> _ = p.recvuntil(b'AAA')
            >>> p.cwd == os.environ.get('TEMP')
            True
            >>> p.sendline(br'cd c:\windows')
            >>> p.sendline(b'echo BBB')
            >>> _ = p.recvuntil(b'BBB')
            >>> p.cwd
            'C:\\'
        """
        try:
            self._cwd = self.peb.ProcessParameters.contents.CurrentDirectory.DosPath.str
        except Exception:
            pass

        return self._cwd
    
    def _validate(self, cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """

        orig_cwd = cwd
        cwd = cwd or os.path.curdir

        argv, env = normalize_argv_env(argv, env, self, 4)
        if env:
            env = {bytes(k): bytes(v) for k, v in env}
        if argv:
            argv = list(map(bytes, argv))

        #
        # Validate executable
        #
        # - Must be an absolute or relative path to the target executable
        # - If not, attempt to resolve the name in $PATH
        #
        if not executable:
            if not argv:
                self.error("Must specify argv or executable")
            executable = argv[0]

        if not isinstance(executable, str):
            executable = executable.decode('utf-8')

        path = env and env.get(b'PATH')
        if path:
            path = path.decode()
        else:
            path = os.environ.get('PATH')
        # Do not change absolute paths to binaries
        if executable.startswith(os.path.sep):
            pass

        # If there's no path component, it's in $PATH or relative to the
        # target directory.
        #
        # For example, 'sh'
        elif os.path.sep not in executable and which(executable, path=path):
            executable = which(executable, path=path)

        # Either there is a path component, or the binary is not in $PATH
        # For example, 'foo/bar' or 'bar' with cwd=='foo'
        elif os.path.sep not in executable:
            tmp = executable
            executable = os.path.join(cwd, executable)
            self.warn_once("Could not find executable %r in $PATH, using %r instead" % (tmp, executable))

        # There is a path component and user specified a working directory,
        # it must be relative to that directory. For example, 'bar/baz' with
        # cwd='foo' or './baz' with cwd='foo/bar'
        elif orig_cwd:
            executable = os.path.join(orig_cwd, executable)

        if not os.path.exists(executable):
            self.error("%r does not exist"  % executable)
        if not os.path.isfile(executable):
            self.error("%r is not a file" % executable)
        if not os.access(executable, os.X_OK):
            self.error("%r is not marked as executable (+x)" % executable)

        return executable, argv, env
    
    def __getattr__(self, attr):
        """Permit pass-through access to the underlying process object for
        fields like ``pid`` and ``stdin``.
        """
        if hasattr(self.proc, attr):
            return getattr(self.proc, attr)
        # if hasattr(self.win_process, attr):
        #     return getattr(self.win_process, attr)
        raise AttributeError("'process_win' object has no attribute '%s'" % attr)
    
    def kill(self):
        """kill()

        Kills the process.
        """
        self.close()

    def poll(self, block = False):
        """poll(block = False) -> int

        Arguments:
            block(bool): Wait for the process to exit

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """

        if block:
            self.wait_for_close()

        self.proc.poll()
        returncode = self.proc.returncode

        if returncode is not None and not self._stop_noticed:
            self._stop_noticed = time.time()
            signame = ''
            if returncode in ntstatus_names:
                signame = ' (%s)' % (ntstatus_names[returncode])

            self.info("Process %r stopped with exit code %#x%s (pid %i)" % (self.display,
                                                                  returncode,
                                                                  signame,
                                                                  self.pid))
        return returncode
    
    def communicate(self, stdin = None):
        """communicate(stdin = None) -> str

        Calls :meth:`subprocess.Popen.communicate` method on the process.
        """

        return self.proc.communicate(stdin)

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if not self.connected_raw('recv'):
            raise EOFError

        if not self.can_recv_raw(self.timeout):
            return b''

        # This will only be reached if we either have data,
        # or we have reached an EOF. In either case, it
        # should be safe to read without expecting it to block.
        data = b''

        count = 0
        while count < numb:
            if self._read_queue.empty():
                break
            last_byte = self._read_queue.get(block = self.timeout is not None, timeout = self.timeout)
            data += last_byte
            count += 1
        
        return data

    def send_raw(self, data):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if not self.connected_raw('send'):
            raise EOFError

        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except IOError:
            raise EOFError

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        if not self.connected_raw('recv'):
            return False
        
        return not self._read_queue.empty()

    def connected_raw(self, direction):
        if direction == 'any':
            return self.poll() is None
        elif direction == 'send':
            return not self.proc.stdin.closed
        elif direction == 'recv':
            return not self.proc.stdout.closed

    def close(self):
        if self.proc is None:
            return

        # First check if we are already dead
        self.poll()

        # Don't try to kill the process twice.
        self.win_process = None

        if not self._stop_noticed:
            try:
                self.proc.kill()
                self.proc.wait()
                self._stop_noticed = time.time()
                self.info('Stopped process %r (pid %i)' % (self.executable, self.pid))
            except OSError:
                pass

    def __del__(self):
        # Don't try to kill the process twice.
        self.win_process = None

    def fileno(self):
        if not self.connected():
            self.error("A stopped process does not have a file number")

        return self.proc.stdout.fileno()

    def shutdown_raw(self, direction):
        if direction == "send":
            self.proc.stdin.close()

        if direction == "recv":
            self.proc.stdout.close()

        if False not in [self.proc.stdin.closed, self.proc.stdout.closed]:
            self.close()
    
    @property
    def imports(self):
        """imports returns a dict of main EXE imports like {'ntdll.dll': {'Sleep': <IATEntry type - .addr .value>, ...}, ...}"""
        if not self.check_initialized():
            raise Exception("Error: PEB not initialized while getting the imports")

        pe = self.peb.modules[0].pe
        if not self._imports:
            pe = self.peb.modules[0].pe
            self._imports = {dll.lower(): {imp.name: imp for imp in imps} for dll, imps in pe.imports.items() if dll}
        return self._imports
    
    @property
    def libs(self):
        """libs returns a dict of loaded modules with their baseaddr like {'ntdll.dll': 0x123456000, ...}"""
        if not self.check_initialized():
            raise Exception("Error: PEB not initialized while getting the loaded modules")
        if not self._libs:
            self._libs = {module.name.lower(): module.baseaddr for module in self.peb.modules if module.name}
        return self._libs
    
    @property
    def symbols(self):
        """symbols returns a dict of the process exports (all DLL) like {'ntdll.dll': {'Sleep': addr, 213: addr, ...}, ...}"""
        if not self.check_initialized():
            raise Exception("Error: PEB not initialized while getting the exports")

        if not self._symbols:
            self._symbols = {module.pe.export_name.lower(): module.pe.exports for module in self.peb.modules if module.pe.export_name}
        return self._symbols

    def leak(self, address, count=1):
        """leak(address, count = 1) reads count bytes of the process memory at address"""
        if not self.check_initialized():
            raise Exception("Error: PEB not initialized while reading memory")
        try:
            return self.win_process.read_memory(address, count)
        except Exception as e:
            log.warning(str(e))
            return b''

    readmem = leak

    def writemem(self, address, data):
        """Writes memory within the process at the specified address."""
        try:
            return self.win_process.write_memory(address, data)
        except Exception as e:
            log.warning(str(e))
            return b''

    @property
    def stdin(self):
        """Shorthand for ``self.proc.stdin``

        See: :obj:`.process.proc`
        """
        return self.proc.stdin
    @property
    def stdout(self):
        """Shorthand for ``self.proc.stdout``

        See: :obj:`.process.proc`
        """
        return self.proc.stdout
    @property
    def stderr(self):
        """Shorthand for ``self.proc.stderr``

        See: :obj:`.process.proc`
        """
        return self.proc.stderr

    @property
    def peb(self):
        """Shorthand for ``self.win_process.peb``

        See: :obj:`.process_win.win_process`
        """
        return self.win_process.peb

# Keep reading the process's output in a separate thread,
# since there's no non-blocking read in python on Windows.
def _read_in_thread(recv_queue, proc_stdout):
    while True:
        b = proc_stdout.read(1)
        if b:
            recv_queue.put(b)
        else:
            break
