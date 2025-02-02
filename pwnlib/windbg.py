"""
During exploit development, it is frequently useful to debug the
target binary under WinDbg. This module provides a simple interface
to do so under Windows.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process

Debugging Tips
--------------

The :func:`attach` and :func:`debug` functions will likely be your bread and
butter for debugging.

Both allow you to provide a script to pass to WinDbg when it is started, so that
it can automatically set your breakpoints.

Attaching to Processes
~~~~~~~~~~~~~~~~~~~~~~

To attach to an existing process, just use :func:`attach`.  You can pass a PID,
a process name (including file extension), or a :class:`.process`.

Spawning New Processes
~~~~~~~~~~~~~~~~~~~~~~

Attaching to processes with :func:`attach` is useful, but the state the process
is in may vary.  If you need to attach to a process very early, and debug it from
the very first instruction (or even the start of ``main``), you instead should use
:func:`debug`.

When you use :func:`debug`, the return value is a :class:`.tube` object
that you interact with exactly like normal.

Tips and Troubleshooting
------------------------

``NOPTRACE`` magic argument
~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's quite cumbersom to comment and un-comment lines containing `attach`.

You can cause these lines to be a no-op by running your script with the
``NOPTRACE`` argument appended, or with ``PWNLIB_NOPTRACE=1`` in the environment.
(The name is borrowed from ptrace syscall on Linux.)

::

    $ python exploit.py NOPTRACE
    [+] Starting local process 'chall.exe': Done
    [!] Skipping debug attach since context.noptrace==True
    ...

Member Documentation
===============================
"""
from __future__ import absolute_import
import atexit
import os
import signal

import subprocess

import six

from pwnlib import tubes
from pwnlib.context import LocalContext
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util import misc
from pwnlib.util import proc

log = getLogger(__name__)

CREATE_SUSPENDED = 0x00000004

@LocalContext
def debug(args, dbgscript=None, exe=None, env=None, creationflags=0, **kwargs):
    """debug(args, dbgscript=None, exe=None, env=None, creationflags=0) -> tube

    Launch a process in suspended state, attach debugger and resume process.

    Arguments:
        args(list): Arguments to the process, similar to :class:`.process`.
        dbgscript(str): windbg script to run.
        exe(str): Path to the executable on disk.
        env(dict): Environment to start the binary in.
        creationflags(int): Flags to pass to :func:`.process.process`.

    Returns:
        :class:`.process`: A tube connected to the target process.

    Notes:

        .. code-block: python

            # Create a new process, and stop it at 'main'
            io = windbg.debug('calc', '''
            bp $exentry
            go
            ''')

        When the debugger opens via :func:`.debug`, it will initially be stopped on the very first
        instruction of the entry point.
    """
    if isinstance(
        args, six.integer_types + (tubes.process.process, tubes.ssh.ssh_channel)
    ):
        log.error("Use windbg.attach() to debug a running process")

    if context.noptrace:
        log.warn_once("Skipping debugger since context.noptrace==True")
        return tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    
    dbgscript = dbgscript or ''
    if isinstance(dbgscript, six.string_types):
        dbgscript = dbgscript.split('\n')
    # resume main thread
    if context.debugger_selection in ('windbg', ''):
        dbgscript = ['~0m'] + dbgscript
    creationflags |= CREATE_SUSPENDED
    io = tubes.process.process(args, executable=exe, env=env, creationflags=creationflags)
    attach(target=io, dbgscript=dbgscript, **kwargs)

    return io

def binary():
    """binary() -> str

    Returns the path to the debugger binary depending on the context.
    :attr:`.context.debugger_selection` is used to determine which debugger to use.

    Returns:
        str: Path to the appropriate debugger binary to use.
    """
    if context.debugger_selection == 'x64dbg':
        return _lookup_x64dbg()

    if not context.debugger_selection or context.debugger_selection == 'windbg':
        if context.windbg_binary:
            windbg = misc.which(context.windbg_binary)
            if not windbg:
                log.warn_once('Path to WinDBG binary `{}` not found'.format(context.windbg_binary))
            return windbg

        windbg = misc.which('windbgx.exe') or misc.which('windbg.exe')
        if not windbg:
            log.error('windbg is not installed or in system PATH')
        return windbg
    log.error('Invalid debugger selection: %s', context.debugger_selection)

def _lookup_x64dbg():
    if context.x64dbg_binary:
        x64dbg = misc.which(context.x64dbg_binary)
        if not x64dbg:
            log.warn_once('Path to x64dbg binary `{}` not found'.format(context.x64dbg_binary))
        return x64dbg

    x64dbg = misc.which('x96dbg.exe')
    if x64dbg:
        return x64dbg

    # See if the "Debug with x64dbg" shell extension is installed
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r'exefile\shell\Debug with x64dbg\Command') as key:
            regcmd = winreg.QueryValueEx(key, None)
            # ('"C:\\Users\\User\\Downloads\\x64dbg\\bin\\x96dbg.exe" "%1"', 2)
            if regcmd[1] != winreg.REG_EXPAND_SZ:
                log.error('x64dbg registry key is not REG_EXPAND_SZ')
            command = regcmd[0].split('"')[1]
            if not os.path.exists(command):
                log.error('x64dbg path from registry does not exist')
            return command
    except FileNotFoundError:
        pass

    log.error('x64dbg is not installed or in system PATH')

@LocalContext
def attach(target, dbgscript=None, dbg_args=[]):
    """attach(target, dbgscript=None, dbg_args=[]) -> int

    Attach to a running process with WinDbg or x64dbg.

    Arguments:
        target(int, str, process): Process to attach to.
        dbgscript(str, list): Debugger script to run after attaching.
        dbg_args(list): Additional arguments to pass to the debugger.

    Returns:
        int: PID of the debugger process.

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :class:`.process`
            Process to connect to
    
    Examples:

        Attach to a process by PID

        >>> pid = windbg.attach(1234) # doctest: +SKIP

        Attach to the youngest process by name

        >>> pid = windbg.attach('cmd.exe') # doctest: +SKIP

        Attach a debugger to a :class:`.process` tube and automate interaction

        >>> io = process('cmd') # doctest: +SKIP
        >>> pid = windbg.attach(io, dbgscript='''
        ... bp kernelbase!WriteFile
        ... g
        ... ''') # doctest: +SKIP
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # let's see if we can find a pid to attach to
    pid = None
    if isinstance(target, six.integer_types):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pids = list(proc.pidof(target))
        if not pids:
            log.error('No such process: %s', target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
    else:
        log.error("don't know how to attach to target: %r", target)

    if not pid:
        log.error('could not find target process')
    
    cmd = [binary()]
    if dbg_args:
        cmd.extend(dbg_args)
    
    cmd.extend(['-p', str(pid)])

    dbgscript = dbgscript or ''
    if isinstance(dbgscript, six.string_types):
        dbgscript = dbgscript.split('\n')
    if isinstance(dbgscript, list):
        dbgscript = ';'.join(script.strip() for script in dbgscript if script.strip())
    if dbgscript:
        cmd.extend(['-c', dbgscript])
    
    log.info("Launching a new process: %r" % cmd)

    io = subprocess.Popen(cmd)
    debugger_pid = io.pid

    def kill():
        try:
            os.kill(debugger_pid, signal.SIGTERM)
        except OSError:
            pass

    atexit.register(kill)

    if context.native:
        proc.wait_for_debugger(pid, debugger_pid)

    return debugger_pid

def minidump_on_crash(process, dump_type='mini'):
    if context.noptrace:
        log.warn_once("Skipping minidump since context.noptrace==True")
        return None
    
    DUMP_TYPES = {
        'mini': '-mm',
        'full': '-ma',
        'triage': '-mt',
        'miniplus': '-mp',
    }

    if dump_type not in DUMP_TYPES:
        log.error('Invalid dump type: %s', dump_type)
    
    minidump_path = './dump.%s.%i.dmp' % (os.path.basename(process.executable),
                                        process.pid)

    procdump = misc.which('procdump.exe')
    if not procdump:
        log.error('procdump is not installed or in system PATH. Install the Windows Sysinternals Suite first.')

    # -e      Write a dump when the process encounters an unhandled exception.
    # -n      Number of dumps to write before exiting.
    # -o      Overwrite an existing dump file.
    # -t      Write a dump when the process terminates.
    argv = [procdump, DUMP_TYPES[dump_type], '-o', '-e', '-t', str(process.pid), minidump_path]
    proc = subprocess.Popen(argv, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # procdump returns 1 even if it succeeds..
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        log.debug('procdump stdout: %s', stdout)
        log.debug('procdump stderr: %s', stderr)
        return None
    
    def cleanup():
        stdout, stderr = proc.communicate()
        log.debug('procdump stdout: %s', stdout)
        log.debug('procdump stderr: %s', stderr)
        proc.kill()
        if os.path.exists(minidump_path):
            os.unlink(minidump_path)
    atexit.register(cleanup)
    
    return minidump_path

def minidump(process, dump_type='mini'):
    if context.noptrace:
        log.warn_once("Skipping minidump since context.noptrace==True")
        return

    # use minidump's createminidump util
    from minidump.utils.createminidump import create_dump, MINIDUMP_TYPE
    minidump_path = './dump.%s.%i.dmp' % (os.path.basename(process.executable),
                                        process.pid)
    minidump_type = MINIDUMP_TYPE.MiniDumpNormal | MINIDUMP_TYPE.MiniDumpWithHandleData | \
                    MINIDUMP_TYPE.MiniDumpWithIndirectlyReferencedMemory | \
                    MINIDUMP_TYPE.MiniDumpWithProcessThreadData | \
                    MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo | \
                    MINIDUMP_TYPE.MiniDumpWithThreadInfo | \
                    MINIDUMP_TYPE.MiniDumpWithUnloadedModules
    create_dump(process.pid, minidump_path, minidump_type, with_debug=False)

    # DUMP_TYPES = {
    #     'mini': '-mm',
    #     'full': '-ma',
    #     'triage': '-mt',
    #     'miniplus': '-mp',
    # }

    # if dump_type not in DUMP_TYPES:
    #     log.error('Invalid dump type: %s', dump_type)

    # procdump = misc.which('procdump.exe')
    # if not procdump:
    #     log.error('procdump is not installed or in system PATH. Install the Windows Sysinternals Suite first.')

    # argv = [procdump, DUMP_TYPES[dump_type], '-o', '-n', '1', str(process.pid), minidump_path]
    # proc = subprocess.run(argv, timeout=10, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # # procdump returns 1 even if it succeeds..
    # if proc.stderr:
    #     log.debug('procdump stdout: %s', proc.stdout)
    #     log.debug('procdump stderr: %s', proc.stderr)
    if not os.path.exists(minidump_path):
        log.error('Could not generate a minidump for process %d', process.pid)
    
    from minidump.minidumpfile import MinidumpFile
    return MinidumpFile.parse(minidump_path)
