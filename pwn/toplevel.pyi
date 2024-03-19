from typing import Any
from typing_extensions import Protocol

import pwnlib.log

# export modules and functions
import collections as collections
import logging as logging
import math as math
import operator as operator
import os as os
import platform as platform
import re as re
import socks as socks
import signal as signal
import string as string
import struct as struct
import subprocess as subprocess
import sys as sys
import tempfile as tempfile
import threading as threading
import time as time
from pprint import pprint as pprint

import pwnlib as pwnlib
from pwnlib import *
from pwnlib.asm import *
from pwnlib.context import Thread as Thread
from pwnlib.context import context as context, LocalContext as LocalContext
from pwnlib.dynelf import DynELF as DynELF
from pwnlib.encoders import *
from pwnlib.elf.corefile import Core as Core, Corefile as Corefile, Coredump as Coredump
from pwnlib.elf.elf import ELF as ELF, load as load
from pwnlib.encoders import *
from pwnlib.exception import PwnlibException as PwnlibException
from pwnlib.gdb import (
    attach as attach,
    debug_assembly as debug_assembly,
    debug_shellcode as debug_shellcode,
)
from pwnlib.filepointer import *
from pwnlib.filesystem import *
from pwnlib.flag import *
from pwnlib.fmtstr import (
    FmtStr as FmtStr,
    fmtstr_payload as fmtstr_payload,
    fmtstr_split as fmtstr_split,
)
from pwnlib.log import getLogger as getLogger
from pwnlib.memleak import MemLeak as MemLeak, RelativeMemLeak as RelativeMemLeak
from pwnlib.regsort import *
from pwnlib.replacements import *
from pwnlib.rop import ROP as ROP
from pwnlib.rop.call import AppendedArgument as AppendedArgument
from pwnlib.rop.srop import SigreturnFrame as SigreturnFrame
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload as Ret2dlresolvePayload
from pwnlib.runner import *
from pwnlib.term.readline import str_input as str_input
from pwnlib.timeout import Timeout as Timeout
from pwnlib.tubes.listen import listen as listen
from pwnlib.tubes.process import (
    process as process,
    PTY as PTY,
    PIPE as PIPE,
    STDOUT as STDOUT,
)
from pwnlib.tubes.remote import (
    remote as remote,
    tcp as tcp,
    udp as udp,
    connect as connect,
)
from pwnlib.tubes.serialtube import serialtube as serialtube
from pwnlib.tubes.server import server as server
from pwnlib.tubes.ssh import ssh as ssh
from pwnlib.tubes.tube import tube as tube
from pwnlib.ui import *
from pwnlib.util import crc as crc
from pwnlib.util import iters as iters
from pwnlib.util import net as net
from pwnlib.util import proc as proc
from pwnlib.util import safeeval as safeeval
from pwnlib.util.crc import BitPolynom as BitPolynom
from pwnlib.util.cyclic import *
from pwnlib.util.fiddling import *
from pwnlib.util.getdents import *
from pwnlib.util.hashes import *
from pwnlib.util.lists import *
from pwnlib.util.misc import *
from pwnlib.util.packing import *
from pwnlib.util.proc import pidof as pidof
from pwnlib.util.sh_string import (
    sh_string as sh_string,
    sh_prepare as sh_prepare,
    sh_command_with as sh_command_with,
)
from pwnlib.util.splash import *
from pwnlib.util.web import *

from six.moves import cPickle as pickle, cStringIO as StringIO
from six import BytesIO as BytesIO

class LogFunction(Protocol):
    def __call__(self, message: str, *args: Any, **kwargs: Any) -> None: ...

log: pwnlib.log.Logger
error: LogFunction
warning: LogFunction
warn: LogFunction
info: LogFunction
debug: LogFunction
success: LogFunction
