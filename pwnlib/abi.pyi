from typing_extensions import Literal

from pwnlib.context import LocalContext

class ABI:
    stack: str
    register_arguments: list[str]
    arg_alignment: int
    stack_minimum: int
    returns: bool

    def __init__(
        self, stack: str, regs: list[str], align: int, minimum: int
    ) -> None: ...
    @staticmethod
    @LocalContext
    def default() -> ABI: ...
    @staticmethod
    @LocalContext
    def syscall() -> SyscallABI: ...
    @staticmethod
    @LocalContext
    def sigreturn() -> SigreturnABI: ...

class SyscallABI(ABI):
    syscall_register: str

class SigreturnABI(SyscallABI): ...

linux_i386: ABI
linux_amd64: ABI
linux_arm: ABI
linux_aarch64: ABI
linux_mips: ABI
linux_ppc: ABI
linux_ppc64: ABI
linux_riscv32: ABI
linux_riscv64: ABI

sysv_i386: ABI
sysv_amd64: ABI
sysv_arm: ABI
sysv_aarch64: ABI
sysv_mips: ABI
sysv_ppc: ABI
sysv_ppc64: ABI
sysv_riscv32: ABI
sysv_riscv64: ABI

linux_i386_syscall: SyscallABI
linux_amd64_syscall: SyscallABI
linux_arm_syscall: SyscallABI
linux_aarch64_syscall: SyscallABI
linux_mips_syscall: SyscallABI
linux_ppc_syscall: SyscallABI
linux_ppc64_syscall: SyscallABI
linux_riscv32_syscall: SyscallABI
linux_riscv64_syscall: SyscallABI

linux_i386_sigreturn: SigreturnABI
linux_amd64_sigreturn: SigreturnABI
linux_arm_sigreturn: SigreturnABI
linux_aarch64_sigreturn: SigreturnABI
linux_riscv32_sigreturn: SigreturnABI
linux_riscv64_sigreturn: SigreturnABI

sysv_i386_sigreturn: SigreturnABI
sysv_amd64_sigreturn: SigreturnABI
sysv_arm_sigreturn: SigreturnABI
sysv_aarch64_sigreturn: SigreturnABI
sysv_riscv32_sigreturn: SigreturnABI
sysv_riscv64_sigreturn: SigreturnABI

freebsd_i386: ABI
freebsd_amd64: ABI
freebsd_arm: ABI
freebsd_aarch64: ABI
freebsd_mips: ABI
freebsd_ppc: ABI
freebsd_ppc64: ABI

freebsd_i386_syscall: SyscallABI
freebsd_amd64_syscall: SyscallABI
freebsd_arm_syscall: SyscallABI
freebsd_aarch64_syscall: SyscallABI
freebsd_mips_syscall: SyscallABI
freebsd_ppc_syscall: SyscallABI
freebsd_ppc64_syscall: SyscallABI

freebsd_i386_sigreturn: SigreturnABI
freebsd_amd64_sigreturn: SigreturnABI
freebsd_arm_sigreturn: SigreturnABI
freebsd_aarch64_sigreturn: SigreturnABI

windows_i386: ABI
windows_amd64: ABI

darwin_aarch64: ABI
darwin_aarch64_syscall: SyscallABI
darwin_aarch64_sigreturn: SigreturnABI

darwin_amd64: ABI
darwin_amd64_syscall: SyscallABI
darwin_amd64_sigreturn: SigreturnABI
