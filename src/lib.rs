mod arch;
use arch::UserRegs;

use libc::{pid_t, ptrace, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH};
use std::{mem, process::Child};
use thiserror::Error;

/// Utility function that converts the usize inputs individually with the appropriate endianness into a Vec<u8>
fn usize_arr_to_u8(data: &[usize]) -> Vec<u8> {
    let mut arr: Vec<u8> = Vec::new();
    for p in data {
        if cfg!(target_endian = "big") {
            arr.extend_from_slice(&p.to_be_bytes());
        } else {
            arr.extend_from_slice(&p.to_le_bytes());
        }
    }
    return arr;
}

/// Enum containing all errors tracing can witness
#[derive(Debug, Error)]
pub enum TraceError {
    /// Error spawning from syscall interactions
    #[error("Ptrace error: `{0}`")]
    Ptrace(std::io::Error),

    /// Error during read and writing of process's memory
    #[error("IO Error: `{0}`")]
    Io(#[from] std::io::Error),

    /// Contexted error
    #[error("General `{0}`")]
    General(&'static str),
}

/// Internal Result type
pub type TraceResult<T> = Result<T, TraceError>;

/// Trait representing the type represents a process and has a unique process identifier, pid.
pub trait ProcessIdentifier {
    /// Acces the pid
    fn pid(&self) -> pid_t;
}

/// A raw process, initialized by an explicit pid. Unsafe and prone to permission errors beware,
/// know your environment and security restrictions.
pub struct RawProcess {
    pid: pid_t,
}

impl ProcessIdentifier for RawProcess {
    fn pid(&self) -> pid_t {
        self.pid
    }
}

impl RawProcess {
    /// Initialize raw process with the explicit pid
    pub fn new(pid: pid_t) -> Self {
        Self { pid }
    }
}

/// An owned process.
pub struct OwnedProcess {
    child: Child,
}

/// An owned process can be initialized from a Child os process
impl From<Child> for OwnedProcess {
    fn from(value: Child) -> Self {
        Self { child: value }
    }
}

/// Will attempt to kill the child on drop.
/// Never panics only logs an error
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            tracing::error!("Unable to kill owned process's child {e:?}");
        } else {
            tracing::info!("Owned process has been killed.");
        }
    }
}

impl ProcessIdentifier for OwnedProcess {
    fn pid(&self) -> pid_t {
        self.child.id() as pid_t
    }
}

/// A process actively being traced.
/// Simply a wrapper around a type with an identifiable process identifier.
pub struct TracedProcess<T>
where
    T: ProcessIdentifier,
{
    process: T,
}

impl<T> ProcessIdentifier for TracedProcess<T>
where
    T: ProcessIdentifier,
{
    fn pid(&self) -> pid_t {
        self.process.pid()
    }
}

/// The available wait options
#[allow(unused)]
enum WaitOptions {
    None,
    NoHang,
    Untraced,
    Continued,
}

/// A wait option can be extracted from an i32
impl From<WaitOptions> for i32 {
    fn from(val: WaitOptions) -> Self {
        match val {
            WaitOptions::None => 0,
            WaitOptions::NoHang => libc::WNOHANG,
            WaitOptions::Untraced => libc::WUNTRACED,
            WaitOptions::Continued => libc::WCONTINUED,
        }
    }
}

/// Wait status result of a ptrace step
struct WaitStatus(i32);

impl WaitStatus {
    /// is stopped status
    fn is_stop(&self) -> bool {
        libc::WIFSTOPPED(self.0)
    }

    /// is signaled status
    fn is_signaled(&self) -> bool {
        libc::WIFSIGNALED(self.0)
    }

    /// is continued status
    fn is_continued(&self) -> bool {
        libc::WIFCONTINUED(self.0)
    }

    /// is exited status
    fn is_exited(&self) -> bool {
        libc::WIFEXITED(self.0)
    }

    /// is stopcode status
    fn stop_code(&self) -> i32 {
        libc::WSTOPSIG(self.0)
    }
}

impl std::fmt::Debug for WaitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaitStatus")
            .field("is_stopped", &self.is_stop())
            .field("is_signaled", &self.is_signaled())
            .field("is_continued", &self.is_continued())
            .field("is_exited", &self.is_exited())
            .field("stop_code", &self.stop_code())
            .finish()
    }
}

/// Represents a traced process which is in the process of building a `frame`.
/// `frame` can be thought of a mutable view into a stopped process's execution.
/// Given you own a process frame, it is an appropriate time to edit registers, change instructions, and edit memory.
pub struct ProcessFrame<T>
where
    T: ProcessIdentifier,
{
    process: TracedProcess<T>,
}

impl<T> ProcessFrame<T>
where
    T: ProcessIdentifier,
{
    /// aarch64 specific get registers functionality.
    /// uses iovec's and GETREGSET
    #[cfg(target_arch = "aarch64")]
    pub fn query_registers(&mut self) -> TraceResult<UserRegs> {
        let mut registers: UserRegs = unsafe { mem::zeroed() };
        let mut iovec = libc::iovec {
            iov_base: &mut registers as *mut _ as *mut core::ffi::c_void,
            iov_len: std::mem::size_of::<UserRegs>() as libc::size_t,
        };

        let result = unsafe { ptrace(libc::PTRACE_GETREGSET, self.process.pid(), 1, &mut iovec) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(registers),
        }
    }

    /// aarch64 specific set registers functionality.
    /// uses iovec's and SETREGSET
    #[cfg(target_arch = "aarch64")]
    pub fn set_registers(&mut self, mut registers: UserRegs) -> TraceResult<()> {
        let mut iovec = libc::iovec {
            iov_base: &mut registers as *mut _ as *mut core::ffi::c_void,
            iov_len: std::mem::size_of::<UserRegs>() as libc::size_t,
        };

        let result = unsafe { ptrace(libc::PTRACE_SETREGSET, self.process.pid(), 1, &mut iovec) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

    /// Attempts to invoke a remote function with the provided parameters.
    /// Internally this is an os cfg controlled function that write the inputted parameters according to the architectures expectations.
    /// Additionally it prepares the provided return address
    #[cfg(target_arch = "aarch64")]
    pub fn invoke_remote(
        mut self,
        func_address: usize,
        return_address: usize,
        parameters: &[usize],
    ) -> TraceResult<(UserRegs, ProcessFrame<T>)> {
        use std::mem::size_of;

        const REGISTER_ARGUMENTS: usize = 8;
        let mut current_registers = self.query_registers()?;
        tracing::trace!(
            "Initial registers acquired Current PC: {:X?}",
            current_registers.program_counter()
        );

        let cached_registers = current_registers.clone();
        current_registers.set_stack_pointer(current_registers.stack_pointer() & !0xfusize);
        for (i, param) in parameters[..std::cmp::min(parameters.len(), REGISTER_ARGUMENTS)]
            .iter()
            .enumerate()
        {
            let reg: usize = *param;
            current_registers.regs[i] = reg as u64;
            tracing::trace!("Applying register {i} with param {}", reg);
        }

        if parameters.len() > REGISTER_ARGUMENTS {
            let stack_arguments = &parameters[REGISTER_ARGUMENTS..];
            tracing::trace!("Remaining stack arguments: {:?}", stack_arguments);

            // adjust stack pointer
            current_registers.set_stack_pointer(
                current_registers.stack_pointer()
                    - (((stack_arguments.len() + 1) & !1usize) * size_of::<usize>()),
            );

            self.write_memory(
                current_registers.stack_pointer(),
                usize_arr_to_u8(stack_arguments).as_slice(),
            )?;
        };

        // set registers cached_registers
        current_registers.set_program_counter(func_address);
        if (current_registers.program_counter() & 1) != 0 {
            current_registers.set_program_counter(current_registers.program_counter() & !1);
            current_registers
                .set_cpsr((current_registers.cpsr() as u32 | (arch::CPSR_T_MASK)) as usize);
        } else {
            current_registers
                .set_cpsr((current_registers.cpsr() as u32 & !(arch::CPSR_T_MASK)) as usize);
        }
        current_registers.set_lr(return_address);
        tracing::trace!(
            "Executing with PC: {:X?}, and arguments {parameters:?}",
            func_address
        );

        self.set_registers(current_registers)?;
        tracing::trace!("Registers successfully injected.");

        let mut frame = self.step_cont()?;
        let result_regs = frame.query_registers()?;
        tracing::trace!("Result {result_regs:#?}");

        frame.set_registers(cached_registers)?;
        Ok((result_regs, frame))
    }

    /// gets process frame registers.
    /// internally uses GETREGS
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
    pub fn query_registers(&mut self) -> TraceResult<UserRegs> {
        let mut registers: UserRegs = unsafe { mem::zeroed() };
        let result = unsafe { ptrace(libc::PTRACE_GETREGS, self.process.pid(), 0, &mut registers) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(registers),
        }
    }

    /// sets a process frame registers.
    /// internally uses SETREGS
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
    pub fn set_registers(&mut self, registers: UserRegs) -> TraceResult<()> {
        let result = unsafe { ptrace(libc::PTRACE_SETREGS, self.process.pid(), 0, &registers) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

    /// Attempts to invoke a remote function with the provided parameters.
    /// Internally this is an os cfg controlled function that write the inputted parameters according to the architectures expectations.
    /// Additionally it prepares the provided return address
    #[cfg(target_arch = "arm")]
    pub fn invoke_remote(
        mut self,
        func_address: usize,
        return_address: usize,
        parameters: &[usize],
    ) -> TraceResult<(UserRegs, ProcessFrame<T>)> {
        use std::mem::size_of;

        const REGISTER_ARGUMENTS: usize = 4;
        let mut current_registers = self.query_registers()?;
        tracing::info!(
            "Initial registers acquired Current PC: {:X?}",
            current_registers.program_counter()
        );

        let cached_registers = current_registers.clone();
        current_registers.set_stack_pointer(current_registers.stack_pointer() & !0xfusize);
        for (i, param) in parameters[..std::cmp::min(parameters.len(), REGISTER_ARGUMENTS)]
            .iter()
            .enumerate()
        {
            let reg: u32 = (*param).try_into().unwrap();
            current_registers.regs[i] = reg;
            tracing::trace!("Applying register {i} with param {}", reg);
        }

        if parameters.len() > REGISTER_ARGUMENTS {
            let stack_arguments = &parameters[REGISTER_ARGUMENTS..];
            tracing::trace!("Remaining stack arguments: {:?}", stack_arguments);

            // adjust stack pointer
            current_registers.set_stack_pointer(
                current_registers.stack_pointer()
                    - (((stack_arguments.len() + 3) & !3usize) * size_of::<usize>()),
            );

            self.write_memory(
                current_registers.stack_pointer(),
                usize_arr_to_u8(stack_arguments).as_slice(),
            )?;
        };

        // set registers cached_registers
        current_registers.set_program_counter(func_address);
        if (current_registers.program_counter() & 1) != 0 {
            current_registers.set_program_counter(current_registers.program_counter() & !1);
            current_registers
                .set_cpsr((current_registers.cpsr() as u32 | (arch::CPSR_T_MASK)) as usize);
        } else {
            current_registers
                .set_cpsr((current_registers.cpsr() as u32 & !(arch::CPSR_T_MASK)) as usize);
        }
        current_registers.set_lr(return_address);
        tracing::trace!(
            "Executing with PC: {:X?}, and arguments {parameters:?}",
            func_address
        );

        self.set_registers(current_registers)?;
        tracing::trace!("Registers successfully injected.");

        let mut frame = self.step_cont()?;
        let result_regs = frame.query_registers()?;
        tracing::trace!("Result {result_regs:#?}");

        frame.set_registers(cached_registers)?;
        Ok((result_regs, frame))
    }

    /// Attempts to invoke a remote function with the provided parameters.
    /// Internally this is an os cfg controlled function that write the inputted parameters according to the architectures expectations.
    /// Additionally it prepares the provided return address
    #[cfg(target_arch = "x86")]
    pub fn invoke_remote(
        mut self,
        func_address: usize,
        return_address: usize,
        parameters: &[usize],
    ) -> TraceResult<(UserRegs, ProcessFrame<T>)> {
        use std::mem::size_of;

        let mut current_registers = self.query_registers()?;
        tracing::trace!(
            "Initial registers acquired Current PC: {:X?}",
            current_registers.program_counter()
        );

        let cached_registers = current_registers.clone();
        let param_count = parameters.len();
        current_registers.set_stack_pointer(current_registers.stack_pointer() & !0xfusize);

        tracing::trace!("Function parameters: {:?}", parameters);

        if param_count > 0 {
            // adjust stack pointer
            current_registers.set_stack_pointer(
                current_registers.stack_pointer()
                    - (((param_count + 3) & !3usize) * size_of::<usize>()),
            );
            self.write_memory(
                current_registers.stack_pointer(),
                usize_arr_to_u8(parameters).as_slice(),
            )?;
        }

        // return address is bottom of stack!
        current_registers.set_stack_pointer(current_registers.stack_pointer() - size_of::<usize>());
        self.write_memory(
            current_registers.stack_pointer(),
            &return_address.to_le_bytes(),
        )?;

        current_registers.eax = 0;
        current_registers.orig_eax = 0;

        // set registers cached_registers
        current_registers.set_program_counter(func_address);
        tracing::trace!(
            "Executing with PC: {:X?}, and arguments {parameters:?}",
            func_address
        );

        self.set_registers(current_registers)?;
        tracing::trace!("Registers successfully injected.");

        let mut frame = self.step_cont()?;
        let result_regs = frame.query_registers()?;
        tracing::trace!("Result {result_regs:#?}");

        frame.set_registers(cached_registers)?;
        Ok((result_regs, frame))
    }

    /// Attempts to invoke a remote function with the provided parameters.
    /// Internally this is an os cfg controlled function that write the inputted parameters according to the architectures expectations.
    /// Additionally it prepares the provided return address
    #[cfg(target_arch = "x86_64")]
    pub fn invoke_remote(
        mut self,
        func_address: usize,
        return_address: usize,
        parameters: &[usize],
    ) -> TraceResult<(UserRegs, ProcessFrame<T>)> {
        use std::mem::size_of;

        const REGISTER_ARGUMENTS: usize = 6;
        let mut current_registers = self.query_registers()?;
        tracing::info!(
            "Initial registers acquired Current PC: {:X?}",
            current_registers.program_counter()
        );

        let cached_registers = current_registers.clone();
        let param_count = parameters.len();
        current_registers.set_stack_pointer(current_registers.stack_pointer() & !0xfusize);

        // You gotta a better idea???????
        if param_count > 0 {
            current_registers.rdi = parameters[0] as u64;
        }
        if param_count > 1 {
            current_registers.rsi = parameters[1] as u64;
        }
        if param_count > 2 {
            current_registers.rdx = parameters[2] as u64;
        }
        if param_count > 3 {
            current_registers.rcx = parameters[3] as u64;
        }
        if param_count > 4 {
            current_registers.r8 = parameters[4] as u64;
        }
        if param_count > 5 {
            current_registers.r9 = parameters[5] as u64;
        }

        if parameters.len() > REGISTER_ARGUMENTS {
            let stack_arguments = &parameters[REGISTER_ARGUMENTS..];
            tracing::trace!("Remaining stack arguments: {:?}", stack_arguments);

            // adjust stack pointer
            current_registers.set_stack_pointer(
                current_registers.stack_pointer()
                    - (((stack_arguments.len() + 1) & !1usize) * size_of::<usize>()),
            );
            self.write_memory(
                current_registers.stack_pointer(),
                usize_arr_to_u8(stack_arguments).as_slice(),
            )?;
        };

        // return address is bottom of stack!
        current_registers.set_stack_pointer(current_registers.stack_pointer() - size_of::<usize>());
        self.write_memory(
            current_registers.stack_pointer(),
            &return_address.to_le_bytes(),
        )?;

        current_registers.rax = 0;
        current_registers.orig_rax = 0;

        // set registers cached_registers
        current_registers.set_program_counter(func_address);
        tracing::trace!(
            "Executing with PC: {:X?}, and arguments {parameters:?}",
            func_address
        );

        self.set_registers(current_registers)?;
        tracing::trace!("Registers successfully injected.");

        let mut frame = self.step_cont()?;
        let result_regs = frame.query_registers()?;
        tracing::info!("Result {result_regs:#?}");

        frame.set_registers(cached_registers)?;
        Ok((result_regs, frame))
    }

    /// Attempts to read a process's memory from fs
    pub fn read_memory(&mut self, addr: usize, len: usize) -> TraceResult<Vec<u8>> {
        let mut data = vec![0; len];
        let len_read = self.read_memory_mut(addr, &mut data)?;
        data.truncate(len_read);
        Ok(data)
    }

    /// Attempts to read a mutable section of a process's memory from fs
    pub fn read_memory_mut(&self, addr: usize, data: &mut [u8]) -> TraceResult<usize> {
        use std::os::unix::fs::FileExt;
        let mem = std::fs::File::open(self.process.proc_mem_path())?;
        let len = mem.read_at(data, addr.try_into().unwrap())?;
        Ok(len)
    }

    /// Attempts to write to a section of the process's memory
    pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> TraceResult<usize> {
        use std::os::unix::fs::FileExt;
        let mem = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.process.proc_mem_path())?;
        let len = mem.write_at(data, addr.try_into().unwrap())?;
        Ok(len)
    }

    /// Continue the process frame, consuming self.
    fn step_cont(mut self) -> TraceResult<ProcessFrame<T>> {
        self.process.cont()?;
        self.process.next_frame()
    }
}

/// Drop implementation that attempts to ptrace detach from the process.
/// On failure there is a warning, but this does not ever panic.
impl<T> Drop for TracedProcess<T>
where
    T: ProcessIdentifier,
{
    fn drop(&mut self) {
        let pid = self.pid();
        match self.detach() {
            Ok(()) => tracing::info!("Successfully detached from Pid: {pid}"),
            Err(e) => tracing::error!("Failed to detach from Pid: {pid}, {e:#?}"),
        }
    }
}

impl<T> TracedProcess<T>
where
    T: ProcessIdentifier,
{
    /// Attempt to detach from the traced process
    fn detach(&mut self) -> TraceResult<()> {
        let result = unsafe { ptrace(PTRACE_DETACH, self.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

    /// Attempt to attach from the traced process
    pub fn attach(process: T) -> TraceResult<Self> {
        let result = unsafe { ptrace(PTRACE_ATTACH, process.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(Self { process }),
        }
    }

    /// pid of the actively traced process
    pub fn pid(&self) -> pid_t {
        self.process.pid()
    }

    /// continue execution
    fn cont(&mut self) -> TraceResult<()> {
        let result = unsafe { ptrace(PTRACE_CONT, self.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

    /// wait for a status
    fn wait(&mut self, options: WaitOptions) -> TraceResult<WaitStatus> {
        let mut raw_status = 0;
        let result = unsafe { libc::waitpid(self.process.pid(), &mut raw_status, options.into()) };
        if result == -1 {
            return Err(TraceError::Ptrace(std::io::Error::last_os_error()));
        }

        let status = WaitStatus(raw_status);
        tracing::info!("{status:?}");
        Ok(status)
    }

    /// wait for an untraced status consuming self and opening a process frame
    pub fn next_frame(mut self) -> TraceResult<ProcessFrame<T>> {
        let wait_status = self.wait(WaitOptions::Untraced)?;
        if wait_status.is_exited() {
            return Err(TraceError::General("Waiting stop received an exit signal"));
        }

        Ok(ProcessFrame { process: self })
    }

    /// path to the process's memory
    fn proc_mem_path(&self) -> String {
        format!("/proc/{}/mem", self.process.pid())
    }
}
