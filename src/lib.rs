mod arch;
use arch::UserRegs;

use libc::{pid_t, ptrace, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH};
use std::{mem, process::Child};
use thiserror::Error;

fn usize_arr_to_u8(data: &[usize]) -> Vec<u8> {
    let mut arr: Vec<u8> = Vec::new();
    for p in data {
        arr.extend_from_slice(&p.to_le_bytes());
    }
    return arr;
}

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("Ptrace error: `{0}`")]
    Ptrace(std::io::Error),

    #[error("IO Error: `{0}`")]
    Io(#[from] std::io::Error),

    #[error("General `{0}`")]
    General(&'static str),
}

type TraceResult<T> = Result<T, TraceError>;

pub trait ProcessIdentifier {
    fn pid(&self) -> pid_t;
}

pub struct RawProcess {
    pid: pid_t,
}

impl ProcessIdentifier for RawProcess {
    fn pid(&self) -> pid_t {
        self.pid
    }
}

impl RawProcess {
    pub fn new(pid: pid_t) -> Self {
        Self { pid }
    }
}

pub struct OwnedProcess {
    child: Child,
}

impl From<Child> for OwnedProcess {
    fn from(value: Child) -> Self {
        Self { child: value }
    }
}

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

#[allow(unused)]
enum WaitOptions {
    None,
    NoHang,
    Untraced,
    Continued,
}

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

struct WaitStatus(i32);

impl WaitStatus {
    fn is_stop(&self) -> bool {
        libc::WIFSTOPPED(self.0)
    }

    fn is_signaled(&self) -> bool {
        libc::WIFSIGNALED(self.0)
    }

    fn is_continued(&self) -> bool {
        libc::WIFCONTINUED(self.0)
    }

    fn is_exited(&self) -> bool {
        libc::WIFEXITED(self.0)
    }

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

pub struct ProcessFrame<T>
where
    T: ProcessIdentifier,
{
    process: TracedProcess<T>,
}

impl<T> std::fmt::Debug for ProcessFrame<T>
where
    T: ProcessIdentifier,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProcessFrame ( pid: {} )", self.process.pid())
    }
}

impl<T> ProcessFrame<T>
where
    T: ProcessIdentifier,
{
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
                current_registers.stack_pointer() - (stack_arguments.len() * size_of::<usize>()),
            );

            self.write_memory(current_registers.stack_pointer(), usize_arr_to_u8(stack_arguments).as_slice())?;
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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
    pub fn query_registers(&mut self) -> TraceResult<UserRegs> {
        let mut registers: UserRegs = unsafe { mem::zeroed() };
        let result = unsafe { ptrace(libc::PTRACE_GETREGS, self.process.pid(), 0, &mut registers) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(registers),
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"))]
    pub fn set_registers(&mut self, registers: UserRegs) -> TraceResult<()> {
        let result = unsafe { ptrace(libc::PTRACE_SETREGS, self.process.pid(), 0, &registers) };

        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

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
                current_registers.stack_pointer() - (stack_arguments.len() * size_of::<usize>()),
            );

            self.write_memory(current_registers.stack_pointer(), usize_arr_to_u8(stack_arguments).as_slice())?;
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

        tracing::trace!("Function parameters: {:?}", parameters);

        // adjust stack pointer
        current_registers.set_stack_pointer(
            current_registers.stack_pointer() - (param_count * size_of::<usize>()),
        );
        self.write_memory(current_registers.stack_pointer(), usize_arr_to_u8(parameters).as_slice())?;

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
                current_registers.stack_pointer() - (stack_arguments.len() * size_of::<usize>()),
            );
            self.write_memory(current_registers.stack_pointer(), usize_arr_to_u8(stack_arguments).as_slice())?;
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

    pub fn read_memory(&mut self, addr: usize, len: usize) -> TraceResult<Vec<u8>> {
        let mut data = vec![0; len];
        let len_read = self.read_memory_mut(addr, &mut data)?;
        data.truncate(len_read);
        Ok(data)
    }

    pub fn read_memory_mut(&self, addr: usize, data: &mut [u8]) -> TraceResult<usize> {
        use std::os::unix::fs::FileExt;
        let mem = std::fs::File::open(self.process.proc_mem_path())?;
        let len = mem.read_at(data, addr.try_into().unwrap())?;
        Ok(len)
    }

    pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> TraceResult<usize> {
        use std::os::unix::fs::FileExt;
        let mem = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.process.proc_mem_path())?;
        let len = mem.write_at(data, addr.try_into().unwrap())?;
        Ok(len)
    }

    fn step_cont(mut self) -> TraceResult<ProcessFrame<T>> {
        self.process.cont()?;
        self.process.next_frame()
    }
}

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
    fn detach(&mut self) -> TraceResult<()> {
        let result = unsafe { ptrace(PTRACE_DETACH, self.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

    pub fn attach(process: T) -> TraceResult<Self> {
        let result = unsafe { ptrace(PTRACE_ATTACH, process.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(Self { process }),
        }
    }

    pub fn pid(&self) -> pid_t {
        self.process.pid()
    }

    fn cont(&mut self) -> TraceResult<()> {
        let result = unsafe { ptrace(PTRACE_CONT, self.pid(), 0, 0) };
        match result == -1 {
            true => Err(TraceError::Ptrace(std::io::Error::last_os_error())),
            false => Ok(()),
        }
    }

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

    pub fn next_frame(mut self) -> TraceResult<ProcessFrame<T>> {
        let wait_status = self.wait(WaitOptions::Untraced)?;
        if wait_status.is_exited() {
            return Err(TraceError::General("Waiting stop received an exit signal"));
        }

        Ok(ProcessFrame { process: self })
    }

    fn proc_mem_path(&self) -> String {
        format!("/proc/{}/mem", self.process.pid())
    }
}
