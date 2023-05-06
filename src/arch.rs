#[cfg(target_arch = "x86")]
mod x86 {

    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct UserRegs {
        pub ebx: i32,
        pub ecx: i32,
        pub edx: i32,
        pub esi: i32,
        pub edi: i32,
        pub ebp: i32,
        pub eax: i32,
        pub xds: i32,
        pub xes: i32,
        pub xfs: i32,
        pub xgs: i32,
        pub orig_eax: i32,
        pub eip: i32,
        pub xcs: i32,
        pub eflags: i32,
        pub esp: i32,
        pub xss: i32,
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct UserRegs {
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub r11: u64,
        pub r10: u64,
        pub r9: u64,
        pub r8: u64,
        pub rax: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub orig_rax: u64,
        pub rip: u64,
        pub cs: u64,
        pub eflags: u64,
        pub rsp: u64,
        pub ss: u64,
        pub fs_base: u64,
        pub gs_base: u64,
        pub ds: u64,
        pub es: u64,
        pub fs: u64,
        pub gs: u64,
    }

    impl UserRegs {
        pub fn return_value(&self) -> usize {
            self.rax as usize
        }

        pub fn program_counter(&self) -> usize {
            self.rip as usize
        }

        pub fn set_program_counter(&mut self, program_counter: usize) {
            self.rip = program_counter as u64
        }

        pub fn stack_pointer(&self) -> usize {
            self.rsp as usize
        }

        pub fn set_stack_pointer(&mut self, stack_pointer: usize) {
            self.rsp = stack_pointer as u64
        }
    }
}

#[cfg(target_arch = "arm")]
mod arm {

    pub const CPSR_T_MASK: u32 = 1 << 5;

    /// Note: Entries 0-15 match r0..r15
    /// Entry 16 is used to store the CPSR register.
    /// Entry 17 is used to store the "orig_r0" value.
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct UserRegs {
        pub regs: [u32; 18],
    }

    impl UserRegs {
        pub fn return_value(&self) -> usize {
            self.regs[0] as usize
        }

        pub fn stack_pointer(&self) -> usize {
            self.regs[13] as usize
        }

        pub fn set_stack_pointer(&mut self, stack_pointer: usize) {
            self.regs[13] = stack_pointer as u32
        }

        pub fn lr(&self) -> usize {
            self.regs[14] as usize
        }

        pub fn set_lr(&mut self, lr: usize) {
            self.regs[14] = lr as u32
        }

        pub fn program_counter(&self) -> usize {
            self.regs[15] as usize
        }

        pub fn set_program_counter(&mut self, program_counter: usize) {
            self.regs[15] = program_counter as u32
        }

        pub fn cpsr(&self) -> usize {
            self.regs[16] as usize
        }

        pub fn set_cpsr(&mut self, cpsr: usize) {
            self.regs[16] = cpsr as u32
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {

    pub const CPSR_T_MASK: u32 = 1 << 5;

    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct UserRegs {
        pub regs: [u64; 31],
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
    }

    impl UserRegs {
        pub fn return_value(&self) -> usize {
            self.regs[0] as usize
        }

        pub fn stack_pointer(&self) -> usize {
            self.sp as usize
        }

        pub fn set_stack_pointer(&mut self, stack_pointer: usize) {
            self.sp = stack_pointer as u64
        }

        pub fn lr(&self) -> usize {
            self.regs[30] as usize
        }

        pub fn set_lr(&mut self, lr: usize) {
            self.regs[30] = lr as u64
        }

        pub fn program_counter(&self) -> usize {
            self.pc as usize
        }

        pub fn set_program_counter(&mut self, program_counter: usize) {
            self.pc = program_counter as u64
        }

        pub fn cpsr(&self) -> usize {
            self.pstate as usize
        }

        pub fn set_cpsr(&mut self, cpsr: usize) {
            self.pstate = cpsr as u64
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "arm")]
pub use arm::*;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "x86")]
pub use x86::*;
