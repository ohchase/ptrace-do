# Ptrace-do
[![Rust](https://img.shields.io/badge/Rust-%23000000.svg?e&logo=rust&logoColor=white)](#)
![Crates.io](https://img.shields.io/crates/v/ptrace-do)
![Docs.rs](https://img.shields.io/docsrs/ptrace-do/latest)
![Downloads](https://img.shields.io/crates/d/ptrace-do)
![Crates.io License](https://img.shields.io/crates/l/ptrace-do)

Provides ability to use ptrace to execute functions in remote processes.
Mostly for runtime shared library injection.

## Support
### Ptrace-do supports the primary market share of build targets to be used with crate
- ![i686-unknown-linux-gnu](https://github.com/ohchase/ptrace-do/actions/workflows/i686-unknown-linux-gnu.yml/badge.svg)
- ![x86_64-unknown-linux-gnu](https://github.com/ohchase/ptrace-do/actions/workflows/x86_64-unknown-linux-gnu.yml/badge.svg)
- ![aarch64-unknown-linux-gnu](https://github.com/ohchase/ptrace-do/actions/workflows/aarch64-unknown-linux-gnu.yml/badge.svg)
- ![arm-unknown-linux-gnueabi](https://github.com/ohchase/ptrace-do/actions/workflows/arm-unknown-linux-gnueabi.yml/badge.svg)
- ![i686-linux-android](https://github.com/ohchase/ptrace-do/actions/workflows/i686-linux-android.yml/badge.svg)
- ![x86_64-linux-android](https://github.com/ohchase/ptrace-do/actions/workflows/x86_64-linux-android.yml/badge.svg)
- ![aarch64-linux-android](https://github.com/ohchase/ptrace-do/actions/workflows/aarch64-linux-android.yml/badge.svg)
- ![arm-linux-androideabi](https://github.com/ohchase/ptrace-do/actions/workflows/arm-linux-androideabi.yml/badge.svg)
- ![armv7-linux-androideabi](https://github.com/ohchase/ptrace-do/actions/workflows/armv7-linux-androideabi.yml/badge.svg)

## Relevant
[Yaui](https://github.com/ohchase/yaui)

A fully Rust command line application providing a worked example command line interface for injecting shared objects into running unix processes. Serves as a great example of how this crate can be used to its fully capacity.

[Plt-rs](https://github.com/ohchase/plt-rs)

A fully Rust library providing the ability to hook a unix's application Procedural Link Table, PLT, at runtime. If you are striving to both inject a shared object into a running unix process, and would then like to detour functions such as libc::recv or libc::send for network packet inspection/augmentation; this library may of benefit for you.

[ptrace_do](https://github.com/emptymonkey/ptrace_do)

This Rust library was named `ptrace-do`, and I want to explicitly acknowledge this could have been an inappropriate and poor decision on my part. I used the same name as a historically popular c project, because the objectives of the projects were similar in that they both strive to provide an ergonomic interface over syscall injection with ptrace. To clarify the work in this crate has absolutely no relationship to the ptrace_do implemenation by emptymonkey. This crate is completely designed in Rust and not a crate providing a type safe rust api of the c ffi of emptymonkey's ptrace_do implementation. 

## Example
### Invoking Libc Getpid in a remote process
```rust
use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{ProcessIdentifier, RawProcess, TracedProcess};

fn find_mod_map_fuzzy(mod_name: &str, process: &impl ProcessIdentifier) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process.pid()).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p.to_str().map(|s| s.contains(mod_name)).unwrap_or(false),
        None => false,
    })
}

pub fn find_remote_procedure(
    mod_name: &str,
    owned_process: &impl ProcessIdentifier,
    remote_process: &impl ProcessIdentifier,
    function_address: usize,
) -> Option<usize> {
    let internal_module = find_mod_map_fuzzy(mod_name, owned_process)?;
    tracing::info!(
        "Identifed internal range {mod_name:?} ({:?}) at {:X?}",
        internal_module.filename(),
        internal_module.start()
    );

    let remote_module = find_mod_map_fuzzy(mod_name, remote_process)?;
    tracing::info!(
        "Identifed remote range {mod_name:?} ({:?}) at {:X?}",
        remote_module.filename(),
        remote_module.start()
    );

    Some(function_address - internal_module.start() + remote_module.start())
}

fn main() {
    tracing_subscriber::fmt().init();

    let target_pid: pid_t = 7777;
    let traced_process = TracedProcess::attach(RawProcess::new(target_pid)).expect("active process running with desired pid");

    tracing::info!("Successfully attached to the process");
    let libc_path = "libc";
    let getpid_remote_procedure = find_remote_procedure(
        libc_path,
        &RawProcess::new(std::process::id() as pid_t),
        &traced_process,
        libc::getpid as usize,
    )
    .expect("active process links libc::getpid");
    tracing::info!("Found remote getpid procedure at : {getpid_remote_procedure:X?}");

    let frame = traced_process.next_frame().expect("able to acquire a stopped frame in the process");
    tracing::info!("Successfully waited for a frame");

    let (regs, _frame) = frame.invoke_remote(getpid_remote_procedure, 0, &[])?;
    tracing::info!("Successfully executed remote getpid");

    let traceed_pid = regs.return_value() as pid_t;
    tracing::info!("The return value (Traceed Pid) was {}", traceed_pid);
}
```

