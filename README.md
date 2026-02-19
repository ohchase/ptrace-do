# ptrace-do
[![Rust](https://img.shields.io/badge/Rust-%23000000.svg?e&logo=rust&logoColor=white)](#)
![Crates.io](https://img.shields.io/crates/v/ptrace-do)
![Docs.rs](https://img.shields.io/docsrs/ptrace-do/latest)
![Downloads](https://img.shields.io/crates/d/ptrace-do)
![Crates.io License](https://img.shields.io/crates/l/ptrace-do)

Provides ability to use ptrace to execute functions in remote processes.
Mostly for runtime shared library injection.

## Platform Support

Ptrace-do supports the primary intended platform targets where this library would be of usage
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
[yaui](https://github.com/ohchase/yaui)

A fully Rust command line application providing a worked example command line interface for injecting shared objects into running unix processes. Serves as a great example of how this crate can be used to its fully capacity.

[plt-rs](https://github.com/ohchase/plt-rs)

A fully Rust library providing the ability to hook a unix's application Procedural Link Table, PLT, at runtime. If you are striving to both inject a shared object into a running unix process, and would then like to detour functions such as libc::recv or libc::send for network packet inspection/augmentation; this library may of benefit for you.

[ptrace_do](https://github.com/emptymonkey/ptrace_do)

This Rust library was named `ptrace-do`, and I want to explicitly acknowledge this could have been an inappropriate and poor decision on my part. I used the same name as a historically popular c project, because the objectives of the projects were similar in that they both strive to provide an ergonomic interface over syscall injection with ptrace. To clarify the work in this crate has absolutely no relationship to the ptrace_do implemenation by emptymonkey. This crate is completely designed in Rust and not a crate providing a type safe rust api of the c ffi of emptymonkey's ptrace_do implementation. 

## Example
### Invoking Libc Getpid in a remote process

In this example we fork the current application, and spawn a child process to trace over.
This helps us avoid many security related restrictions which must be considered when using this library in practice. Definitely check out the yaui project to see about real security and access permission that must be considered when tracing external processes.
```rust
fn main() -> Result<()> {
    println!("parent: process with pid: {}", process::id());

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            anyhow::bail!("fork failed");
        } else if pid == 0 {
            // Child process - just sleep to allow tracing
            println!("child : process started with pid: {}", process::id());
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        } else {
            // Parent process - spawn a thread to trace the child
            println!("parent: forked child process spawned with pid: {}", pid);

            // Give the child a moment to start
            thread::sleep(Duration::from_millis(100));

            println!("parent: attaching to child process {}", pid);

            let traced_process = TracedProcess::attach(pid)?;
            println!("parent: successfully attached to the process");

            let frame = traced_process.next_frame()?;
            println!("parent: successfully waited for a frame");

            // Execute remote getpid in the child process
            let (regs, _frame) = frame.invoke_remote(libc::getpid as usize, 0, &[])?;
            println!("parent: successfully executed remote getpid");
            let traced_pid = regs.return_value() as pid_t;
            println!("parent: the return value (Traced Pid) was {}", traced_pid);

            // Clean up: kill the child process
            println!("parent: killing child process");
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
            println!("parent: child process terminated");
        }
    }

    Ok(())
}
```

example output
````
parent: process with pid: 26042
parent: forked child process spawned with pid: 26068
child : process started with pid: 26068
parent: attaching to child process 26068
parent: successfully attached to the process
parent: successfully waited for a frame
parent: successfully executed remote getpid
parent: the return value (Traced Pid) was 26068
parent: killing child process
parent: child process terminated
```
