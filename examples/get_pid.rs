use anyhow::Result;
use libc::pid_t;
use ptrace_do::TracedProcess;
use std::process;
use std::thread;
use std::time::Duration;

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
