use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{ProcessIdentifier, RawProcess, TracedProcess};

fn find_mod_map_fuzzy(mod_name: &str, process: &impl ProcessIdentifier) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process.pid()).expect("able to access proc maps");
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
    println!(
        "Identifed internal range {mod_name:?} ({:?}) at {:X?}",
        internal_module.filename(),
        internal_module.start()
    );

    let remote_module = find_mod_map_fuzzy(mod_name, remote_process)?;
    println!(
        "Identifed remote range {mod_name:?} ({:?}) at {:X?}",
        remote_module.filename(),
        remote_module.start()
    );

    Some(function_address - internal_module.start() + remote_module.start())
}

fn main() {
    let target_pid: pid_t = 7777;
    let traced_process = TracedProcess::attach(RawProcess::new(target_pid))
        .expect("active process running with desired pid");

    println!("Successfully attached to the process");
    let libc_path = "libc";
    let getpid_remote_procedure = find_remote_procedure(
        libc_path,
        &RawProcess::new(std::process::id() as pid_t),
        &traced_process,
        libc::getpid as usize,
    )
    .expect("active process links libc::getpid");
    println!("Found remote getpid procedure at: {getpid_remote_procedure:X?}");

    let frame = traced_process
        .next_frame()
        .expect("able to wait for a process frame");
    println!("Successfully waited for a frame");

    // we do not need the frame any further after this, but if you wanted to do more function calls you would hold on to the frame for further execution.
    let (regs, _frame) = frame
        .invoke_remote(getpid_remote_procedure, 0, &[])
        .expect("able to execute getpid");
    println!("Successfully executed remote getpid");

    let traceed_pid = regs.return_value() as pid_t;
    println!("The return value (Traceed Pid) was {traceed_pid}");

    // we didn't hold on to the frame any further, but you could for instance recall getpid again here or chroot, etc...
}
