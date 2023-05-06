use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{RawProcess, TracedProcess};

fn find_mod_map_fuzzy(mod_name: &str, pid: pid_t) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(pid).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p.to_str().map(|s| s.contains(mod_name)).unwrap_or(false),
        None => false,
    })
}

pub fn find_remote_procedure(
    mod_name: &str,
    remote_pid: pid_t,
    function_address: usize,
) -> Option<usize> {
    let remote_module = find_mod_map_fuzzy(mod_name, remote_pid)?;
    tracing::info!(
        "Identifed remote range {mod_name:?} ({:?}) at {:X?}",
        remote_module.filename(),
        remote_module.start()
    );
    let internal_module = find_mod_map_fuzzy(mod_name, std::process::id() as pid_t)?;
    tracing::info!(
        "Identifed internal range {mod_name:?} ({:?}) at {:X?}",
        internal_module.filename(),
        internal_module.start()
    );
    Some(function_address - internal_module.start() + remote_module.start())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let remote_pid: pid_t = 23803;

    let traced_process = TracedProcess::attach(RawProcess::new(remote_pid))?;
    tracing::info!("Successfully attached to the process");

    let libc_path = "libc.so.6";
    let getpid_remote_procedure =
        find_remote_procedure(libc_path, remote_pid, libc::getpid as usize).unwrap();
    tracing::info!("Found remote getpid procedure at : {getpid_remote_procedure:X?}");

    let frame = traced_process.next_frame()?;
    tracing::info!("Successfully waited for a frame");

    let (regs, _frame) = frame.invoke_remote(getpid_remote_procedure, 0, &[])?;
    tracing::info!("Successfully executed remote getpid");

    let traceed_pid = regs.return_value() as pid_t;
    tracing::info!("The return value (Traceed Pid) was {}", traceed_pid);

    Ok(())
}
