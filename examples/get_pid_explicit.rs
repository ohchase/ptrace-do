/// Example of getting pid of process by simply specifying the pid
use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{ProcessIdentifier, RawProcess, TracedProcess};

/// Just searches the proc maps for a module ending with the provided mod_name
fn find_mod_map_fuzzy(mod_name: &str, pid: pid_t) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(pid).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p.to_str().map(|s| s.contains(mod_name)).unwrap_or(false),
        None => false,
    })
}

/// This `finds` the remote procedure's virtual offsets.
/// This checks for the target library in our own process and sees how far into the lib the function was mapped for us.
/// We can then apply this offset to the traced process's mapping of the same library.
/// Thus we end up at the target process's function
fn find_remote_procedure<P: ProcessIdentifier>(
    mod_name: &str,
    owned_process: &P,
    remote_process: &TracedProcess<P>,
    function_address: usize,
) -> Option<usize> {
    let internal_module = find_mod_map_fuzzy(mod_name, owned_process.pid())?;
    tracing::info!(
        "Identifed internal range {mod_name:?} ({:?}) at {:X?}",
        internal_module.filename(),
        internal_module.start()
    );

    let remote_module = find_mod_map_fuzzy(mod_name, remote_process.pid())?;
    tracing::info!(
        "Identifed remote range {mod_name:?} ({:?}) at {:X?}",
        remote_module.filename(),
        remote_module.start()
    );

    Some(function_address - internal_module.start() + remote_module.start())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // start your target process and figure out its pid.
    // ps -A | grep my_cool_bin .... etc
    let target_pid: pid_t = 7777;
    let traced_process = TracedProcess::attach(RawProcess::new(target_pid))?;

    tracing::info!("Successfully attached to the process");

    let libc_path = "libc";
    let getpid_remote_procedure = find_remote_procedure(
        libc_path,
        &RawProcess::new(std::process::id() as pid_t),
        &traced_process,
        libc::getpid as usize,
    )
    .unwrap();
    tracing::info!("Found remote getpid procedure at : {getpid_remote_procedure:X?}");

    let frame = traced_process.next_frame()?;
    tracing::info!("Successfully waited for a frame");

    let (regs, _frame) = frame.invoke_remote(getpid_remote_procedure, 0, &[])?;
    tracing::info!("Successfully executed remote getpid");

    let traceed_pid = regs.return_value() as pid_t;
    tracing::info!("The return value (Traceed Pid) was {}", traceed_pid);

    Ok(())
}
