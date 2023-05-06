/// Example of invoking getpid in a remote `OwnedProcess` versus a raw one
/// An owned process wraps a child and kills it when the traceer is dropped.
use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{OwnedProcess, ProcessIdentifier, RawProcess, TracedProcess};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let mut executable_path = std::env::current_exe()?;
    executable_path.pop();
    executable_path.push("sample_application");

    tracing::info!("Executable path is: {:?}", executable_path);
    let process = OwnedProcess::from(
        std::process::Command::new(executable_path)
            .spawn()
            .expect("spawn"),
    );

    std::thread::sleep(std::time::Duration::from_secs(2));
    tracing::info!("Spawned process and waited a little.");

    let traced_process = TracedProcess::attach(process)?;

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
