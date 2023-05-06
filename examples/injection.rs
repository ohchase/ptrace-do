fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    // let opt = Opt::from_args();
    // tracing::info!("{:?}", opt);

    // let payload_location = std::fs::canonicalize(&opt.payload)?;
    // let payload_location = payload_location.to_str().expect("str");

    // let process = RawProcess {
    //     pid: opt.target_pid,
    // };

    // let libc_path = "/apex/com.android.runtime/lib64/bionic/libc.so";

    // // <= 23
    // let linker_path = "/apex/com.android.runtime/bin/linker64";

    // let libdl_path = "/apex/com.android.runtime/lib64/bionic/libdl.so";

    // let traced_process = TracedProcess::attach(process)?;
    // tracing::info!("Successfully attached to the process");

    // let mmap_remote_procedure = traced_process
    //     .find_remote_procedure(libc_path, libc::mmap as usize)?
    //     .expect("mmap remote");
    // tracing::info!("Identified remote mmap procedure at {mmap_remote_procedure:X?}");

    // let dlopen_remote_procedure = traced_process
    //     .find_remote_procedure(libdl_path, libc::dlopen as usize)?
    //     .expect("dlopen remote");
    // tracing::info!("Found remote dlopen procedure at : {dlopen_remote_procedure:X?}");

    // let libc_base_addr = traced_process
    //     .find_module_map(libc_path)?
    //     .expect("find libc base")
    //     .start();
    // tracing::info!("Identified libc base address for bionic namespace: {libc_base_addr:X?}");

    // let frame = traced_process.next_frame()?;
    // tracing::info!("Successfully waited for a frame");

    // let mmap_params: [usize; 6] = [
    //     0,
    //     0x3000,
    //     (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)
    //         .try_into()
    //         .unwrap(),
    //     (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE)
    //         .try_into()
    //         .unwrap(),
    //     0,
    //     0,
    // ];
    // let (regs, mut frame) =
    //     frame.invoke_remote(mmap_remote_procedure, libc_base_addr, &mmap_params)?;
    // tracing::info!("Successfully executed remote mmap function");
    // tracing::info!("The return value was {:X?}", regs.return_value());
    // let allocated_memory_addr = regs.return_value();

    // let payload_location = format!("{payload_location}\0");
    // let _memory = frame.write_memory(allocated_memory_addr, payload_location.as_bytes())?;
    // tracing::info!(
    //     "Successfully wrote payload {} to {:X?}",
    //     payload_location,
    //     regs.return_value()
    // );

    // let dlopen_params: [usize; 2] = [
    //     allocated_memory_addr,
    //     (libc::RTLD_NOW | libc::RTLD_GLOBAL).try_into().unwrap(),
    // ];
    // let (regs, _frame) =
    //     frame.invoke_remote(dlopen_remote_procedure, libc_base_addr, &dlopen_params)?;
    // tracing::info!("Successfully executed remote dlopen function");
    // tracing::info!("The return value was {:X?}", regs.return_value());

    // // drop frame
    // // drop tracer

    Ok(())
}
