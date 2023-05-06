fn main() {
    println!("Hello my pid is: {}", unsafe { libc::getpid() });

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        println!("Tick.");
    }
}
