//! remote_link-service: LocalSystem service that keeps RemoteLink usable on the
//! login/UAC secure desktop. Subcommands: install | uninstall | run (SCM) | helper (internal).
mod protocol;
#[cfg(windows)]
mod service;

fn main() {
    #[cfg(windows)]
    std::process::exit(service::main());
    #[cfg(not(windows))]
    {
        eprintln!("remote_link-service is Windows-only");
        std::process::exit(1);
    }
}
