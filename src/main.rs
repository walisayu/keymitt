//! keymitt — let AI agents use your secrets without ever seeing them.

mod approval;
mod audit;
mod backup;
mod cli;
mod config;
mod exec;
mod files;
mod http;
mod policy;
mod redact;
mod server;
mod template;
mod vault;

fn main() -> std::process::ExitCode {
    cli::main()
}
