//! Placeholder entry point so the workspace resolves.
//!
//! The simulator builder was interrupted before writing the real CLI; it owns
//! this file and will replace it with the scenario runner and the blind A/B
//! comparison subcommands.

fn main() {
    eprintln!("gdc-sim: CLI not implemented yet; the library is usable from tests.");
    std::process::exit(2);
}
