use clap::Parser;
use talk_ctl::{Cli, run};

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("talkctl: {e}");
        std::process::exit(1);
    }
}
