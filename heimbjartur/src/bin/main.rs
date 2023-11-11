use clap::Parser;

use heimbjartur::benchmark;
use heimbjartur::cli::{Mode, CLI};
use heimbjartur::tester;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = CLI::parse();
    
    match std::env::var("RUST_LOG") {
        Err(_) => std::env::set_var("RUST_LOG", "info"),
        _ => {}
    };

    env_logger::init();

    match cli.mode {
        Mode::Benchmark(benchmark_config) => benchmark::start_benchmark(benchmark_config.file_name),
        Mode::Tester(tester) => tester::start_testing(tester).await?,
    }

    Ok(())
}
