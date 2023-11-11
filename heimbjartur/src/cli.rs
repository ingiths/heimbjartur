use std::path::PathBuf;

use clap;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct CLI {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    Benchmark(BenchmarkConfig),
    Tester(Tester),
}

#[derive(Parser)]
pub struct BenchmarkConfig {
    #[clap(long = "file_name", required = true)]
    pub file_name: PathBuf,
}

#[derive(Parser)]
pub struct Tester {
    #[clap(short, long, default_value = "kprobe")]
    pub binary: String,
    #[clap(short, long, default_value = "kprobe_extract_skb_information")]
    pub name: String,
    #[command(subcommand)]
    pub mode: TesterMode,
}

#[derive(Subcommand)]
pub enum TesterMode {
    Single {
        #[clap(short, long = "src", value_name = "SRC", required = true, index = 1)]
        src: String,
        #[clap(short, long = "dst", value_name = "DST", required = true, index = 2)]
        dst: String,
        #[clap(short,
            long = "protocol", 
            required = true,
            value_parser=clap::builder::PossibleValuesParser::new(["tcp", "udp"]),
            index = 3
        )]
        protocol: String,
        #[clap(short,
            long = "expect", 
            required = true,
            value_parser=clap::builder::PossibleValuesParser::new(["pass", "drop"]),
            index = 4
        )]
        expect: String,
    },
    Multiple {
        #[clap(
            long = "file_name",
            value_name = "FILE_NAME",
            required = true,
            index = 1
        )]
        file_name: PathBuf,
    },
}
