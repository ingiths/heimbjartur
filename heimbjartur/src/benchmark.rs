use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Instant;

use crate::util;

pub fn start_benchmark(path: PathBuf) {
    let tests = util::parse_test_file(path);
    println!("Sending {} test packets", tests.len());
    let mut tx = util::init_channel();
    let actual_destination = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let now = Instant::now();

    for test_packet in tests {
        tx.send_to(test_packet, actual_destination).ok();
    }

    println!("Time elapsed: {}", now.elapsed().as_millis());
}
