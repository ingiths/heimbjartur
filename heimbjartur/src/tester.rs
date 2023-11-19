use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;

use aya::maps::Queue;
use aya::programs::KProbe;
use aya::Bpf;
use aya_log::BpfLogger;
use log::{debug, error, info, warn};
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::cli::{Tester, TesterMode};
use crate::skb::SKB_DROP_REASON;
use crate::tpacket::{TestPacket, TestPacketAnswer};
use crate::util::{self, parse_addr, parse_wildcard};

fn load_and_attach_kprobe<'a>(
    bpf: &'a mut Bpf,
    name: String,
) -> Result<&'a mut KProbe, anyhow::Error> {
    let program: &mut KProbe = bpf.program_mut(name.as_str()).unwrap().try_into()?;
    program.load()?;
    program.attach("kfree_skb_reason", 0)?;
    Ok(program)
}

fn test_single(test_packet: TestPacket) -> usize {
    let mut tx = util::init_channel();
    match tx.send_to(
        test_packet.as_packet().to_immutable(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    ) {
        Ok(n) => debug!("Sent {} bytes", n),
        Err(e) => debug!("Error sending packet: {}", e),
    }
    1
}

fn test_multiple(path: PathBuf) -> usize {
    let tests = util::parse_test_file(path);
    let mut tx = util::init_channel();
    let actual_destination = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let test_count = tests.len();

    let now = Instant::now();

    for test_packet in tests {
        tx.send_to(test_packet, actual_destination).ok();
    }

    println!("elapsed tmp {}", now.elapsed().as_millis());

    test_count
}

pub async fn start_testing(tester: Tester) -> Result<(), anyhow::Error> {
    let binary = tester.binary;
    let mut bpf = Bpf::load_file(binary.as_str())?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        eprintln!("failed to initialize eBPF logger: {}", e);
    }

    load_and_attach_kprobe(&mut bpf, tester.name)?;

    let mut packet_queue: Queue<_, TestPacketAnswer> =
        Queue::try_from(bpf.map_mut("PACKET_LIST").unwrap())?;

    let test_suite_count = match tester.mode {
        TesterMode::Single {
            src,
            dst,
            protocol,
            expect,
        } => {
            let protocol = match protocol.as_str() {
                "tcp" => IpNextHeaderProtocols::Tcp,
                "udp" => IpNextHeaderProtocols::Udp,
                &_ => unimplemented!(),
            };

            parse_addr(src.clone());

            let src = parse_addr(src);
            let dst = parse_addr(dst);
            let pairs: Vec<(SocketAddr, SocketAddr)> = src
                .iter()
                .flat_map(|&x1| dst.iter().map(move |&x2| (x1, x2)))
                .collect();

            let expect = match expect.to_lowercase().as_str() {
                "pass" => crate::PASS,
                "drop" => crate::DROP,
                _ => unreachable!(),
            };

            let test_packets = pairs
                .iter()
                .map(|x| TestPacket::new(x.0, x.1, protocol, expect))
                .collect::<Vec<TestPacket>>();
            let test_count = test_packets.len();

            let mut tx = util::init_channel();
            test_packets.into_iter().for_each(move |t| {
                match tx.send_to(
                    t.as_packet().to_immutable(),
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                ) {
                    Ok(n) => debug!("Sent {} bytes", n),
                    Err(e) => debug!("Error sending packet: {}", e),
                };
            });

            test_count
        }
        TesterMode::Multiple { file_name } => test_multiple(file_name),
    };

    let mut count = 0;

    println!("Evaluating {} tests", test_suite_count);

    let mut failures = Vec::new();

    let now = Instant::now();
    loop {
        if count == test_suite_count {
            break;
        }

        count += 1;

        if let Ok(packet) = packet_queue.pop(0) {
            debug!(
                "[{}/{}] {} {}",
                count, test_suite_count, packet, packet.expect
            );
            // Test failure if packet was dropped and pass was expected,
            if packet.drop_reason == SKB_DROP_REASON::SKB_DROP_REASON_NETFILTER_DROP.into()
                && packet.expect == crate::PASS
            {
                let skb_drop_reason = SKB_DROP_REASON::try_from(packet.drop_reason).unwrap();
                failures.push(format!(
                    "Test {} NOT OK: {}, expected PASS, got DROP ({:#?})",
                    count, packet, skb_drop_reason
                ));
            // Test failure if packet was allowed through and drop was expected,
            } else if packet.drop_reason != SKB_DROP_REASON::SKB_DROP_REASON_NETFILTER_DROP.into()
                && packet.expect == crate::DROP
            {
                let skb_drop_reason = SKB_DROP_REASON::try_from(packet.drop_reason).unwrap();
                failures.push(format!(
                    "Test {} NOT OK: {}, expected DROP, got PASS ({:#?})",
                    count, packet, skb_drop_reason
                ));
            }
        } else {
            if now.elapsed().as_secs() >= 10 {
                warn!("Not all tests were evaluated due to timeout!");
                break;
            }
        }
    }
    info!(
        "Evaluated {} tests in {} milliseconds",
        test_suite_count,
        now.elapsed().as_millis()
    );

    if failures.is_empty() {
        info!("All tests passed");
    } else {
        warn!(
            "Result: {}/{} tests passed",
            test_suite_count - failures.len(),
            test_suite_count
        );
    }

    failures.iter().for_each(|s| error!("{}", s));

    Ok(())
}
