use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::transport::{transport_channel, TransportSender};

use crate::tpacket::TestPacket;

pub fn init_channel() -> TransportSender {
    let protocol = pnet::transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Test1);
    let (tx, _) = match transport_channel(128, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };
    tx
}

pub fn parse_addr<T: Into<String>>(socket_addr: T) -> Vec<SocketAddr> {
    let socket_addr = socket_addr.into();

    let (address, port): (&str, u16) = if socket_addr.contains(":") {
        let parts = socket_addr.split(":").collect::<Vec<_>>();
        (parts[0], parts[1].parse().unwrap())
    } else {
        (socket_addr.as_str(), rand::random::<u16>())
    };

    let mut parts = address.split(".");

    let a = match parts.next() {
        Some(x) => {
            if x == "*" {
                (1..255).map(move |x| x.to_string()).collect()
            } else {
                vec![x.to_string()]
            }
        }
        None => panic!("Oh no"),
    };
    let b = match parts.next() {
        Some(x) => {
            if x == "*" {
                (1..255).map(move |x| x.to_string()).collect()
            } else {
                vec![x.to_string()]
            }
        }
        None => panic!("Oh no"),
    };
    let c = match parts.next() {
        Some(x) => {
            if x == "*" {
                (1..255).map(move |x| x.to_string()).collect()
            } else {
                vec![x.to_string()]
            }
        }
        None => panic!("Oh no"),
    };
    let d = match parts.next() {
        Some(x) => {
            if x == "*" {
                (1..255).map(move |x| x.to_string()).collect()
            } else {
                vec![x.to_string()]
            }
        }
        None => panic!("Oh no"),
    };

    let mut combinations = Vec::new();
    for x1 in a {
        for x2 in b.clone() {
            for x3 in c.clone() {
                for x4 in d.clone() {
                    combinations.push(
                        format!("{}.{}.{}.{}:{}", x1, x2, x3, x4, port)
                            .parse()
                            .unwrap(),
                    )
                }
            }
        }
    }

    combinations
}

pub fn parse_socket_address_with_fallback<T: Into<String>>(
    addr: T,
) -> Result<SocketAddr, anyhow::Error> {
    let addr = addr.into();
    match addr.parse() {
        Ok(addr) => Ok(addr),
        Err(_) => Ok(format!("{}:{}", addr, rand::random::<u16>()).parse()?),
    }
}

pub fn parse_test_file(path: PathBuf) -> Vec<MutableIpv4Packet<'static>> {
    let mut tests = Vec::new();
    for line in fs::read_to_string(path).unwrap().lines() {
        let line = line.to_string();
        let parts = line.split(' ').collect::<Vec<&str>>();
        let src = parse_socket_address_with_fallback(parts[0])
            .expect(format!("Failed to parse test suite ({})", parts[0]).as_str());
        let dst = parse_socket_address_with_fallback(parts[1])
            .expect(format!("Failed to parse test suite ({})", parts[1]).as_str());
        let proto = match parts[2].to_lowercase().as_str() {
            "tcp" => IpNextHeaderProtocols::Tcp,
            "udp" => IpNextHeaderProtocols::Udp,
            _ => unimplemented!(),
        };
        let expected_result = match parts[3].to_lowercase().as_str() {
            "pass" => crate::PASS,
            "drop" => crate::DROP,
            _ => unimplemented!(),
        };

        tests.push(TestPacket::new(src, dst, proto, expected_result).as_packet())
    }

    tests
}
