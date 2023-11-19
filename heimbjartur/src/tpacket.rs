use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aya::Pod;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;

const TCP_HEADER_LENGTH: usize = 20;
const UDP_HEADER_LENGTH: usize = 8;
// The IPv4 header is variable in size due to the optional 14th field (options).
// The IHL field contains the size of the IPv4 header; it has 4 bits that specify the number of 32-bit words in the header.
// The minimum value for this field is 5,[32] which indicates a length of 5 × 32 bits = 160 bits = 20 bytes.
const IP_HEADER_LENGTH: usize = 5;

#[derive(Clone, Debug)]
pub struct TestPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub proto: IpNextHeaderProtocol,
    // Expect either crate::PASS or crate::DROP
    pub expect: u8,
}

impl TestPacket {
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        proto: IpNextHeaderProtocol,
        expect: u8,
    ) -> TestPacket {
        TestPacket {
            src,
            dst,
            proto,
            expect,
        }
    }

    pub fn as_packet(self) -> MutableIpv4Packet<'static> {
        let source = match self.src.ip() {
            IpAddr::V4(ip) => ip,
            _ => unimplemented!(),
        };

        let dest = match self.dst.ip() {
            IpAddr::V4(ip) => ip,
            _ => unimplemented!(),
        };

        let payload = &[self.expect as u8; 1];

        let (packet, length): (Box<dyn Packet>, usize) = match self.proto {
            IpNextHeaderProtocols::Tcp => (
                Box::new(self.create_tcp_packet(source, dest, payload)),
                TCP_HEADER_LENGTH + 1,
            ),
            IpNextHeaderProtocols::Udp => (
                Box::new(self.create_udp_packet(payload)),
                UDP_HEADER_LENGTH + 1,
            ),
            _ => unimplemented!(),
        };

        // IP_LENGTH + <TCP_LENGTH | UDP_LENGTH> + <EXPECT>
        let ip_data = vec![0_u8; IP_HEADER_LENGTH * 4 + length + 1];
        let mut ip_packet = MutableIpv4Packet::owned(ip_data).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(IP_HEADER_LENGTH as u8);
        ip_packet.set_dscp(3);
        ip_packet.set_ecn(0);
        ip_packet.set_ttl(0);
        ip_packet.set_total_length((IP_HEADER_LENGTH * 4 + length) as u16);
        ip_packet.set_next_level_protocol(self.proto);
        ip_packet.set_destination(dest);
        ip_packet.set_source(source);
        ip_packet.set_payload(packet.packet());

        ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));

        ip_packet
    }

    fn create_tcp_packet(
        &self,
        source: Ipv4Addr,
        dest: Ipv4Addr,
        payload: &[u8],
    ) -> MutableTcpPacket {
        // The length of the data section is not specified in the segment header;
        // it can be calculated by subtracting the combined length of
        // the segment header and IP header from the total IP datagram length specified in the IP header.
        let tcp_data = vec![0_u8; TCP_HEADER_LENGTH + 1];
        let mut tcp_packet = MutableTcpPacket::owned(tcp_data).unwrap();
        tcp_packet.set_source(self.src.port());
        tcp_packet.set_destination(self.dst.port());
        tcp_packet.set_sequence(0);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset((TCP_HEADER_LENGTH / 4) as u8);
        tcp_packet.set_reserved(0);
        tcp_packet.set_flags(0b1111_1111);
        tcp_packet.set_window(1);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_payload(&payload);
        tcp_packet.set_checksum(ipv4_checksum(&tcp_packet.to_immutable(), &source, &dest));
        tcp_packet
    }

    fn create_udp_packet(&self, payload: &[u8]) -> MutableUdpPacket {
        let udp_data = vec![0_u8; UDP_HEADER_LENGTH + 1];
        let mut udp_packet = MutableUdpPacket::owned(udp_data).unwrap();
        udp_packet.set_source(self.src.port());
        udp_packet.set_destination(self.dst.port());
        udp_packet.set_length(UDP_HEADER_LENGTH as u16);
        // Optional checksum field
        udp_packet.set_checksum(0);
        udp_packet.set_payload(&payload);
        udp_packet
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TestPacketAnswer {
    pub src_addr: u32,
    pub src_port: u16,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub drop_reason: u8,
    pub expect: u8,
}

unsafe impl Pod for TestPacketAnswer {}

impl fmt::Display for TestPacketAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol_str = match self.protocol {
            6 => "TCP",
            17 => "UDP",
            _ => unimplemented!(),
        };

        let expect_str = match self.expect {
            crate::PASS => "PASS",
            crate::DROP => "DROP",
            _ => unimplemented!(),
        };
        write!(
            f,
            "[{}:{} -> {}:{} {} {}]",
            Ipv4Addr::from(self.src_addr),
            self.src_port,
            Ipv4Addr::from(self.dst_addr),
            self.dst_port,
            protocol_str,
            expect_str
        )
    }
}
