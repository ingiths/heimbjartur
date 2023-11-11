pub mod benchmark;
pub mod cli;
pub mod skb;
pub mod tester;
pub mod tpacket;
pub(crate) mod util;

pub const PASS: u8 = 1;
pub const DROP: u8 = 0;
