#![no_std]
#![no_main]
#![allow(warnings)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings_generated;

use aya_bpf::macros::map;
use aya_bpf::maps::Queue;
use aya_bpf::{helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext};
use aya_bpf_bindings::bindings;
use aya_log_ebpf::{debug, error, info, warn};

const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;

// TODO: Batch mode?
// Million entries
#[map]
static PACKET_LIST: Queue<TestPacketAnswer> = Queue::with_max_entries(1024 * 1024 * 10, 0);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TestPacketAnswer {
    pub src_addr: u32,
    pub src_port: u16,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub drop_reason: u8,
    pub pass_through: u8,
}

#[inline]
fn read_pointer_value<T>(offset: usize) -> Option<T> {
    match unsafe { bpf_probe_read_kernel(offset as *const T) } {
        Ok(value) => Some(value),
        Err(e) => None,
    }
}

fn check_for_test_packet(ctx: ProbeContext) -> Result<(), i64> {
    let reason: u8 = ctx.arg(1).or(Some(255u8)).unwrap();

    let skb_pointer: *const bindings_generated::sk_buff = match ctx.arg(0) {
        Some(pointer) => pointer,
        None => return Ok(()),
    };

    if skb_pointer.is_null() {
        return Ok(());
    }

    let skb: bindings_generated::sk_buff = read_pointer_value(skb_pointer as usize).ok_or(1)?;

    if skb.head as usize == skb.data as usize {
        return Ok(());
    }

    let skb_head_value = skb.head as usize;

    let protocol = unsafe { skb.__bindgen_anon_5.__bindgen_anon_1.as_ref().protocol };
    let transport_header = unsafe {
        skb.__bindgen_anon_5
            .__bindgen_anon_1
            .as_ref()
            .transport_header
    };
    let network_header = unsafe {
        skb.__bindgen_anon_5
            .__bindgen_anon_1
            .as_ref()
            .network_header
    };
    let mac_header = unsafe { skb.__bindgen_anon_5.__bindgen_anon_1.as_ref().mac_header };

    let iphdr: bindings_generated::iphdr =
        read_pointer_value(skb_head_value + network_header as usize).ok_or(0)?;

    if iphdr.version() != 4 {
        return Ok(());
    }

    let saddr = unsafe { iphdr.__bindgen_anon_1.__bindgen_anon_1.saddr };
    let daddr = unsafe { iphdr.__bindgen_anon_1.__bindgen_anon_1.daddr };

    if iphdr.tos >> 2 == 3 {
        // A test packet has been found
        if iphdr.protocol == TCP_PROTOCOL {
            let tcphdr: bindings_generated::tcphdr =
                read_pointer_value(skb_head_value + transport_header as usize).ok_or(0)?;
            let pass_through: u8 =
                read_pointer_value(skb_head_value + transport_header as usize + 20).ok_or(0)?;
            let p = TestPacketAnswer {
                src_addr: saddr.to_be(),
                src_port: tcphdr.source.to_be(),
                dst_addr: daddr.to_be(),
                dst_port: tcphdr.dest.to_be(),
                protocol: TCP_PROTOCOL,
                drop_reason: reason,
                pass_through,
            };
            PACKET_LIST.push(&p, 0)?;
        } else if iphdr.protocol == UDP_PROTOCOL {
            let udphdr: bindings_generated::udphdr =
                read_pointer_value(skb_head_value + transport_header as usize).ok_or(0)?;
            let pass_through: u8 =
                read_pointer_value(skb_head_value + transport_header as usize + 8).ok_or(0)?;
            let p = TestPacketAnswer {
                src_addr: saddr.to_be(),
                src_port: udphdr.source.to_be(),
                dst_addr: daddr.to_be(),
                dst_port: udphdr.dest.to_be(),
                protocol: UDP_PROTOCOL,
                drop_reason: reason,
                pass_through,
            };
            PACKET_LIST.push(&p, 0)?;
        }
    }
    Ok(())
}

#[kprobe]
pub fn kprobe_extract_skb_information(ctx: ProbeContext) -> u32 {
    check_for_test_packet(ctx);
    // Always return 0, no matter what happens when parsing
    0
}

#[kprobe]
pub fn debug_no_extract(ctx: ProbeContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
