#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{LruHashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::{info, log};
use hackathon_ids_common::EventInfo;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[repr(C)]
#[derive(Debug)]
struct FlowKey {
    l4_proto: u8,
    _pad1: u8,
    _pad2: u16,
    ip_src: u32,
    ip_dst: u32,
    port_src: u16,
    port_dst: u16,
}

#[repr(C)]
#[derive(Debug)]
struct FlowInfo {
    num_packets: u64,
    last_packet_ts: u64,
    total_len: u64,
}

#[map(name = "FLOW_INFO_TABLE")]
static mut FLOW_INFO_TABLE: LruHashMap<FlowKey, FlowInfo> =
    LruHashMap::<FlowKey, FlowInfo>::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

use core::mem;
// utility to get access to packet offset
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn hackathon_ids(ctx: XdpContext) -> u32 {
    match try_hackathon_ids(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_hackathon_ids(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    let ts = unsafe { bpf_ktime_get_ns() };

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        EtherType::Ipv6 => {
            info!(&ctx, "IPV6");
            return Ok(xdp_action::XDP_PASS);
        }
        EtherType::Loop => {
            info!(&ctx, "Loop");
            return Ok(xdp_action::XDP_PASS);
        }
        EtherType::FibreChannel => {
            info!(&ctx, "fibre");
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            info!(&ctx, "other");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };
    let iplen = unsafe { (*ipv4hdr).tot_len };

    let (source_port, dest_port) = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(()),
    };

    let key = FlowKey {
        l4_proto: proto as u8,
        _pad1: 0,
        _pad2: 0,
        ip_src: source_addr,
        ip_dst: dest_addr,
        port_src: source_port,
        port_dst: dest_port,
    };

    let reversed_key = FlowKey {
        l4_proto: proto as u8,
        _pad1: 0,
        _pad2: 0,
        ip_src: dest_addr,
        ip_dst: source_addr,
        port_src: dest_port,
        port_dst: source_port,
    };

    if let Some(data_ptr) = unsafe {
        FLOW_INFO_TABLE
            .get_ptr_mut(&key)
            .or_else(|| FLOW_INFO_TABLE.get_ptr_mut(&reversed_key))
    } {
        let total_packets = unsafe { (*data_ptr).num_packets + 1 };
        let total_len = unsafe { (*data_ptr).total_len + iplen as u64 };
        let delta = unsafe { ts - (*data_ptr).last_packet_ts };
        unsafe {
            (*data_ptr).num_packets = total_packets;
            (*data_ptr).last_packet_ts = ts;
            (*data_ptr).total_len = total_len;
        }

        info!(
            &ctx,
            "inc flow {} {}:{} -> {}:{} packets number {} delta: {} total: {}",
            proto as u8,
            source_addr,
            source_port,
            dest_addr,
            dest_port,
            total_packets,
            delta,
            total_len
        );

        if let Some(mut buf) = EVENTS.reserve::<EventInfo>(0) {
            unsafe {
                let info = buf.as_mut_ptr();
                (*info).num_packets = total_packets;
                (*info).total_len = total_len;
            };

            buf.submit(0);
        }

    } else {
        let data = FlowInfo {
            num_packets: 0,
            last_packet_ts: ts,
            total_len: 0,
        };

        unsafe {
            FLOW_INFO_TABLE
                .insert(&key, &data, 0)
                .expect("Error inserting flow info");
        }

        info!(
            &ctx,
            "new flow {} {}:{} -> {}:{}",
            proto as u8,
            source_addr,
            source_port,
            dest_addr,
            dest_port
        );

        
    }

    //
    /*
    info!(&ctx, " {} {:i}:{} -> {:i}:{}", match proto {
        IpProto::Tcp => "TCP",
        IpProto::Udp => "UDP",
        _ => "Other",
    } , source_addr, source_port, dest_addr, dest_port);

    if let Some(mut buf) = EVENTS.reserve::<PacketInfo>(0) {
        unsafe {
            let pkt_info = buf.as_mut_ptr();
            (*pkt_info).ip_dst = dest_addr;
            (*pkt_info).ip_src = source_addr;
            (*pkt_info).port_dst = dest_port;
            (*pkt_info).port_src = source_port;
            (*pkt_info).proto = proto as u8;
         };

        buf.submit(0);
    }
    */

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
