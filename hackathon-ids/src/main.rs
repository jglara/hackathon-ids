
use std::collections::HashSet;
use std::net::Ipv4Addr;
use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use hackathon_ids_common::EventInfo;
use log::{debug, info, warn};
use ml::data::IDSItem;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;


use burn::backend::NdArray;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hackathon-ids"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hackathon-ids"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("hackathon_ids").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let (tx, mut rx) = mpsc::channel(1024);

    let cancel_i = CancellationToken::new();
    let cancel_task_1 = cancel_i.clone();
    let cancel_task_2 = cancel_i.clone();

    let task_1 = tokio::spawn(async move {
        let events: RingBuf<_> = bpf.take_map("EVENTS").unwrap().try_into().unwrap();

        let mut events_fd = AsyncFd::new(events).unwrap();

        loop {
            tokio::select! {
                _ = cancel_task_1.cancelled() => {
                    break;
                }
                Ok(mut guard) = events_fd.readable_mut() => {
                    let events = guard.get_inner_mut();

                    while let Some(ring_event) = events.next() {
                        // process the event


                        let ptr = ring_event.as_ptr() as *const EventInfo;
                        let info = unsafe { ptr.read_unaligned() };

                        debug!("Received some event! {:?}", info);
                        tx.send(info).await.unwrap();
                    }
                }
            }
        }
    });

    let task_2 = tokio::spawn(async move {
        type MyBackend = NdArray;
        //type MyAutodiffBackend = Autodiff<MyBackend>;

        let device = burn::backend::ndarray::NdArrayDevice::default();
        let artifact_dir = "./ml/guide.lock";

        let mut attacks: HashSet<u32> =  HashSet::new();

        /*let info = rx.recv().await.unwrap();
        info.*/
        
        

        loop {
            tokio::select! {
              _ = cancel_task_2.cancelled() => {
                  break;
              }
              Some(info) = rx.recv() => {
                if attacks.get(&info.ip_src).is_none() { // is not blocked already
                  
                  let total_len = info.total_len as f32;
                  let total_iat = info.total_iat as f32;
                  let num_pkts = info.num_packets as f32;
                  let len_mean = total_len / num_pkts;

                  let item= IDSItem {
                    dst_port: info.port_dst,
                    total_length_bwd_packet: total_len,
                    bwd_iat_total: total_iat,
                    bwd_iat_mean: total_iat / num_pkts,
                    bwd_packet_length_mean: len_mean,
                    bwd_packet_length_std: (info.len as f32 - len_mean).abs() / num_pkts,
                    label: "".to_string() };

                  debug!("Received {item:?}");
                  let output = ml::inference::infer::<MyBackend>(artifact_dir, device, item);
                  if output == 1 {
                    info!("Detected an attack from {}:{} to {}:{} ", Ipv4Addr::from(info.ip_src), info.port_src, Ipv4Addr::from(info.ip_dst), info.port_dst);
                    attacks.insert(info.ip_src);
                    
                  }
                }
              }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    cancel_i.cancel();

    info!("Exiting...");
    task_1.await?;
    task_2.await?;

    Ok(())
}
