use core::net;

use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use hackathon_ids_common::EventInfo;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use burn::tensor::Tensor;
use burn::backend::Wgpu;

// Type alias for the backend to use.
type Backend = Wgpu;

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
    program.attach(&opt.iface, XdpFlags::default())
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
                        /*
                        let (head, body, _tail) = unsafe { ring_event.align_to::<PacketInfo>() };
                        assert!(head.is_empty(), "Data was not aligned");
                        let pkt_info = &body[0];
                        */
        
                        let ptr = ring_event.as_ptr() as *const EventInfo;
                        let info = unsafe { ptr.read_unaligned() };
        
                        info!("Received some event! {:?}", info);
                        tx.send(info).await.unwrap();
                    }        
                }
            }
            /* 
            let mut guard = events_fd.readable_mut().await.unwrap();
            let events = guard.get_inner_mut();

            while let Some(ring_event) = events.next() {
                // process the event
                /*
                let (head, body, _tail) = unsafe { ring_event.align_to::<PacketInfo>() };
                assert!(head.is_empty(), "Data was not aligned");
                let pkt_info = &body[0];
                */

                let ptr = ring_event.as_ptr() as *const EventInfo;
                let info = unsafe { ptr.read_unaligned() };

                info!("Received some event! {:?}", info);
            }*/
        }
    });

    let task_2 = tokio::spawn(async move {
        loop { 
          tokio::select! {
            _ = cancel_task_2.cancelled() => {
                break;
            }
            Some(info) = rx.recv() => {

                let device = Default::default();
                // Creation of two tensors, the first with explicit values and the second one with ones, with the same shape as the first
                let tensor_1 = Tensor::<Backend, 2>::from_data([[2., 3.], [4., 5.]], &device);
                let tensor_2 = Tensor::<Backend, 2>::ones_like(&tensor_1);
        

                info!("Processing event {:?} {} ", info, tensor_1+tensor_2);
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
