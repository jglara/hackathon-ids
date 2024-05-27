#![no_std]



#[derive(Debug)]
#[repr(C)]
pub struct EventInfo {
    pub num_packets: u64,
    pub total_len: u64,
}
