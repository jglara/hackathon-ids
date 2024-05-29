#![no_std]



#[derive(Debug)]
#[repr(C)]
pub struct EventInfo {
    pub ip_src: u32,
    pub ip_dst: u32,
    pub port_src: u16,
    pub port_dst: u16,
    
    pub num_packets: u64,
    pub len: u64, 
    pub total_len: u64,
    pub iat: u64,
    pub total_iat: u64,
}
