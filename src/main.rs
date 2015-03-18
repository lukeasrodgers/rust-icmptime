extern crate getopts;
extern crate pnet;
extern crate time;

use getopts::Options;
use std::os;
use std::net::{IpAddr};
use std::str::FromStr;

use pnet::transport::TransportProtocol::{Ipv4};
use pnet::old_packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::{Layer3};
use pnet::transport::{transport_channel};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};


fn main() {
    let args: Vec<String> = os::args();
    let mut opts = Options::new();
    let matches = match opts.parse(args.tail()) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string())
    };
    let addr_arg = matches.free[0].as_slice();
    let addr: IpAddr = FromStr::from_str(addr_arg.as_slice()).unwrap();

    let protocol = Layer3(IpNextHeaderProtocols::Test1);
    let (mut icmp_sender, mut icmp_receiver) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel:
                        {}", e)
    };
    let packet = build_icmp_time_request_packet();
}

fn build_icmp_time_request_packet() -> IcmpRequestPacket {
    let ip_type = 14u8;
    let ip_code = 0u8;
    let ip_checksum = 0u16; // calculate; 16 bits
    let identifier = 0u16; // what should this be? used to match requests to replies; 16 bits
    let sequence = 0u16; // what should this be? used to match requests to replies;
    let originate_timestamp = 0u32; // get from systime
    let receive_timestamp = 0u32; // not used
    let transmit_timestamp = 0u32; // not used
    let mut packet = IcmpRequestPacket::new();
    packet
}

struct IcmpRequestPacket {
    ip_type: u8,
    ip_code: u8,
    ip_checksum: u16,
    identifier: u16,
    sequence: u16,
    originate_timestamp: u32,
    receive_timestamp: u32,
    transmit_timestamp: u32
}

impl IcmpRequestPacket {
    fn new() -> IcmpRequestPacket {
        let mut packet = IcmpRequestPacket {
            ip_type: 13,
            ip_code: 0,
            ip_checksum: 0,
            identifier: 0,
            sequence: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0
        };
        packet.set_originate_timestamp();
        packet.set_checksum();
        packet
    }

    fn calculate_checksum(&self) -> u16 {
        // implement me
        let mut vec: Vec<u16> = vec![];
        1
    }

    fn set_checksum(&mut self) {
        self.ip_checksum = self.calculate_checksum();
    }

    fn set_originate_timestamp(&mut self) {
        self.originate_timestamp = time_after_utc();
    }
}

fn time_after_utc() -> u32 {
    let t = time::now_utc();
    let s: i32 = t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec;
    s as u32
}
