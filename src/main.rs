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
use pnet::old_packet::{Packet};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};


fn main() {
    let args: Vec<String> = os::args();
    let mut opts = Options::new();
    let matches = match opts.parse(args.tail()) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string())
    };
    match matches.free.len() {
        0 => panic!("must provide ip address"),
        _ => {}
    }
    let addr_arg = matches.free[0].as_slice();
    let addr: IpAddr = FromStr::from_str(addr_arg.as_slice()).unwrap();

    let protocol = Layer3(IpNextHeaderProtocols::Test1);
    let (mut icmp_sender, mut icmp_receiver) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel:
                        {}", e)
    };
    let packet_vec: Vec<u8> = vec![];
    let packet = build_icmp_time_request_packet(packet_vec.as_slice());
}

fn build_icmp_time_request_packet<'p>(packet_slice: &'p [u8]) -> IcmpRequestPacket<'p> {
    let mut packet = IcmpRequestPacket::new(packet_slice);
    packet
}

pub trait IcmpPacket : Ipv4Packet {
    fn calculate_icmp_checksum(&self) -> u16 {
        let start_offset = self.get_header_length() as usize * 4;
        let chunked: Vec<u16> = self.packet().slice_from(start_offset).
            chunks(2).
            map(|x| x.iter().fold(0u16, |sum, y|
                                  if sum == 0 {
                                      sum + (*y as u16) << 4
                                  }
                                  else {
                                      sum + *y as u16
                                  }
                                 )).collect();
        ones_complement_sum(chunked.as_slice())
    }
}

struct IcmpRequestPacket<'p> {
    ip_type: u8,
    ip_code: u8,
    ip_checksum: u16,
    identifier: u16,
    sequence: u16,
    originate_timestamp: u32,
    receive_timestamp: u32,
    transmit_timestamp: u32,
    packet: &'p [u8]
}

// pretty much copy-pasted from pnet, not sure if inline directives are necessary
impl<'a> Packet for IcmpRequestPacket<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { &self.packet[20..] }
    // use of 20 here should be fine for our case, IHL is 5, no IP options in header
}


impl<'p> Ipv4Packet for IcmpRequestPacket<'p> {}

impl<'p> IcmpRequestPacket<'p> {
    fn new(packet_slice: &'p [u8]) -> IcmpRequestPacket {
        let mut packet = IcmpRequestPacket {
            ip_type: 13,
            ip_code: 0,
            ip_checksum: 0,
            identifier: 0,
            sequence: 0,
            originate_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
            packet: packet_slice
        };
        packet.set_originate_timestamp();
        // note we actually want to do this just before sending, not yet
        packet.set_checksum();
        packet
    }

    fn calculate_checksum(&self) -> u16 {
        // implement me
        let mut vec: Vec<u16> = vec![];
        vec.push((self.ip_type + self.ip_code) as u16);
        vec.push(self.ip_checksum);
        vec.push(self.identifier);
        vec.push(self.sequence);
        vec.push((self.originate_timestamp >> 16) as u16);
        vec.push(self.originate_timestamp as u16);
        vec.push((self.receive_timestamp >> 16) as u16);
        vec.push(self.receive_timestamp as u16);
        vec.push((self.transmit_timestamp >> 16) as u16);
        vec.push(self.transmit_timestamp as u16);
        ones_complement_sum(vec.as_slice())
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

fn ones_complement_sum(sl: &[u16]) -> u16 {
    let sum = sl.iter().fold(0u32, |sum, x| sum + (*x as u32));
    65535 - (sum as u16) - (sum >> 16) as u16
}

mod tests {
    use super::ones_complement_sum;

    // examples for ones complement sum taken from web
    #[test]
    fn test_ones_complement_sum() {
        let mut vec: Vec<u16> = vec![];
        vec.push(0x4500);
        vec.push(0x003c);
        vec.push(0x1c46);
        vec.push(0x4000);
        vec.push(0x4006);
        vec.push(0x0000);
        vec.push(0xac10);
        vec.push(0x0a63);
        vec.push(0xac10);
        vec.push(0x0a0c);
        let r = vec.as_slice();
        assert_eq!(ones_complement_sum(r), 0xB1E6);
    }

    #[test]
    fn another_test_ones_complement_sum() {
        let mut vec: Vec<u16> = vec![];
        vec.push(0x0800);
        vec.push(0x0000);
        vec.push(0x0001);
        vec.push(0x1008);
        vec.push(0x6162);
        vec.push(0x6364);
        vec.push(0x6566);
        vec.push(0x6768);
        vec.push(0x696a);
        vec.push(0x6b6c);
        vec.push(0x6d6e);
        vec.push(0x6f70);
        vec.push(0x7172);
        vec.push(0x7374);
        vec.push(0x7576);
        vec.push(0x7761);
        vec.push(0x6263);
        vec.push(0x6465);
        vec.push(0x6667);
        vec.push(0x6869);
        let r = vec.as_slice();
        assert_eq!(ones_complement_sum(r), 15699);
    }
}
