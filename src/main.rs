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
        // start at end of IP header packet
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

    fn start_of_icmp(&self) -> usize {
        self.get_header_length() as usize * 4
    }

    fn get_ip_type(&self) -> u8 {
        let start = self.start_of_icmp();
        self.packet()[start]
    }

    fn get_ip_code(&self) -> u8 {
        let start = self.start_of_icmp();
        self.packet()[start + 1]
    }

    fn get_ip_checksum(&self) -> u16 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 2] as u16) << 8;
        let b2 = (self.packet()[start + 3] as u16);
        b1 | b2
    }

    fn get_identifier(&self) -> u16 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 4] as u16) << 8;
        let b2 = (self.packet()[start + 5] as u16);
        b1 | b2
    }

    fn get_sequence(&self) -> u16 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 6] as u16) << 8;
        let b2 = (self.packet()[start + 7] as u16);
        b1 | b2
    }

    fn get_originate_timestamp(&self) -> u32 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 8] as u32) << 24;
        let b2 = (self.packet()[start + 9] as u32) << 16;
        let b3 = (self.packet()[start + 10] as u32) << 8;
        let b4 = (self.packet()[start + 11] as u32);
        b1 | b2 | b3 | b4
    }

    fn get_receive_timestamp(&self) -> u32 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 12] as u32) << 24;
        let b2 = (self.packet()[start + 13] as u32) << 16;
        let b3 = (self.packet()[start + 14] as u32) << 8;
        let b4 = (self.packet()[start + 15] as u32);
        b1 | b2 | b3 | b4
    }

    fn get_transmit_timestamp(&self) -> u32 {
        let start = self.start_of_icmp();
        let b1 = (self.packet()[start + 16] as u32) << 24;
        let b2 = (self.packet()[start + 17] as u32) << 16;
        let b3 = (self.packet()[start + 18] as u32) << 8;
        let b4 = (self.packet()[start + 19] as u32);
        b1 | b2 | b3 | b4
    }
}

pub struct IcmpRequestPacket<'p> {
    packet: &'p [u8]
}

pub struct MutIcmpRequestPacket<'p> {
    packet: &'p mut [u8]
}

// pretty much copy-pasted from pnet, not sure if inline directives are necessary
impl<'a> Packet for IcmpRequestPacket<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { &self.packet[20..] }
    // use of 20 here should be fine for our case, IHL is 5, no IP options in header
}

impl<'a> Packet for MutIcmpRequestPacket<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { &self.packet[20..] }
    // use of 20 here should be fine for our case, IHL is 5, no IP options in header
}


impl<'p> Ipv4Packet for IcmpRequestPacket<'p> {}
impl<'p> IcmpPacket for IcmpRequestPacket<'p> {}

impl<'p> Ipv4Packet for MutIcmpRequestPacket<'p> {}
impl<'p> IcmpPacket for MutIcmpRequestPacket<'p> {}

impl<'p> IcmpRequestPacket<'p> {
    fn new(packet_slice: &'p [u8]) -> IcmpRequestPacket {
        IcmpRequestPacket {
            packet: packet_slice
        }
    }
}

impl<'p> MutIcmpRequestPacket<'p> {
    fn new(packet_slice: &'p mut [u8]) -> MutIcmpRequestPacket {
        MutIcmpRequestPacket {
            packet: packet_slice
        }
    }

    fn set_checksum(&mut self) {
        let start = self.start_of_icmp();
        let checksum = self.calculate_icmp_checksum();
        self.packet[start + 2] = (checksum >> 8) as u8;
        self.packet[start + 3] = (checksum & 0xf) as u8;
    }

    fn set_originate_timestamp(&mut self) {
        let start = self.start_of_icmp();
        let time = time_after_utc();
        // dbl check this offset
        self.packet[start + 8] = (time >> 24) as u8;
        self.packet[start + 9] = ((time >> 16) & 0xf0) as u8;
        self.packet[start + 10] = ((time >> 8) & 0xff0) as u8;
        self.packet[start + 11] = time as u8;
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
