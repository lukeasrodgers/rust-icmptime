extern crate pnet;

use pnet::old_packet::{Packet};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};

use util;

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
        util::ones_complement_sum(chunked.as_slice())
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
    pub fn new(packet_slice: &'p [u8]) -> IcmpRequestPacket {
        IcmpRequestPacket {
            packet: packet_slice
        }
    }
}

impl<'p> MutIcmpRequestPacket<'p> {
    pub fn new(packet_slice: &'p mut [u8]) -> MutIcmpRequestPacket {
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
        let time = util::seconds_after_utc();
        // dbl check this offset
        self.packet[start + 8] = (time >> 24) as u8;
        self.packet[start + 9] = ((time >> 16) & 0xf0) as u8;
        self.packet[start + 10] = ((time >> 8) & 0xff0) as u8;
        self.packet[start + 11] = time as u8;
    }
}
