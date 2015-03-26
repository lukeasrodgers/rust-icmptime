extern crate pnet;

use std::old_io::net::ip::{IpAddr, Ipv4Addr};
use pnet::old_packet::{Packet};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};
use pnet::old_packet::ip::{IpNextHeaderProtocol,IpNextHeaderProtocols};

use util;

pub trait IcmpPacket : Ipv4Packet {
    fn calculate_icmp_checksum(&self) -> u16 {
        // start at end of IP header packet
        let start_offset = self.start_of_icmp();
        util::ones_complement_sum(self.packet().slice_from(start_offset))
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

    pub fn allocation_size() -> usize {
        // 20 for IP header, 8 for ICMP header, 12 for ICMP data
        20 + 8 + 12
    }

    pub fn prepare_for_sending(&mut self, dest_addr: &IpAddr, src_addr: &IpAddr) {
        self.set_version(4);
        self.set_header_length(5);
        self.set_dscp(0);
        self.set_total_length(40);
        self.set_identification(257);
        // setting flags seems to result in malformed ICMP packets with a
        // fragment offset.
        self.set_flags(0);
        self.set_fragment_offset(0);
        self.set_ttl(64);
        self.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        self.set_destination(*dest_addr);
        self.set_source(*src_addr);
        self.checksum();

        self.set_icmp_type();
        self.set_icmp_code();
        self.set_icmp_identifier(0x9b69);
        self.set_icmp_sequence(1);
        let time = util::msecs_after_utc();
        self.set_originate_timestamp(time);
        self.set_icmp_checksum();
        let start_offset = self.start_of_icmp();
    }

    fn set_icmp_checksum(&mut self) {
        let start = self.start_of_icmp();
        let checksum = self.calculate_icmp_checksum();
        self.packet[start + 2] = (checksum >> 8) as u8;
        self.packet[start + 3] = checksum as u8;
    }

    fn get_icmp_checksum(&self) -> u16 {
        let start = self.start_of_icmp();
        let a = self.packet[start + 2];
        let b = self.packet[start + 3];
        ((a as u16) << 8 | (b as u16)) as u16
    }

    fn set_icmp_type(&mut self) {
        let start = self.start_of_icmp();
        self.packet[start] = 13;
    }

    fn set_icmp_code(&mut self) {
        let start = self.start_of_icmp();
        self.packet[start + 1] = 0;
    }

    fn set_icmp_identifier(&mut self, id: u16) {
        let start = self.start_of_icmp();
        self.packet[start + 4] = (id >> 8) as u8;
        self.packet[start + 5] = id as u8;
    }

    fn set_icmp_sequence(&mut self, sequence: u16) {
        let start = self.start_of_icmp();
        self.packet[start + 6] = (sequence >> 8) as u8;
        self.packet[start + 7] = sequence as u8;
    }

    fn set_originate_timestamp(&mut self, time: u32) {
        let start = self.start_of_icmp();
        // dbl check this offset
        self.packet[start + 8] = (time >> 24) as u8;
        self.packet[start + 9] = ((time >> 16) & 0xf0) as u8;
        self.packet[start + 10] = ((time >> 8) & 0xff0) as u8;
        self.packet[start + 11] = time as u8;
    }

    pub fn set_version(&mut self, version: u8) {
        let ver = version << 4;
        self.packet[0] = (self.packet[0] & 0x0F) | ver;
    }


    /// Set the header length field for the packet
    pub fn set_header_length(&mut self, ihl: u8) {
        let len = ihl & 0xF;
        self.packet[0] = (self.packet[0] & 0xF0) | len;
    }



    /// Set the DSCP field for the packet
    pub fn set_dscp(&mut self, dscp: u8) {
        let cp = dscp & 0xFC;
        self.packet[1] = (self.packet[1] & 3) | (cp << 2);
    }

    /// Set the ECN field for the packet
    pub fn set_ecn(&mut self, ecn: u8) {
        let cn = ecn & 3;
        self.packet[1] = (self.packet[1] & 0xFC) | cn;
    }

    /// Set the total length field for the packet
    pub fn set_total_length(&mut self, len: u16) {
        self.packet[2] = (len >> 8) as u8;
        self.packet[3] = (len & 0xFF) as u8;
    }

    /// Set the identification field for the packet
    pub fn set_identification(&mut self, identification: u16) {
        self.packet[4] = (identification >> 8) as u8;
        self.packet[5] = (identification & 0x00FF) as u8;
    }

    /// Set the flags field for the packet
    pub fn set_flags(&mut self, flags: u8) {
        let fs = (flags & 7) << 5;
        self.packet[6] = (self.packet[6] & 0x1F) | fs;
    }

    /// Set the fragment offset field for the packet
    pub fn set_fragment_offset(&mut self, offset: u16) {
        let fo = offset & 0x1FFF;
        self.packet[6] = (self.packet[6] & 0xE0) | ((fo & 0xFF00) >> 8) as u8;
        self.packet[7] = (fo & 0xFF) as u8;
    }

    /// Set the TTL field for the packet
    pub fn set_ttl(&mut self, ttl: u8) {
        self.packet[8] = ttl;
    }

    /// Set the next level protocol field for the packet
    pub fn set_next_level_protocol(&mut self, IpNextHeaderProtocol(protocol): IpNextHeaderProtocol) {
        self.packet[9] = protocol;
    }

    /// Set the checksum field for the packet
    pub fn set_checksum(&mut self, checksum: u16) {
        let cs1 = ((checksum & 0xFF00) >> 8) as u8;
        let cs2 = (checksum & 0x00FF) as u8;
        self.packet[10] = cs1;
        self.packet[11] = cs2;
    }

    /// Set the source address for the packet
    pub fn set_source(&mut self, ip: IpAddr) {
        match ip {
            Ipv4Addr(a, b, c, d) => {
                self.packet[12] = a;
                self.packet[13] = b;
                self.packet[14] = c;
                self.packet[15] = d;
            },
            _ => ()
        }
    }

    /// Set the destination field for the packet
    pub fn set_destination(&mut self, ip: IpAddr) {
        match ip {
            Ipv4Addr(a, b, c, d) => {
                self.packet[16] = a;
                self.packet[17] = b;
                self.packet[18] = c;
                self.packet[19] = d;
            },
            _ => ()
        }
    }

    /// Calculate the checksum of the packet and then set the field to the value
    /// calculated
    pub fn checksum(&mut self) {
        let checksum = self.calculate_checksum();
        self.set_checksum(checksum);
    }

}

mod tests {
    use super::*;
    use std::str::FromStr;
    use std::iter::repeat;
    use std::old_io::net::ip::{IpAddr, Ipv4Addr};
    use pnet::old_packet::ip::{IpNextHeaderProtocol,IpNextHeaderProtocols};

    #[test]
    fn calculate_checksum() {
        let size = MutIcmpRequestPacket::allocation_size();
        let mut vec: Vec<u8> = repeat(0u8).take(size).collect();
        let mut packet = MutIcmpRequestPacket::new(vec.as_mut_slice());
        let src_addr: IpAddr = FromStr::from_str("192.168.0.3").unwrap();
        let dst_addr: IpAddr = FromStr::from_str("96.127.180.194").unwrap();

        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_dscp(0);
        packet.set_total_length(40);
        packet.set_identification(257);
        // setting flags seems to result in malformed ICMP packets with a
        // fragment offset.
        packet.set_flags(0);
        packet.set_fragment_offset(0);
        packet.set_ttl(64);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        packet.set_destination(dst_addr);
        packet.set_source(src_addr);
        packet.checksum();

        packet.set_icmp_type();
        packet.set_icmp_code();
        packet.set_icmp_identifier(0x9b69);
        packet.set_icmp_sequence(1);
        packet.set_originate_timestamp(1);
        packet.set_icmp_checksum();

        let r = 0x5794;
        assert_eq!(r, packet.get_icmp_checksum());
    }

    #[test]
    fn calculate_checksum_again() {
        let size = MutIcmpRequestPacket::allocation_size();
        let mut vec: Vec<u8> = repeat(0u8).take(size).collect();
        let mut packet = MutIcmpRequestPacket::new(vec.as_mut_slice());
        let src_addr: IpAddr = FromStr::from_str("192.168.0.3").unwrap();
        let dst_addr: IpAddr = FromStr::from_str("96.127.180.194").unwrap();

        packet.set_version(4);
        packet.set_header_length(5);
        packet.set_dscp(0);
        packet.set_total_length(40);
        packet.set_identification(257);
        // setting flags seems to result in malformed ICMP packets with a
        // fragment offset.
        packet.set_flags(0);
        packet.set_fragment_offset(0);
        packet.set_ttl(64);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        packet.set_destination(dst_addr);
        packet.set_source(src_addr);
        packet.checksum();

        packet.packet[20] = 0xd;
        packet.packet[21] = 0;
        packet.packet[22] = 0;
        packet.packet[23] = 0;
        packet.packet[24] = 0x9b;
        packet.packet[25] = 0x69;
        packet.packet[26] = 0;
        packet.packet[27] = 01;
        packet.packet[28] = 0;
        packet.packet[29] = 0xf0;
        packet.packet[30] = 0xb0;
        packet.packet[31] = 0xe0;
        packet.packet[32] = 0;
        packet.packet[33] = 0;
        packet.packet[34] = 0;
        packet.packet[35] = 0;
        packet.packet[36] = 0;
        packet.packet[37] = 0;
        packet.packet[38] = 0;
        packet.packet[39] = 0;
        packet.set_icmp_checksum();

        let r = 0xa5c4;
        assert_eq!(r, packet.get_icmp_checksum());
    }
}
