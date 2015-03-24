extern crate getopts;
extern crate pnet;

use getopts::Options;
use std::os;
use std::str::FromStr;

use pnet::transport::TransportProtocol::{Ipv4};
use pnet::old_packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::{Layer3};
use pnet::transport::{transport_channel};
use pnet::old_packet::{Packet};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};

pub mod packet;
use packet::{IcmpPacket,IcmpRequestPacket};

mod util;

pub fn build_icmp_time_request_packet<'p>(packet_slice: &'p [u8]) -> IcmpRequestPacket<'p> {
    let mut packet = IcmpRequestPacket::new(packet_slice);
    packet
}
