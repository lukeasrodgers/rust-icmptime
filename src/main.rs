extern crate getopts;
extern crate pnet;
extern crate "rust-icmptime" as icmptime;

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

use icmptime::{build_icmp_time_request_packet};

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
