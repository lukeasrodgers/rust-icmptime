extern crate getopts;
extern crate pnet;
extern crate "rust-icmptime" as icmptime;

use getopts::Options;
use std::os;
use std::old_io::net::ip::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::net::lookup_host;
use std::net::{SocketAddr};
use std::net::SocketAddr::*;
use std::net::ip::Ipv4Addr;

use pnet::transport::TransportProtocol::{Ipv4};
use pnet::old_packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::{Layer3};
use pnet::transport::{transport_channel};
use pnet::old_packet::{Packet};
use pnet::old_packet::ipv4::{Ipv4Header, Ipv4Packet};
use pnet::util::{NetworkInterface, get_network_interfaces};

use icmptime::packet::{MutIcmpRequestPacket};

use std::iter::repeat;

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
    let dst_addr_arg = matches.free[0].as_slice();
    let dst_addr: IpAddr = FromStr::from_str(dst_addr_arg.as_slice()).unwrap();

    let src_addr = ipv4_ip();

    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut icmp_sender, mut icmp_receiver) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel:
                        {}", e)
    };
    let size = MutIcmpRequestPacket::allocation_size();
    let mut vec: Vec<u8> = repeat(0u8).take(size).collect();
    let mut packet = MutIcmpRequestPacket::new(vec.as_mut_slice());
    packet.prepare_for_sending(&dst_addr, &src_addr);

    match icmp_sender.send_to(packet, dst_addr) {
        Ok(n) => println!("sent"),
        Err(e) => panic!("failed to send packet: {}", e)
    }
}

fn ipv4_ip() -> IpAddr {
    let iface = (*get_network_interfaces().as_slice().iter().
        filter(|i| match i.ips { Some(_) => true, None => false }).
        filter(|i| !i.is_loopback() ).
        find(|i| match i.ips {
            Some(ref ips) => ips.as_slice().iter().any(|ip| match *ip { Ipv4Addr(_, _, _, _) => true, _  => false }),
            None => false
        }).unwrap()).clone();
    println!("iface: {:?}", iface);
    let ipv4 = iface.ips.unwrap().as_slice().iter().find(|ip| match *ip { &Ipv4Addr(_, _, _, _) => true, _  => false }).unwrap().clone();
    ipv4
}
