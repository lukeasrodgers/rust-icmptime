extern crate getopts;
extern crate pnet;

use getopts::Options;
use std::os;
use std::net::{IpAddr};
use std::str::FromStr;

use pnet::transport::TransportProtocol::{Ipv4};
use pnet::old_packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::{Layer3};
use pnet::transport::{transport_channel};

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
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel:
                        {}", e)
    };
}
