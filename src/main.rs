extern crate getopts;

use getopts::Options;
use std::os;
use std::net::{SocketAddr};
use std::str::FromStr;

fn main() {
    let args: Vec<String> = os::args();
    let mut opts = Options::new();
    let matches = match opts.parse(args.tail()) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string())
    };
    let addr_arg = matches.free[0].as_slice();
    let addr:SocketAddr = FromStr::from_str(addr_arg.as_slice()).unwrap();
}
