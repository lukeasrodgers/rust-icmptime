# rust-icmptime

Simple commandline tool in rust to send ICMP time request packets, inspired by [TCP Illustrated](http://books.google.com/books/about/TCP_IP_Illustrated_Volume_1.html?id=a23OAn5i8R0C).

Writing this as a learning tool for rust and TCP/IP. Very much a work in progress. 

Uses rust [libpnet](https://github.com/libpnet/libpnet) in probably suboptimal and incorrect ways.

## issues

* bad organization
* a bunch of the code for `MutIcmpRequestPacket` is not specific to ICMP request packets, could/should probably be in a trait.
* essentially just copy-pasted implementation of a bunch of IP header-relateds for `MutIcmpRequestPacket` from `MutableIpv4Header`, like `set_flags`. Not sure what the best way around this would
be. One option would be to not have a new struct for `MutIcmpRequestPacket` and just add methods (via a new trait?) to libpnet's `MutableIpv4Header` struct, but I like the idea
of having a separate struct. Another approach would be to keep the separate struct, not re-implement any of the `MutableIpv4Header` methods, then just tack on the ICMP-specific bytes
at the end of the IP header, after the checksum has been calculated, etc. Another approach would be to rewrite `MutableIpv4Header` to be trait instead of a struct.
* whenever I attempt to send to an IP address other than 127.0.0.1, this fails with EADDRNOTAVAIL, not sure why.

## Things learned:

* Rust traits can provide default implementations, as libpnet does with the `Ipv4Packet` trait [here](https://github.com/libpnet/libpnet/blob/4759805f054fa1d9d5c8709fa5de02a35a53bfd5/src/old_packet/ipv4.rs#L118-216).
* Networking stack implementations will vary with regard to how they handle ICMP messages. Some are handled by the kernel, while for
others, if there are any user processes that have registered an interest in such types of messages, they will passed to the appropriate
user processes.
* Packets (and by extension ethernet frames) are just strings of bits that contain information at certain predefined offets/locations that indicate what type of protocol is involved,
what the data is, etc. I suppose I knew this in a sense already, but this really drove it home.
* OSX by default ignores ICMP timestamp requests

MIT Licence.
