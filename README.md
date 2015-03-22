# rust-icmptime

Simple commandline tool in rust to send ICMP time request packets, inspired by [TCP Illustrated](http://books.google.com/books/about/TCP_IP_Illustrated_Volume_1.html?id=a23OAn5i8R0C).

Writing this as a learning tool for rust and TCP/IP. Very much a work in progress. 

Uses rust [libpnet](https://github.com/libpnet/libpnet) in probably suboptimal and incorrect ways.

## Things learned:

* Rust traits can provide default implementations, as libpnet does with the `Ipv4Packet` trait [here](https://github.com/libpnet/libpnet/blob/4759805f054fa1d9d5c8709fa5de02a35a53bfd5/src/old_packet/ipv4.rs#L118-216).
* Networking stack implementations will vary with regard to how they handle ICMP messages. Some are handled by the kernel, while for
others, if there are any user processes that have registered an interest in such types of messages, they will passed to the appropriate
user processes.
* Packets (and by extension ethernet frames) are just strings of bits that contain information at certain predefined offets/locations that indicate what type of protocol is involved,
what the data is, etc. I suppose I knew this in a sense already, but this really drove it home.

MIT Licence.
