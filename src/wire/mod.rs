/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides two levels
of functionality.

 * First, it provides functions to extract fields from sequences of octets,
   and to insert fields into sequences of octets. This happens `Packet` family of
   structures, e.g. [EthernetFrame] or [Ipv4Packet].
 * Second, in cases where the space of valid field values is much smaller than the space
   of possible field values, it provides a compact, high-level representation
   of packet data that can be parsed from and emitted into a sequence of octets.
   This happens through the `Repr` family of structs and enums, e.g. [ArpRepr] or [Ipv4Repr].

[EthernetFrame]: struct.EthernetFrame.html
[Ipv4Packet]: struct.Ipv4Packet.html
[ArpRepr]: enum.ArpRepr.html
[Ipv4Repr]: struct.Ipv4Repr.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.

In the `Repr` family of data structures, the `Repr::parse()` method never panics
as long as `Packet::new_checked()` (or `Packet::check_len()`) has succeeded, and
the `Repr::emit()` method never panics as long as the underlying buffer is exactly
`Repr::buffer_len()` octets long.

# Examples

To emit an IP packet header into an octet buffer, and then parse it back:

```rust
#
# {
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    next_header: IpProtocol::Tcp,
    payload_len: 10,
    hop_limit:   64,
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
}
{ // parsing
    let packet = Ipv4Packet::new_checked(&buffer)
                            .expect("truncated packet");
    let parsed = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())
                          .expect("malformed packet");
    assert_eq!(repr, parsed);
}
# }
```
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

mod arp;
pub(crate) mod dhcpv4;
mod ethernet;
mod icmp;

mod icmpv4;

mod icmpv6;
pub(crate) mod ip;

pub(crate) mod ipv4;

pub(crate) mod ipv6;

mod ipv6ext_header;

mod ipv6fragment;

mod ipv6hbh;

mod ipv6option;

mod ipv6routing;

mod mld;
mod ndisc;
mod ndiscoption;
mod tcp;
mod udp;

use core::fmt;

pub use self::pretty_print::PrettyPrinter;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    Repr as EthernetRepr, HEADER_LEN as ETHERNET_HEADER_LEN,
};

pub use self::arp::{
    Hardware as ArpHardware, Operation as ArpOperation, Packet as ArpPacket, Repr as ArpRepr,
};

pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint,
    ListenEndpoint as IpListenEndpoint, Protocol as IpProtocol, Repr as IpRepr,
    Version as IpVersion,
};

pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, Key as Ipv4FragKey, Packet as Ipv4Packet,
    Repr as Ipv4Repr, HEADER_LEN as IPV4_HEADER_LEN, MIN_MTU as IPV4_MIN_MTU,
    MULTICAST_ALL_ROUTERS as IPV4_MULTICAST_ALL_ROUTERS,
    MULTICAST_ALL_SYSTEMS as IPV4_MULTICAST_ALL_SYSTEMS,
};

pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;

pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, Packet as Ipv6Packet, Repr as Ipv6Repr,
    HEADER_LEN as IPV6_HEADER_LEN,
    LINK_LOCAL_ALL_MLDV2_ROUTERS as IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
    LINK_LOCAL_ALL_NODES as IPV6_LINK_LOCAL_ALL_NODES,
    LINK_LOCAL_ALL_ROUTERS as IPV6_LINK_LOCAL_ALL_ROUTERS,
    LINK_LOCAL_ALL_RPL_NODES as IPV6_LINK_LOCAL_ALL_RPL_NODES, MIN_MTU as IPV6_MIN_MTU,
};

pub(crate) use self::ipv6::{AddressExt as Ipv6AddressExt, MulticastScope as Ipv6MulticastScope};

pub use self::ipv6option::{
    FailureType as Ipv6OptionFailureType, Ipv6Option, Ipv6OptionsIterator, Repr as Ipv6OptionRepr,
    RouterAlert as Ipv6OptionRouterAlert, Type as Ipv6OptionType,
};

pub use self::ipv6ext_header::{Header as Ipv6ExtHeader, Repr as Ipv6ExtHeaderRepr};

pub use self::ipv6fragment::{Header as Ipv6FragmentHeader, Repr as Ipv6FragmentRepr};

pub use self::ipv6hbh::{Header as Ipv6HopByHopHeader, Repr as Ipv6HopByHopRepr};

pub use self::ipv6routing::{
    Header as Ipv6RoutingHeader, Repr as Ipv6RoutingRepr, Type as Ipv6RoutingType,
};

pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, Repr as Icmpv4Repr,
    TimeExceeded as Icmpv4TimeExceeded,
};

pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, Repr as Icmpv6Repr, TimeExceeded as Icmpv6TimeExceeded,
};

pub use self::icmp::Repr as IcmpRepr;

pub use self::ndisc::{
    NeighborFlags as NdiscNeighborFlags, Repr as NdiscRepr, RouterFlags as NdiscRouterFlags,
};

pub use self::ndiscoption::{
    NdiscOption, PrefixInfoFlags as NdiscPrefixInfoFlags,
    PrefixInformation as NdiscPrefixInformation, RedirectedHeader as NdiscRedirectedHeader,
    Repr as NdiscOptionRepr, Type as NdiscOptionType,
};

pub use self::mld::{
    AddressRecord as MldAddressRecord, AddressRecordRepr as MldAddressRecordRepr,
    RecordType as MldRecordType, Repr as MldRepr,
};

pub use self::udp::{Packet as UdpPacket, Repr as UdpRepr, HEADER_LEN as UDP_HEADER_LEN};

pub use self::tcp::{
    Control as TcpControl, Packet as TcpPacket, Repr as TcpRepr, SeqNumber as TcpSeqNumber,
    TcpOption, TcpTimestampGenerator, TcpTimestampRepr, HEADER_LEN as TCP_HEADER_LEN,
};

pub use self::dhcpv4::{
    DhcpOption, DhcpOptionWriter, Flags as DhcpFlags, MessageType as DhcpMessageType,
    OpCode as DhcpOpCode, Packet as DhcpPacket, Repr as DhcpRepr, CLIENT_PORT as DHCP_CLIENT_PORT,
    MAX_DNS_SERVER_COUNT as DHCP_MAX_DNS_SERVER_COUNT, SERVER_PORT as DHCP_SERVER_PORT,
};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by smoltcp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub struct Error;

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Representation of an hardware address, such as an Ethernet address or an IEEE802.15.4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum HardwareAddress {
    Ethernet(EthernetAddress),
}

impl HardwareAddress {
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
        }
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
        }
    }

    /// Query whether the address is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
        }
    }

    pub(crate) fn ethernet_or_panic(&self) -> EthernetAddress {
        match self {
            HardwareAddress::Ethernet(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("HardwareAddress is not Ethernet."),
        }
    }
}

impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
        }
    }
}

impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

pub const MAX_HARDWARE_ADDRESS_LEN: usize = 6;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub struct RawHardwareAddress {
    len: u8,
    data: [u8; MAX_HARDWARE_ADDRESS_LEN],
}

impl RawHardwareAddress {
    /// Create a new `RawHardwareAddress` from a byte slice.
    ///
    /// # Panics
    /// Panics if `addr.len() > MAX_HARDWARE_ADDRESS_LEN`.
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HARDWARE_ADDRESS_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self {
            len: addr.len() as u8,
            data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn parse(&self) -> Result<HardwareAddress> {
        if self.len() != 6 {
            return Err(Error);
        }
        Ok(HardwareAddress::Ethernet(EthernetAddress::from_bytes(
            self.as_bytes(),
        )))
    }
}

impl core::fmt::Display for RawHardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<EthernetAddress> for RawHardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

impl From<HardwareAddress> for RawHardwareAddress {
    fn from(addr: HardwareAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}
