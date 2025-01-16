use crate::phy::DeviceCapabilities;
use crate::wire::*;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]

pub(crate) enum EthernetPacket<'a> {
    Arp(ArpRepr),
    Ip(Packet<'a>),
}

#[derive(Debug, PartialEq)]

pub(crate) enum Packet<'p> {
    Ipv4(PacketV4<'p>),

    Ipv6(PacketV6<'p>),
}

impl<'p> Packet<'p> {
    pub(crate) fn new(ip_repr: IpRepr, payload: IpPayload<'p>) -> Self {
        match ip_repr {
            IpRepr::Ipv4(header) => Self::new_ipv4(header, payload),

            IpRepr::Ipv6(header) => Self::new_ipv6(header, payload),
        }
    }

    pub(crate) fn new_ipv4(ip_repr: Ipv4Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv4(PacketV4 {
            header: ip_repr,
            payload,
        })
    }

    pub(crate) fn new_ipv6(ip_repr: Ipv6Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv6(PacketV6 {
            header: ip_repr,
            hop_by_hop: None,
            fragment: None,
            routing: None,
            payload,
        })
    }

    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            Packet::Ipv4(p) => IpRepr::Ipv4(p.header),

            Packet::Ipv6(p) => IpRepr::Ipv6(p.header),
        }
    }

    pub(crate) fn payload(&mut self) -> &mut IpPayload<'p> {
        match self {
            Packet::Ipv4(p) => &mut p.payload,
            Packet::Ipv6(p) => &mut p.payload,
        }
    }

    pub(crate) fn emit_payload(
        &mut self,
        _ip_repr: &IpRepr,
        payload: &mut [u8],
        caps: &DeviceCapabilities,
    ) {
        match self.payload() {
            IpPayload::Icmpv4(icmpv4_repr) => {
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum)
            }

            IpPayload::Icmpv6(icmpv6_repr) => {
                let ipv6_repr = match _ip_repr {
                    IpRepr::Ipv4(_) => unreachable!(),
                    IpRepr::Ipv6(repr) => repr,
                };

                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(payload),
                    &caps.checksum,
                )
            }

            IpPayload::HopByHopIcmpv6(hbh_repr, icmpv6_repr) => {
                let ipv6_repr = match _ip_repr {
                    IpRepr::Ipv4(_) => unreachable!(),
                    IpRepr::Ipv6(repr) => repr,
                };

                let ipv6_ext_hdr = Ipv6ExtHeaderRepr {
                    next_header: IpProtocol::Icmpv6,
                    length: 0,
                    data: &[],
                };
                ipv6_ext_hdr.emit(&mut Ipv6ExtHeader::new_unchecked(
                    &mut payload[..ipv6_ext_hdr.header_len()],
                ));

                let hbh_start = ipv6_ext_hdr.header_len();
                let hbh_end = hbh_start + hbh_repr.buffer_len();
                hbh_repr.emit(&mut Ipv6HopByHopHeader::new_unchecked(
                    &mut payload[hbh_start..hbh_end],
                ));

                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(&mut payload[hbh_end..]),
                    &caps.checksum,
                );
            }

            IpPayload::Raw(raw_packet) => payload.copy_from_slice(raw_packet),
            IpPayload::Udp(udp_repr, inner_payload) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                inner_payload.len(),
                |buf| buf.copy_from_slice(inner_payload),
                &caps.checksum,
            ),
            IpPayload::Tcp(tcp_repr) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= _ip_repr.header_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(payload),
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    &caps.checksum,
                );
            }
            IpPayload::Dhcpv4(udp_repr, dhcp_repr) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                dhcp_repr.buffer_len(),
                |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                &caps.checksum,
            ),
        }
    }
}

#[derive(Debug, PartialEq)]

pub(crate) struct PacketV4<'p> {
    header: Ipv4Repr,
    payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]

pub(crate) struct PacketV6<'p> {
    pub(crate) header: Ipv6Repr,
    pub(crate) hop_by_hop: Option<Ipv6HopByHopRepr<'p>>,
    pub(crate) fragment: Option<Ipv6FragmentRepr>,
    pub(crate) routing: Option<Ipv6RoutingRepr<'p>>,
    pub(crate) payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]

pub(crate) enum IpPayload<'p> {
    Icmpv4(Icmpv4Repr<'p>),

    Icmpv6(Icmpv6Repr<'p>),

    HopByHopIcmpv6(Ipv6HopByHopRepr<'p>, Icmpv6Repr<'p>),
    Raw(&'p [u8]),
    Udp(UdpRepr, &'p [u8]),
    Tcp(TcpRepr<'p>),
    Dhcpv4(UdpRepr, DhcpRepr<'p>),
}

pub(crate) fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minimum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    len.min(mtu - header_len * 2 - 8)
}
