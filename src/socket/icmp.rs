use core::cmp;

use crate::phy::ChecksumCapabilities;
use crate::socket::{Context, PollAt};

use crate::storage::Empty;
use crate::wire::IcmpRepr;

use crate::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Repr};

use crate::wire::{Icmpv6Packet, Icmpv6Repr, Ipv6Repr};
use crate::wire::{IpAddress, IpListenEndpoint, IpProtocol, IpRepr};
use crate::wire::{UdpPacket, UdpRepr};

/// Error returned by [`Socket::bind`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub enum SendError {
    Unaddressable,
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// Type of endpoint to bind the ICMP socket to. See [IcmpSocket::bind] for
/// more details.
///
/// [IcmpSocket::bind]: struct.IcmpSocket.html#method.bind
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]

pub enum Endpoint {
    #[default]
    Unspecified,
    Ident(u16),
    Udp(IpListenEndpoint),
}

impl Endpoint {
    pub fn is_specified(&self) -> bool {
        match *self {
            Endpoint::Ident(_) => true,
            Endpoint::Udp(endpoint) => endpoint.port != 0,
            Endpoint::Unspecified => false,
        }
    }
}

/// An ICMP packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<IpAddress>;

/// An ICMP packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, IpAddress>;

/// A ICMP socket
///
/// An ICMP socket is bound to a specific [IcmpEndpoint] which may
/// be a specific UDP port to listen for ICMP error messages related
/// to the port or a specific ICMP identifier value. See [bind] for
/// more details.
///
/// [IcmpEndpoint]: enum.IcmpEndpoint.html
/// [bind]: #method.bind
#[derive(Debug)]
pub struct Socket<'a> {
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
    /// The endpoint this socket is communicating with
    endpoint: Endpoint,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
}

impl<'a> Socket<'a> {
    /// Create an ICMP socket with the given buffers.
    pub fn new(rx_buffer: PacketBuffer<'a>, tx_buffer: PacketBuffer<'a>) -> Socket<'a> {
        Socket {
            rx_buffer,
            tx_buffer,
            endpoint: Default::default(),
            hop_limit: None,
        }
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Bind the socket to the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if `endpoint` is unspecified (see [is_specified]).
    ///
    pub fn bind<T: Into<Endpoint>>(&mut self, endpoint: T) -> Result<(), BindError> {
        let endpoint = endpoint.into();
        if !endpoint.is_specified() {
            return Err(BindError::Unaddressable);
        }

        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        self.endpoint = endpoint;

        Ok(())
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint != Endpoint::Unspecified
    }

    /// Enqueue a packet to be sent to a given remote address, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Truncated)` if the requested size is larger than the packet buffer
    /// size, and `Err(Error::Unaddressable)` if the remote address is unspecified.
    pub fn send(&mut self, size: usize, endpoint: IpAddress) -> Result<&mut [u8], SendError> {
        if endpoint.is_unspecified() {
            return Err(SendError::Unaddressable);
        }

        let packet_buf = self
            .tx_buffer
            .enqueue(size, endpoint)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!("icmp:{}: buffer to send {} octets", endpoint, size);
        Ok(packet_buf)
    }

    /// Enqueue a packet to be send to a given remote address and pass the buffer
    /// to the provided closure. The closure then returns the size of the data written
    /// into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(
        &mut self,
        max_size: usize,
        endpoint: IpAddress,
        f: F,
    ) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        if endpoint.is_unspecified() {
            return Err(SendError::Unaddressable);
        }

        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, endpoint, f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!("icmp:{}: buffer to send {} octets", endpoint, size);
        Ok(size)
    }

    /// Enqueue a packet to be sent to a given remote address, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpAddress) -> Result<(), SendError> {
        let packet_buf = self.send(data.len(), endpoint)?;
        packet_buf.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the `IpAddress` as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpAddress), RecvError> {
        let (endpoint, packet_buf) = self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "icmp:{}: receive {} buffered octets",
            endpoint,
            packet_buf.len()
        );
        Ok((packet_buf, endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the `IpAddress`
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpAddress), RecvError> {
        let (buffer, endpoint) = self.recv()?;

        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = cmp::min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Return the amount of octets queued in the transmit buffer.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// Return the amount of octets queued in the receive buffer.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    /// Fitler determining whether the socket accepts a given ICMPv4 packet.
    /// Accepted packets are enqueued into the socket's receive buffer.
    
    #[inline]
    pub(crate) fn accepts_v4(
        &self,
        cx: &mut Context,
        ip_repr: &Ipv4Repr,
        icmp_repr: &Icmpv4Repr,
    ) -> bool {
        match (&self.endpoint, icmp_repr) {
            // If we are bound to ICMP errors associated to a UDP port, only
            // accept Destination Unreachable or Time Exceeded messages with
            // the data containing a UDP packet send from the local port we
            // are bound to.
            (
                &Endpoint::Udp(endpoint),
                &Icmpv4Repr::DstUnreachable { data, header, .. }
                | &Icmpv4Repr::TimeExceeded { data, header, .. },
            ) if endpoint.addr.is_none() || endpoint.addr == Some(ip_repr.dst_addr.into()) => {
                let packet = UdpPacket::new_unchecked(data);
                match UdpRepr::parse(
                    &packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    &cx.checksum_caps(),
                ) {
                    Ok(repr) => endpoint.port == repr.src_port,
                    Err(_) => false,
                }
            }
            // If we are bound to a specific ICMP identifier value, only accept an
            // Echo Request/Reply with the identifier field matching the endpoint
            // port.
            (&Endpoint::Ident(bound_ident), &Icmpv4Repr::EchoRequest { ident, .. })
            | (&Endpoint::Ident(bound_ident), &Icmpv4Repr::EchoReply { ident, .. }) => {
                ident == bound_ident
            }
            _ => false,
        }
    }

    /// Fitler determining whether the socket accepts a given ICMPv6 packet.
    /// Accepted packets are enqueued into the socket's receive buffer.
    
    #[inline]
    pub(crate) fn accepts_v6(
        &self,
        cx: &mut Context,
        ip_repr: &Ipv6Repr,
        icmp_repr: &Icmpv6Repr,
    ) -> bool {
        match (&self.endpoint, icmp_repr) {
            // If we are bound to ICMP errors associated to a UDP port, only
            // accept Destination Unreachable or Time Exceeded messages with
            // the data containing a UDP packet send from the local port we
            // are bound to.
            (
                &Endpoint::Udp(endpoint),
                &Icmpv6Repr::DstUnreachable { data, header, .. }
                | &Icmpv6Repr::TimeExceeded { data, header, .. },
            ) if endpoint.addr.is_none() || endpoint.addr == Some(ip_repr.dst_addr.into()) => {
                let packet = UdpPacket::new_unchecked(data);
                match UdpRepr::parse(
                    &packet,
                    &header.src_addr.into(),
                    &header.dst_addr.into(),
                    &cx.checksum_caps(),
                ) {
                    Ok(repr) => endpoint.port == repr.src_port,
                    Err(_) => false,
                }
            }
            // If we are bound to a specific ICMP identifier value, only accept an
            // Echo Request/Reply with the identifier field matching the endpoint
            // port.
            (
                &Endpoint::Ident(bound_ident),
                &Icmpv6Repr::EchoRequest { ident, .. } | &Icmpv6Repr::EchoReply { ident, .. },
            ) => ident == bound_ident,
            _ => false,
        }
    }

    
    pub(crate) fn process_v4(
        &mut self,
        _cx: &mut Context,
        ip_repr: &Ipv4Repr,
        icmp_repr: &Icmpv4Repr,
    ) {
        net_trace!("icmp: receiving {} octets", icmp_repr.buffer_len());

        match self
            .rx_buffer
            .enqueue(icmp_repr.buffer_len(), ip_repr.src_addr.into())
        {
            Ok(packet_buf) => {
                icmp_repr.emit(
                    &mut Icmpv4Packet::new_unchecked(packet_buf),
                    &ChecksumCapabilities::default(),
                );
            }
            Err(_) => net_trace!("icmp: buffer full, dropped incoming packet"),
        }
    }

    
    pub(crate) fn process_v6(
        &mut self,
        _cx: &mut Context,
        ip_repr: &Ipv6Repr,
        icmp_repr: &Icmpv6Repr,
    ) {
        net_trace!("icmp: receiving {} octets", icmp_repr.buffer_len());

        match self
            .rx_buffer
            .enqueue(icmp_repr.buffer_len(), ip_repr.src_addr.into())
        {
            Ok(packet_buf) => icmp_repr.emit(
                &ip_repr.src_addr,
                &ip_repr.dst_addr,
                &mut Icmpv6Packet::new_unchecked(packet_buf),
                &ChecksumCapabilities::default(),
            ),
            Err(_) => net_trace!("icmp: buffer full, dropped incoming packet"),
        }
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, IcmpRepr)) -> Result<(), E>,
    {
        let hop_limit = self.hop_limit.unwrap_or(64);
        let res = self.tx_buffer.dequeue_with(|remote_endpoint, packet_buf| {
            net_trace!(
                "icmp:{}: sending {} octets",
                remote_endpoint,
                packet_buf.len()
            );
            match *remote_endpoint {
                
                IpAddress::Ipv4(dst_addr) => {
                    let src_addr = match cx.get_source_address_ipv4(&dst_addr) {
                        Some(addr) => addr,
                        None => {
                            net_trace!(
                                "icmp:{}: not find suitable source address, dropping",
                                remote_endpoint
                            );
                            return Ok(());
                        }
                    };
                    let packet = Icmpv4Packet::new_unchecked(&*packet_buf);
                    let repr = match Icmpv4Repr::parse(&packet, &ChecksumCapabilities::ignored()) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!(
                                "icmp:{}: malformed packet in queue, dropping",
                                remote_endpoint
                            );
                            return Ok(());
                        }
                    };
                    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
                        src_addr,
                        dst_addr,
                        next_header: IpProtocol::Icmp,
                        payload_len: repr.buffer_len(),
                        hop_limit,
                    });
                    emit(cx, (ip_repr, IcmpRepr::Ipv4(repr)))
                }
                
                IpAddress::Ipv6(dst_addr) => {
                    let src_addr = cx.get_source_address_ipv6(&dst_addr);

                    let packet = Icmpv6Packet::new_unchecked(&*packet_buf);
                    let repr = match Icmpv6Repr::parse(
                        &src_addr,
                        &dst_addr,
                        &packet,
                        &ChecksumCapabilities::ignored(),
                    ) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!(
                                "icmp:{}: malformed packet in queue, dropping",
                                remote_endpoint
                            );
                            return Ok(());
                        }
                    };
                    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
                        src_addr,
                        dst_addr,
                        next_header: IpProtocol::Icmpv6,
                        payload_len: repr.buffer_len(),
                        hop_limit,
                    });
                    emit(cx, (ip_repr, IcmpRepr::Ipv6(repr)))
                }
            }
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => Ok(()),
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}
