use crate::iface::Context;
use crate::socket::PollAt;
use core::cmp::min;

use crate::storage::Empty;
use crate::wire::{IpProtocol, IpRepr, IpVersion};

use crate::wire::{Ipv4Packet, Ipv4Repr};

use crate::wire::{Ipv6Packet, Ipv6Repr};

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
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
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

/// A UDP packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<()>;

/// A UDP packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, ()>;

/// A raw IP socket.
///
/// A raw socket is bound to a specific IP protocol, and owns
/// transmit and receive packet buffers.
#[derive(Debug)]
pub struct Socket<'a> {
    ip_version: IpVersion,
    ip_protocol: IpProtocol,
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
}

impl<'a> Socket<'a> {
    /// Create a raw IP socket bound to the given IP version and datagram protocol,
    /// with the given buffers.
    pub fn new(
        ip_version: IpVersion,
        ip_protocol: IpProtocol,
        rx_buffer: PacketBuffer<'a>,
        tx_buffer: PacketBuffer<'a>,
    ) -> Socket<'a> {
        Socket {
            ip_version,
            ip_protocol,
            rx_buffer,
            tx_buffer,
        }
    }

    /// Return the IP version the socket is bound to.
    #[inline]
    pub fn ip_version(&self) -> IpVersion {
        self.ip_version
    }

    /// Return the IP protocol the socket is bound to.
    #[inline]
    pub fn ip_protocol(&self) -> IpProtocol {
        self.ip_protocol
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

    /// Enqueue a packet to send, and return a pointer to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    ///
    /// If the buffer is filled in a way that does not match the socket's
    /// IP version or protocol, the packet will be silently dropped.
    ///
    /// **Note:** The IP header is parsed and re-serialized, and may not match
    /// the header actually transmitted bit for bit.
    pub fn send(&mut self, size: usize) -> Result<&mut [u8], SendError> {
        let packet_buf = self
            .tx_buffer
            .enqueue(size, ())
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw:{}:{}: buffer to send {} octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// Enqueue a packet to be send and pass the buffer to the provided closure.
    /// The closure then returns the size of the data written into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(&mut self, max_size: usize, f: F) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let size = self
            .tx_buffer
            .enqueue_with_infallible(max_size, (), f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "raw:{}:{}: buffer to send {} octets",
            self.ip_version,
            self.ip_protocol,
            size
        );

        Ok(size)
    }

    /// Enqueue a packet to send, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet, and return a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    ///
    /// **Note:** The IP header is parsed and re-serialized, and may not match
    /// the header actually received bit for bit.
    pub fn recv(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw:{}:{}: receive {} buffered octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );
        Ok(packet_buf)
    }

    /// Dequeue a packet, and copy the payload into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.recv()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// Peek at a packet in the receive buffer and return a pointer to the
    /// payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<&[u8], RecvError> {
        let ((), packet_buf) = self.rx_buffer.peek().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "raw:{}:{}: receive {} buffered octets",
            self.ip_version,
            self.ip_protocol,
            packet_buf.len()
        );

        Ok(packet_buf)
    }

    /// Peek at a packet in the receive buffer, copy the payload into the given slice,
    /// and return the amount of octets copied without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let buffer = self.peek()?;
        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok(length)
    }

    /// Return the amount of octets queued in the transmit buffer.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// Return the amount of octets queued in the receive buffer.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr) -> bool {
        if ip_repr.version() != self.ip_version {
            return false;
        }
        if ip_repr.next_header() != self.ip_protocol {
            return false;
        }

        true
    }

    pub(crate) fn process(&mut self, cx: &mut Context, ip_repr: &IpRepr, payload: &[u8]) {
        debug_assert!(self.accepts(ip_repr));

        let header_len = ip_repr.header_len();
        let total_len = header_len + payload.len();

        net_trace!(
            "raw:{}:{}: receiving {} octets",
            self.ip_version,
            self.ip_protocol,
            total_len
        );

        match self.rx_buffer.enqueue(total_len, ()) {
            Ok(buf) => {
                ip_repr.emit(&mut buf[..header_len], &cx.checksum_caps());
                buf[header_len..].copy_from_slice(payload);
            }
            Err(_) => net_trace!(
                "raw:{}:{}: buffer full, dropped incoming packet",
                self.ip_version,
                self.ip_protocol
            ),
        }
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, &[u8])) -> Result<(), E>,
    {
        let ip_protocol = self.ip_protocol;
        let ip_version = self.ip_version;
        let _checksum_caps = &cx.checksum_caps();
        let res = self.tx_buffer.dequeue_with(|&mut (), buffer| {
            match IpVersion::of_packet(buffer) {
                
                Ok(IpVersion::Ipv4) => {
                    let mut packet = match Ipv4Packet::new_checked(buffer) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    if packet.next_header() != ip_protocol {
                        net_trace!("raw: sent packet with wrong ip protocol, dropping.");
                        return Ok(());
                    }
                    if _checksum_caps.ipv4.tx() {
                        packet.fill_checksum();
                    } else {
                        // make sure we get a consistently zeroed checksum,
                        // since implementations might rely on it
                        packet.set_checksum(0);
                    }

                    let packet = Ipv4Packet::new_unchecked(&*packet.into_inner());
                    let ipv4_repr = match Ipv4Repr::parse(&packet, _checksum_caps) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv4 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    net_trace!("raw:{}:{}: sending", ip_version, ip_protocol);
                    emit(cx, (IpRepr::Ipv4(ipv4_repr), packet.payload()))
                }
                
                Ok(IpVersion::Ipv6) => {
                    let packet = match Ipv6Packet::new_checked(buffer) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };
                    if packet.next_header() != ip_protocol {
                        net_trace!("raw: sent ipv6 packet with wrong ip protocol, dropping.");
                        return Ok(());
                    }
                    let packet = Ipv6Packet::new_unchecked(&*packet.into_inner());
                    let ipv6_repr = match Ipv6Repr::parse(&packet) {
                        Ok(x) => x,
                        Err(_) => {
                            net_trace!("raw: malformed ipv6 packet in queue, dropping.");
                            return Ok(());
                        }
                    };

                    net_trace!("raw:{}:{}: sending", ip_version, ip_protocol);
                    emit(cx, (IpRepr::Ipv6(ipv6_repr), packet.payload()))
                }
                Err(_) => {
                    net_trace!("raw: sent packet with invalid IP version, dropping.");
                    Ok(())
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
