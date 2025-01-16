/*! Communication between endpoints.

The `socket` module deals with *network endpoints* and *buffering*.
It provides interfaces for accessing buffers of data, and protocol state machines
for filling and emptying these buffers.

The programming interface implemented here differs greatly from the common Berkeley socket
interface. Specifically, in the Berkeley interface the buffering is implicit:
the operating system decides on the good size for a buffer and manages it.
The interface implemented by this module uses explicit buffering: you decide on the good
size for a buffer, allocate it, and let the networking stack use it.
*/

use crate::iface::Context;
use crate::time::Instant;

pub mod dhcpv4;
pub mod icmp;
pub mod raw;
pub mod tcp;
pub mod udp;

/// Gives an indication on the next time the socket should be polled.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]

pub(crate) enum PollAt {
    /// The socket needs to be polled immediately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value to a concrete socket, use the [AnySocket] trait,
/// e.g. to get `udp::Socket`, call `udp::Socket::downcast(socket)`.
///
/// It is usually more convenient to use [SocketSet::get] instead.
///
/// [AnySocket]: trait.AnySocket.html
/// [SocketSet::get]: struct.SocketSet.html#method.get
#[derive(Debug)]
pub enum Socket<'a> {
    Raw(raw::Socket<'a>),
    Icmp(icmp::Socket<'a>),
    Udp(udp::Socket<'a>),
    Tcp(tcp::Socket<'a>),
    Dhcpv4(dhcpv4::Socket<'a>),
}

impl<'a> Socket<'a> {
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        match self {
            Socket::Raw(s) => s.poll_at(cx),
            Socket::Icmp(s) => s.poll_at(cx),
            Socket::Udp(s) => s.poll_at(cx),
            Socket::Tcp(s) => s.poll_at(cx),
            Socket::Dhcpv4(s) => s.poll_at(cx),
        }
    }
}

/// A conversion trait for network sockets.
pub trait AnySocket<'a> {
    fn upcast(self) -> Socket<'a>;
    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self>
    where
        Self: Sized;
    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized;
}

macro_rules! from_socket {
    ($socket:ty, $variant:ident) => {
        impl<'a> AnySocket<'a> for $socket {
            fn upcast(self) -> Socket<'a> {
                Socket::$variant(self)
            }

            fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }

            fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self> {
                #[allow(unreachable_patterns)]
                match socket {
                    Socket::$variant(socket) => Some(socket),
                    _ => None,
                }
            }
        }
    };
}

from_socket!(raw::Socket<'a>, Raw);
from_socket!(icmp::Socket<'a>, Icmp);
from_socket!(udp::Socket<'a>, Udp);
from_socket!(tcp::Socket<'a>, Tcp);
from_socket!(dhcpv4::Socket<'a>, Dhcpv4);
