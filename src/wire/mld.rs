// Packet implementation for the Multicast Listener Discovery
// protocol. See [RFC 3810] and [RFC 2710].
//
// [RFC 3810]: https://tools.ietf.org/html/rfc3810
// [RFC 2710]: https://tools.ietf.org/html/rfc2710

use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};
use crate::wire::icmpv6::{field, Message, Packet};
use crate::wire::{Ipv6Address, Ipv6AddressExt};

enum_with_unknown! {
    /// MLDv2 Multicast Listener Report Record Type. See [RFC 3810 § 5.2.12] for
    /// more details.
    ///
    /// [RFC 3810 § 5.2.12]: https://tools.ietf.org/html/rfc3010#section-5.2.12
    pub enum RecordType(u8) {
        /// Interface has a filter mode of INCLUDE for the specified multicast address.
        ModeIsInclude   = 0x01,
        /// Interface has a filter mode of EXCLUDE for the specified multicast address.
        ModeIsExclude   = 0x02,
        /// Interface has changed to a filter mode of INCLUDE for the specified
        /// multicast address.
        ChangeToInclude = 0x03,
        /// Interface has changed to a filter mode of EXCLUDE for the specified
        /// multicast address.
        ChangeToExclude = 0x04,
        /// Interface wishes to listen to the sources in the specified list.
        AllowNewSources = 0x05,
        /// Interface no longer wishes to listen to the sources in the specified list.
        BlockOldSources = 0x06
    }
}

/// Getters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the maximum response code field.
    #[inline]
    pub fn max_resp_code(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::MAX_RESP_CODE])
    }

    /// Return the address being queried.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::QUERY_MCAST_ADDR])
    }

    /// Return the Suppress Router-Side Processing flag.
    #[inline]
    pub fn s_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[field::SQRV] & 0x08) != 0
    }

    /// Return the Querier's Robustness Variable.
    #[inline]
    pub fn qrv(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::SQRV] & 0x7
    }

    /// Return the Querier's Query Interval Code.
    #[inline]
    pub fn qqic(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::QQIC]
    }

    /// Return number of sources.
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::QUERY_NUM_SRCS])
    }
}

/// Getters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the number of Multicast Address Records.
    #[inline]
    pub fn nr_mcast_addr_rcrds(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::NR_MCAST_RCRDS])
    }
}

/// Setters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the maximum response code field.
    #[inline]
    pub fn set_max_resp_code(&mut self, code: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::MAX_RESP_CODE], code);
    }

    /// Set the address being queried.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        let data = self.buffer.as_mut();
        data[field::QUERY_MCAST_ADDR].copy_from_slice(&addr.octets());
    }

    /// Set the Suppress Router-Side Processing flag.
    #[inline]
    pub fn set_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        let current = data[field::SQRV];
        data[field::SQRV] = 0x8 | (current & 0x7);
    }

    /// Clear the Suppress Router-Side Processing flag.
    #[inline]
    pub fn clear_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        data[field::SQRV] &= 0x7;
    }

    /// Set the Querier's Robustness Variable.
    #[inline]
    pub fn set_qrv(&mut self, value: u8) {
        assert!(value < 8);
        let data = self.buffer.as_mut();
        data[field::SQRV] = (data[field::SQRV] & 0x8) | value & 0x7;
    }

    /// Set the Querier's Query Interval Code.
    #[inline]
    pub fn set_qqic(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::QQIC] = value;
    }

    /// Set number of sources.
    #[inline]
    pub fn set_num_srcs(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::QUERY_NUM_SRCS], value);
    }
}

/// Setters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the number of Multicast Address Records.
    #[inline]
    pub fn set_nr_mcast_addr_rcrds(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::NR_MCAST_RCRDS], value)
    }
}

/// A read/write wrapper around an MLDv2 Listener Report Message Address Record.
#[derive(Debug, PartialEq, Eq, Clone)]

pub struct AddressRecord<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Imbue a raw octet buffer with a Address Record structure.
    pub const fn new_unchecked(buffer: T) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::RECORD_MCAST_ADDR.end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

/// Getters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[inline]
    pub fn record_type(&self) -> RecordType {
        let data = self.buffer.as_ref();
        RecordType::from(data[field::RECORD_TYPE])
    }

    /// Return the length of the auxiliary data.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::AUX_DATA_LEN]
    }

    /// Return the number of sources field.
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::RECORD_NUM_SRCS])
    }

    /// Return the multicast address field.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        Ipv6Address::from_bytes(&data[field::RECORD_MCAST_ADDR])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AddressRecord<&'a T> {
    /// Return a pointer to the address records.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::RECORD_MCAST_ADDR.end..]
    }
}

/// Setters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsMut<[u8]> + AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[inline]
    pub fn set_record_type(&mut self, rty: RecordType) {
        let data = self.buffer.as_mut();
        data[field::RECORD_TYPE] = rty.into();
    }

    /// Return the length of the auxiliary data.
    #[inline]
    pub fn set_aux_data_len(&mut self, len: u8) {
        let data = self.buffer.as_mut();
        data[field::AUX_DATA_LEN] = len;
    }

    /// Return the number of sources field.
    #[inline]
    pub fn set_num_srcs(&mut self, num_srcs: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::RECORD_NUM_SRCS], num_srcs);
    }

    /// Return the multicast address field.
    ///
    /// # Panics
    /// This function panics if the given address is not a multicast address.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        assert!(addr.is_multicast());
        let data = self.buffer.as_mut();
        data[field::RECORD_MCAST_ADDR].copy_from_slice(&addr.octets());
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressRecord<T> {
    /// Return a pointer to the address records.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::RECORD_MCAST_ADDR.end..]
    }
}

/// A high level representation of an MLDv2 Listener Report Message Address Record.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub struct AddressRecordRepr<'a> {
    pub record_type: RecordType,
    pub aux_data_len: u8,
    pub num_srcs: u16,
    pub mcast_addr: Ipv6Address,
    pub payload: &'a [u8],
}

impl<'a> AddressRecordRepr<'a> {
    /// Create a new MLDv2 address record representation with an empty payload.
    pub const fn new(record_type: RecordType, mcast_addr: Ipv6Address) -> Self {
        Self {
            record_type,
            aux_data_len: 0,
            num_srcs: 0,
            mcast_addr,
            payload: &[],
        }
    }

    /// Parse an MLDv2 address record and return a high-level representation.
    pub fn parse<T>(record: &AddressRecord<&'a T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Self {
            num_srcs: record.num_srcs(),
            mcast_addr: record.mcast_addr(),
            record_type: record.record_type(),
            aux_data_len: record.aux_data_len(),
            payload: record.payload(),
        })
    }

    /// Return the length of a record that will be emitted from this high-level
    /// representation, not including any payload data.
    pub fn buffer_len(&self) -> usize {
        field::RECORD_MCAST_ADDR.end
    }

    /// Emit a high-level representation into an MLDv2 address record.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, record: &mut AddressRecord<T>) {
        record.set_record_type(self.record_type);
        record.set_aux_data_len(self.aux_data_len);
        record.set_num_srcs(self.num_srcs);
        record.set_mcast_addr(self.mcast_addr);
    }
}

/// A high-level representation of an MLDv2 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub enum Repr<'a> {
    Query {
        max_resp_code: u16,
        mcast_addr: Ipv6Address,
        s_flag: bool,
        qrv: u8,
        qqic: u8,
        num_srcs: u16,
        data: &'a [u8],
    },
    Report {
        nr_mcast_addr_rcrds: u16,
        data: &'a [u8],
    },
    ReportRecordReprs(&'a [AddressRecordRepr<'a>]),
}

impl<'a> Repr<'a> {
    /// Parse an MLDv2 packet and return a high-level representation.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;
        match packet.msg_type() {
            Message::MldQuery => Ok(Repr::Query {
                max_resp_code: packet.max_resp_code(),
                mcast_addr: packet.mcast_addr(),
                s_flag: packet.s_flag(),
                qrv: packet.qrv(),
                qqic: packet.qqic(),
                num_srcs: packet.num_srcs(),
                data: packet.payload(),
            }),
            Message::MldReport => Ok(Repr::Report {
                nr_mcast_addr_rcrds: packet.nr_mcast_addr_rcrds(),
                data: packet.payload(),
            }),
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        match self {
            Repr::Query { data, .. } => field::QUERY_NUM_SRCS.end + data.len(),
            Repr::Report { data, .. } => field::NR_MCAST_RCRDS.end + data.len(),
            Repr::ReportRecordReprs(_data) => field::NR_MCAST_RCRDS.end,
        }
    }

    /// Emit a high-level representation into an MLDv2 packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        match self {
            Repr::Query {
                max_resp_code,
                mcast_addr,
                s_flag,
                qrv,
                qqic,
                num_srcs,
                data,
            } => {
                packet.set_msg_type(Message::MldQuery);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_max_resp_code(*max_resp_code);
                packet.set_mcast_addr(*mcast_addr);
                if *s_flag {
                    packet.set_s_flag();
                } else {
                    packet.clear_s_flag();
                }
                packet.set_qrv(*qrv);
                packet.set_qqic(*qqic);
                packet.set_num_srcs(*num_srcs);
                packet.payload_mut().copy_from_slice(&data[..]);
            }
            Repr::Report {
                nr_mcast_addr_rcrds,
                data,
            } => {
                packet.set_msg_type(Message::MldReport);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_nr_mcast_addr_rcrds(*nr_mcast_addr_rcrds);
                packet.payload_mut().copy_from_slice(&data[..]);
            }
            Repr::ReportRecordReprs(records) => {
                packet.set_msg_type(Message::MldReport);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_nr_mcast_addr_rcrds(records.len() as u16);
                let mut payload = packet.payload_mut();
                for record in *records {
                    record.emit(&mut AddressRecord::new_unchecked(&mut *payload));
                    payload = &mut payload[record.buffer_len()..];
                }
            }
        }
    }
}
