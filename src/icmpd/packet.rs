use error::{ParsingResult, ParsingError};
use netutils::Checksum;
use std::mem;

#[repr(packed)]
pub struct Header {
    icmp_type: u8,
    icmp_code: u8,
    crc: u16,
}

pub struct Packet<'a> {
    header: &'a Header,
    payload: &'a [u8],
}

pub struct MutPacket<'a> {
    header: &'a mut Header,
    payload: &'a mut [u8],
}

pub enum PacketKind {
    EchoRequest,
    EchoResponse,
    HostUnreachable,
    PortUnreachable,
    ProtoUnreachable,
    Unknown,
}

impl<'a> Packet<'a> {
    pub fn from_bytes<'b>(bytes: &'b [u8]) -> ParsingResult<Packet<'a>>
        where 'b: 'a
    {
        if bytes.len() < mem::size_of::<Header>() {
            Err(ParsingError::NotEnoughData)
        } else {
            let (header_bytes, payload_bytes) = bytes.split_at(mem::size_of::<Header>());
            let packet = Packet {
                header: unsafe { mem::transmute(header_bytes.as_ptr()) },
                payload: payload_bytes,
            };
            if packet.is_checksum_ok() {
                Ok(packet)
            } else {
                Err(ParsingError::IncorrectChecksum)
            }
        }
    }

    fn is_checksum_ok(&self) -> bool {
        let header_ptr = self.header as *const Header as usize;
        let total_size = self.get_total_data_size();
        let mut crc = unsafe { Checksum::sum(header_ptr, total_size) };
        crc -= u16::from_be(self.header.crc) as usize;
        let crc = Checksum::compile(crc);
        crc == u16::from_be(self.header.crc)
    }

    pub fn get_kind(&self) -> PacketKind {
        match (self.header.icmp_type, self.header.icmp_code) {
            (ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE) => PacketKind::EchoRequest,
            (ECHO_RESPONSE_TYPE, ECHO_RESPONSE_CODE) => PacketKind::EchoResponse,
            (UNREACHABLE_TYPE, UNREACHABLE_HOST_CODE) => PacketKind::HostUnreachable,
            (UNREACHABLE_TYPE, UNREACHABLE_PROTO_CODE) => PacketKind::ProtoUnreachable,
            (UNREACHABLE_TYPE, UNREACHABLE_PORT_CODE) => PacketKind::PortUnreachable,
            _ => PacketKind::Unknown,
        }
    }

    pub fn get_payload(&self) -> &[u8] {
        self.payload
    }

    pub fn get_total_data_size(&self) -> usize {
        mem::size_of::<Header>() + self.payload.len()
    }
}

impl<'a> MutPacket<'a> {
    pub fn from_bytes<'b>(bytes: &'b mut [u8]) -> ParsingResult<MutPacket<'a>>
        where 'b: 'a
    {
        if bytes.len() < mem::size_of::<Header>() {
            Err(ParsingError::NotEnoughData)
        } else {
            let (header_bytes, payload_bytes) = bytes.split_at_mut(mem::size_of::<Header>());
            Ok(MutPacket {
                   header: unsafe { mem::transmute(header_bytes.as_ptr()) },
                   payload: payload_bytes,
               })
        }
    }

    pub fn set_kind(&mut self, packet_type: PacketKind) {
        let (new_type, new_code) = match packet_type {
            EchoRequest => (ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE),
            EchoResponse => (ECHO_RESPONSE_TYPE, ECHO_RESPONSE_CODE),
            HostUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_HOST_CODE),
            PortUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_PORT_CODE),
            ProtoUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_PROTO_CODE),
            Unknown => (self.header.icmp_type, self.header.icmp_code),
        };
        self.header.icmp_type = new_type;
        self.header.icmp_code = new_code;
    }

    pub fn compute_checksum(&mut self) {
        self.header.crc = 0;
        let header_ptr = self.header as *mut Header as usize;
        let total_size = mem::size_of::<Header>() + self.payload.len();
        let crc = Checksum::compile(unsafe { Checksum::sum(header_ptr, total_size) });
        self.header.crc = crc
    }

    pub fn get_payload(&mut self) -> &mut [u8] {
        self.payload
    }
}

const ECHO_REQUEST_TYPE: u8 = 8;
const ECHO_REQUEST_CODE: u8 = 0;
const ECHO_RESPONSE_TYPE: u8 = 0;
const ECHO_RESPONSE_CODE: u8 = 0;
const UNREACHABLE_TYPE: u8 = 3;
const UNREACHABLE_HOST_CODE: u8 = 1;
const UNREACHABLE_PROTO_CODE: u8 = 2;
const UNREACHABLE_PORT_CODE: u8 = 3;
