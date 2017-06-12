use error::{PacketResult, PacketError};
use netutils::Checksum;
use std::mem;

#[repr(packed)]
pub struct Header {
    icmp_type: u8,
    icmp_code: u8,
    crc: u16,
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct EchoHeader {
    id: u16,
    seq: u16,
}

pub enum SubHeader<'a> {
    Echo(&'a EchoHeader),
    None,
}

pub struct Packet<'a> {
    header: &'a Header,
    payload: &'a [u8],
    subheader: SubHeader<'a>,
}

pub struct MutPacket<'a> {
    header: &'a mut Header,
    payload: &'a mut [u8],
    subheader: SubHeader<'a>,
}

pub enum PacketKind {
    EchoRequest,
    EchoResponse,
    HostUnreachable,
    PortUnreachable,
    ProtoUnreachable,
    Unknown,
}

impl EchoHeader {
    pub fn new(id: u16, seq: u16) -> EchoHeader {
        EchoHeader {
            id: id.to_be(),
            seq: seq.to_be(),
        }
    }

    pub fn get_id(&self) -> u16 {
        u16::from_be(self.id)
    }

    pub fn get_seq(&self) -> u16 {
        u16::from_be(self.seq)
    }
}

impl<'a> SubHeader<'a> {
    pub fn get_size(&self) -> usize {
        match *self {
            SubHeader::None => 0,
            SubHeader::Echo(_) => mem::size_of::<EchoHeader>(),
        }
    }
}

impl<'a> Packet<'a> {
    pub fn from_bytes<'b>(bytes: &'b [u8]) -> PacketResult<Packet<'a>>
        where 'b: 'a
    {
        if bytes.len() < mem::size_of::<Header>() {
            Err(PacketError::NotEnoughData)
        } else {
            let (header_bytes, payload_bytes) = bytes.split_at(mem::size_of::<Header>());
            let mut packet = Packet {
                header: unsafe { mem::transmute(header_bytes.as_ptr()) },
                payload: payload_bytes,
                subheader: SubHeader::None,
            };
            if !packet.is_checksum_ok() {
                return Err(PacketError::IncorrectChecksum);
            }
            match packet.get_kind() {
                PacketKind::EchoResponse => {
                    if packet.payload.len() < mem::size_of::<EchoHeader>() {
                        return Err(PacketError::NoEchoHeader);
                    }
                    let (echo_header_payload, payload) =
                        packet.payload.split_at(mem::size_of::<EchoHeader>());
                    packet.subheader =
                        SubHeader::Echo(unsafe { mem::transmute(echo_header_payload.as_ptr()) });
                    packet.payload = payload;
                    Ok(packet)
                }
                _ => Ok(packet),
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
        mem::size_of::<Header>() + self.subheader.get_size() + self.payload.len()
    }

    pub fn get_subheader(&self) -> &SubHeader<'a> {
        &self.subheader
    }
}

impl<'a> MutPacket<'a> {
    pub fn from_bytes<'b>(bytes: &'b mut [u8]) -> PacketResult<MutPacket<'a>>
        where 'b: 'a
    {
        if bytes.len() < mem::size_of::<Header>() {
            Err(PacketError::NotEnoughData)
        } else {
            let (header_bytes, payload_bytes) = bytes.split_at_mut(mem::size_of::<Header>());
            Ok(MutPacket {
                   header: unsafe { mem::transmute(header_bytes.as_ptr()) },
                   payload: payload_bytes,
                   subheader: SubHeader::None,
               })
        }
    }

    pub fn set_subheader(self, subheader: &SubHeader) -> PacketResult<MutPacket<'a>> {
        match self.subheader {
            SubHeader::None => {}
            _ => return Err(PacketError::SubheaderAlreadPresent),
        };

        if self.payload.len() < subheader.get_size() {
            return Err(PacketError::NotEnoughData);
        }

        let (subheader_bytes, new_payload) = self.payload.split_at_mut(subheader.get_size());
        let new_subheader = match *subheader {
            SubHeader::Echo(echo_sub_header) => {
                let echo_sub_header_mut: &mut EchoHeader =
                    unsafe { mem::transmute(subheader_bytes.as_ptr()) };
                *echo_sub_header_mut = echo_sub_header.clone();
                SubHeader::Echo(echo_sub_header_mut)
            }
            SubHeader::None => SubHeader::None,
        };
        Ok(MutPacket {
               header: self.header,
               payload: new_payload,
               subheader: new_subheader,
           })
    }

    pub fn set_kind(&mut self, packet_type: PacketKind) {
        let (new_type, new_code) = match packet_type {
            PacketKind::EchoRequest => (ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE),
            PacketKind::EchoResponse => (ECHO_RESPONSE_TYPE, ECHO_RESPONSE_CODE),
            PacketKind::HostUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_HOST_CODE),
            PacketKind::PortUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_PORT_CODE),
            PacketKind::ProtoUnreachable => (UNREACHABLE_TYPE, UNREACHABLE_PROTO_CODE),
            PacketKind::Unknown => (self.header.icmp_type, self.header.icmp_code),
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

    pub fn get_total_header_size(subheader: &SubHeader) -> usize {
        mem::size_of::<Header>() + subheader.get_size()
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
