use error::{Result, Error, PacketError};
use netutils::{Ipv4, Ipv4Header, Checksum, n16};
use netutils;
use packet::{Header, Packet, MutPacket, PacketKind, SubHeader, EchoHeader};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use syscall::SchemeMut;
use syscall;

//Some reasonable limits, 65k is a waste of memory
const MAX_PACKET_SIZE: usize = 2048;
const MAX_ICMP_PAYLOAD_SIZE: usize = 2000;

enum HandleType {
    Echo,
}

struct Handle {
    handle_type: HandleType,
    events: usize,
    flags: usize,
    ip_addr: Ipv4Addr,
    payload_queue: VecDeque<Vec<u8>>,
    seq: u16,
}

impl Handle {
    pub fn new(handle_type: HandleType, ip_addr: Ipv4Addr, flags: usize) -> Handle {
        Handle {
            handle_type,
            events: 0,
            ip_addr,
            payload_queue: VecDeque::new(),
            flags,
            seq: 0,
        }
    }
}

pub struct Icmpd {
    icmp_file: File,
    scheme_file: File,
    next_fd: usize,
    echo_ips: BTreeMap<Ipv4Addr, HashSet<usize>>,
    handles: BTreeMap<usize, Handle>,
}

impl Icmpd {
    pub fn new(icmp_file: File, scheme_file: File) -> Icmpd {
        Icmpd {
            icmp_file,
            scheme_file,
            next_fd: 0,
            echo_ips: BTreeMap::new(),
            handles: BTreeMap::new(),
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.scheme_file.read(&mut packet)? == 0 {
                break;
            }
            self.handle(&mut packet);
        }
        Ok(None)
    }

    pub fn on_icmp_packet(&mut self) -> Result<Option<()>> {
        let mut packet_buffer = [0; MAX_PACKET_SIZE];
        loop {
            let bytes_readed =
                self.icmp_file
                    .read(&mut packet_buffer)
                    .map_err(|e| Error::from_io_error(e, "failed to read a packet from ip:1"))?;
            if bytes_readed == 0 {
                break;
            }
            let ip_packet = Ipv4::from_bytes(&packet_buffer[..bytes_readed])
                .ok_or(Error::from_parsing_error(PacketError::NotEnoughData,
                                                 "failed to parse ip header"))?;
            let icmp_packet =
                Packet::from_bytes(&ip_packet.data)
                    .map_err(|e| Error::from_parsing_error(e, "failed to parse ICMP packet"))?;

            match icmp_packet.get_kind() {
                PacketKind::EchoRequest => self.on_echo_request(&ip_packet, &icmp_packet)?,
                PacketKind::EchoResponse => self.on_echo_response(&ip_packet, &icmp_packet)?,
                _ => (),
            }
        }
        Ok(None)
    }

    fn on_echo_request(&mut self, ip_packet: &Ipv4, icmp_packet: &Packet) -> Result<()> {
        let echo_response = produce_icmp_packet(Ipv4Addr::from(ip_packet.header.src.bytes),
                                                PacketKind::EchoResponse,
                                                &SubHeader::None,
                                                icmp_packet.get_payload())?;
        self.icmp_file
            .write(&echo_response)
            .map_err(|e| Error::from_io_error(e, " can't send an echo response packet"))
            .map(|_| ())
    }

    fn on_echo_response(&mut self, ip_packet: &Ipv4, icmp_packet: &Packet) -> Result<()> {
        if let Some(fd_set) = self.echo_ips
               .get_mut(&Ipv4Addr::from(ip_packet.header.src.bytes)) {
            for fd in fd_set.iter() {
                if let Some(handle) = self.handles.get_mut(fd) {
                    if let &SubHeader::Echo(echo_subheader) = icmp_packet.get_subheader() {
                        if echo_subheader.get_id() == *fd as u16 {
                            handle
                                .payload_queue
                                .push_back(Vec::from(icmp_packet.get_payload()));
                            post_fevent(&mut self.scheme_file,
                                        *fd,
                                        syscall::EVENT_READ,
                                        icmp_packet.get_payload().len())?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn open_echo(&mut self, ip_addr: Ipv4Addr, flags: usize) -> syscall::Result<usize> {
        let fd = self.next_fd;
        self.next_fd += 1;
        let handle = Handle::new(HandleType::Echo, ip_addr, flags);
        self.handles.insert(fd, handle);
        self.echo_ips
            .entry(ip_addr)
            .or_insert_with(|| HashSet::new())
            .insert(fd);
        Ok(fd)
    }

    fn read_echo(handle: &mut Handle, buf: &mut [u8]) -> syscall::Result<usize> {
        if let Some(payload) = handle.payload_queue.pop_front() {
            //TODO replace with a proper memcpy
            let mut i = 0;
            while i < buf.len() && i < payload.len() {
                buf[i] = payload[i];
                i += 1;
            }
            Ok(i)
        } else {
            Ok(0)
        }
    }
}

impl SchemeMut for Icmpd {
    fn open(&mut self, url: &[u8], flags: usize, _uid: u32, _gid: u32) -> syscall::Result<usize> {
        use std::str;
        use std::str::FromStr;

        // if uid != 0 {
        //     return Err(syscall::Error::new(syscall::EACCES));
        // }

        let path = str::from_utf8(url)
            .or(Err(syscall::Error::new(syscall::EINVAL)))?;
        let mut parts = path.split("/");
        let method = parts.next().ok_or(syscall::Error::new(syscall::EINVAL))?;
        match method {
            "echo" => {
                let addr = parts.next().ok_or(syscall::Error::new(syscall::EINVAL))?;
                let addr = Ipv4Addr::from_str(&addr)
                    .map_err(|_| syscall::Error::new(syscall::EINVAL))?;
                self.open_echo(addr, flags)
            }
            _ => Err(syscall::Error::new(syscall::EINVAL)),
        }
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        let (ip, ip_set) = {
            let handle = self.handles
                .get_mut(&fd)
                .ok_or(syscall::Error::new(syscall::EBADF))?;
            match handle.handle_type {
                HandleType::Echo => (handle.ip_addr, &mut self.echo_ips),
            }
        };
        self.handles.remove(&fd);
        let remove_ip = if let Some(fd_set) = ip_set.get_mut(&ip) {
            fd_set.remove(&fd);
            fd_set.is_empty()
        } else {
            false
        };

        if remove_ip {
            ip_set.remove(&ip);
        }

        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        if buf.len() > MAX_ICMP_PAYLOAD_SIZE {
            return Err(syscall::Error::new(syscall::EMSGSIZE));
        }
        let handle = self.handles
            .get_mut(&fd)
            .ok_or(syscall::Error::new(syscall::EBADF))?;
        match handle.handle_type {
            HandleType::Echo => {
                let echo_request =
                    produce_icmp_packet(handle.ip_addr,
                                        PacketKind::EchoRequest,
                                        &SubHeader::Echo(&EchoHeader::new(fd as u16, handle.seq)),
                                        buf)
                            .map_err(|_| syscall::Error::new(syscall::EPROTO))?;
                handle.seq += 1;
                self.icmp_file
                    .write(&echo_request)
                    .map_err(|_| syscall::Error::new(syscall::EPROTO))
            }
        }
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        let handle = self.handles
            .get_mut(&fd)
            .ok_or(syscall::Error::new(syscall::EBADF))?;
        match handle.handle_type {
            HandleType::Echo => Icmpd::read_echo(handle, buf),
        }
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        let handle = self.handles
            .get_mut(&fd)
            .ok_or(syscall::Error::new(syscall::EBADF))?;
        handle.events = events;
        Ok(fd)
    }
}

fn produce_icmp_packet(to_ip: Ipv4Addr,
                       kind: PacketKind,
                       subheader: &SubHeader,
                       payload: &[u8])
                       -> Result<Vec<u8>> {
    let mut ip_data = vec![0; MutPacket::get_total_header_size(subheader) + payload.len()];
    {
        let mut out_icmp_packet =
            MutPacket::from_bytes(&mut ip_data)
                .map_err(|e| Error::from_parsing_error(e, "can't parse empty icmp header"))?;
        out_icmp_packet = out_icmp_packet
            .set_subheader(subheader)
            .map_err(|e| Error::from_parsing_error(e, "can't set subheader"))?;
        out_icmp_packet.set_kind(kind);
        {
            let out_payload = out_icmp_packet.get_payload();
            if out_payload.len() != payload.len() {
                return Err(Error::from_parsing_error(PacketError::NotEnoughData,
                                                     " can't copy icmp payload to echo response"));
            }
            //WARNING: copy_from_slice can panic if the slices' lengths are different
            out_payload.copy_from_slice(payload);
        }
        out_icmp_packet.compute_checksum();
    }
    let out_ip_packet = Ipv4 {
        header: Ipv4Header {
            ver_hlen: 0x45,
            services: 0,
            len: n16::new((ip_data.len() + mem::size_of::<Ipv4Header>()) as u16),
            id: n16::new(0),
            flags_fragment: n16::new(0),
            ttl: 64,
            proto: 1,
            checksum: Checksum { data: 0 },
            src: netutils::Ipv4Addr::NULL,
            dst: netutils::Ipv4Addr { bytes: to_ip.octets() },
        },
        options: Vec::new(),
        data: ip_data,
    };
    Ok(out_ip_packet.to_bytes())
}

fn post_fevent(scheme_file: &mut File, fd: usize, event: usize, data_len: usize) -> Result<()> {
    scheme_file
        .write(&syscall::Packet {
                   id: 0,
                   pid: 0,
                   uid: 0,
                   gid: 0,
                   a: syscall::number::SYS_FEVENT,
                   b: fd,
                   c: event,
                   d: data_len,
               })
        .map(|_| ())
        .map_err(|e| Error::from_io_error(e, "failed to post fevent"))
}
