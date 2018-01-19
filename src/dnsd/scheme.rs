use redox_netstack::error::{Error, Result};
use event::{subscribe_to_fd, unsubscribe_from_fd};
use std::borrow::ToOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::btree_map::Entry;
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::RawFd;
use std::str;
use std::rc::Rc;
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use dns_parser::{Builder, Packet as DNSPacket, RRData, ResponseCode};
use dns_parser::{QueryClass, QueryType};

enum DnsFile {
    Resolved { data: Rc<[u8]>, pos: usize },
    Waiting { domain: String },
}

enum Domain {
    Resolved {
        data: Rc<[u8]>,
    },
    Requested {
        waiting_fds: BTreeSet<usize>,
        socket_fd: RawFd,
    },
}

struct Domains {
    domains: BTreeMap<String, Domain>,
    requests: BTreeMap<RawFd, String>,
}

impl Domains {
    fn new() -> Domains {
        Domains {
            domains: BTreeMap::new(),
            requests: BTreeMap::new(),
        }
    }

    fn request_domain(&mut self, domain: &str) -> Option<RawFd> {
        trace!("Requesting domain {}", domain);
        let mut builder = Builder::new_query(1, true);
        builder.add_question(domain, QueryType::A, QueryClass::IN);
        let packet = match builder.build() {
            Ok(packet) => packet,
            _ => return None,
        };
        let udp_fd = match syscall::open(
            "udp:8.8.8.8:53",
            syscall::O_RDWR | syscall::O_CREAT | syscall::O_NONBLOCK,
        ) {
            Ok(fd) => fd as RawFd,
            _ => return None,
        };
        if syscall::write(udp_fd as usize, &packet) != Ok(packet.len()) {
            syscall::close(udp_fd as usize);
            return None;
        }
        trace!("Requesting domain {} fd {}", domain, udp_fd);
        subscribe_to_fd(udp_fd);
        self.requests.insert(udp_fd, domain.to_owned());
        Some(udp_fd)
    }

    fn on_fd_event(&mut self, fd: RawFd) -> Option<BTreeSet<usize>> {
        trace!("On FD event {}", fd);
        let e = match self.requests.entry(fd) {
            Entry::Vacant(_) => {
                return None;
            }
            Entry::Occupied(e) => e,
        };
        let mut buf = [0u8; 4096];
        let readed = match syscall::read(fd as usize, &mut buf) {
            Ok(readed) => readed,
            _ => {
                return None;
            }
        };
        let pkt = match DNSPacket::parse(&buf) {
            Ok(pkt) => pkt,
            _ => {
                return None;
            }
        };
        if pkt.header.response_code != ResponseCode::NoError || pkt.answers.len() == 0 {
            return None;
        }
        let mut result = String::new();
        for answer in pkt.answers {
            match answer.data {
                RRData::A(ip) => {
                    result += &format!("{}\n", ip);
                }
                _ => {} // ignore
            }
        }
        if result.is_empty() {
            return None;
        }
        let data = Rc::from(result.into_bytes());
        syscall::close(fd as usize);
        unsubscribe_from_fd(fd);
        let domain = e.remove();
        let mut domain_data = Domain::Resolved { data };
        trace!("On FD event {} {} resolved", fd, domain);
        match self.domains.entry(domain) {
            Entry::Vacant(e) => {
                e.insert(domain_data);
                None
            }
            Entry::Occupied(mut e) => {
                mem::swap(e.get_mut(), &mut domain_data);
                if let Domain::Requested { waiting_fds, .. } = domain_data {
                    Some(waiting_fds)
                } else {
                    None
                }
            }
        }
    }

    fn file_from_domain(&mut self, domain: &str, fd: usize) -> DnsFile {
        if let Some(mut domain_data) = self.domains.get_mut(domain) {
            match *domain_data {
                Domain::Resolved { ref data } => DnsFile::Resolved {
                    data: Rc::clone(data),
                    pos: 0,
                },
                Domain::Requested {
                    ref mut waiting_fds,
                    ..
                } => {
                    waiting_fds.insert(fd);
                    DnsFile::Waiting {
                        domain: domain.to_owned(),
                    }
                }
            }
        } else {
            if let Some(socket_fd) = self.request_domain(domain) {
                let mut waiting_fds = BTreeSet::new();
                waiting_fds.insert(fd);
                self.domains.insert(
                    domain.to_owned(),
                    Domain::Requested {
                        waiting_fds,
                        socket_fd,
                    },
                );
            }
            DnsFile::Waiting {
                domain: domain.to_owned(),
            }
        }
    }

    fn unwait_fd(&mut self, domain: &str, fd: usize) {
        if let Some(mut domain_data) = self.domains.get_mut(domain) {
            if let Domain::Requested {
                ref mut waiting_fds,
                ..
            } = *domain_data
            {
                waiting_fds.remove(&fd);
            }
        }
    }
}

pub struct Dnsd {
    dns_file: File,
    time_file: File,
    files: BTreeMap<usize, DnsFile>,
    domains: Domains,
    wait_map: BTreeMap<usize, SyscallPacket>,
    next_fd: usize,
}

impl Dnsd {
    pub fn new(dns_file: File, time_file: File) -> Dnsd {
        Dnsd {
            dns_file,
            time_file,
            files: BTreeMap::new(),
            domains: Domains::new(),
            wait_map: BTreeMap::new(),
            next_fd: 1,
        }
    }

    pub fn on_time_event(&mut self) -> Result<Option<()>> {
        Ok(None)
    }

    pub fn on_dns_file_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = SyscallPacket::default();
            if self.dns_file.read(&mut packet)? == 0 {
                break;
            }
            let a = packet.a;
            self.handle(&mut packet);
            if packet.a != (-syscall::EWOULDBLOCK) as usize {
                self.dns_file.write_all(&packet)?;
            } else {
                packet.a = a;
                self.handle_block(packet)?;
            }
        }
        Ok(None)
    }

    pub fn on_unknown_fd_event(&mut self, fd: RawFd) -> Result<Option<()>> {
        trace!("Unknown fd event {}", fd);
        if let Some(fds_to_wakeup) = self.domains.on_fd_event(fd) {
            let mut syscall_packets = vec![];
            for fd in &fds_to_wakeup {
                if let Some(packet) = self.wait_map.remove(&fd) {
                    syscall_packets.push(packet);
                }
            }

            for mut packet in syscall_packets.drain(..) {
                self.handle(&mut packet);
                let _ = self.dns_file.write_all(&packet);
            }
        }
        Ok(None)
    }

    fn handle_block(&mut self, packet: SyscallPacket) -> Result<()> {
        let fd = packet.b;
        self.wait_map.insert(fd, packet);
        Ok(())
    }
}

impl SchemeMut for Dnsd {
    fn open(&mut self, url: &[u8], flags: usize, _uid: u32, _gid: u32) -> SyscallResult<usize> {
        trace!("Open");
        let domain = str::from_utf8(url).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
        trace!("Open {}", &domain);
        if domain.is_empty() {
            return Err(SyscallError::new(syscall::EINVAL));
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        let dns_file = self.domains.file_from_domain(domain, fd);
        self.files.insert(fd, dns_file);
        trace!("Open {} {}", &domain, fd);
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        trace!("Close {}", fd);
        let mut file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if let DnsFile::Waiting { ref domain } = *file {
            self.domains.unwait_fd(domain, fd);
        }

        self.files.remove(&fd);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        Err(SyscallError::new(syscall::EINVAL))
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        trace!("Read {}", fd);
        let mut file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if let DnsFile::Waiting { ref domain } = *file {
            *file = self.domains.file_from_domain(domain, fd)
        }

        match *file {
            DnsFile::Resolved {
                ref data,
                ref mut pos,
            } => {
                let mut i = 0;
                while i < buf.len() && *pos < data.len() {
                    buf[i] = data[*pos];
                    i += 1;
                    *pos += 1;
                }
                Ok(i)
            }
            DnsFile::Waiting { .. } => Err(SyscallError::new(syscall::EWOULDBLOCK)),
        }
    }

    fn fevent(&mut self, fd: usize, events: usize) -> SyscallResult<usize> {
        Ok(0)
    }

    fn fsync(&mut self, fd: usize) -> SyscallResult<usize> {
        Ok(0)
    }
}
