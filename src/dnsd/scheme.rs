use redox_netstack::error::{Error, Result};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::RawFd;
use std::str;
use std::rc::Rc;
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

enum DnsFile {
    Resolved { data: Rc<[u8]>, pos: usize },
    Waiting { domain: String },
}

enum Domain {
    Resolved { data: Rc<[u8]> },
    Requested { waiting_fds: Vec<usize> },
}

pub struct Dnsd {
    dns_file: File,
    time_file: File,
    files: BTreeMap<usize, DnsFile>,
    domains: BTreeMap<String, Domain>,
    next_fd: usize,
}

impl Dnsd {
    pub fn new(dns_file: File, time_file: File) -> Dnsd {
        Dnsd {
            dns_file,
            time_file,
            files: BTreeMap::new(),
            domains: BTreeMap::new(),
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
        Ok(None)
    }

    fn handle_block(&mut self, mut packet: SyscallPacket) -> Result<()> {
        Ok(())
    }

    fn request_domain(&mut self, domain: &str, fd: usize) {}
}

impl SchemeMut for Dnsd {
    fn open(&mut self, url: &[u8], flags: usize, _uid: u32, _gid: u32) -> SyscallResult<usize> {
        let domain : String = str::from_utf8(url)
            .or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?
            .into();
        if domain.is_empty() {
            return Err(SyscallError::new(syscall::EINVAL));
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        let dns_file = if let Some(mut domain_data) = self.domains.get_mut(&domain) {
            match *domain_data {
                Domain::Resolved { ref data } => DnsFile::Resolved {
                    data: Rc::clone(data),
                    pos: 0,
                },
                Domain::Requested {
                    ref mut waiting_fds,
                } => {
                    waiting_fds.push(fd);
                    DnsFile::Waiting { domain }
                }
            }
        } else {
            self.request_domain(&domain, fd);
            DnsFile::Waiting { domain }
        };
        self.files.insert(fd, dns_file);
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        self.files.remove(&fd);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        Err(SyscallError::new(syscall::EINVAL))
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        let file = self.files.get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        Ok(0)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> SyscallResult<usize> {
        Ok(0)
    }

    fn fsync(&mut self, fd: usize) -> SyscallResult<usize> {
        Ok(0)
    }
}
