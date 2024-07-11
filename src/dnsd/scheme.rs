use std::borrow::ToOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::VecDeque;
use std::collections::btree_map::Entry;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::os::unix::io::RawFd;
use std::str;
use std::str::FromStr;
use std::rc::Rc;
use std::net::Ipv4Addr;

use libredox::flag;
use syscall::data::TimeSpec;
use syscall::{Error as SyscallError, EventFlags as SyscallEventFlags, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use event::EventQueue;
use redox_netstack::error::{Error, Result};

use dns_parser::{Builder, Packet as DNSPacket, RRData, ResponseCode};
use dns_parser::{QueryClass, QueryType};

use crate::EventSource;

enum DnsFile {
    Resolved { data: Rc<[u8]>, pos: usize },
    Waiting { domain: String },
    Timeout,
    Failed,
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

enum DnsParsingResult {
    WakeUpFiles(BTreeSet<usize>),
    FailFiles(BTreeSet<usize>),
}

struct Domains {
    nameserver: Ipv4Addr,
    domains: BTreeMap<Rc<str>, Domain>,
    requests: BTreeMap<RawFd, Rc<str>>,
    resolved_timeouts: VecDeque<(TimeSpec, Rc<str>)>,
    requested_timeouts: VecDeque<(TimeSpec, Rc<str>)>,
}

impl Domains {
    fn new() -> Domains {
        let mut domains = Domains {
            nameserver: Ipv4Addr::new(8, 8, 8, 8),
            domains: BTreeMap::new(),
            requests: BTreeMap::new(),
            resolved_timeouts: VecDeque::new(),
            requested_timeouts: VecDeque::new(),
        };
        domains.update_nameserver();
        domains
    }

    pub fn update_nameserver(&mut self) {
        if let Ok(mut file) = File::open("/scheme/netcfg/resolv/nameserver") {
            let mut nameserver = String::new();
            if file.read_to_string(&mut nameserver).is_ok() {
                if let Some(line) = nameserver.lines().next() {
                    if let Ok(ip) = Ipv4Addr::from_str(line) {
                        trace!("Changing nameserver to {}", ip);
                        self.nameserver = ip;
                    }
                }
            }
        }
    }

    fn request_domain(&mut self, domain: &str, queue: &EventQueue<EventSource>) -> Option<RawFd> {
        trace!("Requesting domain {}", domain);
        let mut builder = Builder::new_query(1, true);
        builder.add_question(domain, QueryType::A, QueryClass::IN);
        let packet = builder.build().ok()?;
        let udp_fd = libredox::call::open(
            &format!("udp:{}:53", self.nameserver),
            libredox::flag::O_RDWR | libredox::flag::O_CREAT | libredox::flag::O_NONBLOCK,
            0,
        ).ok()?;
        if libredox::call::write(udp_fd, &packet) != Ok(packet.len()) {
            libredox::call::close(udp_fd).ok()?;
            return None;
        }
        queue.subscribe(udp_fd, EventSource::Other, event::EventFlags::READ).ok()?;
        self.requests.insert(udp_fd as RawFd, domain.to_owned().into());
        Some(udp_fd as RawFd)
    }

    fn on_time_event(&mut self, cur_time: &TimeSpec, queue: &EventQueue<EventSource>) -> Result<BTreeSet<usize>> {
        while let Some((timeout, domain)) = self.resolved_timeouts.pop_front() {
            if timeout.tv_sec > cur_time.tv_sec
                || (timeout.tv_sec == cur_time.tv_sec && timeout.tv_nsec > cur_time.tv_nsec)
            {
                self.resolved_timeouts.push_front((timeout, domain));
                break;
            }
            trace!("Timing out resolved domain {:?}", domain);
            match self.domains.entry(domain) {
                Entry::Vacant(_) => {}
                Entry::Occupied(e) => {
                    if let Domain::Resolved { .. } = *e.get() {
                        e.remove();
                    }
                }
            }
        }

        let mut fds_to_wakeup = BTreeSet::new();

        while let Some((timeout, domain)) = self.requested_timeouts.pop_front() {
            if timeout.tv_sec > cur_time.tv_sec
                || (timeout.tv_sec == cur_time.tv_sec && timeout.tv_nsec > cur_time.tv_nsec)
            {
                self.requested_timeouts.push_front((timeout, domain));
                break;
            }
            trace!("Timing out requested domain {:?}", domain);
            match self.domains.entry(domain) {
                Entry::Vacant(_) => {}
                Entry::Occupied(e) => {
                    if let Domain::Requested { .. } = *e.get() {
                        if let Domain::Requested {
                            mut waiting_fds,
                            socket_fd,
                        } = e.remove()
                        {
                            fds_to_wakeup.append(&mut waiting_fds);
                            queue.unsubscribe(socket_fd as usize).map_err(|e| Error::from_syscall_error(e.into(), "unsubscribe failure"))?;
                            let _ = libredox::call::close(socket_fd as usize);
                        }
                    }
                }
            }
        }

        Ok(fds_to_wakeup)
    }

    fn on_fd_event(&mut self, fd: RawFd, cur_time: &TimeSpec, queue: &EventQueue<EventSource>) -> Option<DnsParsingResult> {
        let e = match self.requests.entry(fd) {
            Entry::Vacant(_) => {
                return None;
            }
            Entry::Occupied(e) => e,
        };
        let mut buf = [0u8; 0x1000];
        let readed = libredox::call::read(fd as usize, &mut buf).ok()?;
        if readed == 0 {
            return None;
        }
        let pkt = DNSPacket::parse(&buf).ok()?;
        if pkt.header.response_code != ResponseCode::NoError || pkt.answers.is_empty() {
            if let Some(query) = pkt.questions.iter().next() {
                if query.qname.to_string().to_lowercase() == e.get().as_ref() {
                    queue.unsubscribe(fd as usize).ok()?;
                    libredox::call::close(fd as usize).ok()?;
                    let domain = e.remove();
                    self.requested_timeouts
                        .retain(|&(_, ref d)| d.as_ref() != domain.as_ref());
                    if let Entry::Occupied(e) = self.domains.entry(domain) {
                        let domain_data = e.remove();
                        return if let Domain::Requested { waiting_fds, .. } = domain_data {
                            Some(DnsParsingResult::FailFiles(waiting_fds))
                        } else {
                            None
                        };
                    }
                }
            }
            return None;
        }
        let mut result = String::new();
        for answer in pkt.answers {
            if answer.name.to_string().to_lowercase() != e.get().as_ref() {
                continue;
            }
            if let RRData::A(ip) = answer.data {
                result += &format!("{}\n", ip);
            }
        }
        if result.is_empty() {
            return None;
        }
        let data = Rc::from(result.into_bytes());
        queue.unsubscribe(fd as usize).ok()?;
        libredox::call::close(fd as usize).ok()?;
        let domain = e.remove();
        let mut domain_data = Domain::Resolved { data };
        trace!("On FD event {} {} resolved", fd, domain);

        let mut resolved_timeout = *cur_time;
        resolved_timeout.tv_sec += Dnsd::RESOLVED_TIMEOUT_S;

        self.resolved_timeouts
            .push_back((resolved_timeout, Rc::clone(&domain)));

        self.requested_timeouts
            .retain(|&(_, ref d)| d.as_ref() != domain.as_ref());

        match self.domains.entry(domain) {
            Entry::Vacant(e) => {
                e.insert(domain_data);
                None
            }
            Entry::Occupied(mut e) => {
                mem::swap(e.get_mut(), &mut domain_data);
                if let Domain::Requested { waiting_fds, .. } = domain_data {
                    Some(DnsParsingResult::WakeUpFiles(waiting_fds))
                } else {
                    None
                }
            }
        }
    }

    fn file_from_domain(&mut self, domain: &str, fd: usize, cur_time: &TimeSpec, queue: &EventQueue<EventSource>) -> DnsFile {
        if let Some(domain_data) = self.domains.get_mut(domain) {
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
            if let Some(socket_fd) = self.request_domain(domain, queue) {
                let mut waiting_fds = BTreeSet::new();
                let domain = domain.to_owned().into();
                waiting_fds.insert(fd);
                self.domains.insert(
                    Rc::clone(&domain),
                    Domain::Requested {
                        waiting_fds,
                        socket_fd,
                    },
                );
                let mut timeout = *cur_time;
                timeout.tv_sec += Dnsd::REQUEST_TIMEOUT_S;
                self.requested_timeouts.push_back((timeout, domain));
            }
            DnsFile::Waiting {
                domain: domain.to_owned(),
            }
        }
    }

    fn unwait_fd(&mut self, domain: &str, fd: usize) {
        if let Some(domain_data) = self.domains.get_mut(domain) {
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

pub struct Dnsd<'q> {
    dns_file: File,
    time_file: File,
    queue: &'q EventQueue<EventSource>,
    files: BTreeMap<usize, DnsFile>,
    domains: Domains,
    wait_map: BTreeMap<usize, SyscallPacket>,
    next_fd: usize,
}

impl<'q> Dnsd<'q> {
    const RESOLVED_TIMEOUT_S: i64 = 5 * 60;
    const REQUEST_TIMEOUT_S: i64 = 30;
    const TIME_EVENT_TIMEOUT_S: i64 = 5;

    pub fn new(dns_file: File, time_file: File, queue: &'q EventQueue<EventSource>) -> Dnsd {
        Dnsd {
            dns_file,
            time_file,
            queue,
            files: BTreeMap::new(),
            domains: Domains::new(),
            wait_map: BTreeMap::new(),
            next_fd: 1,
        }
    }

    pub fn on_time_event(&mut self) -> Result<()> {
        let mut time = TimeSpec::default();
        if self.time_file.read(&mut time)? < mem::size_of::<TimeSpec>() {
            return Err(Error::from_syscall_error(
                syscall::Error::new(syscall::EBADF),
                "Can't read current time",
            ));
        }

        let fds_to_wakeup = self.domains.on_time_event(&time, self.queue)?;
        if !fds_to_wakeup.is_empty() {
            for fd in &fds_to_wakeup {
                if let Some(file) = self.files.get_mut(fd) {
                    *file = DnsFile::Timeout;
                }
            }
            self.wakeup_fds(&fds_to_wakeup);
        }

        time.tv_sec += Dnsd::TIME_EVENT_TIMEOUT_S;
        self.time_file
            .write_all(&time)
            .map_err(|e| Error::from_io_error(e, "Failed to write to time file"))?;
        Ok(())
    }

    pub fn on_dns_file_event(&mut self) -> Result<bool> {
        loop {
            let mut packet = SyscallPacket::default();
            match self.dns_file.read(&mut packet) {
                Ok(0) => {
                    //TODO: Cleanup must occur
                    return Ok(false);
                },
                Ok(_) => (),
                Err(err) => if err.kind() == ErrorKind::WouldBlock {
                    return Ok(true);
                } else {
                    return Err(Error::from(err));
                }
            }
            // TODO: implement cancellation
            let a = packet.a;
            self.handle(&mut packet);
            if packet.a != (-syscall::EWOULDBLOCK) as usize {
                self.dns_file.write_all(&packet)?;
            } else {
                packet.a = a;
                self.handle_block(packet)?;
            }
        }
    }

    pub fn on_unknown_fd_event(&mut self, fd: RawFd) -> Result<()> {
        trace!("Unknown fd event {}", fd);
        let cur_time = libredox::call::clock_gettime(libredox::flag::CLOCK_MONOTONIC)
            .map_err(|e| Error::from_syscall_error(e.into(), "Can't get time"))?;
        // TODO
        let cur_time = TimeSpec { tv_sec: cur_time.tv_sec, tv_nsec: cur_time.tv_nsec as _ };

        match self.domains.on_fd_event(fd, &cur_time, self.queue) {
            Some(DnsParsingResult::FailFiles(fds_to_fail)) => {
                for fd in &fds_to_fail {
                    if let Some(file) = self.files.get_mut(fd) {
                        *file = DnsFile::Failed;
                    }
                }
                self.wakeup_fds(&fds_to_fail);
            }
            Some(DnsParsingResult::WakeUpFiles(fds_to_wakeup)) => {
                self.wakeup_fds(&fds_to_wakeup);
            }
            None => {}
        }
        Ok(())
    }

    pub fn on_nameserver_event(&mut self) -> Result<()> {
        self.domains.update_nameserver();
        Ok(())
    }

    fn wakeup_fds(&mut self, fds_to_wakeup: &BTreeSet<usize>) {
        let mut syscall_packets = vec![];
        for fd in fds_to_wakeup {
            if let Some(packet) = self.wait_map.remove(fd) {
                syscall_packets.push(packet);
            }
        }

        for mut packet in syscall_packets.drain(..) {
            self.handle(&mut packet);
            let _ = self.dns_file.write_all(&packet);
        }
    }

    fn handle_block(&mut self, packet: SyscallPacket) -> Result<()> {
        let fd = packet.b;
        self.wait_map.insert(fd, packet);
        Ok(())
    }

    fn validate_domain(domain: &str) -> bool {
        if domain.len() > 256 {
            return false;
        }

        for part in domain.split('.') {
            if part.len() >= 63 {
                return false;
            }
        }

        true
    }
}

impl SchemeMut for Dnsd<'_> {
    fn open(&mut self, url: &str, _flags: usize, _uid: u32, _gid: u32) -> SyscallResult<usize> {
        let domain = url.to_lowercase();
        if domain.is_empty() || !Dnsd::validate_domain(&domain) {
            return Err(SyscallError::new(syscall::EINVAL));
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        let cur_time = libredox::call::clock_gettime(flag::CLOCK_MONOTONIC)?;
        let dns_file = self.domains.file_from_domain(&domain, fd, &TimeSpec { tv_sec: cur_time.tv_sec, tv_nsec: cur_time.tv_nsec as i32 }, self.queue);
        self.files.insert(fd, dns_file);
        trace!("Open {} {}", &domain, fd);
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        trace!("Close {}", fd);
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if let DnsFile::Waiting { ref domain } = *file {
            self.domains.unwait_fd(domain, fd);
        }

        self.files.remove(&fd);
        Ok(0)
    }

    fn write(&mut self, _fd: usize, _buf: &[u8]) -> SyscallResult<usize> {
        Err(SyscallError::new(syscall::EINVAL))
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        trace!("Read {}", fd);
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        let cur_time = libredox::call::clock_gettime(flag::CLOCK_MONOTONIC)?;

        if let DnsFile::Waiting { ref domain } = *file {
            *file = self.domains.file_from_domain(domain, fd, &TimeSpec { tv_sec: cur_time.tv_sec, tv_nsec: cur_time.tv_nsec as i32 }, self.queue);
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
            DnsFile::Timeout => Err(SyscallError::new(syscall::ETIMEDOUT)),
            DnsFile::Failed => Err(SyscallError::new(syscall::ENODATA)),
        }
    }

    fn fevent(&mut self, _fd: usize, _events: SyscallEventFlags) -> SyscallResult<SyscallEventFlags> {
        Ok(SyscallEventFlags::empty())
    }

    fn fsync(&mut self, _fd: usize) -> SyscallResult<usize> {
        Ok(0)
    }
}
