use netutils::getcfg;
use smoltcp::iface::{ArpCache, EthernetInterface};
use smoltcp::socket::SocketSet as SmoltcpSocketSet;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Instant;
use syscall::data::TimeSpec;
use syscall;

use buffer_pool::{Buffer, BufferPool};
use device::NetworkDevice;
use error::{Error, Result};
use arp_cache::LoArpCache;
use self::ip::IpScheme;
use self::tcp::TcpScheme;
use self::udp::UdpScheme;

mod ip;
mod socket;
mod tcp;
mod udp;

type SocketSet = SmoltcpSocketSet<'static, 'static, 'static>;

pub struct Smolnetd {
    network_file: Rc<RefCell<File>>,
    time_file: File,

    iface: EthernetInterface<'static, 'static, 'static, NetworkDevice>,
    socket_set: Rc<RefCell<SocketSet>>,

    startup_time: Instant,

    ip_scheme: IpScheme,
    udp_scheme: UdpScheme,
    tcp_scheme: TcpScheme,

    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    buffer_pool: Rc<RefCell<BufferPool>>,
}

impl Smolnetd {
    const MAX_PACKET_SIZE: usize = 2048;
    const SOCKET_BUFFER_SIZE: usize = 128; //packets
    const MIN_CHECK_TIMEOUT_MS: i64 = 10;
    const MAX_CHECK_TIMEOUT_MS: i64 = 500;

    pub fn new(
        network_file: File,
        ip_file: File,
        udp_file: File,
        tcp_file: File,
        time_file: File,
    ) -> Smolnetd {
        let hardware_addr = EthernetAddress::from_str(getcfg("mac").unwrap().trim())
            .expect("Can't parse the 'mac' cfg");
        let local_ip =
            IpAddress::from_str(getcfg("ip").unwrap().trim()).expect("Can't parse the 'ip' cfg.");
        let protocol_addrs = [
            IpCidr::new(local_ip, 24),
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
        ];
        let default_gw = Ipv4Address::from_str(getcfg("ip_router").unwrap().trim())
            .expect("Can't parse the 'ip_router' cfg.");


        let buffer_pool = Rc::new(RefCell::new(BufferPool::new(Self::MAX_PACKET_SIZE)));
        let input_queue = Rc::new(RefCell::new(VecDeque::new()));
        let network_file = Rc::new(RefCell::new(network_file));
        let network_device = NetworkDevice::new(
            Rc::clone(&network_file),
            Rc::clone(&input_queue),
            hardware_addr,
            buffer_pool.clone(),
        );
        let arp_cache = LoArpCache::new(protocol_addrs.iter().map(IpCidr::address));
        let iface = EthernetInterface::new(
            Box::new(network_device),
            Box::new(arp_cache) as Box<ArpCache>,
            hardware_addr,
            protocol_addrs,
            Some(default_gw),
        );
        let socket_set = Rc::new(RefCell::new(SocketSet::new(vec![])));
        Smolnetd {
            iface,
            socket_set: Rc::clone(&socket_set),
            startup_time: Instant::now(),
            time_file,
            ip_scheme: IpScheme::new(Rc::clone(&socket_set), ip_file),
            udp_scheme: UdpScheme::new(Rc::clone(&socket_set), udp_file),
            tcp_scheme: TcpScheme::new(Rc::clone(&socket_set), tcp_file),
            input_queue,
            network_file,
            buffer_pool,
        }
    }

    pub fn on_network_scheme_event(&mut self) -> Result<Option<()>> {
        if self.read_frames()? > 0 {
            self.poll().map(Some)?;
        }
        Ok(None)
    }

    pub fn on_ip_scheme_event(&mut self) -> Result<Option<()>> {
        self.ip_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(None)
    }

    pub fn on_udp_scheme_event(&mut self) -> Result<Option<()>> {
        self.udp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(None)
    }

    pub fn on_tcp_scheme_event(&mut self) -> Result<Option<()>> {
        self.tcp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(None)
    }

    pub fn on_time_event(&mut self) -> Result<Option<()>> {
        let timeout = self.poll()?;
        self.schedule_time_event(timeout)?;
        Ok(None)
    }

    fn schedule_time_event(&mut self, timeout: i64) -> Result<()> {
        let mut time = TimeSpec::default();
        if self.time_file.read(&mut time)? < size_of::<TimeSpec>() {
            return Err(Error::from_syscall_error(
                syscall::Error::new(syscall::EBADF),
                "Can't read current time",
            ));
        }
        let mut time_ms = time.tv_sec * 1000i64 + i64::from(time.tv_nsec) / 1_000_000i64;
        time_ms += timeout;
        time.tv_sec = time_ms / 1000;
        time.tv_nsec = ((time_ms % 1000) * 1_000_000) as i32;
        self.time_file
            .write_all(&time)
            .map_err(|e| Error::from_io_error(e, "Failed to write to time file"))?;
        Ok(())
    }

    fn poll(&mut self) -> Result<i64> {
        let mut iter_limit = 10usize;
        let timeout = loop {
            iter_limit -= 1;
            if iter_limit == 0 {
                break 0;
            }
            let timestamp = self.get_timestamp();
            match self.iface
                .poll(&mut *self.socket_set.borrow_mut(), timestamp)
            {
                Err(err) => {
                    error!("poll error: {}", err);
                    break 0;
                }
                Ok(None) => {
                    break ::std::u64::MAX;
                }
                Ok(Some(n)) if n > 0 => {
                    break n;
                }
                _ => {}
            }
        };
        self.notify_sockets()?;
        Ok(::std::cmp::min(
            ::std::cmp::max(Smolnetd::MIN_CHECK_TIMEOUT_MS, timeout as i64),
            Smolnetd::MAX_CHECK_TIMEOUT_MS,
        ))
    }

    fn read_frames(&mut self) -> Result<usize> {
        let mut total_frames = 0;
        loop {
            let mut buffer = self.buffer_pool.borrow_mut().get_buffer();
            let count = self.network_file
                .borrow_mut()
                .read(&mut buffer)
                .map_err(|e| {
                    Error::from_io_error(e, "Failed to read from network file")
                })?;
            if count == 0 {
                break;
            }
            buffer.resize(count);
            self.input_queue.borrow_mut().push_back(buffer);
            total_frames += 1;
        }
        Ok(total_frames)
    }

    fn get_timestamp(&self) -> u64 {
        let duration = Instant::now().duration_since(self.startup_time);
        (duration.as_secs() * 1000) + u64::from(duration.subsec_nanos() / 1_000_000)
    }

    fn notify_sockets(&mut self) -> Result<()> {
        self.ip_scheme.notify_sockets()?;
        self.udp_scheme.notify_sockets()?;
        self.tcp_scheme.notify_sockets()
    }
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

fn parse_endpoint(socket: &str) -> IpEndpoint {
    let mut socket_parts = socket.split(':');
    let host = IpAddress::Ipv4(
        Ipv4Address::from_str(socket_parts.next().unwrap_or(""))
            .unwrap_or_else(|_| Ipv4Address::new(0, 0, 0, 0)),
    );

    let port = socket_parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .unwrap_or(0);
    IpEndpoint::new(host, port)
}
