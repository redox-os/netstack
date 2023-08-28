use netutils::getcfg;
use smoltcp;
use smoltcp::iface::{Interface as SmoltcpInterface, Routes, Config};
use smoltcp::phy::Tracer;
use crate::scheme::smoltcp::iface::SocketSet as SmoltcpSocketSet;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address, IpListenEndpoint, HardwareAddress};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::rc::Rc;
use std::str::FromStr;
use syscall::data::TimeSpec;
use syscall;

use crate::buffer_pool::{Buffer, BufferPool};
use crate::device::NetworkDevice;
use redox_netstack::error::{Error, Result};
use self::ip::IpScheme;
use self::tcp::TcpScheme;
use self::udp::UdpScheme;
use self::icmp::IcmpScheme;
use self::netcfg::NetCfgScheme;

mod ip;
mod socket;
mod tcp;
mod udp;
mod icmp;
mod netcfg;

type SocketSet = SmoltcpSocketSet<'static>;
type Interface = Rc<RefCell<SmoltcpInterface>>;

const MAX_DURATION: Duration = Duration::from_millis(u64::MAX);
const MIN_DURATION: Duration = Duration::from_millis(0);

pub struct Smolnetd {
    network_file: Rc<RefCell<File>>,
    network_device: Tracer<NetworkDevice>,
    time_file: File,

    iface: Interface,
    socket_set: Rc<RefCell<SocketSet>>,
    timer: ::std::time::Instant,

    ip_scheme: IpScheme,
    udp_scheme: UdpScheme,
    tcp_scheme: TcpScheme,
    icmp_scheme: IcmpScheme,
    netcfg_scheme: NetCfgScheme,

    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    buffer_pool: Rc<RefCell<BufferPool>>,
}

impl Smolnetd {
    const MAX_PACKET_SIZE: usize = 2048;
    const SOCKET_BUFFER_SIZE: usize = 128; //packets
    const MIN_CHECK_TIMEOUT: Duration = Duration::from_millis(10);
    const MAX_CHECK_TIMEOUT: Duration = Duration::from_millis(500);

    pub fn new(
        network_file: File,
        ip_file: File,
        udp_file: File,
        tcp_file: File,
        icmp_file: File,
        time_file: File,
        netcfg_file: File,
    ) -> Smolnetd {
        let hardware_addr = EthernetAddress::from_str(getcfg("mac").unwrap().trim())
            .expect("Can't parse the 'mac' cfg");
        let local_ip =
            IpAddress::from_str(getcfg("ip").unwrap().trim()).expect("Can't parse the 'ip' cfg.");
        let protocol_addrs = vec![
            IpCidr::new(local_ip, 24),
            IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8),
        ];
        let default_gw = Ipv4Address::from_str(getcfg("ip_router").unwrap().trim())
            .expect("Can't parse the 'ip_router' cfg.");

        let buffer_pool = Rc::new(RefCell::new(BufferPool::new(Self::MAX_PACKET_SIZE)));
        let input_queue = Rc::new(RefCell::new(VecDeque::new()));
        let network_file = Rc::new(RefCell::new(network_file));
        let mut network_device = Tracer::new(NetworkDevice::new(
            Rc::clone(&network_file),
            Rc::clone(&input_queue),
            hardware_addr,
            Rc::clone(&buffer_pool),
        ), |_timestamp, printer| {
            trace!("{}", printer)
        });
        let config = Config::new(HardwareAddress::Ethernet(hardware_addr));
        let mut iface = SmoltcpInterface::new(config, &mut network_device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| ip_addrs.extend(protocol_addrs));
        iface.routes_mut().add_default_ipv4_route(default_gw).expect("Failed to add default gateway");

        let iface = Rc::new(RefCell::new(iface));
        let socket_set = Rc::new(RefCell::new(SocketSet::new(vec![])));
        Smolnetd {
            iface: Rc::clone(&iface),
            network_device,
            socket_set: Rc::clone(&socket_set),
            timer: ::std::time::Instant::now(),
            time_file,
            ip_scheme: IpScheme::new(Rc::clone(&iface), Rc::clone(&socket_set), ip_file),
            udp_scheme: UdpScheme::new(Rc::clone(&iface), Rc::clone(&socket_set), udp_file),
            tcp_scheme: TcpScheme::new(Rc::clone(&iface), Rc::clone(&socket_set), tcp_file),
            icmp_scheme: IcmpScheme::new(Rc::clone(&iface), Rc::clone(&socket_set), icmp_file),
            netcfg_scheme: NetCfgScheme::new(Rc::clone(&iface), netcfg_file),
            input_queue,
            network_file,
            buffer_pool,
        }
    }

    pub fn on_network_scheme_event(&mut self) -> Result<Option<()>> {
        if self.read_frames()? > 0 {
            self.poll()?;
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

    pub fn on_icmp_scheme_event(&mut self) -> Result<Option<()>> {
        self.icmp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(None)
    }

    pub fn on_time_event(&mut self) -> Result<Option<()>> {
        let timeout = self.poll()?;
        self.schedule_time_event(timeout)?;
        //TODO: Fix network scheme to ensure events are not missed
        self.on_network_scheme_event()
    }

    pub fn on_netcfg_scheme_event(&mut self) -> Result<Option<()>> {
        self.netcfg_scheme.on_scheme_event()?;
        Ok(None)
    }

    fn schedule_time_event(&mut self, timeout: Duration) -> Result<()> {
        let mut time = TimeSpec::default();
        if self.time_file.read(&mut time)? < size_of::<TimeSpec>() {
            return Err(Error::from_syscall_error(
                syscall::Error::new(syscall::EBADF),
                "Can't read current time",
            ));
        }
        let mut time_ms = time.tv_sec * 1000i64 + i64::from(time.tv_nsec) / 1_000_000i64;
        time_ms += timeout.total_millis() as i64;
        time.tv_sec = time_ms / 1000;
        time.tv_nsec = ((time_ms % 1000) * 1_000_000) as i32;
        self.time_file
            .write_all(&time)
            .map_err(|e| Error::from_io_error(e, "Failed to write to time file"))?;
        Ok(())
    }

    fn poll(&mut self) -> Result<Duration> {
        let timeout = {
            let mut iter_limit = 10usize;
            let mut iface = self.iface.borrow_mut();
            let mut socket_set = self.socket_set.borrow_mut();
            let timestamp = Instant::from(self.timer);
            loop {
                if iter_limit == 0 {
                    break MIN_DURATION;
                }
                iter_limit -= 1;

                // TODO: Check what if the bool returned by poll can be useful 
                iface.poll(timestamp, &mut self.network_device, &mut socket_set);

                match iface.poll_delay(timestamp, &socket_set) {
                    Some(delay) if delay == Duration::ZERO => { }
                    Some(delay) => {
                        break ::std::cmp::min(MAX_DURATION, delay)
                    }
                    None => break MAX_DURATION
                };
            }
        };

        self.notify_sockets()?;

        Ok(::std::cmp::min(
            ::std::cmp::max(Smolnetd::MIN_CHECK_TIMEOUT, timeout),
            Smolnetd::MAX_CHECK_TIMEOUT,
        ))
    }

    fn read_frames(&mut self) -> Result<usize> {
        let mut total_frames = 0;
        loop {
            let mut buffer = self.buffer_pool.borrow_mut().get_buffer();
            let count = match self.network_file.borrow_mut().read(&mut buffer) {
                Ok(count) => count,
                Err(err) => match err.kind() {
                    io::ErrorKind::WouldBlock => break,
                    _ => return Err(
                        Error::from_io_error(err, "Failed to read from network file")
                    )
                }
            };
            buffer.resize(count);
            self.input_queue.borrow_mut().push_back(buffer);
            total_frames += 1;
        }
        Ok(total_frames)
    }

    fn notify_sockets(&mut self) -> Result<()> {
        self.ip_scheme.notify_sockets()?;
        self.udp_scheme.notify_sockets()?;
        self.tcp_scheme.notify_sockets()?;
        self.icmp_scheme.notify_sockets()
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

fn parse_endpoint(socket: &str) -> IpListenEndpoint {
    let mut socket_parts = socket.split(':');
    let host = 
        Ipv4Address::from_str(socket_parts.next().unwrap_or("")).ok().filter(|addr| !addr.is_unspecified()).map(IpAddress::Ipv4);
    

    let port = socket_parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .unwrap_or(0);
    IpListenEndpoint{ addr: host, port}
}
