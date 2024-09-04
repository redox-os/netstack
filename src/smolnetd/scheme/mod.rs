use crate::link::ethernet::EthernetLink;
use crate::link::LinkDevice;
use crate::link::{loopback::LoopbackDevice, DeviceList};
use crate::router::route_table::{RouteTable, Rule};
use crate::router::Router;
use crate::scheme::smoltcp::iface::SocketSet as SmoltcpSocketSet;
use libredox::Fd;
use netutils::getcfg;
use smoltcp;
use smoltcp::iface::{Config, Interface as SmoltcpInterface};
use smoltcp::phy::Tracer;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address,
};
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};
use std::rc::Rc;
use std::str::FromStr;
use syscall;
use syscall::data::TimeSpec;

use self::icmp::IcmpScheme;
use self::ip::IpScheme;
use self::netcfg::NetCfgScheme;
use self::tcp::TcpScheme;
use self::udp::UdpScheme;
use redox_netstack::error::{Error, Result};

mod icmp;
mod ip;
mod netcfg;
mod socket;
mod tcp;
mod udp;

type SocketSet = SmoltcpSocketSet<'static>;
type Interface = Rc<RefCell<SmoltcpInterface>>;

const MAX_DURATION: Duration = Duration::from_millis(u64::MAX);
const MIN_DURATION: Duration = Duration::from_millis(0);

pub struct Smolnetd {
    router_device: Tracer<Router>,
    iface: Interface,
    time_file: File,

    socket_set: Rc<RefCell<SocketSet>>,
    timer: ::std::time::Instant,

    ip_scheme: IpScheme,
    udp_scheme: UdpScheme,
    tcp_scheme: TcpScheme,
    icmp_scheme: IcmpScheme,
    netcfg_scheme: NetCfgScheme,
}

impl Smolnetd {
    pub const MAX_PACKET_SIZE: usize = 2048;
    pub const SOCKET_BUFFER_SIZE: usize = 128; //packets
    pub const MIN_CHECK_TIMEOUT: Duration = Duration::from_millis(10);
    pub const MAX_CHECK_TIMEOUT: Duration = Duration::from_millis(500);

    pub fn new(
        network_file: Fd,
        hardware_addr: EthernetAddress,
        ip_file: Fd,
        udp_file: Fd,
        tcp_file: Fd,
        icmp_file: Fd,
        time_file: Fd,
        netcfg_file: Fd,
    ) -> Smolnetd {
        let protocol_addrs = vec![
            //This is a placeholder IP for DHCP
            IpCidr::new(IpAddress::v4(0, 0, 0, 0), 8),
        ];

        let default_gw = Ipv4Address::from_str(getcfg("ip_router").unwrap().trim())
            .expect("Can't parse the 'ip_router' cfg.");

        let devices = Rc::new(RefCell::new(DeviceList::default()));
        let route_table = Rc::new(RefCell::new(RouteTable::default()));
        let mut network_device = Tracer::new(
            Router::new(Rc::clone(&devices), Rc::clone(&route_table)),
            |_timestamp, printer| trace!("{}", printer),
        );

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = SmoltcpInterface::new(config, &mut network_device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| ip_addrs.extend(protocol_addrs));
        iface
            .routes_mut()
            .add_default_ipv4_route(default_gw)
            .expect("Failed to add default gateway");

        let iface = Rc::new(RefCell::new(iface));
        let socket_set = Rc::new(RefCell::new(SocketSet::new(vec![])));

        let loopback = LoopbackDevice::default();
        route_table.borrow_mut().insert_rule(Rule::new(
            "127.0.0.0/8".parse().unwrap(),
            None,
            Rc::clone(loopback.name()),
            "127.0.0.1".parse().unwrap(),
        ));


        let mut eth0 = EthernetLink::new(
            "eth0",
            unsafe { File::from_raw_fd(network_file.into_raw() as RawFd) },
        );
        eth0.set_mac_address(hardware_addr);

        devices.borrow_mut().push(loopback);
        devices.borrow_mut().push(eth0);

        Smolnetd {
            iface: Rc::clone(&iface),
            router_device: network_device,
            socket_set: Rc::clone(&socket_set),
            timer: ::std::time::Instant::now(),
            time_file: unsafe { File::from_raw_fd(time_file.into_raw() as RawFd) },
            ip_scheme: IpScheme::new(
                Rc::clone(&iface),
                Rc::clone(&route_table),
                Rc::clone(&socket_set),
                unsafe { File::from_raw_fd(ip_file.into_raw() as RawFd) },
            ),
            udp_scheme: UdpScheme::new(
                Rc::clone(&iface),
                Rc::clone(&route_table),
                Rc::clone(&socket_set),
                unsafe { File::from_raw_fd(udp_file.into_raw() as RawFd) },
            ),
            tcp_scheme: TcpScheme::new(
                Rc::clone(&iface),
                Rc::clone(&route_table),
                Rc::clone(&socket_set),
                unsafe { File::from_raw_fd(tcp_file.into_raw() as RawFd) },
            ),
            icmp_scheme: IcmpScheme::new(
                Rc::clone(&iface),
                Rc::clone(&route_table),
                Rc::clone(&socket_set),
                unsafe { File::from_raw_fd(icmp_file.into_raw() as RawFd) },
            ),
            netcfg_scheme: NetCfgScheme::new(
                Rc::clone(&iface),
                unsafe { File::from_raw_fd(netcfg_file.into_raw() as RawFd) },
                Rc::clone(&route_table),
                Rc::clone(&devices),
            ),
        }
    }

    pub fn on_network_scheme_event(&mut self) -> Result<()> {
        self.poll()?;
        Ok(())
    }

    pub fn on_ip_scheme_event(&mut self) -> Result<()> {
        self.ip_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(())
    }

    pub fn on_udp_scheme_event(&mut self) -> Result<()> {
        self.udp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(())
    }

    pub fn on_tcp_scheme_event(&mut self) -> Result<()> {
        self.tcp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(())
    }

    pub fn on_icmp_scheme_event(&mut self) -> Result<()> {
        self.icmp_scheme.on_scheme_event()?;
        let _ = self.poll()?;
        Ok(())
    }

    pub fn on_time_event(&mut self) -> Result<()> {
        let timeout = self.poll()?;
        self.schedule_time_event(timeout)?;
        //TODO: Fix network scheme to ensure events are not missed
        self.on_network_scheme_event()
    }

    pub fn on_netcfg_scheme_event(&mut self) -> Result<()> {
        self.netcfg_scheme.on_scheme_event()?;
        Ok(())
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

            loop {
                let timestamp = Instant::from(self.timer);
                if iter_limit == 0 {
                    break MIN_DURATION;
                }
                iter_limit -= 1;

                self.router_device.get_mut().poll(timestamp);

                // TODO: Check what if the bool returned by poll can be useful
                iface.poll(timestamp, &mut self.router_device, &mut socket_set);

                self.router_device.get_mut().dispatch(timestamp);

                if !self.router_device.get_ref().can_recv() {
                    match iface.poll_delay(timestamp, &socket_set) {
                        Some(delay) if delay == Duration::ZERO => {}
                        Some(delay) => break ::std::cmp::min(MAX_DURATION, delay),
                        None => break MAX_DURATION,
                    };
                }
            }
        };

        self.notify_sockets()?;

        Ok(::std::cmp::min(
            ::std::cmp::max(Smolnetd::MIN_CHECK_TIMEOUT, timeout),
            Smolnetd::MAX_CHECK_TIMEOUT,
        ))
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
    let host = Ipv4Address::from_str(socket_parts.next().unwrap_or(""))
        .ok()
        .filter(|addr| !addr.is_unspecified())
        .map(IpAddress::Ipv4);

    let port = socket_parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .unwrap_or(0);
    IpListenEndpoint { addr: host, port }
}
