use netutils::{getcfg, MacAddr};
use smoltcp;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Instant;
use syscall::SchemeMut;
use syscall;

use buffer_pool::{Buffer, BufferPool};
use device::NetworkDevice;
use error::{Error, Result};
use self::ip::IpScheme;
use self::udp::UdpScheme;

mod ip;
mod udp;

type SocketSet = Rc<RefCell<smoltcp::socket::SocketSet<'static, 'static, 'static>>>;

pub struct Smolnetd {
    network_file: Rc<RefCell<File>>,
    ip_file: File,
    udp_file: File,
    time_file: File,

    iface: smoltcp::iface::EthernetInterface<'static, 'static, 'static, NetworkDevice>,
    socket_set: SocketSet,

    startup_time: Instant,

    ip_scheme: IpScheme,
    udp_scheme: UdpScheme,

    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    input_buffer_pool: BufferPool,
}

impl Smolnetd {
    const INGRESS_PACKET_SIZE: usize = 2048;
    const SOCKET_BUFFER_SIZE: usize = 128; //packets
    const CHECK_TIMEOUT_MS: i64 = 1000;

    pub fn new(network_file: File, ip_file: File, udp_file: File, time_file: File) -> Smolnetd {
        let arp_cache = smoltcp::iface::SliceArpCache::new(vec![Default::default(); 8]);
        //TODO Use smoltcp::wire::EthernetAddress::from_str
        let mac_addr = MacAddr::from_str(&getcfg("mac").unwrap().trim());
        let hardware_addr = smoltcp::wire::EthernetAddress(mac_addr.bytes);
        //TODO Use smoltcp::wire::Ipv4Addr::from_str
        let ip_bytes = Ipv4Addr::from_str(&getcfg("ip").unwrap().trim())
            .unwrap()
            .octets();
        let protocol_addrs = [
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(&ip_bytes)),
        ];
        let default_gw = smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(
            &Ipv4Addr::from_str(&getcfg("ip_router").unwrap().trim())
                .unwrap()
                .octets(),
        ));
        trace!("mac {:?} ip {:?}", hardware_addr, protocol_addrs);
        let input_queue = Rc::new(RefCell::new(VecDeque::new()));
        let network_file = Rc::new(RefCell::new(network_file));
        let network_device = NetworkDevice::new(network_file.clone(), input_queue.clone());
        let mut iface = smoltcp::iface::EthernetInterface::new(
            Box::new(network_device),
            Box::new(arp_cache) as Box<smoltcp::iface::ArpCache>,
            hardware_addr,
            protocol_addrs,
        );
        iface.set_default_gateway(24, Some(default_gw));
        let socket_set = Rc::new(RefCell::new(smoltcp::socket::SocketSet::new(vec![])));
        Smolnetd {
            iface,
            socket_set: socket_set.clone(),
            startup_time: Instant::now(),
            ip_file,
            udp_file,
            time_file,
            ip_scheme: IpScheme::new(socket_set.clone()),
            udp_scheme: UdpScheme::new(socket_set.clone()),
            input_queue,
            network_file,
            input_buffer_pool: BufferPool::new(Self::INGRESS_PACKET_SIZE),
        }
    }

    pub fn on_network_scheme_event(&mut self) -> Result<Option<()>> {
        if self.read_frames()? > 0 {
            self.poll().map(Some)?;
        }
        Ok(None)
    }

    pub fn on_ip_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.ip_file.read(&mut packet)? == 0 {
                break;
            }
            self.ip_scheme.handle(&mut packet);
            self.ip_file.write_all(&packet)?;
        }
        Ok(None)
    }

    pub fn on_udp_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.udp_file.read(&mut packet)? == 0 {
                break;
            }
            self.udp_scheme.handle(&mut packet);
            self.udp_file.write_all(&packet)?;
        }
        Ok(None)
    }

    pub fn on_time_event(&mut self) -> Result<Option<()>> {
        let mut time = syscall::data::TimeSpec::default();
        if self.time_file.read(&mut time)? < mem::size_of::<syscall::data::TimeSpec>() {
            panic!();
        }
        let mut time_ms = time.tv_sec * 1000i64 + (time.tv_nsec as i64) / 1_000_000i64;
        time_ms += Smolnetd::CHECK_TIMEOUT_MS;
        time.tv_sec = time_ms / 1000;
        time.tv_nsec = ((time_ms % 1000) * 1_000_00) as i32;
        self.time_file
            .write_all(&time)
            .map_err(|e| Error::from_io_error(e, "Failed to write to time file"))?;

        self.poll().map(Some)?;
        Ok(None)
    }

    fn poll(&mut self) -> Result<()> {
        let timestamp = self.get_timestamp();
        self.iface
            .poll(&mut *self.socket_set.borrow_mut(), timestamp)
            .expect("poll error");
        self.notify_raw_sockets()
    }

    fn read_frames(&mut self) -> Result<usize> {
        let mut total_frames = 0;
        loop {
            let mut buffer = self.input_buffer_pool.get_buffer();
            let count = self.network_file
                .borrow_mut()
                .read(&mut buffer)
                .map_err(|e| {
                    Error::from_io_error(e, "Failed to read from network file")
                })?;
            if count == 0 {
                break;
            }
            trace!("got frame {}", count);
            buffer.resize(count);
            self.input_queue.borrow_mut().push_back(buffer);
            total_frames += 1;
        }
        Ok(total_frames)
    }

    fn get_timestamp(&self) -> u64 {
        let duration = Instant::now().duration_since(self.startup_time);
        let duration_ms = (duration.as_secs() * 1000) + (duration.subsec_nanos() / 1000000) as u64;
        duration_ms
    }

    fn network_fsync(&mut self) -> syscall::Result<usize> {
        use std::os::unix::io::AsRawFd;
        syscall::fsync(self.network_file.borrow_mut().as_raw_fd() as usize)
    }

    fn notify_raw_sockets(&mut self) -> Result<()> {
        let ip_file = &mut self.ip_file;
        self.ip_scheme
            .notify_ready_sockets(|fd| post_fevent(ip_file, fd, syscall::EVENT_READ, 1))?;
        let udp_file = &mut self.udp_file;
        self.udp_scheme
            .notify_ready_sockets(|fd| post_fevent(udp_file, fd, syscall::EVENT_READ, 1))
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
