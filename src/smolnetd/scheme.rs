use netutils::{getcfg, MacAddr};
use smoltcp;
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Instant;
use std::rc::Rc;
use std::cell::RefCell;
use smoltcp::socket::AsSocket;
use syscall::SchemeMut;
use syscall;

use device::NetworkDevice;
use error::{Error, Result};
use buffer_pool::{Buffer, BufferPool};

struct RawHandle {
    flags: usize,
    events: usize,
    socket_handle: smoltcp::socket::SocketHandle,
}

struct UdpHandle {
    flags: usize,
    events: usize,
    remote_endpoint: smoltcp::wire::IpEndpoint,
    socket_handle: smoltcp::socket::SocketHandle,
}

pub struct Smolnetd {
    network_file: Rc<RefCell<File>>,
    ip_file: File,
    udp_file: File,
    time_file: File,

    iface: smoltcp::iface::EthernetInterface<'static, 'static, 'static, NetworkDevice>,
    socket_set: smoltcp::socket::SocketSet<'static, 'static, 'static>,

    startup_time: Instant,
    next_fd: usize,

    raw_sockets: BTreeMap<usize, RawHandle>,
    udp_sockets: BTreeMap<usize, UdpHandle>,

    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    input_buffer_pool: BufferPool,
}

struct IpScheme<'a>(&'a mut Smolnetd);
struct UdpScheme<'a>(&'a mut Smolnetd);

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
        Smolnetd {
            iface,
            socket_set: smoltcp::socket::SocketSet::new(vec![]),
            startup_time: Instant::now(),
            ip_file,
            udp_file,
            time_file,
            raw_sockets: BTreeMap::new(),
            udp_sockets: BTreeMap::new(),
            next_fd: 0,
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
            IpScheme(self).handle(&mut packet);
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
            UdpScheme(self).handle(&mut packet);
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
            .poll(&mut self.socket_set, timestamp)
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
        for (&fd, ref handle) in &self.raw_sockets {
            let socket: &mut smoltcp::socket::RawSocket =
                self.socket_set.get_mut(handle.socket_handle).as_socket();
            if socket.can_send() {
                post_fevent(&mut self.ip_file, fd, syscall::EVENT_READ, 1)?;
            }
        }
        Ok(())
    }
}

impl<'a> syscall::SchemeMut for IpScheme<'a> {
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> syscall::Result<usize> {
        use std::str;

        if uid != 0 {
            return Err(syscall::Error::new(syscall::EACCES));
        }
        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;
        let proto = u8::from_str_radix(path, 16).or(Err(syscall::Error::new(syscall::ENOENT)))?;

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(smoltcp::socket::RawPacketBuffer::new(
                vec![0; NetworkDevice::MTU],
            ));
            tx_packets.push(smoltcp::socket::RawPacketBuffer::new(
                vec![0; NetworkDevice::MTU],
            ));
        }
        let rx_buffer = smoltcp::socket::RawSocketBuffer::new(rx_packets);
        let tx_buffer = smoltcp::socket::RawSocketBuffer::new(tx_packets);
        let raw_socket = smoltcp::socket::RawSocket::new(
            smoltcp::wire::IpVersion::Ipv4,
            smoltcp::wire::IpProtocol::from(proto),
            rx_buffer,
            tx_buffer,
        );

        let socket_handle = self.0.socket_set.add(raw_socket);
        let id = self.0.next_fd;
        trace!("Open {} -> {}", path, id);

        self.0.raw_sockets.insert(
            id,
            RawHandle {
                flags,
                events: 0,
                socket_handle,
            },
        );
        self.0.next_fd += 1;
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("Close {}", fd);
        let socket_handle = {
            let handle = self.0
                .raw_sockets
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle
        };
        self.0.raw_sockets.remove(&fd);
        self.0.socket_set.remove(socket_handle);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("Write {} len {}", fd, buf.len());

        let handle = self.0
            .raw_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let socket: &mut smoltcp::socket::RawSocket =
            self.0.socket_set.get_mut(handle.socket_handle).as_socket();
        socket.send_slice(buf).expect("Can't send slice");
        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        use smoltcp::socket::AsSocket;

        let handle = self.0
            .raw_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let socket: &mut smoltcp::socket::RawSocket =
            self.0.socket_set.get_mut(handle.socket_handle).as_socket();
        if socket.can_recv() {
            let length = socket.recv_slice(buf).expect("Can't receive slice");
            trace!("Read fd {} len {}", fd, length);
            Ok(length)
        } else if handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        }
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("fevent {}", fd);
        let handle = self.0
            .raw_sockets
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        handle.events = events;
        Ok(fd)
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("fsync {}", fd);
        {
            let _handle = self.0
                .raw_sockets
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        self.0.network_fsync()
    }
}

impl<'a> syscall::SchemeMut for UdpScheme<'a> {
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> syscall::Result<usize> {
        use std::str;

        if uid != 0 {
            return Err(syscall::Error::new(syscall::EACCES));
        }
        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;
        let mut parts = path.split("/");
        let (remote_ip, remote_port) = parse_socket(parts.next().unwrap_or(""));
        let (local_ip, local_port) = parse_socket(parts.next().unwrap_or(""));

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(smoltcp::socket::UdpPacketBuffer::new(
                vec![0; NetworkDevice::MTU],
            ));
            tx_packets.push(smoltcp::socket::UdpPacketBuffer::new(
                vec![0; NetworkDevice::MTU],
            ));
        }
        let rx_buffer = smoltcp::socket::UdpSocketBuffer::new(rx_packets);
        let tx_buffer = smoltcp::socket::UdpSocketBuffer::new(tx_packets);
        let mut udp_socket = smoltcp::socket::UdpSocket::new(rx_buffer, tx_buffer);

        if !local_ip.is_unspecified() && local_port != 0 {
            let udp_socket: &mut smoltcp::socket::UdpSocket = udp_socket.as_socket();
            udp_socket.bind(smoltcp::wire::IpEndpoint::new(
                smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_bytes(&local_ip.octets()),
                ),
                local_port,
            )).unwrap();
        }

        let socket_handle = self.0.socket_set.add(udp_socket);
        let id = self.0.next_fd;
        trace!("Open {} -> {}", path, id);

        self.0.udp_sockets.insert(
            id,
            UdpHandle {
                flags,
                events: 0,
                socket_handle,
                remote_endpoint: smoltcp::wire::IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv4(
                        smoltcp::wire::Ipv4Address::from_bytes(&remote_ip.octets()),
                    ),
                    remote_port,
                ),
            },
        );
        self.0.next_fd += 1;
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("Close {}", fd);
        let socket_handle = {
            let handle = self.0
                .udp_sockets
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle
        };
        self.0.udp_sockets.remove(&fd);
        self.0.socket_set.remove(socket_handle);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("Write {} len {}", fd, buf.len());

        let handle = self.0
            .udp_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let socket: &mut smoltcp::socket::UdpSocket =
            self.0.socket_set.get_mut(handle.socket_handle).as_socket();
        socket.send_slice(buf, handle.remote_endpoint).expect("Can't send slice");
        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        trace!("Read {}", fd);

        let handle = self.0
            .udp_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let socket: &mut smoltcp::socket::UdpSocket =
            self.0.socket_set.get_mut(handle.socket_handle).as_socket();
        if socket.can_recv() {
            let (length, _) = socket.recv_slice(buf).expect("Can't receive slice");
            Ok(length)
        } else if handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        }
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("fevent {}", fd);
        let handle = self.0
            .udp_sockets
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        handle.events = events;
        Ok(fd)
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("fsync {}", fd);
        {
            let _handle = self.0
                .udp_sockets
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        self.0.network_fsync()
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

fn parse_socket(socket: &str) -> (Ipv4Addr, u16) {
    let mut socket_parts = socket.split(":");
    let host = Ipv4Addr::from_str(socket_parts.next().unwrap_or("")).unwrap();
    let port = socket_parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .unwrap_or(0);
    (host, port)
}
