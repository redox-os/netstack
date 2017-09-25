use smoltcp::socket::{AsSocket, SocketHandle, UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::str;
use syscall;

use device::NetworkDevice;
use error::Result;
use super::{Smolnetd, SocketSet};
use port_set::PortSet;

enum Setting {
    Ttl,
    ReadTimeout,
    WriteTimeout,
}

struct UdpHandle {
    flags: usize,
    events: usize,
    remote_endpoint: IpEndpoint,
    socket_handle: SocketHandle,
}

enum FdHandle {
    Setting(SocketHandle, Setting),
    Socket(UdpHandle),
}

impl FdHandle {
    fn socket_handle(&self) -> SocketHandle {
        match *self {
            FdHandle::Socket(UdpHandle { socket_handle, .. }) => socket_handle,
            FdHandle::Setting(socket_handle, _) => socket_handle,
        }
    }
}

pub struct UdpScheme {
    next_udp_fd: usize,
    udp_fds: BTreeMap<usize, FdHandle>,
    socket_set: SocketSet,
    port_set: PortSet,
}

impl UdpScheme {
    pub fn new(socket_set: SocketSet) -> UdpScheme {
        UdpScheme {
            next_udp_fd: 1,
            udp_fds: BTreeMap::new(),
            socket_set,
            port_set: PortSet::new(1025u16, 0xFFFFu16).expect("Wrong UDP port numbers"),
        }
    }

    pub fn notify_ready_sockets<F: FnMut(usize) -> Result<()>>(&self, mut f: F) -> Result<()> {
        for (&fd, handle) in &self.udp_fds {
            if let &FdHandle::Socket(UdpHandle { socket_handle, .. }) = handle {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut UdpSocket = socket_set.get_mut(socket_handle).as_socket();
                if socket.can_send() {
                    f(fd)?
                }
            }
        }
        Ok(())
    }
}

impl syscall::SchemeMut for UdpScheme {
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> syscall::Result<usize> {
        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;

        trace!("Udp open {} ", path);

        let mut parts = path.split("/");
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port <= 1024 && uid != 0 {
            return Err(syscall::Error::new(syscall::EACCES));
        }

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
            tx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
        }
        let rx_buffer = UdpSocketBuffer::new(rx_packets);
        let tx_buffer = UdpSocketBuffer::new(tx_packets);
        let mut udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        if local_endpoint.port == 0 {
            local_endpoint.port = self.port_set
                .get_port()
                .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
        } else if !self.port_set.claim_port(local_endpoint.port) {
            return Err(syscall::Error::new(syscall::EADDRINUSE));
        }

        {
            let udp_socket: &mut UdpSocket = udp_socket.as_socket();
            udp_socket
                .bind(local_endpoint)
                .expect("Can't bind udp socket to local endpoint");
        }

        let socket_handle = self.socket_set.borrow_mut().add(udp_socket);
        let id = self.next_udp_fd;

        self.udp_fds.insert(
            id,
            FdHandle::Socket(UdpHandle {
                flags,
                events: 0,
                socket_handle,
                remote_endpoint: remote_endpoint,
            }),
        );
        self.next_udp_fd += 1;
        trace!("Udp open fd {} ", id);
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("Upd close {}", fd);
        let socket_handle = {
            let handle = self.udp_fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle()
        };
        self.udp_fds.remove(&fd);
        let mut socket_set = self.socket_set.borrow_mut();
        let endpoint = {
            let socket: &mut UdpSocket = socket_set.get_mut(socket_handle).as_socket();
            socket.endpoint()
        };
        socket_set.release(socket_handle);
        //TODO: removing sockets in release should make prune unnecessary
        socket_set.prune();
        if endpoint.port != 0 {
            self.port_set.release_port(endpoint.port);
        }
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("Upd write {} len {}", fd, buf.len());

        let handle = self.udp_fds
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        match *handle {
            FdHandle::Setting(_, _) => {
                //TODO: udp settings
                // pretend we've accepted
            }
            FdHandle::Socket(ref handle) => {
                if !handle.remote_endpoint.is_specified() {
                    return Err(syscall::Error::new(syscall::EADDRNOTAVAIL));
                }
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle).as_socket();
                socket
                    .send_slice(buf, handle.remote_endpoint)
                    .expect("Can't send slice");
            }
        }
        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        trace!("udp read {} {}", fd, buf.len());
        let handle = self.udp_fds.get(&fd).ok_or_else(|| {
            trace!("UDP read EBADF {}", fd);
            syscall::Error::new(syscall::EBADF)
        })?;
        match *handle {
            FdHandle::Setting(_, _) => {
                //TODO: udp settings
                Ok(buf.len())
            }
            FdHandle::Socket(ref handle) => {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle).as_socket();
                if socket.can_recv() {
                    let (length, _) = socket.recv_slice(buf).expect("Can't receive slice");
                    trace!("Upd read {}", fd);
                    Ok(length)
                } else if handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
                    Ok(0)
                } else {
                    Err(syscall::Error::new(syscall::EWOULDBLOCK))
                }
            }
        }
    }

    fn dup(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        let path = str::from_utf8(buf).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;
        trace!("udp dup {} {}", fd, path);

        let handle = {
            let handle = self.udp_fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            let socket_handle = handle.socket_handle();

            match path {
                "ttl" => FdHandle::Setting(socket_handle, Setting::Ttl),
                "read_timeout" => FdHandle::Setting(socket_handle, Setting::ReadTimeout),
                "write_timeout" => FdHandle::Setting(socket_handle, Setting::WriteTimeout),
                _ => {
                    let remote_endpoint = parse_endpoint(path);
                    if let &mut FdHandle::Socket(ref udp_handle) = handle {
                        FdHandle::Socket(UdpHandle {
                            flags: udp_handle.flags,
                            events: udp_handle.events,
                            remote_endpoint: if remote_endpoint.is_specified() {
                                remote_endpoint
                            } else {
                                udp_handle.remote_endpoint
                            },
                            socket_handle,
                        })
                    } else {
                        FdHandle::Socket(UdpHandle {
                            flags: 0,
                            events: 0,
                            remote_endpoint: remote_endpoint,
                            socket_handle,
                        })
                    }
                }
            }
        };

        self.socket_set.borrow_mut().retain(handle.socket_handle());
        let port = {
            let mut socket_set = self.socket_set.borrow_mut();
            let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle()).as_socket();
            socket.endpoint().port
        };
        self.port_set.acquire_port(port);

        let id = self.next_udp_fd;
        self.udp_fds.insert(id, handle);
        self.next_udp_fd += 1;

        Ok(id)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("udp fevent {}", fd);
        let handle = self.udp_fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        match *handle {
            FdHandle::Setting(_, _) => Err(syscall::Error::new(syscall::EBADF)),
            FdHandle::Socket(ref mut handle) => {
                handle.events = events;
                Ok(fd)
            }
        }
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("udp fsync {}", fd);
        {
            let _handle = self.udp_fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }
}

fn parse_endpoint(socket: &str) -> IpEndpoint {
    let mut socket_parts = socket.split(":");
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
