use netutils::Ipv4Addr;
use smoltcp::socket::{AsSocket, SocketHandle, UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use std::collections::BTreeMap;
use syscall;

use device::NetworkDevice;
use error::Result;
use super::{Smolnetd, SocketSet};

pub struct UdpHandle {
    flags: usize,
    events: usize,
    remote_endpoint: IpEndpoint,
    pub socket_handle: SocketHandle,
}

pub struct UdpScheme {
    next_udp_fd: usize,
    udp_sockets: BTreeMap<usize, UdpHandle>,
    socket_set: SocketSet,
}

impl UdpScheme {
    pub fn new(socket_set: SocketSet) -> UdpScheme {
        UdpScheme {
            next_udp_fd: 1,
            udp_sockets: BTreeMap::new(),
            socket_set,
        }
    }

    pub fn notify_ready_sockets<F: FnMut(usize) -> Result<()>>(&self, mut f: F) -> Result<()> {
        for (&fd, ref handle) in &self.udp_sockets {
            let mut socket_set = self.socket_set.borrow_mut();
            let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle).as_socket();
            if socket.can_send() {
                f(fd)?
            }
        }
        Ok(())
    }
}

impl syscall::SchemeMut for UdpScheme {
    fn open(&mut self, url: &[u8], flags: usize, _uid: u32, _gid: u32) -> syscall::Result<usize> {
        use std::str;

        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;
        trace!("Udp open {} ", path);
        let mut parts = path.split("/");
        let (remote_ip, remote_port) = parse_socket(parts.next().unwrap_or(""));
        let (local_ip, local_port) = parse_socket(parts.next().unwrap_or(""));

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
            tx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
        }
        let rx_buffer = UdpSocketBuffer::new(rx_packets);
        let tx_buffer = UdpSocketBuffer::new(tx_packets);
        let mut udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        if local_ip != Ipv4Addr::NULL && local_port != 0 {
            let udp_socket: &mut UdpSocket = udp_socket.as_socket();
            udp_socket
                .bind(IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::from_bytes(&local_ip.bytes)),
                    local_port,
                ))
                .unwrap();
        }

        let socket_handle = self.socket_set.borrow_mut().add(udp_socket);
        let id = self.next_udp_fd;

        self.udp_sockets.insert(
            id,
            UdpHandle {
                flags,
                events: 0,
                socket_handle,
                remote_endpoint: IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::from_bytes(&remote_ip.bytes)),
                    remote_port,
                ),
            },
        );
        self.next_udp_fd += 1;
        trace!("Udp open fd {} ", id);
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("Upd close {}", fd);
        let socket_handle = {
            let handle = self.udp_sockets
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle
        };
        self.udp_sockets.remove(&fd);
        self.socket_set.borrow_mut().remove(socket_handle);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("Upd write {} len {}", fd, buf.len());

        let handle = self.udp_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let mut socket_set = self.socket_set.borrow_mut();
        let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle).as_socket();
        socket
            .send_slice(buf, handle.remote_endpoint)
            .expect("Can't send slice");
        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        let handle = self.udp_sockets.get(&fd).ok_or_else(|| {
            trace!("UDP read EBADF {}", fd);
            syscall::Error::new(syscall::EBADF)
        })?;
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

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("udp fevent {}", fd);
        let handle = self.udp_sockets
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        handle.events = events;
        Ok(fd)
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("udp fsync {}", fd);
        {
            let _handle = self.udp_sockets
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }
}

fn parse_socket(socket: &str) -> (Ipv4Addr, u16) {
    let mut socket_parts = socket.split(":");
    let host = Ipv4Addr::from_str(socket_parts.next().unwrap_or(""));
    let port = socket_parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .unwrap_or(0);
    (host, port)
}
