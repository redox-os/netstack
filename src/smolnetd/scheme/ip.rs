use smoltcp::socket::{AsSocket, RawPacketBuffer, RawSocket, RawSocketBuffer, SocketHandle};
use smoltcp::wire::{IpProtocol, IpVersion};
use std::collections::BTreeMap;
use syscall;

use device::NetworkDevice;
use error::Result;
use super::{Smolnetd, SocketSet};

pub struct RawHandle {
    flags: usize,
    events: usize,
    socket_handle: SocketHandle,
}

pub struct IpScheme {
    next_ip_fd: usize,
    raw_sockets: BTreeMap<usize, RawHandle>,
    socket_set: SocketSet,
}

impl IpScheme {
    pub fn new(socket_set: SocketSet) -> IpScheme {
        IpScheme {
            next_ip_fd: 1,
            raw_sockets: BTreeMap::new(),
            socket_set,
        }
    }

    pub fn notify_ready_sockets<F: FnMut(usize) -> Result<()>>(&self, mut f: F) -> Result<()> {
        for (&fd, ref handle) in &self.raw_sockets {
            let mut socket_set = self.socket_set.borrow_mut();
            let socket: &mut RawSocket = socket_set.get_mut(handle.socket_handle).as_socket();
            if socket.can_send() {
                f(fd)?
            }
        }
        Ok(())
    }
}

impl<'a> syscall::SchemeMut for IpScheme {
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
            rx_packets.push(RawPacketBuffer::new(vec![0; NetworkDevice::MTU]));
            tx_packets.push(RawPacketBuffer::new(vec![0; NetworkDevice::MTU]));
        }
        let rx_buffer = RawSocketBuffer::new(rx_packets);
        let tx_buffer = RawSocketBuffer::new(tx_packets);
        let raw_socket = RawSocket::new(
            IpVersion::Ipv4,
            IpProtocol::from(proto),
            rx_buffer,
            tx_buffer,
        );

        let socket_handle = self.socket_set.borrow_mut().add(raw_socket);
        let id = self.next_ip_fd;
        trace!("IP Open {} -> {}", path, id);

        self.raw_sockets.insert(
            id,
            RawHandle {
                flags,
                events: 0,
                socket_handle,
            },
        );
        self.next_ip_fd += 1;
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("IP Close {}", fd);
        let socket_handle = {
            let handle = self.raw_sockets
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle
        };
        self.raw_sockets.remove(&fd);
        self.socket_set.borrow_mut().remove(socket_handle);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("IP Write {} len {}", fd, buf.len());

        let handle = self.raw_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let mut socket_set = self.socket_set.borrow_mut();
        let socket: &mut RawSocket = socket_set.get_mut(handle.socket_handle).as_socket();
        socket.send_slice(buf).expect("Can't send slice");
        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        use smoltcp::socket::AsSocket;

        let handle = self.raw_sockets
            .get(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let mut socket_set = self.socket_set.borrow_mut();
        let socket: &mut RawSocket = socket_set.get_mut(handle.socket_handle).as_socket();
        if socket.can_recv() {
            let length = socket.recv_slice(buf).expect("Can't receive slice");
            trace!("IP Read fd {} len {}", fd, length);
            Ok(length)
        } else if handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        }
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("IP fevent {}", fd);
        let handle = self.raw_sockets
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        handle.events = events;
        Ok(fd)
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("IP fsync {}", fd);
        {
            let _handle = self.raw_sockets
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }
}
