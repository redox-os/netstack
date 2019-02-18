use smoltcp::socket::{SocketHandle, TcpSocket, TcpSocketBuffer};
use std::str;
use syscall::{Error as SyscallError, Result as SyscallResult};
use syscall;

use port_set::PortSet;
use super::socket::{DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme};
use super::{parse_endpoint, SocketSet};

pub type TcpScheme = SocketScheme<TcpSocket<'static>>;

impl<'a> SchemeSocket for TcpSocket<'a> {
    type SchemeDataT = PortSet;
    type DataT = ();
    type SettingT = ();

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(49_152u16, 65_535u16).expect("Wrong TCP port numbers")
    }

    fn can_send(&self) -> bool {
        self.can_send()
    }

    fn can_recv(&self) -> bool {
        self.can_recv()
    }

    fn hop_limit(&self) -> u8 {
        self.hop_limit().unwrap_or(64)
    }

    fn set_hop_limit(&mut self, hop_limit: u8) {
        self.set_hop_limit(Some(hop_limit));
    }

    fn get_setting(
        _file: &SocketFile<Self::DataT>,
        _setting: Self::SettingT,
        _buf: &mut [u8],
    ) -> SyscallResult<usize> {
        Ok(0)
    }

    fn set_setting(
        _file: &mut SocketFile<Self::DataT>,
        _setting: Self::SettingT,
        _buf: &[u8],
    ) -> SyscallResult<usize> {
        Ok(0)
    }

    fn new_socket(
        socket_set: &mut SocketSet,
        path: &str,
        uid: u32,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<(SocketHandle, Self::DataT)> {
        trace!("TCP open {}", path);
        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port > 0 && local_endpoint.port <= 1024 && uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }

        let rx_packets = vec![0; 0xffff];
        let tx_packets = vec![0; 0xffff];
        let rx_buffer = TcpSocketBuffer::new(rx_packets);
        let tx_buffer = TcpSocketBuffer::new(tx_packets);
        let socket = TcpSocket::new(rx_buffer, tx_buffer);

        if local_endpoint.port == 0 {
            local_endpoint.port = port_set
                .get_port()
                .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
        } else if !port_set.claim_port(local_endpoint.port) {
            return Err(SyscallError::new(syscall::EADDRINUSE));
        }

        let socket_handle = socket_set.add(socket);

        let mut tcp_socket = socket_set.get::<TcpSocket>(socket_handle);

        if remote_endpoint.is_specified() {
            trace!("Connecting tcp {} {}", local_endpoint, remote_endpoint);
            tcp_socket
                .connect(remote_endpoint, local_endpoint)
                .expect("Can't connect tcp socket ");
        } else {
            trace!("Listening tcp {}", local_endpoint);
            tcp_socket
                .listen(local_endpoint)
                .expect("Can't listen on local endpoint");
        }

        Ok((socket_handle, ()))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<()> {
        if let SchemeFile::Socket(_) = *file {
            port_set.release_port(self.local_endpoint().port);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<Option<usize>> {
        if !self.is_active() {
            Err(SyscallError::new(syscall::ENOTCONN))
        } else if self.can_send() {
            self.send_slice(buf).expect("Can't send slice");
            Ok(Some(buf.len()))
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Ok(None) // internally scheduled to re-write
        }
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> SyscallResult<Option<usize>> {
        if !self.is_active() {
            Err(SyscallError::new(syscall::ENOTCONN))
        } else if self.can_recv() {
            let length = self.recv_slice(buf).expect("Can't receive slice");
            Ok(Some(length))
        } else if !self.may_recv() {
            Ok(Some(0))
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Ok(None) // internally scheduled to re-read
        }
    }

    fn dup(
        socket_set: &mut SocketSet,
        file: &mut SchemeFile<Self>,
        path: &str,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<DupResult<Self>> {
        let socket_handle = file.socket_handle();

        let (is_active, local_endpoint) = {
            let socket = socket_set.get::<TcpSocket>(socket_handle);
            (socket.is_active(), socket.local_endpoint())
        };

        let file = match path {
            "listen" => if let SchemeFile::Socket(ref tcp_handle) = *file {
                if !is_active {
                    if tcp_handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
                        return Err(SyscallError::new(syscall::EAGAIN));
                    } else {
                        return Ok(None);
                    }
                }
                trace!("TCP creating new listening socket");
                let new_handle = SchemeFile::Socket(tcp_handle.clone_with_data(()));

                let rx_packets = vec![0; 0xffff];
                let tx_packets = vec![0; 0xffff];
                let rx_buffer = TcpSocketBuffer::new(rx_packets);
                let tx_buffer = TcpSocketBuffer::new(tx_packets);
                let socket = TcpSocket::new(rx_buffer, tx_buffer);
                let new_socket_handle = socket_set.add(socket);
                {
                    let mut tcp_socket = socket_set.get::<TcpSocket>(new_socket_handle);
                    tcp_socket
                        .listen(local_endpoint)
                        .expect("Can't listen on local endpoint");
                }
                port_set.acquire_port(local_endpoint.port);
                return Ok(Some((new_handle, Some((new_socket_handle, ())))));
            } else {
                return Err(SyscallError::new(syscall::EBADF));
            },
            _ => {
                trace!("TCP dup unknown {}", path);
                if let SchemeFile::Socket(ref tcp_handle) = *file {
                    SchemeFile::Socket(tcp_handle.clone_with_data(()))
                } else {
                    SchemeFile::Socket(SocketFile::new_with_data(socket_handle, ()))
                }
            }
        };

        if let SchemeFile::Socket(_) = file {
            port_set.acquire_port(local_endpoint.port);
        }

        Ok(Some((file, None)))
    }

    fn fpath(&self, _: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
        let path = format!("tcp:{}/{}", self.remote_endpoint(), self.local_endpoint());
        let path = path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }
}
