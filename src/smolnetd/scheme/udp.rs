use smoltcp::socket::{SocketHandle, UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::IpEndpoint;
use std::str;
use syscall::{Error as SyscallError, Result as SyscallResult};
use syscall;

use device::NetworkDevice;
use port_set::PortSet;
use super::socket::{DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme};
use super::{parse_endpoint, Smolnetd, SocketSet};

pub type UdpScheme = SocketScheme<UdpSocket<'static, 'static>>;

impl<'a, 'b> SchemeSocket for UdpSocket<'a, 'b> {
    type SchemeDataT = PortSet;
    type DataT = IpEndpoint;
    type SettingT = ();

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(49_152u16, 65_535u16).expect("Wrong UDP port numbers")
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
        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port > 0 && local_endpoint.port <= 1024 && uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
            tx_packets.push(UdpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
        }
        let rx_buffer = UdpSocketBuffer::new(rx_packets);
        let tx_buffer = UdpSocketBuffer::new(tx_packets);
        let udp_socket = UdpSocket::new(rx_buffer, tx_buffer);

        if local_endpoint.port == 0 {
            local_endpoint.port = port_set
                .get_port()
                .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
        } else if !port_set.claim_port(local_endpoint.port) {
            return Err(SyscallError::new(syscall::EADDRINUSE));
        }

        let socket_handle = socket_set.add(udp_socket);

        let mut udp_socket = socket_set.get::<UdpSocket>(socket_handle);
        udp_socket
            .bind(local_endpoint)
            .expect("Can't bind udp socket to local endpoint");

        Ok((socket_handle, remote_endpoint))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<()> {
        if let SchemeFile::Socket(_) = *file {
            port_set.release_port(self.endpoint().port);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<Option<usize>> {
        if !file.data.is_specified() {
            return Err(SyscallError::new(syscall::EADDRNOTAVAIL));
        }
        if self.can_send() {
            self.send_slice(buf, file.data).expect("Can't send slice");
            Ok(Some(buf.len()))
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Ok(None) // internally scheduled to re-read
        }
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> SyscallResult<Option<usize>> {
        if self.can_recv() {
            let (length, _) = self.recv_slice(buf).expect("Can't receive slice");
            Ok(Some(length))
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
        let file = match path {
            _ => {
                let remote_endpoint = parse_endpoint(path);
                if let SchemeFile::Socket(ref udp_handle) = *file {
                    SchemeFile::Socket(udp_handle.clone_with_data(
                        if remote_endpoint.is_specified() {
                            remote_endpoint
                        } else {
                            udp_handle.data
                        },
                    ))
                } else {
                    SchemeFile::Socket(SocketFile::new_with_data(socket_handle, remote_endpoint))
                }
            }
        };

        let endpoint = {
            let socket = socket_set.get::<UdpSocket>(socket_handle);
            socket.endpoint()
        };

        if let SchemeFile::Socket(_) = file {
            port_set.acquire_port(endpoint.port);
        }

        Ok((file, None))
    }

    fn fpath(&self, file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
        if let SchemeFile::Socket(ref socket_file) = *file {
            let path = format!("udp:{}/{}", socket_file.data, self.endpoint());
            let path = path.as_bytes();

            let mut i = 0;
            while i < buf.len() && i < path.len() {
                buf[i] = path[i];
                i += 1;
            }

            Ok(i)
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
    }
}
