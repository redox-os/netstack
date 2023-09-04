use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use std::fmt::Write;
use std::str;
use syscall;
use syscall::{Error as SyscallError, Result as SyscallResult};

use super::socket::{Context, DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme};
use super::{parse_endpoint, SocketSet};
use crate::port_set::PortSet;

pub type TcpScheme = SocketScheme<TcpSocket<'static>>;

impl<'a> SchemeSocket for TcpSocket<'a> {
    type SchemeDataT = PortSet;
    type DataT = Option<IpListenEndpoint>;
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

    fn may_recv(&self) -> bool {
        self.may_recv()
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
        context: &Context,
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

        let tcp_socket = socket_set.get_mut::<TcpSocket>(socket_handle);

        let listen_enpoint = if remote_endpoint.is_specified() {
            let local_endpoint_addr = match local_endpoint.addr {
                Some(addr) if !addr.is_unspecified() => Some(addr),
                _ => {
                    let route_table = context.route_table.borrow();
                    let addr = route_table
                        .lookup_src_addr(&remote_endpoint.addr.expect("Checked in is_specified"));
                    if matches!(addr, None) {
                        error!("Opening a TCP connection with a probably invalid source IP as no route have been found for destination: {}", remote_endpoint);
                    }
                    addr
                }
            };
            let local_endpoint = IpListenEndpoint {
                addr: local_endpoint_addr,
                port: local_endpoint.port,
            };

            trace!("Connecting tcp {} {}", local_endpoint, remote_endpoint);
            tcp_socket
                .connect(
                    context.iface.borrow_mut().context(),
                    IpEndpoint::new(remote_endpoint.addr.unwrap(), remote_endpoint.port),
                    local_endpoint,
                )
                .expect("Can't connect tcp socket ");
            None
        } else {
            trace!("Listening tcp {}", local_endpoint);
            tcp_socket
                .listen(local_endpoint)
                .expect("Can't listen on local endpoint");
            Some(local_endpoint)
        };

        Ok((socket_handle, listen_enpoint))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<()> {
        if let SchemeFile::Socket(SocketFile { data, .. }) = *file {
            if let Some(endpoint) = self.local_endpoint() {
                // Socket was connected on some port
                port_set.release_port(endpoint.port);
            } else if let Some(endpoint) = data {
                // Socket was listening on some port
                port_set.release_port(endpoint.port);
            }
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
            "listen" => {
                if let SchemeFile::Socket(ref tcp_handle) = *file {
                    let Some(listen_enpoint) = tcp_handle.data else {
                        // This socket is not listening so we can't accept a connection 
                        return Err(SyscallError::new(syscall::EINVAL));
                    };

                    if !is_active {
                        // Socket listening but no connection received
                        if tcp_handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
                            return Err(SyscallError::new(syscall::EAGAIN));
                        } else {
                            return Ok(None);
                        }
                    }
                    trace!("TCP creating new listening socket");
                    // We pass None as data because this new handle is to the active connection so
                    // not a listening socket
                    let new_handle = SchemeFile::Socket(tcp_handle.clone_with_data(None));

                    // Creating a socket to continue listening
                    let rx_packets = vec![0; 0xffff];
                    let tx_packets = vec![0; 0xffff];
                    let rx_buffer = TcpSocketBuffer::new(rx_packets);
                    let tx_buffer = TcpSocketBuffer::new(tx_packets);
                    let socket = TcpSocket::new(rx_buffer, tx_buffer);
                    let new_socket_handle = socket_set.add(socket);
                    {
                        let tcp_socket = socket_set.get_mut::<TcpSocket>(new_socket_handle);
                        tcp_socket
                            .listen(listen_enpoint)
                            .expect("Can't listen on local endpoint");
                    }
                    // We got a new connection to the socket so acquire the port
                    port_set.acquire_port(
                        local_endpoint
                            .expect("Socket was active so local endpoint must be set")
                            .port,
                    );
                    return Ok(Some((
                        new_handle,
                        Some((new_socket_handle, Some(listen_enpoint))),
                    )));
                } else {
                    return Err(SyscallError::new(syscall::EBADF));
                }
            }
            _ => {
                trace!("TCP dup unknown {}", path);
                if let SchemeFile::Socket(ref tcp_handle) = *file {
                    SchemeFile::Socket(tcp_handle.clone_with_data(tcp_handle.data))
                } else {
                    SchemeFile::Socket(SocketFile::new_with_data(socket_handle, None))
                }
            }
        };

        if let SchemeFile::Socket(_) = file {
            if let Some(local_endpoint) = local_endpoint {
                port_set.acquire_port(local_endpoint.port);
            }
        }

        Ok(Some((file, None)))
    }

    fn fpath(&self, file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
        let unspecified = "0.0.0.0:0";
        let mut path = String::from("tcp:");
        match self.remote_endpoint() {
            Some(endpoint) => write!(&mut path, "{}", endpoint).unwrap(),
            None => path.push_str(unspecified),
        }
        path.push('/');
        match (self.local_endpoint(), file) {
            (Some(endpoint), _) => write!(&mut path, "{}", endpoint).unwrap(),
            (
                None,
                SchemeFile::Socket(SocketFile {
                    data: Some(endpoint),
                    ..
                }),
            ) => {
                if endpoint.is_specified() {
                    write!(&mut path, "{}", endpoint).unwrap()
                } else {
                    write!(&mut path, "0.0.0.0:{}", endpoint.port).unwrap()
                }
            }
            _ => path.push_str(unspecified),
        }
        trace!("fpath: {}", path);
        let path = path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }
}
