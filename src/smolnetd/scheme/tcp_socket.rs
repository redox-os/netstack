use super::socket::*;

use smoltcp::socket::{AsSocket, Socket, SocketHandle, TcpSocket, TcpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use std::io::{Read, Write};
use std::str::FromStr;
use std::str;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use syscall::data::TimeSpec;
use syscall;

use port_set::PortSet;

pub type TcpScheme = SocketScheme<TcpSocket<'static>>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Setting {
    Ttl,
    ReadTimeout,
    WriteTimeout,
}

impl<'a> SchemeSocket for TcpSocket<'a> {
    type SchemeDataT = PortSet;
    type DataT = ();
    type SettingT = Setting;

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(49_152u16, 65_535u16).expect("Wrong TCP port numbers")
    }

    fn can_send(&self) -> bool {
        self.can_send()
    }

    fn can_recv(&self) -> bool {
        self.can_recv()
    }

    fn get_setting(
        file: &SocketFile<Self::DataT>,
        setting: Self::SettingT,
        buf: &mut [u8],
    ) -> syscall::Result<usize> {
        trace!("TCP get setting {:?}", setting);
        let timespec = match (setting, file.read_timeout, file.write_timeout) {
            (Setting::ReadTimeout, Some(read_timeout), _) => read_timeout,
            (Setting::WriteTimeout, _, Some(write_timeout)) => write_timeout,
            _ => {
                return Ok(0);
            }
        };

        if buf.len() < mem::size_of::<TimeSpec>() {
            Ok(0)
        } else {
            let count = timespec.deref().read(buf).map_err(|err| {
                syscall::Error::new(err.raw_os_error().unwrap_or(syscall::EIO))
            })?;
            Ok(count)
        }
    }

    fn set_setting(
        file: &mut SocketFile<Self::DataT>,
        setting: Self::SettingT,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        trace!("TCP set setting {:?}", setting);
        match setting {
            Setting::ReadTimeout | Setting::WriteTimeout => {
                let (timeout, count) = {
                    if buf.len() < mem::size_of::<TimeSpec>() {
                        (None, 0)
                    } else {
                        let mut timespec = TimeSpec::default();
                        let count = timespec.deref_mut().write(buf).map_err(|err| {
                            syscall::Error::new(err.raw_os_error().unwrap_or(syscall::EIO))
                        })?;
                        (Some(timespec), count)
                    }
                };
                match setting {
                    Setting::ReadTimeout => {
                        file.read_timeout = timeout;
                    }
                    Setting::WriteTimeout => {
                        file.write_timeout = timeout;
                    }
                    _ => {}
                };
                return Ok(count);
            }
            Setting::Ttl => {}
        }
        Ok(0)
    }

    fn new_socket(
        path: &str,
        uid: u32,
        port_set: &mut Self::SchemeDataT,
    ) -> syscall::Result<(Socket<'static, 'static>, Self::DataT)> {
        trace!("TCP open {}", path);
        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port > 0 && local_endpoint.port <= 1024 && uid != 0 {
            return Err(syscall::Error::new(syscall::EACCES));
        }

        let rx_packets = vec![0; 65535];
        let tx_packets = vec![0; 65535];
        let rx_buffer = TcpSocketBuffer::new(rx_packets);
        let tx_buffer = TcpSocketBuffer::new(tx_packets);
        let mut tcp_socket = TcpSocket::new(rx_buffer, tx_buffer);

        if local_endpoint.port == 0 {
            local_endpoint.port = port_set
                .get_port()
                .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
        } else if !port_set.claim_port(local_endpoint.port) {
            return Err(syscall::Error::new(syscall::EADDRINUSE));
        }

        {
            let tcp_socket: &mut TcpSocket = tcp_socket.as_socket();
            trace!("Connecting tcp {} {}", local_endpoint, remote_endpoint);
            tcp_socket
                .connect(remote_endpoint, local_endpoint)
                .expect("Can't connect tcp socket ");
        }

        Ok((tcp_socket, ()))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> syscall::Result<()> {
        if let &SchemeFile::Socket(_) = file {
            port_set.release_port(self.local_endpoint().port);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        if !self.is_open() {
            return Err(syscall::Error::new(syscall::EADDRNOTAVAIL));
        }
        return if self.can_send() {
            self.send_slice(buf).expect("Can't send slice");
            Ok(buf.len())
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        };
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> syscall::Result<usize> {
        return if self.can_recv() {
            let length = self.recv_slice(buf).expect("Can't receive slice");
            Ok(length)
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        };
    }

    fn dup(
        &self,
        file: &mut SchemeFile<Self>,
        fd: usize,
        socket_handle: SocketHandle,
        path: &str,
        port_set: &mut Self::SchemeDataT,
    ) -> syscall::Result<SchemeFile<Self>> {
        trace!("TCP dup {}", path);
        let handle = match path {
            "ttl" => SchemeFile::Setting(SettingFile {
                socket_handle,
                fd,
                setting: Setting::Ttl,
            }),
            "read_timeout" => SchemeFile::Setting(SettingFile {
                socket_handle,
                fd,
                setting: Setting::ReadTimeout,
            }),
            "write_timeout" => SchemeFile::Setting(SettingFile {
                socket_handle,
                fd,
                setting: Setting::WriteTimeout,
            }),
            _ => if let SchemeFile::Socket(ref tcp_handle) = *file {
                SchemeFile::Socket(tcp_handle.clone_with_data(()))
            } else {
                SchemeFile::Socket(SocketFile::new_with_data(socket_handle, ()))
            },
        };

        if let SchemeFile::Socket(_) = handle {
            port_set.acquire_port(self.local_endpoint().port);
        }

        Ok(handle)
    }
}

fn parse_endpoint(socket: &str) -> IpEndpoint {
    let mut socket_parts = socket.split(':');
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