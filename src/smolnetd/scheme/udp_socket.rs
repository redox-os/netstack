use super::socket::*;

use smoltcp::socket::{AsSocket, Socket, SocketHandle, UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use std::io::{Read, Write};
use std::str::FromStr;
use std::str;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use syscall::data::TimeSpec;
use syscall;

use device::NetworkDevice;
use super::Smolnetd;
use port_set::PortSet;

pub type UdpScheme = SocketScheme<UdpSocket<'static, 'static>>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Setting {
    Ttl,
    ReadTimeout,
    WriteTimeout,
}

impl<'a, 'b> SchemeSocket for UdpSocket<'a, 'b> {
    type SchemeDataT = PortSet;
    type DataT = IpEndpoint;
    type SettingT = Setting;

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(49_152u16, 65_535u16).expect("Wrong UDP port numbers")
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
        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port > 0 && local_endpoint.port <= 1024 && uid != 0 {
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
            local_endpoint.port = port_set
                .get_port()
                .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
        } else if !port_set.claim_port(local_endpoint.port) {
            return Err(syscall::Error::new(syscall::EADDRINUSE));
        }

        {
            let udp_socket: &mut UdpSocket = udp_socket.as_socket();
            udp_socket
                .bind(local_endpoint)
                .expect("Can't bind udp socket to local endpoint");
        }

        Ok((udp_socket, remote_endpoint))
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        port_set: &mut Self::SchemeDataT,
    ) -> syscall::Result<()> {
        if let &SchemeFile::Socket(_) = file {
            port_set.release_port(self.endpoint().port);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        if !file.data.is_specified() {
            return Err(syscall::Error::new(syscall::EADDRNOTAVAIL));
        }
        return if self.can_send() {
            self.send_slice(buf, file.data).expect("Can't send slice");
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
            let (length, _) = self.recv_slice(buf).expect("Can't receive slice");
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

        if let SchemeFile::Socket(_) = handle {
            port_set.acquire_port(self.endpoint().port);
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
