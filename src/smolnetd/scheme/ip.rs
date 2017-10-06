use super::socket::*;

use smoltcp::socket::{RawPacketBuffer, RawSocket, RawSocketBuffer, SocketHandle};
use smoltcp::wire::{IpProtocol, IpVersion};
use smoltcp;
use std::io::{Read, Write};
use std::str;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use syscall::data::TimeSpec;
use syscall;

use device::NetworkDevice;
use super::Smolnetd;

pub type IpScheme = SocketScheme<RawSocket<'static, 'static>>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Setting {
    ReadTimeout,
    WriteTimeout,
}

impl<'a, 'b> SchemeSocket for RawSocket<'a, 'b> {
    type SchemeDataT = ();
    type DataT = ();
    type SettingT = Setting;

    fn new_scheme_data() -> Self::SchemeDataT {
        ()
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
                };
                return Ok(count);
            }
        }
    }

    fn new_socket(
        socket_set: &mut smoltcp::socket::SocketSet<'static, 'static, 'static>,
        path: &str,
        uid: u32,
        _: &mut Self::SchemeDataT,
    ) -> syscall::Result<(SocketHandle, Self::DataT)> {
        if uid != 0 {
            return Err(syscall::Error::new(syscall::EACCES));
        }
        let proto =
            u8::from_str_radix(path, 16).or_else(|_| Err(syscall::Error::new(syscall::ENOENT)))?;

        let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
        for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
            rx_packets.push(RawPacketBuffer::new(vec![0; NetworkDevice::MTU]));
            tx_packets.push(RawPacketBuffer::new(vec![0; NetworkDevice::MTU]));
        }
        let rx_buffer = RawSocketBuffer::new(rx_packets);
        let tx_buffer = RawSocketBuffer::new(tx_packets);
        let ip_socket = RawSocket::new(
            IpVersion::Ipv4,
            IpProtocol::from(proto),
            rx_buffer,
            tx_buffer,
        );

        let socket_handle = socket_set.add(ip_socket);
        Ok((socket_handle, ()))
    }

    fn close_file(&self, _: &SchemeFile<Self>, _: &mut Self::SchemeDataT) -> syscall::Result<()> {
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        if self.can_send() {
            self.send_slice(buf).expect("Can't send slice");
            Ok(buf.len())
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        }
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> syscall::Result<usize> {
        if self.can_recv() {
            let length = self.recv_slice(buf).expect("Can't receive slice");
            Ok(length)
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(syscall::Error::new(syscall::EWOULDBLOCK))
        }
    }

    fn dup(
        _socket_set: &mut smoltcp::socket::SocketSet<'static, 'static, 'static>,
        socket_handle: SocketHandle,
        _file: &mut SchemeFile<Self>,
        fd: usize,
        path: &str,
        _: &mut Self::SchemeDataT,
    ) -> syscall::Result<DupResult<Self>> {
        match path {
            "write_timeout" => Ok((
                SchemeFile::Setting(SettingFile {
                    socket_handle,
                    fd,
                    setting: Setting::WriteTimeout,
                }),
                None,
            )),
            "read_timeout" => Ok((
                SchemeFile::Setting(SettingFile {
                    socket_handle,
                    fd,
                    setting: Setting::ReadTimeout,
                }),
                None,
            )),
            _ => Err(syscall::Error::new(syscall::EBADF)),
        }
    }

    fn fpath(&self, _file: &SchemeFile<Self>, buf: &mut [u8]) -> syscall::Result<usize> {
        let path = format!("ip:{}", self.ip_protocol());
        let path = path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }
}
