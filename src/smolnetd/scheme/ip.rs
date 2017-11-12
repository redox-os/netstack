use smoltcp::socket::{RawPacketBuffer, RawSocket, RawSocketBuffer, SocketHandle};
use smoltcp::wire::{IpProtocol, IpVersion};
use std::str;
use syscall::{Error as SyscallError, Result as SyscallResult};
use syscall;

use device::NetworkDevice;
use super::{Smolnetd, SocketSet};
use super::socket::{DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme};

pub type IpScheme = SocketScheme<RawSocket<'static, 'static>>;

impl<'a, 'b> SchemeSocket for RawSocket<'a, 'b> {
    type SchemeDataT = ();
    type DataT = ();
    type SettingT = ();

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

    fn ttl(&self) -> u8 {
        0
    }

    fn set_ttl(&mut self, _ttl: u8) {}

    fn new_socket(
        socket_set: &mut SocketSet,
        path: &str,
        uid: u32,
        _: &mut Self::SchemeDataT,
    ) -> SyscallResult<(SocketHandle, Self::DataT)> {
        if uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }
        let proto =
            u8::from_str_radix(path, 16).or_else(|_| Err(SyscallError::new(syscall::ENOENT)))?;

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

    fn close_file(&self, _: &SchemeFile<Self>, _: &mut Self::SchemeDataT) -> SyscallResult<()> {
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<usize> {
        if self.can_send() {
            self.send_slice(buf).expect("Can't send slice");
            Ok(buf.len())
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(SyscallError::new(syscall::EWOULDBLOCK))
        }
    }

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        if self.can_recv() {
            let length = self.recv_slice(buf).expect("Can't receive slice");
            Ok(length)
        } else if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Ok(0)
        } else {
            Err(SyscallError::new(syscall::EWOULDBLOCK))
        }
    }

    fn dup(
        _socket_set: &mut SocketSet,
        _file: &mut SchemeFile<Self>,
        _path: &str,
        _: &mut Self::SchemeDataT,
    ) -> SyscallResult<DupResult<Self>> {
        Err(SyscallError::new(syscall::EBADF))
    }

    fn fpath(&self, _file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
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
