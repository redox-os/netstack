use smoltcp::socket::{IcmpEndpoint, IcmpPacketBuffer, IcmpSocket, IcmpSocketBuffer, SocketHandle};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress};
use std::mem;
use std::str;
use syscall::{Error as SyscallError, Result as SyscallResult};
use syscall;

use device::NetworkDevice;
use port_set::PortSet;
use super::socket::{DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme};
use super::{Smolnetd, SocketSet};

pub type IcmpScheme = SocketScheme<IcmpSocket<'static, 'static>>;

enum IcmpSocketType {
    Echo,
}

pub struct IcmpData {
    socket_type: IcmpSocketType,
    ip: IpAddress,
    ident: u16,
}

impl<'a, 'b> SchemeSocket for IcmpSocket<'a, 'b> {
    type SchemeDataT = PortSet;
    type DataT = IcmpData;
    type SettingT = ();

    fn new_scheme_data() -> Self::SchemeDataT {
        PortSet::new(1u16, 0xffffu16).expect("Wrong ICMP ident values")
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
        self.ttl().unwrap_or(64)
    }

    fn set_ttl(&mut self, ttl: u8) {
        self.set_ttl(Some(ttl));
    }

    fn new_socket(
        socket_set: &mut SocketSet,
        path: &str,
        _uid: u32,
        ident_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<(SocketHandle, Self::DataT)> {
        use std::str::FromStr;

        let mut parts = path.split('/');
        let method = parts
            .next()
            .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;

        match method {
            "echo" => {
                let addr = parts
                    .next()
                    .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
                let ip =
                    IpAddress::from_str(addr).map_err(|_| syscall::Error::new(syscall::EINVAL))?;

                let mut rx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
                let mut tx_packets = Vec::with_capacity(Smolnetd::SOCKET_BUFFER_SIZE);
                for _ in 0..Smolnetd::SOCKET_BUFFER_SIZE {
                    rx_packets.push(IcmpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
                    tx_packets.push(IcmpPacketBuffer::new(vec![0; NetworkDevice::MTU]));
                }

                let socket = IcmpSocket::new(IcmpSocketBuffer::new(rx_packets),
                                             IcmpSocketBuffer::new(tx_packets));
                let handle = socket_set.add(socket);
                let mut icmp_socket = socket_set.get::<IcmpSocket>(handle);
                let ident = ident_set
                    .get_port()
                    .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
                icmp_socket
                    .bind(IcmpEndpoint::Ident(ident))
                    .map_err(|_| syscall::Error::new(syscall::EINVAL))?;
                let socket_data = IcmpData {
                    socket_type: IcmpSocketType::Echo,
                    ident,
                    ip,
                };
                Ok((handle, socket_data))
            }
            _ => Err(syscall::Error::new(syscall::EINVAL)),
        }
    }

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        ident_set: &mut Self::SchemeDataT,
    ) -> SyscallResult<()> {
        if let SchemeFile::Socket(ref file) = *file {
            ident_set.release_port(file.data.ident);
        }
        Ok(())
    }

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<usize> {
        if self.can_send() {
            match file.data.socket_type {
                IcmpSocketType::Echo => {
                    if buf.len() < mem::size_of::<u16>() {
                        return Err(SyscallError::new(syscall::EINVAL));
                    }
                    let (seq_buf, payload) = buf.split_at(mem::size_of::<u16>());
                    // Don't really care about endianness here as long as it's consistent with read
                    let seq_no: u16 = u16::from(seq_buf[0]) | (u16::from(seq_buf[1]) << 8);
                    let icmp_repr = Icmpv4Repr::EchoRequest {
                        ident: file.data.ident,
                        seq_no,
                        data: payload,
                    };

                    let icmp_payload = self.send(icmp_repr.buffer_len(), file.data.ip)
                        .map_err(|_| syscall::Error::new(syscall::EINVAL))?;
                    let mut icmp_packet = Icmpv4Packet::new(icmp_payload);
                    //TODO: replace Default with actual caps
                    icmp_repr.emit(&mut icmp_packet, &Default::default());
                    Ok(buf.len())
                }
            }
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
        while self.can_recv() {
            let (payload, _) = self.recv().expect("Can't recv icmp packet");
            let icmp_packet = Icmpv4Packet::new(&payload);
            //TODO: replace default with actual caps
            let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &Default::default()).unwrap();

            if let Icmpv4Repr::EchoReply { seq_no, data, .. } = icmp_repr {
                if buf.len() < mem::size_of::<u16>() + data.len() {
                    return Err(SyscallError::new(syscall::EINVAL));
                }

                // Don't really care about endianness here as long as it's consistent with read
                buf[0] = (seq_no & 0xff) as u8;
                buf[1] = (seq_no >> 8) as u8;

                for i in 0..data.len() {
                    buf[mem::size_of::<u16>() + i] = data[i];
                }

                return Ok(mem::size_of::<u16>() + data.len());
            }
        }

        if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
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

    fn fpath(&self, file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize> {
        if let SchemeFile::Socket(ref socket_file) = *file {
            match socket_file.data.socket_type {
                IcmpSocketType::Echo => {
                    let path = format!("icmp:echo/{}", socket_file.data.ip);
                    let path = path.as_bytes();

                    let mut i = 0;
                    while i < buf.len() && i < path.len() {
                        buf[i] = path[i];
                        i += 1;
                    }

                    Ok(i)
                }
            }
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
    }
}
