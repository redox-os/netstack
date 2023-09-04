use smoltcp::socket::icmp::{Endpoint as IcmpEndpoint, PacketMetadata as IcmpPacketMetadata, Socket as IcmpSocket, PacketBuffer as IcmpSocketBuffer};
use smoltcp::iface::SocketHandle;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress, IpListenEndpoint};
use std::mem;
use std::str;
use syscall::{Error as SyscallError, Result as SyscallResult};
use syscall;
use byteorder::{ByteOrder, NetworkEndian};

use crate::port_set::PortSet;
use crate::router::Router;
use super::socket::{DupResult, SchemeFile, SchemeSocket, SocketFile, SocketScheme, Context};
use super::{Smolnetd, SocketSet};

pub type IcmpScheme = SocketScheme<IcmpSocket<'static>>;

enum IcmpSocketType {
    Echo,
    Udp,
}

pub struct IcmpData {
    socket_type: IcmpSocketType,
    ip: IpAddress,
    ident: u16,
}

impl<'a> SchemeSocket for IcmpSocket<'a> {
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

    fn may_recv(&self) -> bool {
        true
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

    fn hop_limit(&self) -> u8 {
        self.hop_limit().unwrap_or(64)
    }

    fn set_hop_limit(&mut self, hop_limit: u8) {
        self.set_hop_limit(Some(hop_limit));
    }

    fn new_socket(
        socket_set: &mut SocketSet,
        path: &str,
        _uid: u32,
        ident_set: &mut Self::SchemeDataT,
        _context: &Context
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

                let socket = IcmpSocket::new(
                    IcmpSocketBuffer::new(
                        vec![IcmpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
                        vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE]
                    ),
                    IcmpSocketBuffer::new(
                        vec![IcmpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
                        vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE]
                    )
                );
                let handle = socket_set.add(socket);
                let icmp_socket = socket_set.get_mut::<IcmpSocket>(handle);
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
            "udp" => {
                let addr = parts
                    .next()
                    .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
                let ip =
                    IpAddress::from_str(addr).map_err(|_| syscall::Error::new(syscall::EINVAL))?;

                let socket = IcmpSocket::new(
                    IcmpSocketBuffer::new(
                        vec![IcmpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
                        vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE]
                    ),
                    IcmpSocketBuffer::new(
                        vec![IcmpPacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
                        vec![0; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE]
                    )
                );
                let handle = socket_set.add(socket);
                let icmp_socket = socket_set.get_mut::<IcmpSocket>(handle);
                let ident = ident_set
                    .get_port()
                    .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
                icmp_socket
                    .bind(IcmpEndpoint::Udp(IpListenEndpoint::from(ident)))
                    .map_err(|_| syscall::Error::new(syscall::EINVAL))?;
                let socket_data = IcmpData {
                    socket_type: IcmpSocketType::Udp,
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
    ) -> SyscallResult<Option<usize>> {
        if self.can_send() {
            match file.data.socket_type {
                IcmpSocketType::Echo => {
                    if buf.len() < mem::size_of::<u16>() {
                        return Err(SyscallError::new(syscall::EINVAL));
                    }
                    let (seq_buf, payload) = buf.split_at(mem::size_of::<u16>());
                    let seq_no = NetworkEndian::read_u16(seq_buf);
                    let icmp_repr = Icmpv4Repr::EchoRequest {
                        ident: file.data.ident,
                        seq_no,
                        data: payload,
                    };

                    let icmp_payload = self.send(icmp_repr.buffer_len(), file.data.ip)
                        .map_err(|_| syscall::Error::new(syscall::EINVAL))?;
                    let mut icmp_packet = Icmpv4Packet::new_unchecked(icmp_payload);
                    //TODO: replace Default with actual caps
                    icmp_repr.emit(&mut icmp_packet, &Default::default());
                    Ok(Some(buf.len()))
                }
                IcmpSocketType::Udp => {
                    Err(SyscallError::new(syscall::EINVAL))
                }
            }
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
        while self.can_recv() {
            let (payload, _) = self.recv().expect("Can't recv icmp packet");
            let icmp_packet = Icmpv4Packet::new_unchecked(&payload);
            //TODO: replace default with actual caps
            let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &Default::default()).unwrap();

            if let Icmpv4Repr::EchoReply { seq_no, data, .. } = icmp_repr {
                if buf.len() < mem::size_of::<u16>() + data.len() {
                    return Err(SyscallError::new(syscall::EINVAL));
                }
                NetworkEndian::write_u16(&mut buf[0..2], seq_no);

                for i in 0..data.len() {
                    buf[mem::size_of::<u16>() + i] = data[i];
                }

                return Ok(Some(mem::size_of::<u16>() + data.len()));
            }
        }

        if file.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
            Err(SyscallError::new(syscall::EAGAIN))
        } else {
            Ok(None) // internally scheduled to re-read
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
                IcmpSocketType::Udp => {
                    let path = format!("icmp:udp/{}", socket_file.data.ip);
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
