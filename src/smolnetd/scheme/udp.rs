use smoltcp::socket::{AsSocket, SocketHandle, UdpPacketBuffer, UdpSocket, UdpSocketBuffer};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;
use std::str;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use syscall::SchemeMut;
use syscall::data::TimeSpec;
use syscall;

use device::NetworkDevice;
use error::{Error, Result};
use super::{Smolnetd, SocketSet};
use port_set::PortSet;
use super::post_fevent;

#[derive(Copy, Clone, Eq, PartialEq)]
enum Setting {
    Ttl,
    ReadTimeout,
    WriteTimeout,
}

struct UdpHandle {
    flags: usize,
    events: usize,
    remote_endpoint: IpEndpoint,
    read_timeout: Option<TimeSpec>,
    write_timeout: Option<TimeSpec>,
    socket_handle: SocketHandle,
}

struct SettingHandle {
    fd: usize,
    socket_handle: SocketHandle,
    setting: Setting,
}

enum FdHandle {
    Setting(SettingHandle),
    Socket(UdpHandle),
}

impl FdHandle {
    fn socket_handle(&self) -> SocketHandle {
        match *self {
            FdHandle::Socket(UdpHandle { socket_handle, .. }) |
            FdHandle::Setting(SettingHandle { socket_handle, .. }) => socket_handle,
        }
    }
}

struct WaitHandle {
    until: Option<TimeSpec>,
    packet: syscall::Packet,
}

pub struct UdpScheme {
    next_udp_fd: usize,
    udp_fds: BTreeMap<usize, FdHandle>,
    socket_set: SocketSet,
    port_set: PortSet,
    udp_file: File,
    read_wait_queue: BTreeMap<SocketHandle, Vec<WaitHandle>>,
    write_wait_queue: BTreeMap<SocketHandle, Vec<WaitHandle>>,
}

impl UdpScheme {
    pub fn new(socket_set: SocketSet, udp_file: File) -> UdpScheme {
        UdpScheme {
            next_udp_fd: 1,
            udp_fds: BTreeMap::new(),
            socket_set,
            // 49152..65535 is the suggested range for dynamic private ports
            port_set: PortSet::new(49_152u16, 65_535u16).expect("Wrong UDP port numbers"),
            udp_file,
            read_wait_queue: BTreeMap::new(),
            write_wait_queue: BTreeMap::new(),
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.udp_file.read(&mut packet)? == 0 {
                break;
            }
            let a = packet.a;
            self.handle(&mut packet);
            if packet.a != (-syscall::EWOULDBLOCK) as usize {
                self.udp_file.write_all(&packet)?;
            } else {
                packet.a = a;
                self.handle_block(packet)?;
            }
        }
        Ok(None)
    }

    pub fn notify_sockets(&mut self) -> Result<()> {
        for (&fd, handle) in &self.udp_fds {
            if let FdHandle::Socket(UdpHandle { socket_handle, .. }) = *handle {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut UdpSocket = socket_set.get_mut(socket_handle).as_socket();
                if socket.can_send() {
                    post_fevent(&mut self.udp_file, fd, syscall::EVENT_READ, 1)?;
                }
            }
        }
        Ok(())
    }

    fn handle_block(&mut self, mut packet: syscall::Packet) -> Result<()> {
        let syscall_result = self.try_handle_block(&mut packet);
        if let Err(syscall_error) = syscall_result {
            packet.a = (-syscall_error.errno) as usize;
            self.udp_file.write_all(&packet)?;
            Err(Error::from_syscall_error(
                syscall_error,
                "Can't handle blocked socket",
            ))
        } else {
            Ok(())
        }
    }

    fn try_handle_block(&mut self, packet: &mut syscall::Packet) -> syscall::Result<()> {
        let fd = packet.b;
        let (socket_handle, read_timeout, write_timeout) = {
            let handle = self.udp_fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            if let FdHandle::Socket(ref udp_handle) = *handle {
                Ok((
                    udp_handle.socket_handle,
                    udp_handle.read_timeout,
                    udp_handle.write_timeout,
                ))
            } else {
                Err(syscall::Error::new(syscall::EBADF))
            }
        }?;

        let (mut timeout, queue) = match packet.a {
            syscall::SYS_READ => Ok((read_timeout, &mut self.read_wait_queue)),
            syscall::SYS_WRITE => Ok((write_timeout, &mut self.write_wait_queue)),
            _ => Err(syscall::Error::new(syscall::EBADF)),
        }?;

        if let Some(ref mut timeout) = timeout {
            let mut cur_time = TimeSpec::default();
            syscall::clock_gettime(syscall::CLOCK_MONOTONIC, &mut cur_time)?;
            *timeout = add_time(timeout, &cur_time)
        }

        queue
            .entry(socket_handle)
            .or_insert_with(|| vec![])
            .push(WaitHandle {
                until: timeout,
                packet: *packet,
            });

        Ok(())
    }

    fn get_setting(
        &mut self,
        fd: usize,
        setting: Setting,
        buf: &mut [u8],
    ) -> syscall::Result<usize> {
        let handle = self.udp_fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let handle = match *handle {
            FdHandle::Socket(ref mut handle) => handle,
            _ => {
                return Err(syscall::Error::new(syscall::EBADF));
            }
        };
        let timespec = match (setting, handle.read_timeout, handle.write_timeout) {
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

    fn update_setting(
        &mut self,
        fd: usize,
        setting: Setting,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        let handle = self.udp_fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let handle = match *handle {
            FdHandle::Socket(ref mut handle) => handle,
            _ => {
                return Err(syscall::Error::new(syscall::EBADF));
            }
        };
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
                        handle.read_timeout = timeout;
                    }
                    Setting::WriteTimeout => {
                        handle.write_timeout = timeout;
                    }
                    _ => {}
                };
                return Ok(count);
            }
            Setting::Ttl => {}
        }
        Ok(0)
    }
}

impl syscall::SchemeMut for UdpScheme {
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> syscall::Result<usize> {
        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;

        trace!("Udp open {} ", path);

        let mut parts = path.split('/');
        let remote_endpoint = parse_endpoint(parts.next().unwrap_or(""));
        let mut local_endpoint = parse_endpoint(parts.next().unwrap_or(""));

        if local_endpoint.port <= 1024 && uid != 0 {
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
            local_endpoint.port = self.port_set
                .get_port()
                .ok_or_else(|| syscall::Error::new(syscall::EINVAL))?;
        } else if !self.port_set.claim_port(local_endpoint.port) {
            return Err(syscall::Error::new(syscall::EADDRINUSE));
        }

        {
            let udp_socket: &mut UdpSocket = udp_socket.as_socket();
            udp_socket
                .bind(local_endpoint)
                .expect("Can't bind udp socket to local endpoint");
        }

        let socket_handle = self.socket_set.borrow_mut().add(udp_socket);
        let id = self.next_udp_fd;

        self.udp_fds.insert(
            id,
            FdHandle::Socket(UdpHandle {
                flags,
                events: 0,
                socket_handle,
                write_timeout: None,
                read_timeout: None,
                remote_endpoint: remote_endpoint,
            }),
        );
        self.next_udp_fd += 1;
        trace!("Udp open fd {} ", id);
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("Upd close {}", fd);
        let socket_handle = {
            let handle = self.udp_fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle()
        };
        self.udp_fds.remove(&fd);
        let mut socket_set = self.socket_set.borrow_mut();
        let endpoint = {
            let socket: &mut UdpSocket = socket_set.get_mut(socket_handle).as_socket();
            socket.endpoint()
        };
        self.write_wait_queue.remove(&socket_handle);
        self.read_wait_queue.remove(&socket_handle);
        socket_set.release(socket_handle);
        //TODO: removing sockets in release should make prune unnecessary
        socket_set.prune();
        if endpoint.port != 0 {
            self.port_set.release_port(endpoint.port);
        }
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        trace!("Upd write {} len {}", fd, buf.len());

        let (fd, setting) = {
            let handle = self.udp_fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            match *handle {
                FdHandle::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                FdHandle::Socket(ref handle) => {
                    if !handle.remote_endpoint.is_specified() {
                        return Err(syscall::Error::new(syscall::EADDRNOTAVAIL));
                    }
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket: &mut UdpSocket =
                        socket_set.get_mut(handle.socket_handle).as_socket();
                    socket
                        .send_slice(buf, handle.remote_endpoint)
                        .expect("Can't send slice");
                    return Ok(buf.len());
                }
            }
        };
        self.update_setting(fd, setting, buf)
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        trace!("udp read {} {}", fd, buf.len());
        let (fd, setting) = {
            let handle = self.udp_fds.get(&fd).ok_or_else(|| {
                trace!("UDP read EBADF {}", fd);
                syscall::Error::new(syscall::EBADF)
            })?;
            match *handle {
                FdHandle::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                FdHandle::Socket(ref handle) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket: &mut UdpSocket =
                        socket_set.get_mut(handle.socket_handle).as_socket();
                    return if socket.can_recv() {
                        let (length, _) = socket.recv_slice(buf).expect("Can't receive slice");
                        trace!("Upd read {}", fd);
                        Ok(length)
                    } else if handle.flags & syscall::O_NONBLOCK == syscall::O_NONBLOCK {
                        Ok(0)
                    } else {
                        Err(syscall::Error::new(syscall::EWOULDBLOCK))
                    };
                }
            }
        };
        self.get_setting(fd, setting, buf)
    }

    fn dup(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        let path = str::from_utf8(buf).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;
        trace!("udp dup {} {}", fd, path);

        let handle = {
            let handle = self.udp_fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            let socket_handle = handle.socket_handle();

            match path {
                "ttl" => FdHandle::Setting(SettingHandle {
                    socket_handle,
                    fd,
                    setting: Setting::Ttl,
                }),
                "read_timeout" => FdHandle::Setting(SettingHandle {
                    socket_handle,
                    fd,
                    setting: Setting::ReadTimeout,
                }),
                "write_timeout" => FdHandle::Setting(SettingHandle {
                    socket_handle,
                    fd,
                    setting: Setting::WriteTimeout,
                }),
                _ => {
                    let remote_endpoint = parse_endpoint(path);
                    if let FdHandle::Socket(ref udp_handle) = *handle {
                        FdHandle::Socket(UdpHandle {
                            flags: udp_handle.flags,
                            events: udp_handle.events,
                            read_timeout: udp_handle.read_timeout,
                            write_timeout: udp_handle.write_timeout,
                            remote_endpoint: if remote_endpoint.is_specified() {
                                remote_endpoint
                            } else {
                                udp_handle.remote_endpoint
                            },
                            socket_handle,
                        })
                    } else {
                        FdHandle::Socket(UdpHandle {
                            flags: 0,
                            events: 0,
                            read_timeout: None,
                            write_timeout: None,
                            remote_endpoint: remote_endpoint,
                            socket_handle,
                        })
                    }
                }
            }
        };

        self.socket_set.borrow_mut().retain(handle.socket_handle());
        let port = {
            let mut socket_set = self.socket_set.borrow_mut();
            let socket: &mut UdpSocket = socket_set.get_mut(handle.socket_handle()).as_socket();
            socket.endpoint().port
        };
        self.port_set.acquire_port(port);

        let id = self.next_udp_fd;
        self.udp_fds.insert(id, handle);
        self.next_udp_fd += 1;

        Ok(id)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        trace!("udp fevent {}", fd);
        let handle = self.udp_fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        match *handle {
            FdHandle::Setting(_) => Err(syscall::Error::new(syscall::EBADF)),
            FdHandle::Socket(ref mut handle) => {
                handle.events = events;
                Ok(fd)
            }
        }
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        trace!("udp fsync {}", fd);
        {
            let _handle = self.udp_fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
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

fn add_time(a: &TimeSpec, b: &TimeSpec) -> TimeSpec {
    let mut secs = a.tv_sec + b.tv_sec;
    let mut nsecs = a.tv_nsec + b.tv_nsec;

    secs += i64::from(nsecs) / 1_000_000_000;
    nsecs %= 1_000_000_000;

    TimeSpec {
        tv_sec: secs,
        tv_nsec: nsecs,
    }
}
