use smoltcp::socket::{AsSocket, Socket, SocketHandle};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str;
use std::marker::PhantomData;
use syscall::SchemeMut;
use syscall::data::TimeSpec;
use syscall;

use error::{Error, Result};
use super::SocketSet;
use super::post_fevent;

pub struct SocketFile<DataT> {
    pub flags: usize,
    events: usize,
    socket_handle: SocketHandle,
    pub data: DataT,
    pub read_timeout: Option<TimeSpec>,
    pub write_timeout: Option<TimeSpec>,
}

impl<DataT> SocketFile<DataT> {
    pub fn clone_with_data(&self, data: DataT) -> SocketFile<DataT> {
        SocketFile {
            flags: self.flags,
            events: self.events,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            socket_handle: self.socket_handle,
            data
        }
    }

    pub fn new_with_data(socket_handle: SocketHandle, data: DataT) -> SocketFile<DataT> {
        SocketFile {
            flags: 0,
            events: 0,
            read_timeout: None,
            write_timeout: None,
            socket_handle,
            data
        }
    }
}

pub struct SettingFile<SettingT> {
    pub fd: usize,
    pub socket_handle: SocketHandle,
    pub setting: SettingT,
}

pub enum SchemeFile<SocketT>
where
    SocketT: SchemeSocket,
{
    Setting(SettingFile<SocketT::SettingT>),
    Socket(SocketFile<SocketT::DataT>),
}

impl<SocketT> SchemeFile<SocketT>
where
    SocketT: SchemeSocket,
{
    fn socket_handle(&self) -> SocketHandle {
        match *self {
            SchemeFile::Socket(SocketFile { socket_handle, .. }) |
            SchemeFile::Setting(SettingFile { socket_handle, .. }) => socket_handle,
        }
    }
}

#[derive(Default, Clone)]
struct WaitHandle {
    until: Option<TimeSpec>,
    packet: syscall::Packet,
}

#[derive(Default)]
struct WaitQueues {
    read_queue: Vec<WaitHandle>,
    write_queue: Vec<WaitHandle>,
}

pub trait SchemeSocket
where
    Self: ::std::marker::Sized,
{
    type SchemeDataT;
    type DataT;
    type SettingT: Copy;

    fn new_scheme_data() -> Self::SchemeDataT;

    fn can_send(&self) -> bool;
    fn can_recv(&self) -> bool;

    fn get_setting(&SocketFile<Self::DataT>, Self::SettingT, &mut [u8]) -> syscall::Result<usize>;
    fn set_setting(&mut SocketFile<Self::DataT>, Self::SettingT, &[u8]) -> syscall::Result<usize>;

    fn new_socket(
        &str,
        u32,
        &mut Self::SchemeDataT,
    ) -> syscall::Result<(Socket<'static, 'static>, Self::DataT)>;
    fn close_file(&self, &SchemeFile<Self>, &mut Self::SchemeDataT) -> syscall::Result<()>;

    fn write_buf(&mut self, &mut SocketFile<Self::DataT>, buf: &[u8]) -> syscall::Result<usize>;
    fn read_buf(&mut self, &mut SocketFile<Self::DataT>, buf: &mut [u8]) -> syscall::Result<usize>;

    fn dup(
        &self,
        &mut SchemeFile<Self>,
        usize,
        SocketHandle,
        &str,
        &mut Self::SchemeDataT,
    ) -> syscall::Result<SchemeFile<Self>>;
}

type WaitQueueMap = BTreeMap<SocketHandle, WaitQueues>;

pub struct SocketScheme<SocketT>
where
    SocketT: SchemeSocket,
    Socket<'static, 'static>: AsSocket<SocketT>,
{
    next_fd: usize,
    fds: BTreeMap<usize, SchemeFile<SocketT>>,
    socket_set: SocketSet,
    scheme_file: File,
    wait_queue_map: WaitQueueMap,
    scheme_data: SocketT::SchemeDataT,
    _phantom_socket: PhantomData<SocketT>,
}

impl<SocketT> SocketScheme<SocketT>
where
    SocketT: SchemeSocket,
    Socket<'static, 'static>: AsSocket<SocketT>,
{
    pub fn new(socket_set: SocketSet, scheme_file: File) -> SocketScheme<SocketT> {
        SocketScheme {
            next_fd: 1,
            fds: BTreeMap::new(),
            socket_set,
            scheme_data: SocketT::new_scheme_data(),
            scheme_file,
            wait_queue_map: BTreeMap::new(),
            _phantom_socket: PhantomData,
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.scheme_file.read(&mut packet)? == 0 {
                break;
            }
            let a = packet.a;
            self.handle(&mut packet);
            if packet.a != (-syscall::EWOULDBLOCK) as usize {
                self.scheme_file.write_all(&packet)?;
            } else {
                packet.a = a;
                self.handle_block(packet)?;
            }
        }
        Ok(None)
    }

    pub fn notify_sockets(&mut self) -> Result<()> {
        // Notify non-blocking sockets
        for (&fd, handle) in &self.fds {
            if let SchemeFile::Socket(SocketFile {
                socket_handle,
                events,
                ..
            }) = *handle
            {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut SocketT = socket_set.get_mut(socket_handle).as_socket();

                if events & syscall::EVENT_READ == syscall::EVENT_READ && socket.can_recv() {
                    post_fevent(&mut self.scheme_file, fd, syscall::EVENT_READ, 1)?;
                }

                if events & syscall::EVENT_WRITE == syscall::EVENT_WRITE && socket.can_send() {
                    post_fevent(&mut self.scheme_file, fd, syscall::EVENT_WRITE, 1)?;
                }
            }
        }

        // Wake up blocking queue
        self.wake_up_queues()?;

        Ok(())
    }

    fn wake_up_queues(&mut self) -> Result<()> {
        let mut cur_time = TimeSpec::default();
        syscall::clock_gettime(syscall::CLOCK_MONOTONIC, &mut cur_time)
            .map_err(|e| Error::from_syscall_error(e, "Can't get time"))?;

        let socket_handles: Vec<_> = self.wait_queue_map.keys().cloned().collect();

        for socket_handle in socket_handles {
            let (can_recv, can_send) = {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket: &mut SocketT = socket_set.get_mut(socket_handle).as_socket();
                (socket.can_recv(), socket.can_send())
            };

            if can_recv {
                self.wake_up_wait_queue(socket_handle, cur_time, |wq| &mut wq.read_queue)?;
            }

            if can_send {
                self.wake_up_wait_queue(socket_handle, cur_time, |wq| &mut wq.write_queue)?;
            }
        }
        Ok(())
    }

    fn wake_up_wait_queue<F>(
        &mut self,
        socket_handle: SocketHandle,
        cur_time: syscall::TimeSpec,
        f: F,
    ) -> Result<()>
    where
        F: Fn(&mut WaitQueues) -> &mut Vec<WaitHandle>,
    {
        let mut input_queue = if let Some(wait_queues) = self.wait_queue_map.get_mut(&socket_handle)
        {
            ::std::mem::replace(f(wait_queues), vec![])
        } else {
            vec![]
        };

        let mut to_retain = vec![];

        for wait_handle in input_queue.drain(..) {
            let mut packet = wait_handle.packet;
            self.handle(&mut packet);
            if packet.a == (-syscall::EWOULDBLOCK) as usize {
                match wait_handle.until {
                    Some(until)
                        if (until.tv_sec >= cur_time.tv_sec
                            || (until.tv_sec == cur_time.tv_sec
                                && until.tv_nsec >= cur_time.tv_nsec)) =>
                    {
                        trace!("Timeouting fd {}", packet.b);
                        packet.a = (-syscall::ETIMEDOUT) as usize;
                        self.scheme_file.write_all(&packet)?;
                    }
                    _ => {
                        to_retain.push(wait_handle);
                    }
                }
            } else {
                trace!("Waking up fd {}", packet.b);
                self.scheme_file.write_all(&packet)?;
            }
        }

        if let Some(wait_queues) = self.wait_queue_map.get_mut(&socket_handle) {
            f(wait_queues).extend(to_retain);
        }

        Ok(())
    }

    fn handle_block(&mut self, mut packet: syscall::Packet) -> Result<()> {
        trace!("Handling blocking call");
        let syscall_result = self.try_handle_block(&mut packet);
        if let Err(syscall_error) = syscall_result {
            packet.a = (-syscall_error.errno) as usize;
            self.scheme_file.write_all(&packet)?;
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
            let handle = self.fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            if let SchemeFile::Socket(ref scheme_file) = *handle {
                Ok((
                    scheme_file.socket_handle,
                    scheme_file.read_timeout,
                    scheme_file.write_timeout,
                ))
            } else {
                Err(syscall::Error::new(syscall::EBADF))
            }
        }?;

        let mut timeout = match packet.a {
            syscall::SYS_READ => Ok(read_timeout),
            syscall::SYS_WRITE => Ok(write_timeout),
            _ => Err(syscall::Error::new(syscall::EBADF)),
        }?;

        if let Some(ref mut timeout) = timeout {
            let mut cur_time = TimeSpec::default();
            syscall::clock_gettime(syscall::CLOCK_MONOTONIC, &mut cur_time)?;
            *timeout = add_time(timeout, &cur_time)
        }

        trace!("Adding {} to wait queie", fd);
        let wait_queues = self.wait_queue_map
            .entry(socket_handle)
            .or_insert_with(|| WaitQueues::default());

        let queue = match packet.a {
            syscall::SYS_READ => Ok(&mut wait_queues.read_queue),
            syscall::SYS_WRITE => Ok(&mut wait_queues.write_queue),
            _ => Err(syscall::Error::new(syscall::EBADF)),
        }?;

        queue.push(WaitHandle {
            until: timeout,
            packet: *packet,
        });

        Ok(())
    }

    fn get_setting(
        &mut self,
        fd: usize,
        setting: SocketT::SettingT,
        buf: &mut [u8],
    ) -> syscall::Result<usize> {
        let handle = self.fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let handle = match *handle {
            SchemeFile::Socket(ref mut handle) => handle,
            _ => {
                return Err(syscall::Error::new(syscall::EBADF));
            }
        };

        SocketT::get_setting(handle, setting, buf)
    }

    fn update_setting(
        &mut self,
        fd: usize,
        setting: SocketT::SettingT,
        buf: &[u8],
    ) -> syscall::Result<usize> {
        let handle = self.fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        let handle = match *handle {
            SchemeFile::Socket(ref mut handle) => handle,
            _ => {
                return Err(syscall::Error::new(syscall::EBADF));
            }
        };
        SocketT::set_setting(handle, setting, buf)
    }
}

impl<SocketT> syscall::SchemeMut for SocketScheme<SocketT>
where
    SocketT: SchemeSocket,
    Socket<'static, 'static>: AsSocket<SocketT>,
{
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> syscall::Result<usize> {
        let path = str::from_utf8(url).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;

        let (socket, data) = SocketT::new_socket(path, uid, &mut self.scheme_data)?;

        let socket_handle = self.socket_set.borrow_mut().add(socket);
        let id = self.next_fd;

        self.fds.insert(
            id,
            SchemeFile::Socket(SocketFile {
                flags,
                events: 0,
                socket_handle,
                write_timeout: None,
                read_timeout: None,
                data,
            }),
        );
        self.next_fd += 1;
        Ok(id)
    }

    fn close(&mut self, fd: usize) -> syscall::Result<usize> {
        let socket_handle = {
            let handle = self.fds
                .get(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            handle.socket_handle()
        };
        let scheme_file = self.fds.remove(&fd);
        let mut socket_set = self.socket_set.borrow_mut();
        if let Some(scheme_file) = scheme_file {
            let socket: &mut SocketT = socket_set.get_mut(socket_handle).as_socket();
            socket.close_file(&scheme_file, &mut self.scheme_data)?;
        }
        let remove_wq =
            if let Some(ref mut wait_queues) = self.wait_queue_map.get_mut(&socket_handle) {
                wait_queues.read_queue.retain(
                    |&WaitHandle {
                         packet: syscall::Packet { a, .. },
                         ..
                     }| a != fd,
                );
                wait_queues.write_queue.retain(
                    |&WaitHandle {
                         packet: syscall::Packet { a, .. },
                         ..
                     }| a != fd,
                );
                wait_queues.read_queue.is_empty() && wait_queues.write_queue.is_empty()
            } else {
                false
            };
        if remove_wq {
            self.wait_queue_map.remove(&socket_handle);
        }
        socket_set.release(socket_handle);
        //TODO: removing sockets in release should make prune unnecessary
        socket_set.prune();
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        let (fd, setting) = {
            let handle = self.fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            match *handle {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut handle) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket: &mut SocketT = socket_set.get_mut(handle.socket_handle).as_socket();

                    return <SocketT as SchemeSocket>::write_buf(socket, handle, buf);
                }
            }
        };
        self.update_setting(fd, setting, buf)
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> syscall::Result<usize> {
        let (fd, setting) = {
            let handle = self.fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
            match *handle {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut handle) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket: &mut SocketT = socket_set.get_mut(handle.socket_handle).as_socket();
                    return <SocketT as SchemeSocket>::read_buf(socket, handle, buf);
                }
            }
        };
        self.get_setting(fd, setting, buf)
    }

    fn dup(&mut self, fd: usize, buf: &[u8]) -> syscall::Result<usize> {
        let path = str::from_utf8(buf).or_else(|_| Err(syscall::Error::new(syscall::EINVAL)))?;

        let handle = {
            let handle = self.fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;

            let socket_handle = handle.socket_handle();
            let mut socket_set = self.socket_set.borrow_mut();
            let socket: &mut SocketT = socket_set.get_mut(handle.socket_handle()).as_socket();

            socket.dup(handle, fd, socket_handle, path, &mut self.scheme_data)
        }?;

        self.socket_set.borrow_mut().retain(handle.socket_handle());

        let id = self.next_fd;
        self.fds.insert(id, handle);
        self.next_fd += 1;

        Ok(id)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> syscall::Result<usize> {
        let handle = self.fds
            .get_mut(&fd)
            .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        match *handle {
            SchemeFile::Setting(_) => Err(syscall::Error::new(syscall::EBADF)),
            SchemeFile::Socket(ref mut handle) => {
                handle.events = events;
                Ok(fd)
            }
        }
    }

    fn fsync(&mut self, fd: usize) -> syscall::Result<usize> {
        {
            let _handle = self.fds
                .get_mut(&fd)
                .ok_or_else(|| syscall::Error::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }
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
