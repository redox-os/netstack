use smoltcp::socket::{AnySocket, SocketHandle};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;
use std::str;
use syscall::data::TimeSpec;
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use error::{Error, Result};
use super::{SocketSet, post_fevent};

pub struct SocketFile<DataT> {
    pub flags: usize,
    pub data: DataT,

    events: usize,
    socket_handle: SocketHandle,
    read_timeout: Option<TimeSpec>,
    write_timeout: Option<TimeSpec>,
}

impl<DataT> SocketFile<DataT> {
    pub fn clone_with_data(&self, data: DataT) -> SocketFile<DataT> {
        SocketFile {
            flags: self.flags,
            events: self.events,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            socket_handle: self.socket_handle,
            data,
        }
    }

    pub fn new_with_data(socket_handle: SocketHandle, data: DataT) -> SocketFile<DataT> {
        SocketFile {
            flags: 0,
            events: 0,
            read_timeout: None,
            write_timeout: None,
            socket_handle,
            data,
        }
    }
}

#[derive(Copy, Clone)]
enum Setting<SettingT: Copy> {
    Ttl,
    ReadTimeout,
    WriteTimeout,
    #[allow(dead_code)] Other(SettingT),
}

pub struct SettingFile<SettingT: Copy> {
    fd: usize,
    socket_handle: SocketHandle,
    setting: Setting<SettingT>,
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
    pub fn socket_handle(&self) -> SocketHandle {
        match *self {
            SchemeFile::Socket(SocketFile { socket_handle, .. }) |
            SchemeFile::Setting(SettingFile { socket_handle, .. }) => socket_handle,
        }
    }
}

#[derive(Default, Clone)]
struct WaitHandle {
    until: Option<TimeSpec>,
    packet: SyscallPacket,
}

type WaitQueue = Vec<WaitHandle>;

type WaitQueueMap = BTreeMap<SocketHandle, WaitQueue>;

pub type DupResult<T> = (
    SchemeFile<T>,
    Option<(SocketHandle, <T as SchemeSocket>::DataT)>,
);

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

    fn ttl(&self) -> u8;
    fn set_ttl(&mut self, u8);

    fn get_setting(&SocketFile<Self::DataT>, Self::SettingT, &mut [u8]) -> SyscallResult<usize>;
    fn set_setting(&mut SocketFile<Self::DataT>, Self::SettingT, &[u8]) -> SyscallResult<usize>;

    fn new_socket(
        &mut SocketSet,
        &str,
        u32,
        &mut Self::SchemeDataT,
    ) -> SyscallResult<(SocketHandle, Self::DataT)>;

    fn close_file(&self, &SchemeFile<Self>, &mut Self::SchemeDataT) -> SyscallResult<()>;

    fn write_buf(&mut self, &mut SocketFile<Self::DataT>, buf: &[u8]) -> SyscallResult<usize>;

    fn read_buf(&mut self, &mut SocketFile<Self::DataT>, buf: &mut [u8]) -> SyscallResult<usize>;

    fn fpath(&self, &SchemeFile<Self>, &mut [u8]) -> SyscallResult<usize>;

    fn dup(
        &mut SocketSet,
        &mut SchemeFile<Self>,
        &str,
        &mut Self::SchemeDataT,
    ) -> SyscallResult<DupResult<Self>>;
}

pub struct SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static, 'static>,
{
    next_fd: usize,
    files: BTreeMap<usize, SchemeFile<SocketT>>,
    socket_set: Rc<RefCell<SocketSet>>,
    scheme_file: File,
    wait_queue_map: WaitQueueMap,
    scheme_data: SocketT::SchemeDataT,
    _phantom_socket: PhantomData<SocketT>,
}

impl<SocketT> SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static, 'static>,
{
    pub fn new(socket_set: Rc<RefCell<SocketSet>>, scheme_file: File) -> SocketScheme<SocketT> {
        SocketScheme {
            next_fd: 1,
            files: BTreeMap::new(),
            socket_set,
            scheme_data: SocketT::new_scheme_data(),
            scheme_file,
            wait_queue_map: BTreeMap::new(),
            _phantom_socket: PhantomData,
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = SyscallPacket::default();
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
        for (&fd, file) in &self.files {
            if let SchemeFile::Socket(SocketFile {
                socket_handle,
                events,
                ..
            }) = *file
            {
                let mut socket_set = self.socket_set.borrow_mut();
                let socket = socket_set.get::<SocketT>(socket_handle);

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
            self.wake_up_wait_queue(socket_handle, cur_time)?;
        }
        Ok(())
    }

    fn wake_up_wait_queue(
        &mut self,
        socket_handle: SocketHandle,
        cur_time: syscall::TimeSpec,
    ) -> Result<()> {
        let mut input_queue = if let Some(wait_queue) = self.wait_queue_map.get_mut(&socket_handle)
        {
            ::std::mem::replace(wait_queue, vec![])
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
                        if (until.tv_sec < cur_time.tv_sec
                            || (until.tv_sec == cur_time.tv_sec
                                && until.tv_nsec < cur_time.tv_nsec)) =>
                    {
                        packet.a = (-syscall::ETIMEDOUT) as usize;
                        self.scheme_file.write_all(&packet)?;
                    }
                    _ => {
                        to_retain.push(wait_handle);
                    }
                }
            } else {
                self.scheme_file.write_all(&packet)?;
            }
        }

        if let Some(wait_queue) = self.wait_queue_map.get_mut(&socket_handle) {
            wait_queue.extend(to_retain);
        }

        Ok(())
    }

    fn move_file_to_new_socket_handle(
        wait_queue_map: &mut WaitQueueMap,
        fd: usize,
        from: SocketHandle,
        to: SocketHandle,
    ) -> SyscallResult<()> {
        let mut to_move = vec![];

        if let Some(wait_queue) = wait_queue_map.get_mut(&from) {
            to_move = wait_queue
                .drain_filter(|wh| wh.packet.b == fd)
                .collect::<Vec<_>>();
        }

        wait_queue_map
            .entry(to)
            .or_insert_with(|| vec![])
            .extend(to_move);
        Ok(())
    }

    fn handle_block(&mut self, mut packet: SyscallPacket) -> Result<()> {
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

    fn try_handle_block(&mut self, packet: &mut SyscallPacket) -> SyscallResult<()> {
        let fd = packet.b;
        let (socket_handle, read_timeout, write_timeout) = {
            let file = self.files
                .get(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            if let SchemeFile::Socket(ref scheme_file) = *file {
                Ok((
                    scheme_file.socket_handle,
                    scheme_file.read_timeout,
                    scheme_file.write_timeout,
                ))
            } else {
                Err(SyscallError::new(syscall::EBADF))
            }
        }?;

        let mut timeout = match packet.a {
            syscall::SYS_WRITE => Ok(write_timeout),
            syscall::SYS_READ => Ok(read_timeout),
            _ => Ok(None),
        }?;

        if let Some(ref mut timeout) = timeout {
            let mut cur_time = TimeSpec::default();
            syscall::clock_gettime(syscall::CLOCK_MONOTONIC, &mut cur_time)?;
            *timeout = add_time(timeout, &cur_time)
        }

        let wait_queue = self.wait_queue_map
            .entry(socket_handle)
            .or_insert_with(|| vec![]);

        wait_queue.push(WaitHandle {
            until: timeout,
            packet: *packet,
        });

        Ok(())
    }

    fn get_setting(
        &mut self,
        fd: usize,
        setting: Setting<SocketT::SettingT>,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        let file = match *file {
            SchemeFile::Socket(ref mut file) => file,
            _ => {
                return Err(SyscallError::new(syscall::EBADF));
            }
        };

        match setting {
            Setting::Other(setting) => {
                SocketT::get_setting(file, setting, buf)
            },
            Setting::Ttl => {
                if let Some(ttl) = buf.get_mut(0) {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket = socket_set.get::<SocketT>(file.socket_handle);
                    *ttl = socket.ttl();
                    Ok(1)
                } else {
                    Err(SyscallError::new(syscall::EIO))
                }
            },
            Setting::ReadTimeout |
            Setting::WriteTimeout => {
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
                        SyscallError::new(err.raw_os_error().unwrap_or(syscall::EIO))
                    })?;
                    Ok(count)
                }
            }
        }
    }

    fn update_setting(
        &mut self,
        fd: usize,
        setting: Setting<SocketT::SettingT>,
        buf: &[u8],
    ) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        let file = match *file {
            SchemeFile::Socket(ref mut file) => file,
            _ => {
                return Err(SyscallError::new(syscall::EBADF));
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
                            SyscallError::new(err.raw_os_error().unwrap_or(syscall::EIO))
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
                Ok(count)
            }
            Setting::Ttl => {
                if let Some(ttl) = buf.get(0) {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let mut socket = socket_set.get::<SocketT>(file.socket_handle);
                    socket.set_ttl(*ttl);
                    Ok(1)
                } else {
                    Err(SyscallError::new(syscall::EIO))
                }
            }
            Setting::Other(setting) => SocketT::set_setting(file, setting, buf),
        }
    }
}

impl<SocketT> syscall::SchemeMut for SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static, 'static>,
{
    fn open(&mut self, url: &[u8], flags: usize, uid: u32, _gid: u32) -> SyscallResult<usize> {
        let path = str::from_utf8(url).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;

        let (socket_handle, data) = SocketT::new_socket(
            &mut self.socket_set.borrow_mut(),
            path,
            uid,
            &mut self.scheme_data,
        )?;

        let id = self.next_fd;

        self.files.insert(
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

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        let socket_handle = {
            let file = self.files
                .get(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
            file.socket_handle()
        };
        let scheme_file = self.files.remove(&fd);
        let mut socket_set = self.socket_set.borrow_mut();
        if let Some(scheme_file) = scheme_file {
            let socket = socket_set.get::<SocketT>(socket_handle);
            socket.close_file(&scheme_file, &mut self.scheme_data)?;
        }
        let remove_wq =
            if let Some(ref mut wait_queue) = self.wait_queue_map.get_mut(&socket_handle) {
                wait_queue.retain(
                    |&WaitHandle {
                         packet: SyscallPacket { a, .. },
                         ..
                     }| a != fd,
                );
                wait_queue.is_empty()
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

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        let (fd, setting) = {
            let file = self.files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            match *file {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut file) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let mut socket = socket_set.get::<SocketT>(file.socket_handle);
                    return SocketT::write_buf(&mut socket, file, buf);
                }
            }
        };
        self.update_setting(fd, setting, buf)
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        let (fd, setting) = {
            let file = self.files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
            match *file {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut file) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let mut socket = socket_set.get::<SocketT>(file.socket_handle);
                    return SocketT::read_buf(&mut socket, file, buf);
                }
            }
        };
        self.get_setting(fd, setting, buf)
    }

    fn dup(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        let path = str::from_utf8(buf).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;

        let new_file = {
            let file = self.files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            let socket_handle = file.socket_handle();

            let (new_handle, update_with) = match path {
                "ttl" => (
                    SchemeFile::Setting(SettingFile {
                        socket_handle,
                        fd,
                        setting: Setting::Ttl,
                    }),
                    None,
                ),
                "read_timeout" => (
                    SchemeFile::Setting(SettingFile {
                        socket_handle,
                        fd,
                        setting: Setting::ReadTimeout,
                    }),
                    None,
                ),
                "write_timeout" => (
                    SchemeFile::Setting(SettingFile {
                        socket_handle,
                        fd,
                        setting: Setting::WriteTimeout,
                    }),
                    None,
                ),
                _ => SocketT::dup(
                    &mut self.socket_set.borrow_mut(),
                    file,
                    path,
                    &mut self.scheme_data,
                )?,
            };

            if let Some((socket_handle, data)) = update_with {
                if let SchemeFile::Socket(ref mut file) = *file {
                    Self::move_file_to_new_socket_handle(
                        &mut self.wait_queue_map,
                        fd,
                        file.socket_handle,
                        socket_handle,
                    )?;
                    file.socket_handle = socket_handle;
                    file.data = data;
                } else {
                    self.socket_set.borrow_mut().retain(file.socket_handle());
                }
            } else {
                self.socket_set.borrow_mut().retain(file.socket_handle());
            }
            new_handle
        };

        let id = self.next_fd;
        self.files.insert(id, new_file);
        self.next_fd += 1;

        Ok(id)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        match *file {
            SchemeFile::Setting(_) => Err(SyscallError::new(syscall::EBADF)),
            SchemeFile::Socket(ref mut file) => {
                file.events = events;
                Ok(fd)
            }
        }
    }

    fn fsync(&mut self, fd: usize) -> SyscallResult<usize> {
        {
            let _file = self.files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        }
        Ok(0)
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }

    fn fpath(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        let mut socket_set = self.socket_set.borrow_mut();
        let socket = socket_set.get::<SocketT>(file.socket_handle());

        socket.fpath(file, buf)
    }

    fn fcntl(&mut self, fd: usize, cmd: usize, arg: usize) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if let SchemeFile::Socket(ref mut socket_file) = *file {
            match cmd {
                syscall::F_GETFL => Ok(socket_file.flags),
                syscall::F_SETFL => {
                    socket_file.flags = arg & !syscall::O_ACCMODE;
                    Ok(0)
                }
                _ => Err(SyscallError::new(syscall::EINVAL)),
            }
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
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
