use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;
use std::str;

use libredox::flag::{self, CLOCK_MONOTONIC};
use syscall::{self, KSMSG_CANCEL};
use syscall::data::TimeSpec;
use syscall::flag::{EVENT_READ, EVENT_WRITE};
use syscall::{
    Error as SyscallError, EventFlags as SyscallEventFlags, Packet as SyscallPacket,
    Result as SyscallResult, SchemeBlockMut,
};

use super::Interface;
use crate::router::route_table::RouteTable;
use crate::scheme::smoltcp::iface::SocketHandle;
use redox_netstack::error::{Error, Result};
use smoltcp::socket::AnySocket;

use super::{post_fevent, SocketSet};

pub struct Context {
    pub iface: Interface,
    pub route_table: Rc<RefCell<RouteTable>>,
}

pub struct NullFile {
    pub flags: usize,
    pub uid: u32,
    pub gid: u32,
}

pub struct SocketFile<DataT> {
    pub flags: usize,
    pub data: DataT,

    events: usize,
    socket_handle: SocketHandle,
    read_notified: bool,
    write_notified: bool,
    read_timeout: Option<TimeSpec>,
    write_timeout: Option<TimeSpec>,
}

impl<DataT> SocketFile<DataT> {
    pub fn clone_with_data(&self, data: DataT) -> SocketFile<DataT> {
        SocketFile {
            flags: self.flags,
            events: self.events,
            read_notified: false, // we still want to notify about this new socket
            write_notified: false,
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
            read_notified: false,
            write_notified: false,
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
    #[allow(dead_code)]
    Other(SettingT),
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
            SchemeFile::Socket(SocketFile { socket_handle, .. })
            | SchemeFile::Setting(SettingFile { socket_handle, .. }) => socket_handle,
        }
    }

    pub fn events(&mut self, socket_set: &mut SocketSet) -> usize
    where
        SocketT: AnySocket<'static>,
    {
        let mut revents = 0;
        if let &mut SchemeFile::Socket(SocketFile {
            socket_handle,
            events,
            ref mut read_notified,
            ref mut write_notified,
            ..
        }) = self
        {
            let socket = socket_set.get::<SocketT>(socket_handle);

            if events & syscall::EVENT_READ.bits() == syscall::EVENT_READ.bits()
                && (socket.can_recv() || !socket.may_recv())
            {
                if !*read_notified {
                    *read_notified = true;
                    revents |= EVENT_READ.bits();
                }
            } else {
                *read_notified = false;
            }

            if events & syscall::EVENT_WRITE.bits() == syscall::EVENT_WRITE.bits()
                && socket.can_send()
            {
                if !*write_notified {
                    *write_notified = true;
                    revents |= EVENT_WRITE.bits();
                }
            } else {
                *write_notified = false;
            }
        }
        revents
    }
}

#[derive(Default, Clone)]
struct WaitHandle {
    until: Option<TimeSpec>,
    packet: SyscallPacket,
}

type WaitQueue = Vec<WaitHandle>;

pub type DupResult<T> = Option<(
    SchemeFile<T>,
    Option<(SocketHandle, <T as SchemeSocket>::DataT)>,
)>;

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
    fn may_recv(&self) -> bool;

    fn hop_limit(&self) -> u8;
    fn set_hop_limit(&mut self, hop_limit: u8);

    fn get_setting(
        file: &SocketFile<Self::DataT>,
        setting: Self::SettingT,
        buf: &mut [u8],
    ) -> SyscallResult<usize>;
    fn set_setting(
        file: &mut SocketFile<Self::DataT>,
        setting: Self::SettingT,
        buf: &[u8],
    ) -> SyscallResult<usize>;

    fn new_socket(
        sockets: &mut SocketSet,
        path: &str,
        uid: u32,
        data: &mut Self::SchemeDataT,
        context: &Context,
    ) -> SyscallResult<(SocketHandle, Self::DataT)>;

    fn close_file(
        &self,
        file: &SchemeFile<Self>,
        data: &mut Self::SchemeDataT,
    ) -> SyscallResult<()>;

    fn write_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &[u8],
    ) -> SyscallResult<Option<usize>>;

    fn read_buf(
        &mut self,
        file: &mut SocketFile<Self::DataT>,
        buf: &mut [u8],
    ) -> SyscallResult<Option<usize>>;

    fn fpath(&self, file: &SchemeFile<Self>, buf: &mut [u8]) -> SyscallResult<usize>;

    fn dup(
        sockets: &mut SocketSet,
        file: &mut SchemeFile<Self>,
        path: &str,
        data: &mut Self::SchemeDataT,
    ) -> SyscallResult<DupResult<Self>>;
}

pub struct SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static>,
{
    next_fd: usize,
    nulls: BTreeMap<usize, NullFile>,
    files: BTreeMap<usize, SchemeFile<SocketT>>,
    ref_counts: BTreeMap<SocketHandle, usize>,
    context: Context,
    socket_set: Rc<RefCell<SocketSet>>,
    scheme_file: File,
    wait_queue: WaitQueue,
    scheme_data: SocketT::SchemeDataT,
    _phantom_socket: PhantomData<SocketT>,
}

impl<SocketT> SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static>,
{
    pub fn new(
        iface: Interface,
        route_table: Rc<RefCell<RouteTable>>,
        socket_set: Rc<RefCell<SocketSet>>,
        scheme_file: File,
    ) -> SocketScheme<SocketT> {
        SocketScheme {
            next_fd: 1,
            nulls: BTreeMap::new(),
            files: BTreeMap::new(),
            ref_counts: BTreeMap::new(),
            socket_set,
            scheme_data: SocketT::new_scheme_data(),
            scheme_file,
            wait_queue: Vec::new(),
            _phantom_socket: PhantomData,
            context: Context { iface, route_table },
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        let result = loop {
            let mut packet = SyscallPacket::default();
            match self.scheme_file.read(&mut packet) {
                Ok(0) => {
                    //TODO: Cleanup must occur
                    break Some(());
                }
                Ok(_) => (),
                Err(err) => {
                    if err.kind() == ErrorKind::WouldBlock {
                        break None;
                    } else {
                        return Err(Error::from(err));
                    }
                }
            }
            if packet.a == KSMSG_CANCEL {
                println!("smolnetd: todo: handle cancellation");
                continue;
            }
            if let Some(a) = self.handle(&mut packet) {
                packet.a = a;
                self.scheme_file.write_all(&packet)?;
            } else {
                match self.handle_block(&mut packet) {
                    Ok(timeout) => {
                        self.wait_queue.push(WaitHandle {
                            until: timeout,
                            packet,
                        });
                    }
                    Err(err) => {
                        packet.a = (-err.errno) as usize;
                        self.scheme_file.write_all(&packet)?;
                        return Err(Error::from_syscall_error(
                            err,
                            "Can't handle blocked socket",
                        ));
                    }
                }
            }
        };
        Ok(result)
    }

    pub fn notify_sockets(&mut self) -> Result<()> {
        let cur_time = libredox::call::clock_gettime(flag::CLOCK_MONOTONIC)
            .map_err(|e| Error::from_syscall_error(e.into(), "Can't get time"))?;

        // Notify non-blocking sockets
        for (&fd, ref mut file) in &mut self.files {
            let events = {
                let mut socket_set = self.socket_set.borrow_mut();
                file.events(&mut socket_set)
            };
            if events > 0 {
                post_fevent(&mut self.scheme_file, fd, events, 1)?;
            }
        }

        // Wake up blocking queue
        let mut i = 0;
        while i < self.wait_queue.len() {
            let mut packet = self.wait_queue[i].packet;
            if let Some(a) = self.handle(&packet) {
                self.wait_queue.remove(i);
                packet.a = a;
                self.scheme_file.write_all(&packet)?;
            } else {
                match self.wait_queue[i].until {
                    Some(until)
                        if (until.tv_sec < cur_time.tv_sec
                            || (until.tv_sec == cur_time.tv_sec
                                && i64::from(until.tv_nsec) < i64::from(cur_time.tv_nsec))) =>
                    {
                        self.wait_queue.remove(i);
                        packet.a = (-syscall::ETIMEDOUT) as usize;
                        self.scheme_file.write_all(&packet)?;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_block(&mut self, packet: &mut SyscallPacket) -> SyscallResult<Option<TimeSpec>> {
        let fd = packet.b;
        let (read_timeout, write_timeout) = {
            let file = self
                .files
                .get(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            if let SchemeFile::Socket(ref scheme_file) = *file {
                Ok((scheme_file.read_timeout, scheme_file.write_timeout))
            } else {
                Err(SyscallError::new(syscall::EBADF))
            }
        }?;

        let mut timeout = match packet.a {
            syscall::SYS_WRITE => write_timeout,
            syscall::SYS_READ => read_timeout,
            _ => None,
        };

        if let Some(ref mut timeout) = timeout {
            let cur_time = libredox::call::clock_gettime(CLOCK_MONOTONIC)?;
            *timeout = add_time(timeout, &TimeSpec { tv_sec: cur_time.tv_sec, tv_nsec: cur_time.tv_nsec as i32 })
        }

        Ok(timeout)
    }

    fn get_setting(
        &mut self,
        fd: usize,
        setting: Setting<SocketT::SettingT>,
        buf: &mut [u8],
    ) -> SyscallResult<usize> {
        let file = self
            .files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        let file = match *file {
            SchemeFile::Socket(ref mut file) => file,
            _ => {
                return Err(SyscallError::new(syscall::EBADF));
            }
        };

        match setting {
            Setting::Other(setting) => SocketT::get_setting(file, setting, buf),
            Setting::Ttl => {
                if let Some(hop_limit) = buf.get_mut(0) {
                    let socket_set = self.socket_set.borrow();
                    let socket = socket_set.get::<SocketT>(file.socket_handle);
                    *hop_limit = socket.hop_limit();
                    Ok(1)
                } else {
                    Err(SyscallError::new(syscall::EIO))
                }
            }
            Setting::ReadTimeout | Setting::WriteTimeout => {
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
        let file = self
            .files
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
                if let Some(hop_limit) = buf.get(0) {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket = socket_set.get_mut::<SocketT>(file.socket_handle);
                    socket.set_hop_limit(*hop_limit);
                    Ok(1)
                } else {
                    Err(SyscallError::new(syscall::EIO))
                }
            }
            Setting::Other(setting) => SocketT::set_setting(file, setting, buf),
        }
    }
}

impl<SocketT> syscall::SchemeBlockMut for SocketScheme<SocketT>
where
    SocketT: SchemeSocket + AnySocket<'static>,
{
    fn open(
        &mut self,
        path: &str,
        flags: usize,
        uid: u32,
        _gid: u32,
    ) -> SyscallResult<Option<usize>> {
        if path.is_empty() {
            let null = NullFile {
                flags,
                uid,
                gid: _gid,
            };

            let id = self.next_fd;
            self.next_fd += 1;

            self.nulls.insert(id, null);

            Ok(Some(id))
        } else {
            let (socket_handle, data) = SocketT::new_socket(
                &mut self.socket_set.borrow_mut(),
                path,
                uid,
                &mut self.scheme_data,
                &self.context,
            )?;

            let file = SchemeFile::Socket(SocketFile {
                flags,
                events: 0,
                socket_handle,
                read_notified: false,
                write_notified: false,
                write_timeout: None,
                read_timeout: None,
                data,
            });

            let id = self.next_fd;
            self.next_fd += 1;

            self.ref_counts.insert(socket_handle, 1);
            self.files.insert(id, file);

            Ok(Some(id))
        }
    }

    fn close(&mut self, fd: usize) -> SyscallResult<Option<usize>> {
        if let Some(_null) = self.nulls.remove(&fd) {
            return Ok(Some(0));
        }

        let socket_handle = {
            let file = self
                .files
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

        self.wait_queue.retain(
            |&WaitHandle {
                 packet: SyscallPacket { a, .. },
                 ..
             }| a != fd,
        );

        let remove = match self.ref_counts.entry(socket_handle) {
            Entry::Vacant(_) => {
                warn!("Closing a socket_handle with no ref");
                true
            }
            Entry::Occupied(mut e) => {
                if *e.get() == 0 {
                    warn!("Closing a socket_handle with no ref");
                    e.remove();
                    true
                } else {
                    *e.get_mut() -= 1;
                    if *e.get() == 0 {
                        e.remove();
                        true
                    } else {
                        false
                    }
                }
            }
        };

        if remove {
            socket_set.remove(socket_handle);
        }
        Ok(Some(0))
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<Option<usize>> {
        let (fd, setting) = {
            let file = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            match *file {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut file) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket = socket_set.get_mut::<SocketT>(file.socket_handle);
                    let ret = SocketT::write_buf(socket, file, buf);
                    match ret {
                        Ok(None) => {}
                        _ => file.write_notified = false,
                    }
                    return ret;
                }
            }
        };
        self.update_setting(fd, setting, buf).map(Some)
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<Option<usize>> {
        let (fd, setting) = {
            let file = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
            match *file {
                SchemeFile::Setting(ref setting_handle) => {
                    (setting_handle.fd, setting_handle.setting)
                }
                SchemeFile::Socket(ref mut file) => {
                    let mut socket_set = self.socket_set.borrow_mut();
                    let socket = socket_set.get_mut::<SocketT>(file.socket_handle);
                    
                    let ret = SocketT::read_buf(socket, file, buf);
                    match ret {
                        Ok(None) => {}
                        _ => file.read_notified = false
                    }

                    return ret;
                }
            }
        };
        self.get_setting(fd, setting, buf).map(Some)
    }

    fn dup(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<Option<usize>> {
        let path = str::from_utf8(buf).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;

        if let Some((flags, uid, gid)) = self
            .nulls
            .get(&fd)
            .map(|null| (null.flags, null.uid, null.gid))
        {
            return self.open(path, flags, uid, gid);
        }

        let new_file = {
            let file = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            let socket_handle = file.socket_handle();

            let (new_handle, update_with) = match path {
                "hop_limit" => (
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
                _ => match SocketT::dup(
                    &mut self.socket_set.borrow_mut(),
                    file,
                    path,
                    &mut self.scheme_data,
                )? {
                    Some(some) => some,
                    None => return Ok(None),
                },
            };

            if let Some((socket_handle, data)) = update_with {
                if let SchemeFile::Socket(ref mut file) = *file {
                    // We replace the socket_handle pointed by file so update the ref_counts
                    // accordingly
                    self.ref_counts
                        .entry(file.socket_handle)
                        .and_modify(|e| *e = e.saturating_sub(1))
                        .or_insert(0);

                    *self.ref_counts.entry(socket_handle).or_insert(0) += 1;

                    file.socket_handle = socket_handle;
                    file.data = data;
                }
            }
            *self
                .ref_counts
                .entry(new_handle.socket_handle())
                .or_insert(0) += 1;
            new_handle
        };

        let id = self.next_fd;
        self.files.insert(id, new_file);
        self.next_fd += 1;

        Ok(Some(id))
    }

    fn fevent(
        &mut self,
        fd: usize,
        events: SyscallEventFlags,
    ) -> SyscallResult<Option<SyscallEventFlags>> {
        let file = self
            .files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        match *file {
            SchemeFile::Setting(_) => return Err(SyscallError::new(syscall::EBADF)),
            SchemeFile::Socket(ref mut file) => {
                file.events = events.bits();
                file.read_notified = false; // resend missed events
                file.write_notified = false;
            }
        }
        let mut socket_set = self.socket_set.borrow_mut();
        let revents = SyscallEventFlags::from_bits_truncate(file.events(&mut socket_set));
        Ok(Some(revents))
    }

    fn fsync(&mut self, fd: usize) -> SyscallResult<Option<usize>> {
        {
            let _file = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        }
        Ok(Some(0))
        // TODO Implement fsyncing
        // self.0.network_fsync()
    }

    fn fpath(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<Option<usize>> {
        let file = self
            .files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        let socket_set = self.socket_set.borrow();
        let socket = socket_set.get::<SocketT>(file.socket_handle());

        socket.fpath(file, buf).map(Some)
    }

    fn fcntl(&mut self, fd: usize, cmd: usize, arg: usize) -> SyscallResult<Option<usize>> {
        if let Some(ref mut null) = self.nulls.get_mut(&fd) {
            match cmd {
                syscall::F_GETFL => Ok(Some(null.flags)),
                syscall::F_SETFL => {
                    null.flags = arg & !syscall::O_ACCMODE;
                    Ok(Some(0))
                }
                _ => Err(SyscallError::new(syscall::EINVAL)),
            }
        } else {
            let file = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

            if let SchemeFile::Socket(ref mut socket_file) = *file {
                match cmd {
                    syscall::F_GETFL => Ok(Some(socket_file.flags)),
                    syscall::F_SETFL => {
                        socket_file.flags = arg & !syscall::O_ACCMODE;
                        Ok(Some(0))
                    }
                    _ => Err(SyscallError::new(syscall::EINVAL)),
                }
            } else {
                Err(SyscallError::new(syscall::EBADF))
            }
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
