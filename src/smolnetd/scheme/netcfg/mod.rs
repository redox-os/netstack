#[macro_use]
mod nodes;
mod notifier;

use smoltcp::wire::{IpAddress, EthernetAddress, IpCidr, Ipv4Address};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::rc::Rc;
use std::mem;
use std::str::FromStr;
use std::str;
use syscall::data::Stat;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::{Error as SyscallError, EventFlags as SyscallEventFlags, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use self::nodes::*;
use self::notifier::*;
use redox_netstack::error::{Error, Result};
use super::{post_fevent, Interface};

const WRITE_BUFFER_MAX_SIZE: usize = 0xffff;

fn gateway_cidr() -> IpCidr {
    // TODO: const fn
    IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0)
}

fn parse_default_gw(value: &str) -> SyscallResult<Ipv4Address> {
    let mut routes = value.lines();
    if let Some(route) = routes.next() {
        if !routes.next().is_none() {
            return Err(SyscallError::new(syscall::EINVAL));
        }
        let mut words = route.split_whitespace();
        if let Some("default") = words.next() {
            if let Some("via") = words.next() {
                if let Some(ip) = words.next() {
                    return Ipv4Address::from_str(ip)
                        .map_err(|_| SyscallError::new(syscall::EINVAL));
                }
            }
        }
    }
    Err(SyscallError::new(syscall::EINVAL))
}

fn mk_root_node(iface: Interface, notifier: NotifierRef, dns_config: DNSConfigRef) -> CfgNodeRef {
    cfg_node!{
        "resolv" => {
            "nameserver" => {
                rw [dns_config, notifier] (Option<Ipv4Address>, None)
                || {
                    format!("{}\n", dns_config.borrow().name_server)
                }
                |cur_value, line| {
                    if cur_value.is_none() {
                        let ip = Ipv4Address::from_str(line.trim())
                            .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                        if !ip.is_unicast() {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        *cur_value = Some(ip);
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
                |cur_value| {
                    if let Some(ip) = *cur_value {
                        dns_config.borrow_mut().name_server = ip;
                        notifier.borrow_mut().schedule_notify("resolv/nameserver");
                    }
                    Ok(())
                }
            }
        },
        "route" => {
            "list" => {
                ro [iface] || {
                    let mut gateway = None;
                    iface.borrow_mut().routes_mut().update(|map| {
                        gateway = map.get(&gateway_cidr()).map(|route| route.via_router);
                    });
                    if let Some(ip) = gateway {
                        format!("default via {}\n", ip)
                    } else {
                        String::new()
                    }
                }
            },
            "add" => {
                wo [iface, notifier] (Option<Ipv4Address>, None)
                |cur_value, line| {
                    if cur_value.is_none() {
                        let default_gw = parse_default_gw(line)?;
                        if !default_gw.is_unicast() {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        *cur_value = Some(default_gw);
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
                |cur_value| {
                    if let Some(default_gw) = *cur_value {
                        if iface.borrow_mut().routes_mut().add_default_ipv4_route(default_gw).is_err() {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        notifier.borrow_mut().schedule_notify("route/list");
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
            },
            "rm" => {
                wo [iface, notifier] (Option<Ipv4Address>, None)
                |cur_value, line| {
                    if cur_value.is_none() {
                        let default_gw = parse_default_gw(line)?;
                        if !default_gw.is_unicast() {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        *cur_value = Some(default_gw);
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
                |cur_value| {
                    if let Some(default_gw) = *cur_value {
                        let mut iface = iface.borrow_mut();
                        let mut gateway = None;
                        iface.routes_mut().update(|map| {
                            gateway = map.get(&gateway_cidr()).map(|route| route.via_router);
                        });
                        if gateway != Some(IpAddress::Ipv4(default_gw)) {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        iface.routes_mut().update(|map| {
                            map.remove(&gateway_cidr());
                        });
                        notifier.borrow_mut().schedule_notify("route/list");
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
            },
        },
        "ifaces" => {
            "eth0" => {
                "mac" => {
                    rw [iface, notifier] (Option<EthernetAddress>, None)
                    || {
                        format!("{}\n", iface.borrow().ethernet_addr())
                    }
                    |cur_value, line| {
                        if cur_value.is_none() {
                            let mac = EthernetAddress::from_str(line).
                                map_err(|_| SyscallError::new(syscall::EINVAL))?;
                            if !mac.is_unicast() {
                                return Err(SyscallError::new(syscall::EINVAL));
                            }
                            *cur_value = Some(mac);
                            Ok(())
                        } else {
                            Err(SyscallError::new(syscall::EINVAL))
                        }
                    }
                    |cur_value| {
                        if let Some(mac) = *cur_value {
                            iface.borrow_mut().set_ethernet_addr(mac);
                            notifier.borrow_mut().schedule_notify("ifaces/eth0/mac");
                        }
                        Ok(())
                    }
                },
                "addr" => {
                    "list" => {
                        ro [iface]
                        || {
                            let mut ips = String::new();
                            for cidr in iface.borrow().ip_addrs() {
                                ips += &format!("{}\n", cidr);
                            }
                            ips
                        }
                    },
                    "set" => {
                        wo [iface, notifier] (Vec<IpCidr>, Vec::new())
                        |cur_value, line| {
                            let cidr = IpCidr::from_str(line)
                                .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                            if !cidr.address().is_unicast() {
                                return Err(SyscallError::new(syscall::EINVAL));
                            }
                            cur_value.push(cidr);
                            Ok(())
                        }
                        |cur_value| {
                            if !cur_value.is_empty() {
                                let mut iface = iface.borrow_mut();
                                let mut cidrs = vec![];
                                mem::swap(cur_value, &mut cidrs);
                                iface.update_ip_addrs(|s| {
                                    *s = From::from(cidrs);
                                });
                                notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                            }
                            Ok(())
                        }
                    },
                    "add" => {
                        wo [iface, notifier] (Vec<IpCidr>, Vec::new())
                        |cur_value, line| {
                            let cidr = IpCidr::from_str(line)
                                .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                            if !cidr.address().is_unicast() {
                                return Err(SyscallError::new(syscall::EINVAL));
                            }
                            cur_value.push(cidr);
                            Ok(())
                        }
                        |cur_value| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().to_vec();
                            for cidr in cur_value {
                                cidrs.insert(0, *cidr);
                            }
                            iface.update_ip_addrs(|s| {
                                *s = From::from(cidrs);
                            });
                            notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                            Ok(())
                        }
                    },
                    "rm" => {
                        wo [iface, notifier] (Vec<IpCidr>, Vec::new())
                        |cur_value, line| {
                            let cidr = IpCidr::from_str(line)
                                .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                            if !cidr.address().is_unicast() {
                                return Err(SyscallError::new(syscall::EINVAL));
                            }
                            cur_value.push(cidr);
                            Ok(())
                        }
                        |cur_value| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().to_vec();
                            for cidr in cur_value {
                                let pre_retain_len = cidrs.len();
                                cidrs.retain(|&c| c != *cidr);
                                if pre_retain_len == cidrs.len() {
                                    return Err(SyscallError::new(syscall::EINVAL));
                                }
                            }
                            iface.update_ip_addrs(|s| {
                                *s = From::from(cidrs);
                            });
                            notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                            Ok(())
                        }
                    },
                }
            }
        }
    }
}

struct DNSConfig {
    name_server: Ipv4Address,
}

type DNSConfigRef = Rc<RefCell<DNSConfig>>;

struct NetCfgFile {
    path: String,
    is_dir: bool,
    is_writable: bool,
    is_readable: bool,
    node_writer: Option<Box<NodeWriter>>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    pos: usize,
    uid: u32,
    done: bool,
}

impl NetCfgFile {
    fn commit(&mut self) -> SyscallResult<()> {
        if let Some(ref mut node_writer) = self.node_writer {
            if !self.write_buf.is_empty() {
                let line = str::from_utf8(&self.write_buf)
                    .or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
                node_writer.write_line(line)?;
            }
            node_writer.commit()?;
            self.write_buf.clear();
        }
        Ok(())
    }

    fn consume_lines(&mut self) -> SyscallResult<()> {
        if let Some(ref mut node_writer) = self.node_writer {
            let mut swap_with = None;
            {
                let mut lines = self.write_buf.split(|&c| c == b'\n');
                if let Some(mut cur_line) = lines.next() {
                    let mut consumed = false;
                    for next_line in lines {
                        let line = str::from_utf8(cur_line)
                            .or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
                        trace!("writing line {}", line);
                        node_writer.write_line(line)?;
                        cur_line = next_line;
                        consumed = true;
                    }
                    if consumed {
                        swap_with = Some(From::from(cur_line))
                    }
                }
            }
            if let Some(ref mut new_vec) = swap_with {
                mem::swap(&mut self.write_buf, new_vec);
            }
            Ok(())
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
    }
}

pub struct NetCfgScheme {
    scheme_file: File,
    next_fd: usize,
    files: BTreeMap<usize, NetCfgFile>,
    root_node: CfgNodeRef,
    notifier: NotifierRef,
}

impl NetCfgScheme {
    pub fn new(iface: Interface, scheme_file: File) -> NetCfgScheme {
        let notifier = Notifier::new_ref();
        let dns_config = Rc::new(RefCell::new(DNSConfig {
            name_server: Ipv4Address::new(8, 8, 8, 8),
        }));
        NetCfgScheme {
            scheme_file,
            next_fd: 1,
            files: BTreeMap::new(),
            root_node: mk_root_node(iface, Rc::clone(&notifier), dns_config),
            notifier,
        }
    }

    pub fn on_scheme_event(&mut self) -> Result<Option<()>> {
        let result = loop {
            let mut packet = SyscallPacket::default();
            match self.scheme_file.read(&mut packet) {
                Ok(0) => {
                    //TODO: Cleanup must occur
                    break Some(());
                },
                Ok(_) => (),
                Err(err) => if err.kind() == ErrorKind::WouldBlock {
                    break None;
                } else {
                    return Err(Error::from(err));
                }
            }
            self.handle(&mut packet);
            self.scheme_file.write_all(&packet)?;
        };
        self.notify_scheduled_fds();
        Ok(result)
    }

    fn notify_scheduled_fds(&mut self) {
        let fds_to_notify = self.notifier.borrow_mut().get_notified_fds();
        for fd in fds_to_notify {
            let _ = post_fevent(&mut self.scheme_file, fd, syscall::EVENT_READ.bits(), 1);
        }
    }
}

impl SchemeMut for NetCfgScheme {
    fn open(&mut self, path: &str, _flags: usize, uid: u32, _gid: u32) -> SyscallResult<usize> {
        let mut current_node = Rc::clone(&self.root_node);
        for part in path.split('/') {
            if part.is_empty() {
                continue;
            }
            let next_node = current_node
                .borrow_mut()
                .open(part)
                .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
            current_node = next_node;
        }
        let current_node = current_node.borrow();
        let read_buf = Vec::from(current_node.read());
        let fd = self.next_fd;
        trace!("open {} {}", fd, path);
        self.next_fd += 1;
        self.files.insert(
            fd,
            NetCfgFile {
                path: path.to_owned(),
                is_dir: current_node.is_dir(),
                is_writable: current_node.is_writable(),
                is_readable: current_node.is_readable(),
                node_writer: if current_node.is_writable() { current_node.new_writer() } else { None },
                uid,
                pos: 0,
                read_buf,
                write_buf: vec![],
                done: false,
            },
        );
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        trace!("close {}", fd);
        if let Some(mut file) = self.files.remove(&fd) {
            self.notifier.borrow_mut().unsubscribe(&file.path, fd);
            if !file.done {
                file.commit().map(|_| 0)
            } else {
                Ok(0)
            }
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if file.done {
            return Err(SyscallError::new(syscall::EBADF));
        }

        if file.uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }

        if (WRITE_BUFFER_MAX_SIZE - file.write_buf.len()) < buf.len() {
            return Err(SyscallError::new(syscall::EMSGSIZE));
        }

        file.write_buf.extend_from_slice(buf);

        if let Err(e) = file.consume_lines() {
            trace!("Failed write {} {}", fd, e);
            file.done = true;
            return Err(e);
        }

        Ok(buf.len())
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        let mut i = 0;
        while i < buf.len() && file.pos < file.read_buf.len() {
            buf[i] = file.read_buf[file.pos];
            i += 1;
            file.pos += 1;
        }
        Ok(i)
    }

    fn fstat(&mut self, fd: usize, stat: &mut Stat) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        stat.st_mode = if file.is_dir {
            MODE_DIR
        } else {
            MODE_FILE
        };
        if file.is_writable {
            stat.st_mode |= 0o222;
        }
        if file.is_readable {
            stat.st_mode |= 0o444;
        }
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = file.read_buf.len() as u64;

        Ok(0)
    }

    fn fevent(&mut self, fd: usize, events: SyscallEventFlags) -> SyscallResult<SyscallEventFlags> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        if events.contains(syscall::EVENT_READ) {
            self.notifier.borrow_mut().subscribe(&file.path, fd);
        } else {
            self.notifier.borrow_mut().unsubscribe(&file.path, fd);
        }
        Ok(SyscallEventFlags::empty())
    }

    fn fsync(&mut self, fd: usize) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        if !file.done {
            let res = file.commit().map(|_| 0);
            file.done = true;
            res
        } else {
            Err(SyscallError::new(syscall::EBADF))
        }
    }
}
