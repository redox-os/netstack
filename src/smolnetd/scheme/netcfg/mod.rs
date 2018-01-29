#[macro_use]
mod nodes;
mod notifier;

use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::rc::Rc;
use std::str::FromStr;
use std::str;
use syscall::data::Stat;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use self::nodes::*;
use self::notifier::*;
use redox_netstack::error::Result;
use super::{post_fevent, Interface};

const WRITE_BUFFER_MAX_SIZE: usize = 0xffff;

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
                rw [dns_config, notifier]
                || {
                    format!("{}\n", dns_config.borrow().name_server)
                }
                |name_server| {
                    let ip = Ipv4Address::from_str(name_server.trim())
                        .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                    if !ip.is_unicast() {
                        return Err(SyscallError::new(syscall::EINVAL));
                    }
                    dns_config.borrow_mut().name_server = ip;
                    notifier.borrow_mut().schedule_notify("resolv/nameserver");
                    Ok(0)
                }
            }
        },
        "route" => {
            "list" => {
                ro [iface] || {
                    if let Some(ip) = iface.borrow().ipv4_gateway() {
                        format!("default via {}\n", ip)
                    } else {
                        String::new()
                    }
                }
            },
            "add" => {
                wo [iface, notifier] |routes| {
                    let default_gw = parse_default_gw(routes)?;
                    iface.borrow_mut().set_ipv4_gateway(Some(default_gw));
                    notifier.borrow_mut().schedule_notify("route/list");
                    Ok(0)
                }
            },
            "rm" => {
                wo [iface, notifier] |routes| {
                    let default_gw = parse_default_gw(routes)?;
                    let mut iface = iface.borrow_mut();
                    if iface.ipv4_gateway() != Some(default_gw) {
                        return Err(SyscallError::new(syscall::EINVAL));
                    }
                    iface.set_ipv4_gateway(None);
                    notifier.borrow_mut().schedule_notify("route/list");
                    Ok(0)
                }
            }
        },
        "ifaces" => {
            "eth0" => {
                "mac" => {
                    rw [iface, notifier]
                    || {
                        format!("{}\n", iface.borrow().ethernet_addr())
                    }
                    |mac| {
                        let mac = mac.lines().next()
                            .ok_or_else(|| SyscallError::new(syscall::EINVAL))?;
                        let mac = EthernetAddress::from_str(mac).
                            map_err(|_| SyscallError::new(syscall::EINVAL))?;
                        if !mac.is_unicast() {
                            return Err(SyscallError::new(syscall::EINVAL));
                        }
                        iface.borrow_mut().set_ethernet_addr(mac);
                        notifier.borrow_mut().schedule_notify("ifaces/eth0/mac");
                        Ok(0)
                    }
                },
                "addr" => {
                    "list" => {
                        ro [iface] || {
                            let mut ips = String::new();
                            for cidr in iface.borrow().ip_addrs() {
                                ips += &format!("{}\n", cidr);
                            }
                            ips
                        }
                    },
                    "add" => {
                        wo [iface, notifier] |input| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().to_vec();
                            for cidr in input.lines() {
                                let cidr = IpCidr::from_str(cidr)
                                    .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                                if !cidr.address().is_unicast() {
                                    return Err(SyscallError::new(syscall::EINVAL));
                                }
                                cidrs.insert(0, cidr);
                            }
                            iface.update_ip_addrs(|s| {
                                *s = From::from(cidrs);
                            });
                            notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                            Ok(0)
                        }
                    },
                    "rm" => {
                        wo [iface, notifier] |input| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().to_vec();
                            for cidr in input.lines() {
                                let cidr = IpCidr::from_str(cidr)
                                    .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                                if !cidr.address().is_unicast() {
                                    return Err(SyscallError::new(syscall::EINVAL));
                                }
                                let pre_retain_len = cidrs.len();
                                cidrs.retain(|&c| c != cidr);
                                if pre_retain_len == cidrs.len() {
                                    return Err(SyscallError::new(syscall::EINVAL));
                                }
                            }
                            iface.update_ip_addrs(|s| {
                                *s = From::from(cidrs);
                            });
                            notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                            Ok(0)
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
    cfg_node: CfgNodeRef,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    pos: usize,
    uid: u32,
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
        loop {
            let mut packet = SyscallPacket::default();
            if self.scheme_file.read(&mut packet)? == 0 {
                break;
            }
            self.handle(&mut packet);
            self.scheme_file.write_all(&packet)?;
        }
        self.notify_scheduled_fds();
        Ok(None)
    }

    fn notify_scheduled_fds(&mut self) {
        let fds_to_notify = self.notifier.borrow_mut().get_notified_fds();
        for fd in fds_to_notify {
            let _ = post_fevent(&mut self.scheme_file, fd, syscall::EVENT_READ, 1);
        }
    }
}

impl SchemeMut for NetCfgScheme {
    fn open(&mut self, url: &[u8], _flags: usize, uid: u32, _gid: u32) -> SyscallResult<usize> {
        let path = str::from_utf8(url).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
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
        let read_buf = Vec::from(current_node.borrow().read());
        let fd = self.next_fd;
        trace!("open {} {}", fd, path);
        self.next_fd += 1;
        self.files.insert(
            fd,
            NetCfgFile {
                path: path.to_owned(),
                cfg_node: current_node,
                uid,
                pos: 0,
                read_buf,
                write_buf: vec![],
            },
        );
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        trace!("close {}", fd);
        if let Some(file) = self.files.remove(&fd) {
            self.notifier.borrow_mut().unsubscribe(&file.path, fd);
            let node = file.cfg_node.borrow();
            if node.is_writable() {
                let value = str::from_utf8(&file.write_buf)
                    .or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
                node.write(value)
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

        if file.uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }

        if (WRITE_BUFFER_MAX_SIZE - file.write_buf.len()) < buf.len() {
            return Err(SyscallError::new(syscall::EMSGSIZE));
        }
        file.write_buf.extend_from_slice(buf);
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
        let cfg_node = file.cfg_node.borrow();

        stat.st_mode = if cfg_node.is_dir() {
            MODE_DIR
        } else {
            MODE_FILE
        };
        if cfg_node.is_writable() {
            stat.st_mode |= 0o222;
        }
        if cfg_node.is_readable() {
            stat.st_mode |= 0o444;
        }
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = file.read_buf.len() as u64;

        Ok(0)
    }

    fn fevent(&mut self, fd: usize, events: usize) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        if events & syscall::EVENT_READ == syscall::EVENT_READ {
            self.notifier.borrow_mut().subscribe(&file.path, fd);
        } else {
            self.notifier.borrow_mut().unsubscribe(&file.path, fd);
        }
        Ok(fd)
    }
}
