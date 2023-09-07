#[macro_use]
mod nodes;
mod notifier;

use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::rc::Rc;
use std::str;
use std::str::FromStr;
use syscall;
use syscall::data::Stat;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::{
    Error as SyscallError, EventFlags as SyscallEventFlags, Packet as SyscallPacket,
    Result as SyscallResult, SchemeMut,
};

use crate::link::DeviceList;
use crate::router::route_table::{RouteTable, Rule};

use self::nodes::*;
use self::notifier::*;
use super::{post_fevent, Interface};
use redox_netstack::error::{Error, Result};

const WRITE_BUFFER_MAX_SIZE: usize = 0xffff;

fn gateway_cidr() -> IpCidr {
    // TODO: const fn
    IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0)
}

fn parse_route(value: &str, route_table: &RouteTable) -> SyscallResult<Rule> {
    let mut parts = value.split_whitespace();
    let cidr_str = parts.next().ok_or(SyscallError::new(syscall::EINVAL))?;
    let cidr = match cidr_str {
        "default" => gateway_cidr(),
        cidr_str => cidr_str
            .parse()
            .map_err(|_| SyscallError::new(syscall::EINVAL))?,
    };

    let via: IpAddress = match parts.next().ok_or(SyscallError::new(syscall::EINVAL))? {
        "via" => parts
            .next()
            .ok_or(SyscallError::new(syscall::EINVAL))?
            .parse()
            .map_err(|_| SyscallError::new(syscall::EINVAL))?,
        _ => return Err(SyscallError::new(syscall::EINVAL)),
    };

    if !via.is_unicast() {
        return Err(SyscallError::new(syscall::EINVAL));
    }

    let rule = route_table
        .lookup_rule(&via)
        .ok_or(SyscallError::new(syscall::EINVAL))?;

    Ok(Rule::new(cidr, Some(via), rule.dev.clone(), rule.src))
}

fn mk_root_node(
    iface: Interface,
    notifier: NotifierRef,
    dns_config: DNSConfigRef,
    route_table: Rc<RefCell<RouteTable>>,
    devices: Rc<RefCell<DeviceList>>,
) -> CfgNodeRef {
    cfg_node! {
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
                ro [route_table] || {
                    format!("{}", route_table.borrow())
                }
            },
            "add" => {
                wo [iface, notifier, route_table] (Option<Rule>, None)
                |cur_value, line| {
                    if cur_value.is_none() {
                        let route = parse_route(line, &route_table.borrow())?;
                        *cur_value = Some(route);
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
                |cur_value| {
                    if let Some(route) = cur_value.take() {
                        route_table.borrow_mut().insert_rule(route);
                        notifier.borrow_mut().schedule_notify("route/list");
                        Ok(())
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
            },
            "rm" => {
                wo [iface, notifier, route_table] (Option<IpCidr>, None)
                |cur_value, line| {
                    if cur_value.is_none() {
                        match line.parse() {
                            Ok(cidr) => {
                                *cur_value = Some(cidr);
                                Ok(())
                            }
                            Err(_) => Err(SyscallError::new(syscall::EINVAL))
                        }
                    } else {
                        Err(SyscallError::new(syscall::EINVAL))
                    }
                }
                |cur_value| {
                    if let Some(cidr) = *cur_value {
                        route_table.borrow_mut().remove_rule(cidr);
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
                    rw [iface, notifier, devices] (Option<EthernetAddress>, None)
                    || {
                        match devices.borrow().get("eth0") {
                            Some(dev) => {
                                match dev.mac_address() {
                                    Some(addr) => format!("{addr}\n"),
                                    None => "Not configured\n".into(),
                                }
                            }
                            None => "Device not found\n".into(),
                        }
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
                            if let Some(dev) = devices.borrow_mut().get_mut("eth0") {
                                dev.set_mac_address(mac);
                                notifier.borrow_mut().schedule_notify("ifaces/eth0/mac");
                            }
                        }
                        Ok(())
                    }
                },
                "addr" => {
                    "list" => {
                        ro [devices]
                        || {
                            let res = match devices.borrow().get("eth0") {
                                Some(dev) => {
                                    match dev.ip_address() {
                                        Some(addr) => format!("{addr}\n"),
                                        None => "Not configured\n".into(),
                                    }
                                }
                                None => "Device not found\n".into(),
                            };
                            res
                        }
                    },
                    "set" => {
                        wo [iface, notifier, devices, route_table] (Option<IpCidr>, None)
                        |cur_value, line| {
                            if cur_value.is_none() {
                                let cidr = IpCidr::from_str(line)
                                    .map_err(|_| SyscallError::new(syscall::EINVAL))?;
                                if !cidr.address().is_unicast() {
                                    return Err(SyscallError::new(syscall::EINVAL));
                                }
                                *cur_value = Some(cidr);
                                Ok(())
                            } else {
                                Err(SyscallError::new(syscall::EINVAL))
                            }
                        }
                        |cur_value| {
                            // TODO: Multiple IPs
                            if let Some(cidr) = cur_value.take() {
                                if let Some(dev) = devices.borrow_mut().get_mut("eth0") {

                                    let mut route_table = route_table.borrow_mut();
                                    if let Some(old_addr) = dev.ip_address() {
                                        let IpCidr::Ipv4(old_v4_cidr) = old_addr;
                                        let old_network = IpCidr::Ipv4(old_v4_cidr.network());

                                        route_table.remove_rule(old_network);
                                        route_table.change_src(old_addr.address(), cidr.address());
                                        iface.borrow_mut().update_ip_addrs(|addrs| addrs.retain(|addr| *addr != old_addr))
                                    }

                                    dev.set_ip_address(cidr);
                                    // FIXME: Here, the insert 0 is a workaround to let UDP sockets
                                    // work with this interface only.
                                    // Smoltcp takes the first ip address when looking for a source 
                                    // ip address when sending UDP packets.
                                    // This behavior will have to be fixed as it's our route table
                                    // job to find give this source.
                                    iface.borrow_mut().update_ip_addrs(|addrs| addrs.insert(0, cidr).unwrap());

                                    let IpCidr::Ipv4(v4_cidr) = cidr;
                                    let network_cidr = IpCidr::Ipv4(v4_cidr.network());
                                    route_table.insert_rule(Rule::new(network_cidr, None, dev.name().clone(), cidr.address()))
                                }
                                notifier.borrow_mut().schedule_notify("ifaces/eth0/addr/list");
                                notifier.borrow_mut().schedule_notify("route/list");
                            }
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
    node_writer: Option<Box<dyn NodeWriter>>,
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
    pub fn new(
        iface: Interface,
        scheme_file: File,
        route_table: Rc<RefCell<RouteTable>>,
        devices: Rc<RefCell<DeviceList>>,
    ) -> NetCfgScheme {
        let notifier = Notifier::new_ref();
        let dns_config = Rc::new(RefCell::new(DNSConfig {
            name_server: Ipv4Address::new(8, 8, 8, 8),
        }));
        NetCfgScheme {
            scheme_file,
            next_fd: 1,
            files: BTreeMap::new(),
            root_node: mk_root_node(
                iface,
                Rc::clone(&notifier),
                dns_config,
                route_table,
                devices,
            ),
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
                node_writer: if current_node.is_writable() {
                    current_node.new_writer()
                } else {
                    None
                },
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
        let file = self
            .files
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
        let file = self
            .files
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
        let file = self
            .files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;

        stat.st_mode = if file.is_dir { MODE_DIR } else { MODE_FILE };
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
        let file = self
            .files
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
        let file = self
            .files
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
