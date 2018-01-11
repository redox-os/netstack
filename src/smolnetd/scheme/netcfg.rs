// use managed::ManagedSlice;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str;
use std::str::FromStr;
use std::rc::Rc;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};
use syscall::data::Stat;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use error::Result;
use super::Interface;

const WRITE_BUFFER_MAX_SIZE: usize = 0xffff;

type CfgNodeRef = Rc<RefCell<CfgNode>>;

trait CfgNode {
    fn is_dir(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_readable(&self) -> bool {
        true
    }

    fn read(&self) -> String {
        String::new()
    }

    fn write(&self, _buf: &str) -> SyscallResult<usize> {
        Ok(0)
    }

    fn open(&self, _file: &str) -> Option<CfgNodeRef> {
        None
    }
}

struct RONode<F>
where
    F: Fn() -> String,
{
    read_fun: F,
}

impl<F> CfgNode for RONode<F>
where
    F: Fn() -> String,
{
    fn read(&self) -> String {
        (self.read_fun)()
    }
}

impl<F> RONode<F>
where
    F: 'static + Fn() -> String,
{
    fn new(read_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(RONode { read_fun }))
    }
}

struct WONode<F>
where
    F: Fn(&str) -> SyscallResult<usize>,
{
    write_fun: F,
}

impl<F> CfgNode for WONode<F>
where
    F: Fn(&str) -> SyscallResult<usize>,
{
    fn write(&self, buf: &str) -> SyscallResult<usize> {
        (self.write_fun)(buf)
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl<F> WONode<F>
where
    F: 'static + Fn(&str) -> SyscallResult<usize>,
{
    fn new(write_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(WONode { write_fun }))
    }
}

struct RWNode<F, G>
where
    F: Fn() -> String,
    G: Fn(&str) -> SyscallResult<usize>,
{
    read_fun: F,
    write_fun: G,
}

impl<F, G> CfgNode for RWNode<F, G>
where
    F: Fn() -> String,
    G: Fn(&str) -> SyscallResult<usize>,
{
    fn read(&self) -> String {
        (self.read_fun)()
    }

    fn write(&self, buf: &str) -> SyscallResult<usize> {
        (self.write_fun)(buf)
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl<F, G> RWNode<F, G>
where
    F: 'static + Fn() -> String,
    G: 'static + Fn(&str) -> SyscallResult<usize>,
{
    fn new(read_fun: F, write_fun: G) -> CfgNodeRef {
        Rc::new(RefCell::new(RWNode {
            read_fun,
            write_fun,
        }))
    }
}

struct StaticDirNode {
    child_nodes: BTreeMap<String, CfgNodeRef>,
}

impl CfgNode for StaticDirNode {
    fn is_dir(&self) -> bool {
        true
    }

    fn read(&self) -> String {
        let mut files = String::new();
        for child in self.child_nodes.keys() {
            if !files.is_empty() {
                files.push('\n');
            }
            files += child;
        }
        files
    }

    fn open(&self, file: &str) -> Option<CfgNodeRef> {
        self.child_nodes.get(file).map(|node| Rc::clone(node))
    }
}

impl StaticDirNode {
    pub fn new(child_nodes: BTreeMap<String, CfgNodeRef>) -> CfgNodeRef {
        Rc::new(RefCell::new(StaticDirNode { child_nodes }))
    }
}

macro_rules! cfg_node {
    (val $e:expr) => {
        $e
    };
    (ro [ $($c:ident)* ] || $b:block ) => {
        {
            $(let $c = $c.clone();)*
            RONode::new(move|| $b)
        }
    };
    (wo [ $($c:ident)* ] |$i:ident| $b:block ) => {
        {
            $(let $c = $c.clone();)*
            WONode::new(move |$i: &str| $b)
        }
    };
    (rw [ $($c:ident)* ] || $rb:block |$i:ident| $wb:block ) => {
        {
            let read_fun = {
                $(let $c = $c.clone();)*
                move || $rb
            };
            let write_fun = {
                $(let $c = $c.clone();)*
                move |$i: &str| $wb
            };
            RWNode::new(read_fun, write_fun)
        }
    };
    ($($e:expr => { $($t:tt)* }),* $(,)*) => {
        {
            let mut children = BTreeMap::new();
            $(children.insert($e.into(), cfg_node!($($t)*));)*
            StaticDirNode::new(children)
        }
    };
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

fn mk_root_node(iface: Interface) -> CfgNodeRef {
    cfg_node!{
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
                wo [iface] |routes| {
                    let default_gw = parse_default_gw(routes)?;
                    iface.borrow_mut().set_ipv4_gateway(Some(default_gw));
                    Ok(0)
                }
            },
            "rm" => {
                wo [iface] |routes| {
                    let default_gw = parse_default_gw(routes)?;
                    let mut iface = iface.borrow_mut();
                    if iface.ipv4_gateway() != Some(default_gw) {
                        return Err(SyscallError::new(syscall::EINVAL));
                    }
                    iface.set_ipv4_gateway(None);
                    Ok(0)
                }
            }
        },
        "ifaces" => {
            "eth0" => {
                "mac" => {
                    rw [iface]
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
                        wo [iface] |input| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().iter().cloned().collect::<Vec<_>>();
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
                            Ok(0)
                        }
                    },
                    "rm" => {
                        wo [iface] |input| {
                            let mut iface = iface.borrow_mut();
                            let mut cidrs = iface.ip_addrs().iter().cloned().collect::<Vec<_>>();
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
                            Ok(0)
                        }
                    },
                }
            }
        }
    }
}

struct NetCfgFile {
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
}

impl NetCfgScheme {
    pub fn new(iface: Interface, scheme_file: File) -> NetCfgScheme {
        NetCfgScheme {
            scheme_file,
            next_fd: 1,
            files: BTreeMap::new(),
            root_node: mk_root_node(iface),
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
        Ok(None)
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
        self.next_fd += 1;
        self.files.insert(
            fd,
            NetCfgFile {
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
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        let value =
            str::from_utf8(&file.write_buf).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
        file.cfg_node.borrow().write(&value)
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
}
