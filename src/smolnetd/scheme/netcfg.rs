use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str;
use std::str::FromStr;
use std::rc::Rc;
use std::iter::FromIterator;
use smoltcp::wire::{EthernetAddress, Ipv4Address};
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

    fn read(&self) -> Vec<u8> {
        vec![]
    }

    fn write(&self, _buf: &[u8]) -> SyscallResult<usize> {
        Ok(0)
    }

    fn open(&self, _file: &str) -> Option<CfgNodeRef> {
        None
    }
}

struct RONode<F>
where
    F: Fn() -> Vec<u8>,
{
    read_fun: F,
}

impl<F> CfgNode for RONode<F>
where
    F: Fn() -> Vec<u8>,
{
    fn read(&self) -> Vec<u8> {
        (self.read_fun)()
    }
}

impl<F> RONode<F>
where
    F: 'static + Fn() -> Vec<u8>,
{
    fn new(read_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(RONode { read_fun }))
    }
}

struct WONode<F>
where
    F: Fn(&[u8]) -> SyscallResult<usize>,
{
    write_fun: F,
}

impl<F> CfgNode for WONode<F>
where
    F: Fn(&[u8]) -> SyscallResult<usize>,
{
    fn write(&self, buf: &[u8]) -> SyscallResult<usize> {
        (self.write_fun)(buf)
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl<F> WONode<F>
where
    F: 'static + Fn(&[u8]) -> SyscallResult<usize>,
{
    fn new(write_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(WONode { write_fun }))
    }
}

struct RWNode<F, G>
where
    F: Fn() -> Vec<u8>,
    G: Fn(&[u8]) -> SyscallResult<usize>,
{
    read_fun: F,
    write_fun: G,
}

impl<F, G> CfgNode for RWNode<F, G>
where
    F: Fn() -> Vec<u8>,
    G: Fn(&[u8]) -> SyscallResult<usize>,
{
    fn read(&self) -> Vec<u8> {
        (self.read_fun)()
    }

    fn write(&self, buf: &[u8]) -> SyscallResult<usize> {
        (self.write_fun)(buf)
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl<F, G> RWNode<F, G>
where
    F: 'static + Fn() -> Vec<u8>,
    G: 'static + Fn(&[u8]) -> SyscallResult<usize>,
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

    fn read(&self) -> Vec<u8> {
        let mut files = vec![];
        for child in self.child_nodes.keys() {
            if !files.is_empty() {
                files.push(b'\n');
            }
            files.extend(child.bytes());
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

fn parse_default_gw(buf: &[u8]) -> SyscallResult<Ipv4Address> {
    let value = str::from_utf8(buf).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
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

fn mk_route_node(iface: &Interface) -> CfgNodeRef {
    let iface_ = Rc::clone(iface);
    let route_list_node = RONode::new(move || {
        let default_route = if let Some(ip) = iface_.borrow().ipv4_gateway() {
            format!("default via {}\n", ip)
        } else {
            String::new()
        };
        Vec::from_iter(default_route.bytes())
    });
    let iface_ = Rc::clone(iface);
    let route_add_node = WONode::new(move |buf: &[u8]| -> SyscallResult<usize> {
        let default_gw = parse_default_gw(buf)?;
        iface_.borrow_mut().set_ipv4_gateway(Some(default_gw));
        Ok(0)
    });
    let iface_ = Rc::clone(iface);
    let route_rm_node = WONode::new(move |buf: &[u8]| -> SyscallResult<usize> {
        let default_gw = parse_default_gw(buf)?;
        let mut iface = iface_.borrow_mut();
        if iface.ipv4_gateway() != Some(default_gw) {
            return Err(SyscallError::new(syscall::EINVAL));
        }
        iface.set_ipv4_gateway(None);
        Ok(0)
    });
    let mut route_child_nodes = BTreeMap::new();
    route_child_nodes.insert("list".to_owned(), route_list_node);
    route_child_nodes.insert("add".to_owned(), route_add_node);
    route_child_nodes.insert("rm".to_owned(), route_rm_node);
    StaticDirNode::new(route_child_nodes)
}

fn mk_iface_node(iface: &Interface) -> CfgNodeRef {
    let iface_ = Rc::clone(iface);
    let iface__ = Rc::clone(iface);
    let iface_mac_node = RWNode::new(
        move || Vec::from_iter(format!("{}\n", iface_.borrow().ethernet_addr()).bytes()),
        move |buf: &[u8]| -> SyscallResult<usize> {
            let value = str::from_utf8(buf).or_else(|_| Err(SyscallError::new(syscall::EINVAL)))?;
            let mac =
                EthernetAddress::from_str(value).map_err(|_| SyscallError::new(syscall::EINVAL))?;
            if !mac.is_unicast() {
                return Err(SyscallError::new(syscall::EINVAL));
            }
            iface__.borrow_mut().set_ethernet_addr(mac);
            Ok(0)
        },
    );
    let mut iface_child_nodes = BTreeMap::new();
    iface_child_nodes.insert("mac".to_owned(), iface_mac_node);
    StaticDirNode::new(iface_child_nodes)
}

fn mk_root_node(iface: Interface) -> CfgNodeRef {
    let route_node = mk_route_node(&iface);
    let mut ifaces_nodes = BTreeMap::new();

    ifaces_nodes.insert("eth0".to_owned(), mk_iface_node(&iface));
    let ifaces_node = StaticDirNode::new(ifaces_nodes);

    let mut root_child_nodes = BTreeMap::new();
    root_child_nodes.insert("route".to_owned(), route_node);
    root_child_nodes.insert("ifaces".to_owned(), ifaces_node);
    StaticDirNode::new(root_child_nodes)
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
        let read_buf = current_node.borrow().read();
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
        file.cfg_node.borrow().write(&file.write_buf)
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
