use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::str;
use std::rc::Rc;
use std::iter::FromIterator;
use syscall::data::Stat;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::{Error as SyscallError, Packet as SyscallPacket, Result as SyscallResult, SchemeMut};
use syscall;

use error::Result;
use super::Interface;

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

    fn write(&mut self, _buf: &[u8]) -> Option<usize> {
        None
    }

    fn open(&self, _file: &str) -> Option<CfgNodeRef> {
        None
    }

    fn close(&mut self) {}
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

struct RootNode {
    route_node: CfgNodeRef,
    iface_nodes: BTreeMap<String, CfgNodeRef>,
}

impl RootNode {
    pub fn new(iface: Interface) -> RootNode {
        let route_list_node = RONode::new(move || {
            let default_route = if let Some(ip) = iface.borrow().ipv4_gateway() {
                format!("default via {}\n", ip)
            } else {
                String::new()
            };
            Vec::from_iter(default_route.bytes())
        });
        let mut route_child_nodes = BTreeMap::new();
        route_child_nodes.insert("list".to_owned(), route_list_node);
        let route_node = StaticDirNode::new(route_child_nodes);
        let iface_nodes = BTreeMap::new();
        // let eth0_node: CfgNodeRef = Rc::new(RefCell::new(IfaceNode::new(iface)));
        // iface_nodes.insert("eth0".to_owned(), eth0_node);
        RootNode {
            route_node,
            iface_nodes,
        }
    }
}

impl CfgNode for RootNode {
    fn is_dir(&self) -> bool {
        true
    }

    fn open(&self, file: &str) -> Option<CfgNodeRef> {
        match file {
            "route" => Some(Rc::clone(&self.route_node)),
            _ => self.iface_nodes.get(file).map(|node| Rc::clone(node)),
        }
    }

    fn read(&self) -> Vec<u8> {
        let mut files = vec![];
        files.extend_from_slice(b"route");
        for iface in self.iface_nodes.keys() {
            files.push(b'\n');
            files.extend(iface.bytes());
        }
        files
    }
}

struct NetCfgFile {
    cfg_node: CfgNodeRef,
    data: Option<Vec<u8>>,
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
            root_node: Rc::new(RefCell::new(RootNode::new(iface))),
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
        let fd = self.next_fd;
        self.next_fd += 1;
        self.files.insert(
            fd,
            NetCfgFile {
                cfg_node: current_node,
                uid,
                pos: 0,
                data: None,
            },
        );
        Ok(fd)
    }

    fn close(&mut self, fd: usize) -> SyscallResult<usize> {
        self.files
            .get(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?
            .cfg_node
            .borrow_mut()
            .close();
        self.files.remove(&fd);
        Ok(0)
    }

    fn write(&mut self, fd: usize, buf: &[u8]) -> SyscallResult<usize> {
        let file = self.files
            .get(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        if file.uid != 0 {
            return Err(SyscallError::new(syscall::EACCES));
        }
        file.cfg_node
            .borrow_mut()
            .write(buf)
            .ok_or_else(|| SyscallError::new(syscall::EINVAL))
    }

    fn read(&mut self, fd: usize, buf: &mut [u8]) -> SyscallResult<usize> {
        let file = self.files
            .get_mut(&fd)
            .ok_or_else(|| SyscallError::new(syscall::EBADF))?;
        if file.data.is_none() {
            file.data = Some(file.cfg_node.borrow().read())
        }
        if let Some(ref data) = file.data {
            let mut i = 0;
            while i < buf.len() && file.pos < data.len() {
                buf[i] = data[file.pos];
                i += 1;
                file.pos += 1;
            }
            return Ok(i);
        }
        Err(SyscallError::new(syscall::EINVAL))
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

        if file.data.is_none() {
            file.data = Some(file.cfg_node.borrow().read())
        }
        if let Some(ref data) = file.data {
            stat.st_size = data.len() as u64;
        } else {
            stat.st_size = 0;
        }

        Ok(0)
    }
}
