use std::cell::RefCell;
use std::rc::Rc;
use std::collections::BTreeMap;
use syscall::Result as SyscallResult;

pub type CfgNodeRef = Rc<RefCell<CfgNode>>;

pub trait CfgNode {
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

pub struct RONode<F>
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
    pub fn new_ref(read_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(RONode { read_fun }))
    }
}

pub struct WONode<F>
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

    fn is_readable(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl<F> WONode<F>
where
    F: 'static + Fn(&str) -> SyscallResult<usize>,
{
    pub fn new_ref(write_fun: F) -> CfgNodeRef {
        Rc::new(RefCell::new(WONode { write_fun }))
    }
}

pub struct RWNode<F, G>
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
    pub fn new_ref(read_fun: F, write_fun: G) -> CfgNodeRef {
        Rc::new(RefCell::new(RWNode {
            read_fun,
            write_fun,
        }))
    }
}

pub struct StaticDirNode {
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
    pub fn new_ref(child_nodes: BTreeMap<String, CfgNodeRef>) -> CfgNodeRef {
        Rc::new(RefCell::new(StaticDirNode { child_nodes }))
    }
}

macro_rules! cfg_node {
    (val $e:expr) => {
        $e
    };
    (ro [ $($c:ident),* ] || $b:block ) => {
        {
            $(let $c = $c.clone();)*
            RONode::new_ref(move|| $b)
        }
    };
    (wo [ $($c:ident),* ] |$i:ident| $b:block ) => {
        {
            $(let $c = $c.clone();)*
            WONode::new_ref(move |$i: &str| $b)
        }
    };
    (rw [ $($c:ident),* ] || $rb:block |$i:ident| $wb:block ) => {
        {
            let read_fun = {
                $(#[allow(unused_variables)] let $c = $c.clone();)*
                move || $rb
            };
            let write_fun = {
                $(#[allow(unused_variables)] let $c = $c.clone();)*
                move |$i: &str| $wb
            };
            RWNode::new_ref(read_fun, write_fun)
        }
    };
    ($($e:expr => { $($t:tt)* }),* $(,)*) => {
        {
            let mut children = BTreeMap::new();
            $(children.insert($e.into(), cfg_node!($($t)*));)*
            StaticDirNode::new_ref(children)
        }
    };
}
