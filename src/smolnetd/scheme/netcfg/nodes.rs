use std::cell::RefCell;
use std::rc::Rc;
use std::collections::BTreeMap;
use syscall::Result as SyscallResult;

pub type CfgNodeRef = Rc<RefCell<dyn CfgNode>>;

pub trait NodeWriter {
    fn write_line(&mut self, _: &str) -> SyscallResult<()> {
        Ok(())
    }

    fn commit(&mut self) -> SyscallResult<()> {
        Ok(())
    }
}

pub struct SimpleWriter<T, WL, C>
where
    WL: 'static + Fn(&mut T, &str) -> SyscallResult<()>,
    C: 'static + Fn(&mut T) -> SyscallResult<()>,
{
    data: T,
    write_line: WL,
    commit: C,
}

impl<T, WL, C> NodeWriter for SimpleWriter<T, WL, C>
where
    WL: 'static + Fn(&mut T, &str) -> SyscallResult<()>,
    C: 'static + Fn(&mut T) -> SyscallResult<()>,
{
    fn write_line(&mut self, line: &str) -> SyscallResult<()> {
        (self.write_line)(&mut self.data, line)
    }

    fn commit(&mut self) -> SyscallResult<()> {
        (self.commit)(&mut self.data)
    }
}

impl<T, WL, C> SimpleWriter<T, WL, C>
where
    WL: 'static + Fn(&mut T, &str) -> SyscallResult<()>,
    C: 'static + Fn(&mut T) -> SyscallResult<()>,
{
    pub fn new_boxed(data: T, write_line: WL, commit: C) -> Box<Self> {
        Box::new(SimpleWriter {
            data,
            write_line,
            commit,
        })
    }
}

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

    fn open(&self, _file: &str) -> Option<CfgNodeRef> {
        None
    }

    fn new_writer(&self) -> Option<Box<dyn NodeWriter>> {
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

pub struct WONode<W>
where
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    new_writer: W,
}

impl<W> CfgNode for WONode<W>
where
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    fn is_readable(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        true
    }

    fn new_writer(&self) -> Option<Box<dyn NodeWriter>> {
        Some((self.new_writer)())
    }
}

impl<W> WONode<W>
where
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    pub fn new_ref(new_writer: W) -> CfgNodeRef {
        Rc::new(RefCell::new(WONode { new_writer }))
    }
}

pub struct RWNode<F, W>
where
    F: Fn() -> String,
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    read_fun: F,
    new_writer: W,
}

impl<F, W> CfgNode for RWNode<F, W>
where
    F: Fn() -> String,
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    fn read(&self) -> String {
        (self.read_fun)()
    }

    fn is_writable(&self) -> bool {
        true
    }

    fn new_writer(&self) -> Option<Box<dyn NodeWriter>> {
        Some((self.new_writer)())
    }
}

impl<F, W> RWNode<F, W>
where
    F: 'static + Fn() -> String,
    W: 'static + Fn() -> Box<dyn NodeWriter>,
{
    pub fn new_ref(read_fun: F, new_writer: W) -> CfgNodeRef {
        Rc::new(RefCell::new(RWNode {
            read_fun,
            new_writer,
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
    (wo [ $($c:ident),* ] ( $et:ty , $e:expr ) |$data_i:ident, $line_i:ident|
     $write_line:block |$data_i2:ident| $commit:block) => {
        {
            $(#[allow(unused_variables)] let $c = $c.clone();)*
            let new_writer = move || -> Box<dyn NodeWriter> {
                let write_line = {
                    $(#[allow(unused_variables)] let $c = $c.clone();)*
                    move |$data_i: &mut $et, $line_i: &str| $write_line
                };
                let commit = {
                    $(#[allow(unused_variables)] let $c = $c.clone();)*
                    move |$data_i2: &mut $et| $commit
                };
                let data: $et = $e;
                SimpleWriter::new_boxed(data, write_line, commit)
            };
            WONode::new_ref(new_writer)
        }
    };
    (rw [ $($c:ident),* ] ( $et:ty , $e:expr ) || $read_fun:block |$data_i:ident, $line_i:ident|
     $write_line:block |$data_i2:ident| $commit:block) => {
        {
            let read_fun = {
                $(#[allow(unused_variables)] let $c = $c.clone();)*
                move || $read_fun
            };
            $(#[allow(unused_variables)] let $c = $c.clone();)*
            let new_writer = move || -> Box<dyn NodeWriter> {
                let write_line = {
                    $(#[allow(unused_variables)] let $c = $c.clone();)*
                    move |$data_i: &mut $et, $line_i: &str| $write_line
                };
                let commit = {
                    $(#[allow(unused_variables)] let $c = $c.clone();)*
                    move |$data_i2: &mut $et| $commit
                };
                let data: $et = $e;
                SimpleWriter::new_boxed(data, write_line, commit)
            };
            RWNode::new_ref(read_fun, new_writer)
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
