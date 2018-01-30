use std::rc::Rc;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::btree_map::Entry;

pub struct Notifier {
    listeners: BTreeMap<String, BTreeSet<usize>>,
    notified: BTreeSet<usize>,
}

pub type NotifierRef = Rc<RefCell<Notifier>>;

impl Notifier {
    pub fn new_ref() -> NotifierRef {
        Rc::new(RefCell::new(Notifier {
            listeners: BTreeMap::new(),
            notified: BTreeSet::new(),
        }))
    }

    pub fn subscribe(&mut self, path: &str, fd: usize) {
        trace!("Sub fd {} to {}", fd, path);
        match self.listeners.entry(path.to_owned()) {
            Entry::Occupied(mut e) => {
                e.get_mut().insert(fd);
            }
            Entry::Vacant(e) => {
                let mut fds = BTreeSet::new();
                fds.insert(fd);
                e.insert(fds);
            }
        }
    }

    pub fn unsubscribe(&mut self, path: &str, fd: usize) {
        let empty = if let Some(fds) = self.listeners.get_mut(path) {
            if fds.remove(&fd) {
                trace!("Unsub fd {} from {}", fd, path);
            }
            fds.is_empty()
        } else {
            false
        };
        if empty {
            self.listeners.remove(path);
        }
    }

    pub fn schedule_notify(&mut self, path: &str) {
        trace!("Notifying {}", path);
        if let Some(fds) = self.listeners.get(path) {
            self.notified.extend(fds);
        }
    }

    pub fn get_notified_fds(&mut self) -> BTreeSet<usize> {
        use std::mem::swap;
        let mut notified = BTreeSet::new();
        swap(&mut self.notified, &mut notified);
        notified
    }
}
