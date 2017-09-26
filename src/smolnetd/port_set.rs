use std::collections::btree_map::{BTreeMap, Entry};

pub struct PortSet {
    from: u16,
    range: u16,
    next: u16,
    ports: BTreeMap<u16, usize>,
}

impl PortSet {
    pub fn new(from: u16, to: u16) -> Option<PortSet> {
        if from > to {
            return None;
        }
        Some(PortSet {
            from,
            range: to - from + 1,
            next: 0,
            ports: BTreeMap::new(),
        })
    }

    pub fn get_port(&mut self) -> Option<u16> {
        if self.ports.len() >= self.range as usize {
            return None;
        }

        let port = loop {
            if let Entry::Vacant(entry) = self.ports.entry(self.next) {
                entry.insert(1);
                let port = self.from + self.next;
                self.next = self.next.wrapping_add(1);
                break port;
            }
            self.next = self.next.wrapping_add(1);
        };

        Some(port)
    }

    pub fn claim_port(&mut self, port: u16) -> bool {
        if let Entry::Vacant(entry) = self.ports.entry(port) {
            entry.insert(1);
            true
        } else {
            false
        }
    }

    pub fn acquire_port(&mut self, port: u16) {
        *self.ports.entry(port).or_insert(0) += 1;
    }

    pub fn release_port(&mut self, port: u16) {
        if let Entry::Occupied(mut entry) = self.ports.entry(port) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }
}
