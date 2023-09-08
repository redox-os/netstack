use std::fmt::Display;
use std::rc::Rc;

use smoltcp::wire::{IpAddress, IpCidr};

#[derive(Debug)]
pub struct Rule {
    pub filter: IpCidr,
    pub via: Option<IpAddress>,
    pub dev: Rc<str>,
    pub src: IpAddress,
}

impl Rule {
    pub fn new(filter: IpCidr, via: Option<IpAddress>, dev: Rc<str>, src: IpAddress) -> Self {
        Self {
            filter,
            via,
            dev,
            src,
        }
    }
}

impl Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.filter.prefix_len() == 0 {
            write!(f, "default")?;
        } else {
            write!(f, "{} ", self.filter)?;
        }

        if let Some(via) = self.via {
            write!(f, " via {}", via)?;
        }

        write!(f, " dev {}", self.dev)?;
        write!(f, " src {}", self.src)?;

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RouteTable {
    rules: Vec<Rule>,
}

impl RouteTable {
    pub fn lookup_rule(&self, dst: &IpAddress) -> Option<&Rule> {
        self.rules
            .iter()
            .rev()
            .find(|rule| rule.filter.contains_addr(dst))
    }

    pub fn lookup_src_addr(&self, dst: &IpAddress) -> Option<IpAddress> {
        Some(self.lookup_rule(dst)?.src)
    }

    pub fn lookup_gateway(&self, dst: &IpAddress) -> Option<IpAddress> {
        self.lookup_rule(dst)?.via
    }

    pub fn lookup_device(&self, dst: &IpAddress) -> Option<Rc<str>> {
        Some(self.lookup_rule(dst)?.dev.clone())
    }

    pub fn insert_rule(&mut self, new_rule: Rule) {
        let i = match self
            .rules
            .binary_search_by_key(&new_rule.filter.prefix_len(), |rule| {
                rule.filter.prefix_len()
            }) {
            Ok(i) | Err(i) => i,
        };
        self.rules.insert(i, new_rule);
    }

    pub fn remove_rule(&mut self, filter: IpCidr) {
        self.rules.retain(|rule| rule.filter != filter);
    }

    pub fn change_src(&mut self, old_src: IpAddress, new_src: IpAddress) {
        for rule in self.rules.iter_mut().filter(|rule| rule.src == old_src) {
            rule.src = new_src;
        }
    }
}

impl Display for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for rule in self.rules.iter() {
            writeln!(f, "{}", rule)?;
        }

        Ok(())
    }
}
